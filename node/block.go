package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/kwilteam/kwil-db/config"
	"github.com/kwilteam/kwil-db/core/log"
	ktypes "github.com/kwilteam/kwil-db/core/types"
	"github.com/kwilteam/kwil-db/node/peers"
	"github.com/kwilteam/kwil-db/node/types"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	blkReadLimit          = 300_000_000
	defaultBlkGetTimeout  = 90 * time.Second
	defaultBlkSendTimeout = 45 * time.Second
)

func (n *Node) blkGetStreamHandler(s network.Stream) {
	defer s.Close()

	s.SetReadDeadline(time.Now().Add(reqRWTimeout))

	var req blockHashReq
	if _, err := req.ReadFrom(s); err != nil {
		n.log.Debug("Bad get block (hash) request", "error", err)
		return
	}
	n.log.Debug("Peer requested block", "hash", req.Hash)

	blk, ci, err := n.bki.Get(req.Hash)
	if err != nil || ci == nil {
		s.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		s.Write(noData) // don't have it
	} else {
		rawBlk := ktypes.EncodeBlock(blk)
		ciBytes, _ := ci.MarshalBinary()
		s.SetWriteDeadline(time.Now().Add(defaultBlkSendTimeout))
		binary.Write(s, binary.LittleEndian, blk.Header.Height)
		ktypes.WriteCompactBytes(s, ciBytes)
		ktypes.WriteCompactBytes(s, rawBlk)

		mets.ServedBlock(context.Background(), blk.Header.Height, int64(len(rawBlk)))
	}
}

// blkGetHeightStreamHandler is the stream handler for ProtocolIDBlockHeight.
func (n *Node) blkGetHeightStreamHandler(s network.Stream) {
	defer s.Close()

	s.SetReadDeadline(time.Now().Add(reqRWTimeout))

	var req blockHeightReq
	if _, err := req.ReadFrom(s); err != nil {
		n.log.Warn("Bad get block (height) request", "error", err) // Debug when we ship
		return
	}
	n.log.Debug("Peer requested block", "height", req.Height)

	bestHeight, _, _, _ := n.bki.Best()

	hash, blk, ci, err := n.bki.GetByHeight(req.Height)
	if err != nil || ci == nil {
		s.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		s.Write(noData) // don't have it
		// also write our best height
		binary.Write(s, binary.LittleEndian, bestHeight)
	} else {
		rawBlk := ktypes.EncodeBlock(blk) // blkHash := blk.Hash()
		ciBytes, _ := ci.MarshalBinary()
		// maybe we remove hash from the protocol, was thinking receiver could
		// hang up earlier depending...
		s.SetWriteDeadline(time.Now().Add(defaultBlkSendTimeout))
		s.Write(withData)
		s.Write(hash[:])
		ktypes.WriteCompactBytes(s, ciBytes)
		ktypes.WriteCompactBytes(s, rawBlk)
		binary.Write(s, binary.LittleEndian, bestHeight)

		mets.ServedBlock(context.Background(), blk.Header.Height, int64(len(rawBlk)))
	}
}

func (n *Node) blkAnnStreamHandler(s network.Stream) {
	defer s.Close()

	if n.InCatchup() { // we are in catchup, don't accept new blocks
		n.log.Debug("in catchup, not accepting new block announcement messages")
		return
	}

	s.SetDeadline(time.Now().Add(defaultBlkGetTimeout + annRespTimeout + annWriteTimeout)) // combined
	ctx, cancel := context.WithTimeout(context.Background(), defaultBlkGetTimeout)
	defer cancel()

	var reqMsg blockAnnMsg
	if _, err := reqMsg.ReadFrom(s); err != nil {
		n.log.Warn("bad blk ann request", "error", err)
		return
	}

	height, blkHash, hdr, ci, sig := reqMsg.Height, reqMsg.Hash, reqMsg.Header, reqMsg.CommitInfo, reqMsg.LeaderSig
	blkid := blkHash.String()

	// TODO: also get and pass the signature to AcceptCommit to ensure it's
	// legit before we waste bandwidth on spam. We could also make the protocol
	// request the block header, and then CE checks block header.

	if height < 0 {
		n.log.Warn("invalid height in blk ann request", "height", height)
		return
	}

	peerID := s.Conn().RemotePeer()

	n.log.Debug("Accept commit?", "height", height, "blockID", blkid, "appHash", ci.AppHash,
		"from_peer", peers.PeerIDStringer(peerID)) // maybe debug level

	// If we are a validator and this is the commit ann for a proposed block
	// that we already started executing, consensus engine will handle it.
	if !n.ce.AcceptCommit(height, blkHash, hdr, ci, sig) {
		// this either means that the ce already has the block or it is not
		// ready to accept it yet.  In either case, we don't need to do anything
		// here.
		return
	}

	// Possibly ce will handle it regardless.  For now, below is block store
	// code like a sentry node might do.

	need, done := n.bki.PreFetch(blkHash)
	if !need {
		n.log.Debug("ALREADY HAVE OR FETCHING BLOCK")
		return // we have or are currently fetching it, do nothing, assuming we have already re-announced
	}
	var ceProcessing bool
	defer func() {
		if !ceProcessing {
			done() // we did not hand off to CE, release the pre-fetch lock
		}
	}()

	n.log.Debug("retrieving new block", "blockID", blkid)
	t0 := time.Now()

	// First try to get from this stream.
	rawBlk, err := request(s, []byte(getMsg), blkReadLimit)
	if err != nil {
		n.log.Warnf("announcer failed to provide %v due to error: %v, trying other peers", blkid, err)
		// Since we are aware, ask other peers. we could also put this in a goroutine
		s.Close() // close the announcers stream first
		var gotHeight int64
		var gotCI *ktypes.CommitInfo
		var id peer.ID
		gotHeight, rawBlk, gotCI, id, err = n.getBlkWithRetry(ctx, blkHash, 500*time.Millisecond, 10)
		if err != nil {
			n.log.Errorf("unable to retrieve tx %v: %v", blkid, err)
			return
		}
		if gotHeight != height {
			n.log.Errorf("getblk response had unexpected height: wanted %d, got %d", height, gotHeight)
			return
		}
		if gotCI != nil && gotCI.AppHash != ci.AppHash {
			n.log.Errorf("getblk response had unexpected appHash: wanted %v, got %v", ci.AppHash, gotCI.AppHash)
			return
		}
		// Ensure that the peerID from which the block was downloaded is a valid one.
		if id != "" {
			n.log.Errorf("getblk response had unexpected peerID: %v", id)
		}
		peerID = id
	}

	n.log.Debugf("obtained content for block %q in %v", blkid, time.Since(t0))

	blk, err := ktypes.DecodeBlock(rawBlk)
	if err != nil {
		n.log.Infof("decodeBlock failed for %v: %v", blkid, err)
		return
	}
	if blk.Header.Height != height {
		n.log.Infof("getblk response had unexpected height: wanted %d, got %d", height, blk.Header.Height)
		return
	}
	gotBlkHash := blk.Header.Hash()
	if gotBlkHash != blkHash {
		n.log.Infof("invalid block hash: wanted %v, got %x", blkHash, gotBlkHash)
		return
	}

	// re-announce
	n.log.Infof("downloaded block %v of height %d from %v, notifying ce of the block", blkid, height, peerID)
	ceProcessing = true // neuter the deferred done, CE will call it now
	n.ce.NotifyBlockCommit(blk, ci, blkHash, done)
	go func() {
		n.announceRawBlk(context.Background(), blkHash, height, rawBlk, blk.Header, ci, peerID, reqMsg.LeaderSig) // re-announce with the leader's signature
	}()
}

func (n *Node) announceBlk(ctx context.Context, blk *ktypes.Block, ci *ktypes.CommitInfo) {
	blkHash := blk.Hash()
	n.log.Debugln("announceBlk", blk.Header.Height, blkHash, ci.AppHash)
	rawBlk := ktypes.EncodeBlock(blk)
	from := n.host.ID() // this announcement originates from us (not a reannouncement)
	n.announceRawBlk(ctx, blkHash, blk.Header.Height, rawBlk, blk.Header, ci, from, blk.Signature)
}

func (n *Node) announceRawBlk(ctx context.Context, blkHash types.Hash, height int64,
	rawBlk []byte, hdr *ktypes.BlockHeader, ci *ktypes.CommitInfo, from peer.ID, blkSig []byte) {
	peers := n.peers()
	if len(peers) == 0 {
		n.log.Warn("No peers to advertise block to")
		return
	}

	for _, peerID := range peers {
		if peerID == from {
			continue
		}

		n.log.Debugf("advertising block %s (height %d / sz %d / updates %v) to peer %v",
			blkHash, height, len(rawBlk), ci.ParamUpdates, peerID)
		resID, err := blockAnnMsg{
			Hash:       blkHash,
			Height:     height,
			Header:     hdr,
			CommitInfo: ci,
			LeaderSig:  blkSig,
		}.MarshalBinary()
		if err != nil {
			n.log.Error("Unable to marshal block announcement", "error", err)
			continue
		}
		ann := contentAnn{cType: "block announce", ann: resID, content: rawBlk}
		err = n.advertiseToPeer(ctx, peerID, ProtocolIDBlkAnn, ann, defaultBlkSendTimeout)
		if err != nil {
			n.log.Warn("Failed to advertise block", "peer", peerID, "error", err)
			continue
		}
		n.log.Debugf("Advertised content %s to peer %s", ann, peerID)
	}
}

func (n *Node) getBlkWithRetry(ctx context.Context, blkHash types.Hash, baseDelay time.Duration,
	maxAttempts int) (int64, []byte, *ktypes.CommitInfo, peer.ID, error) {
	var attempts int
	for {
		height, raw, ci, peer, err := n.getBlk(ctx, blkHash)
		if err == nil {
			return height, raw, ci, peer, nil
		}

		n.log.Warnf("unable to retrieve block %v (%v), waiting to retry", blkHash, err)

		select {
		case <-ctx.Done():
		case <-time.After(baseDelay):
		}
		baseDelay *= 2
		attempts++
		if attempts >= maxAttempts {
			return 0, nil, nil, "", ErrBlkNotFound
		}
	}
}

func (n *Node) getBlk(ctx context.Context, blkHash types.Hash) (int64, []byte, *ktypes.CommitInfo, peer.ID, error) {
	for _, peer := range n.peers() {
		t0 := time.Now()
		resID, _ := blockHashReq{Hash: blkHash}.MarshalBinary()
		resp, err := requestFrom(ctx, n.host, peer, resID, ProtocolIDBlock, blkReadLimit)
		if errors.Is(err, ErrNotFound) {
			n.log.Info("block not available", "peer", peer, "hash", blkHash)
			continue
		}
		if errors.Is(err, ErrNoResponse) {
			n.log.Info("no response to block request", "peer", peer, "hash", blkHash)
			continue
		}
		if err != nil {
			n.log.Info("block request failed unexpectedly", "peer", peer, "hash", blkHash)
			continue
		}

		if len(resp) < 8 {
			n.log.Info("block response too short", "peer", peer, "hash", blkHash)
			continue
		}
		n.log.Debug("Obtained content for block", "block", blkHash, "elapsed", time.Since(t0))

		rd := bytes.NewReader(resp)
		var height int64
		if err := binary.Read(rd, binary.LittleEndian, &height); err != nil {
			n.log.Info("failed to read block height in the block response", "error", err)
			continue
		}

		ciBts, err := ktypes.ReadCompactBytes(rd)
		if err != nil {
			n.log.Info("failed to read commit info in the block response", "error", err)
			continue
		}

		var ci ktypes.CommitInfo
		if err = ci.UnmarshalBinary(ciBts); err != nil {
			n.log.Info("failed to unmarshal commit info", "error", err)
			continue
		}

		rawBlk, err := ktypes.ReadCompactBytes(rd)
		if err != nil {
			n.log.Info("failed to read block in the block response", "error", err)
			continue
		}

		mets.DownloadedBlock(context.Background(), height, int64(len(rawBlk)))

		return height, rawBlk, &ci, peer, nil
	}
	return 0, nil, nil, "", ErrBlkNotFound
}

func requestBlockHeight(ctx context.Context, host host.Host, peer peer.ID,
	height, readLimit int64, reqTimeout, recvTimeout, idleTimeout time.Duration) ([]byte, error) {

	resID, _ := blockHeightReq{Height: height}.MarshalBinary()
	stream, err := host.NewStream(ctx, peer, ProtocolIDBlockHeight)
	if err != nil {
		return nil, peers.CompressDialError(err)
	}
	defer stream.Close()

	stream.SetWriteDeadline(time.Now().Add(reqTimeout))

	_, err = stream.Write(resID)
	if err != nil {
		return nil, fmt.Errorf("resource get request failed: %w", err)
	}

	resource, err := readAll(stream, readLimit, time.Now().Add(recvTimeout), idleTimeout)
	if err != nil {
		return nil, err
	}
	if len(resource) < 2 { // empty, or just a flag without additional data
		return nil, ErrNoResponse
	}

	// The following convention allows returning extra data in the case that the
	// resource (the block contents) are not available. In this case, the peer's
	// best block. We may consider this more broadly for other protocols.

	flag, resource := resource[0], resource[1:]

	switch flag {
	case noData[0]:
		err := ErrBlkNotFound
		if len(resource) == 8 {
			h := int64(binary.LittleEndian.Uint64(resource))
			err = errors.Join(err, &ErrNotFoundWithBestHeight{
				BestHeight: h,
			})
		}
		return nil, err
	case withData[0]:
		return resource, nil
	default:
		return nil, fmt.Errorf("invalid flag %v in block height response", flag)
	}
}

// readAll reads from a stream until EOF or:
// - the stream is closed
// - the deadline is reached
// - the stream is idle (no chunk read) for idleTimeout
// - the total bytes read exceed the limit
func readAll(s network.Stream, limit int64, deadline time.Time, idleTimeout time.Duration) ([]byte, error) {
	r := io.LimitReader(s, limit)

	const readChunk = 512 // like io.ReadAll
	b := make([]byte, 0, readChunk)

	for {
		// Check absolute deadline for the entire resource.
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout")
		}

		// Set read deadline for this chunk.
		s.SetReadDeadline(time.Now().Add(idleTimeout))

		// The following is verbatim from io.ReadAll.
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n] // reslice past current length
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return b, err
		}

		// Add more capacity, to ensure space for another readChunk read.
		// This is modified from io.ReadAll.
		b = slices.Grow(b, readChunk) // handles: (cap - len) < readChunk
	}
}

func (n *Node) getBlkHeight(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
	return getBlkHeight(ctx, height, n.host, n.log, n.blockSyncCfg)
}

func getBlkHeight(ctx context.Context, height int64, host host.Host, log log.Logger, blockSyncCfg *config.BlockSyncConfig) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
	availablePeers := peerHosts(host)
	if len(availablePeers) == 0 {
		return types.Hash{}, nil, nil, 0, types.ErrPeersNotFound
	}

	cnt := max(len(availablePeers)/5, 1) // 20% of peers
	availablePeers = availablePeers[:cnt]
	// incremented when a peer's best height is one less than the requested height
	// to help determine if the block has not been committed yet and stop
	// requesting the block from other peers if enough peers indicate that the
	// block is not available.
	var bestHCount, notFoundCount int
	var bestHeight int64

	for _, peer := range availablePeers {
		if bestHCount == 5 {
			// stop requesting the block if there is an indication that
			// the block does not exist. i.e. 5 peers indicate that they don't have it
			break
		}

		t0 := time.Now()
		reqTimeout := 2 * time.Second
		recvTimeout := 20 * time.Second
		idleTimeout := 500 * time.Millisecond
		if blockSyncCfg != nil {
			reqTimeout = time.Duration(blockSyncCfg.RequestTimeout)
			recvTimeout = time.Duration(blockSyncCfg.ResponseTimeout)
			idleTimeout = time.Duration(blockSyncCfg.IdleTimeout)
		}
		resp, err := requestBlockHeight(ctx, host, peer, height, blkReadLimit, reqTimeout, recvTimeout, idleTimeout)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrBlkNotFound) {
			notFoundCount++
			be := new(ErrNotFoundWithBestHeight)
			if errors.As(err, &be) {
				theirBest := be.BestHeight
				if theirBest > bestHeight {
					bestHeight = theirBest
				}
				if theirBest == height-1 {
					bestHCount++
				}
				log.Infof("block %d not found on peer %s; their best height is %d", height, peer, theirBest)
			} else {
				log.Warnf("block not available on %v", peer)
			}
			continue
		}
		if errors.Is(err, ErrNoResponse) {
			log.Warnf("no response to block request to %v", peer)
			continue
		}
		if errors.Is(err, context.Canceled) {
			return types.Hash{}, nil, nil, 0, err
		}
		if err != nil {
			// e.g. "i/o deadline reached", probably network error
			log.Warnf("unexpected error from %v: %v", peer, err)
			continue
		}

		if len(resp) < types.HashLen+1 {
			log.Warnf("block response too short")
			continue
		}

		log.Debug("obtained block contents", "height", height, "elapsed", time.Since(t0))

		rd := bytes.NewReader(resp)
		var hash types.Hash

		if _, err := io.ReadFull(rd, hash[:]); err != nil {
			log.Warn("failed to read block hash in the block response", "error", err)
			continue
		}

		ciBts, err := ktypes.ReadCompactBytes(rd)
		if err != nil {
			log.Info("failed to read commit info in the block response", "error", err)
			continue
		}

		var ci ktypes.CommitInfo
		if err = ci.UnmarshalBinary(ciBts); err != nil {
			log.Warn("failed to unmarshal commit info", "error", err)
			continue
		}

		rawBlk, err := ktypes.ReadCompactBytes(rd)
		if err != nil {
			log.Warn("failed to read block in the block response", "error", err)
		}

		var theirBest int64
		err = binary.Read(rd, binary.LittleEndian, &theirBest)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Info("failed to read best block height", "error", err)
				continue
			} // else the peer didn't want to send it (this is backwards compatible)
		} else {
			if theirBest > bestHeight {
				bestHeight = theirBest
			}
		}

		mets.DownloadedBlock(context.Background(), height, int64(len(rawBlk)))

		return hash, rawBlk, &ci, bestHeight, nil
	}

	// Being here, we did not find the block on any peer, either because of
	// unexpected errors (network issues) or the peer(s) said "not found".

	if notFoundCount == 0 {
		// We got through the loop without a single definitive "not found"
		// response, which indicates that we hit a continue statement (error)
		// for each peer. Do NOT signal down the call stack that we believe the
		// block does not exist, as this may direct logic as if we are fully
		// synchronized, when in reality we should keep trying.
		return types.Hash{}, nil, nil, 0, errors.New("all peers failed")
	}

	err := ErrBlkNotFound
	if bestHeight > 0 {
		err = errors.Join(err, &ErrNotFoundWithBestHeight{BestHeight: bestHeight})
	}

	return types.Hash{}, nil, nil, 0, err
}

// ErrNotFoundWithBestHeight is an error that contains a BestHeight field, which
// is used when a block is not found, but the negative responses from peers
// contained their best height.
//
// Use with errors.As.  For example:
//
//	func heightFromErr(err error) int64 {
//		be := new(ErrNotFoundWithBestHeight)
//		if errors.As(err, &be) {
//			return be.BestHeight
//		}
//		return -1
//	}
type ErrNotFoundWithBestHeight struct {
	BestHeight int64
}

func (e *ErrNotFoundWithBestHeight) Error() string {
	return fmt.Sprintf("block not found, best height: %d", e.BestHeight)
}

// BlockByHeight returns the block by height. If height <= 0, the latest block
// will be returned.
func (n *Node) BlockByHeight(height int64) (types.Hash, *ktypes.Block, *ktypes.CommitInfo, error) {
	if height <= 0 { // I think this is correct since block height starts from 1
		height, _, _, _ = n.bki.Best()
	}
	return n.bki.GetByHeight(height)
}

// BlockByHash returns the block by block hash.
func (n *Node) BlockByHash(hash types.Hash) (*ktypes.Block, *ktypes.CommitInfo, error) {
	return n.bki.Get(hash)
}

// RawBlockByHeight returns the block by height. If height <= 0, the latest block
// will be returned.
func (n *Node) RawBlockByHeight(height int64) (types.Hash, []byte, *ktypes.CommitInfo, error) {
	if height <= 0 { // I think this is correct since block height starts from 1
		height, _, _, _ = n.bki.Best()
	}
	return n.bki.GetRawByHeight(height)
}

// RawBlockByHash returns the block by block hash.
func (n *Node) RawBlockByHash(hash types.Hash) ([]byte, *ktypes.CommitInfo, error) {
	return n.bki.GetRaw(hash)
}

// BlockResultByHash returns the block result by block hash.
func (n *Node) BlockResultByHash(hash types.Hash) ([]ktypes.TxResult, error) {
	return n.bki.Results(hash)
}
