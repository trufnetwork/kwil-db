package node

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/peers"
	"github.com/trufnetwork/kwil-db/node/types"
)

// Block-sync peer-sampling
//
// Historical bug: querying only a small fixed fraction (⌈N·0.2⌉, minimum 1)
// of peers could pick a single behind-height peer and stall block sync.  The
// revised algorithm below fixes that by:
//   - keeping a lightweight "peer → best height" cache updated on every
//     announcement or block response,
//   - skipping peers that are definitely behind, and
//   - scaling the sample size with network size (all peers for ≤5, ≥3 or ⅓ for
//     ≤15, and ≥3 or ⅕ thereafter).
//
// When the cache is stale we fall back to the full peer set, so liveness is
// preserved at the cost of extra bandwidth.
//
// The same cache records what asking each peer for a block has cost, and the
// sample is taken in that order rather than at random. See orderPeers.
const (
	blkReadLimit          = 300_000_000
	defaultBlkGetTimeout  = 90 * time.Second
	defaultBlkSendTimeout = 45 * time.Second
	defaultBlkReqTimeout  = 2 * time.Second
	defaultBlkRespTimeout = 20 * time.Second
	defaultBlkIdleTimeout = 500 * time.Millisecond
	cacheTTL              = 15 * time.Minute
	maxEntries            = 5_000

	// peerProbeInterval is how long a peer that is not the first choice waits
	// before it is asked first anyway, which is how a peer that has got faster
	// is noticed. With one near peer and four far ones, that is four far round
	// trips a minute.
	peerProbeInterval = time.Minute

	// A peer whose request failed is not asked first again until
	// peerFailHoldFactor times what the failure cost has passed, doubled for
	// each failure in a row, up to maxPeerFailHold. That holds the cost of
	// retrying a failing peer to a thirtieth of the time spent, for any failure
	// up to the default 20 s response timeout. One that hangs until that
	// timeout is asked first again ten minutes later, where a random pick asked
	// it first on one block in every few. One that refuses in a millisecond can
	// be asked again almost at once, since that costs next to nothing.
	// maxPeerFailHold must stay below cacheTTL: see gcPeerCache.
	peerFailHoldFactor = 30
	maxPeerFailHold    = 10 * time.Minute

	// peerLatencySmoothing is how far one answer moves a peer's latency: a
	// sixteenth of the way. A 20 ms peer needs a single answer of over 4.5 s
	// to fall behind a 300 ms one, so a retransmit or a fat block does not
	// cost it its place, while one that really has slowed to a second loses it
	// in six answers.
	peerLatencySmoothing = 16

	// blkRespBufSize buffers one block response on its way to the stream.
	//
	// A response is a flag, a hash, the commit info, the block and our best
	// height, and WriteCompactBytes sends a length ahead of each variable
	// piece, so unbuffered it leaves as five to seven separate Writes. Each of
	// those is its own yamux frame, with its own header and its own trip
	// through the connection. One buffer collapses a response that fits into a
	// single write, and holds any response at all to three: a buffer's worth,
	// the rest of the block straight to the stream, then the best height. So
	// the size is a ceiling on what gets copied, not on what can be served.
	blkRespBufSize = 16 << 10
)

// blockSyncTimeout returns the duration an operator configured, or fallback if
// they left it at zero.
//
// A zero deadline is never what anyone means by it. time.Now().Add(0) is
// already in the past, so the very first read or write expires and the peer is
// abandoned before it has been given a chance. Config sections are checked in
// Validate methods that `kwild start` never reaches — which is how
// concurrent_chunk_fetchers = 0 gets as far as starting no fetchers at all — so
// the guard belongs here, where the value is used.
func blockSyncTimeout(configured ktypes.Duration, fallback time.Duration) time.Duration {
	if d := time.Duration(configured); d > 0 {
		return d
	}
	return fallback
}

type peerInfo struct {
	height int64
	seenAt time.Time

	// What asking the peer for a block has cost, which decides whom to ask
	// first. See orderPeers.
	latency time.Duration // smoothed time to serve one; zero until it has
	askedAt time.Time     // when it last served or failed a request
	hold    time.Duration // how long it waits after a failure; zero once it serves
}

// served records a request the peer answered with the block, in took.
func (pi *peerInfo) served(took time.Duration, now time.Time) {
	took = max(took, 1) // a zero latency means it never has
	if pi.latency == 0 || pi.hold > 0 || now.Sub(pi.askedAt) > peerProbeInterval {
		// Nothing recent to smooth against. A peer asked first once a minute
		// would otherwise need many minutes to show it had got faster.
		pi.latency = took
	} else {
		pi.latency += (took - pi.latency) / peerLatencySmoothing
	}
	pi.askedAt, pi.hold = now, 0
}

// failed records a request the peer did not answer with the block, which cost
// took.
func (pi *peerInfo) failed(took time.Duration, now time.Time) {
	grow := 2 * pi.hold
	if pi.askedAt.After(now.Add(-took)) {
		// Another request to this peer ended while this one was out, so they
		// failed together, as every request on a connection does when it
		// drops. That is one failure, not a second in a row.
		grow = pi.hold
	}
	pi.hold = min(max(grow, peerFailHoldFactor*took, 1), maxPeerFailHold)
	pi.askedAt = now
}

// dueAt is when the peer is next asked first, whatever its latency: once its
// hold is up if its last request failed, otherwise peerProbeInterval after it
// was last asked. A peer never asked is due from the start.
func (pi peerInfo) dueAt() time.Time {
	if pi.hold > 0 {
		return pi.askedAt.Add(pi.hold)
	}
	return pi.askedAt.Add(peerProbeInterval)
}

// rank is the peer's place in the order orderPeers sorts into, lowest first.
func (pi peerInfo) rank() (group int, latency time.Duration) {
	switch {
	case pi.hold > 0 && pi.latency > 0:
		return 2, pi.latency
	case pi.hold > 0: // failed, and never served: after those that have
		return 2, math.MaxInt64
	case pi.latency == 0: // never asked
		return 1, 0
	default:
		return 0, pi.latency
	}
}

// orderPeers puts peers in the order they are asked for a block, going by what
// asking each of them has cost before, as recorded in known:
//
//   - peers that served their last request, fastest first,
//   - then peers never asked,
//   - then peers whose last request failed, fastest first.
//
// Ties keep the order the peers came in, which peerHosts shuffles, so a node
// that knows nothing yet asks in as random an order as it always did.
//
// Then the one peer most overdue for a turn (see dueAt) is moved to the front.
// That is what keeps a preference from becoming exclusive: every peer is asked
// first now and then, so one that has got faster or recovered is noticed, at a
// cost of one peer asked out of turn per request. A peer held back sorts last:
// with five peers or fewer getBlkHeight asks every one, so it is still asked
// after the others; with more, the sample usually stops before it.
//
// If every peer is held back, the holds no longer tell them apart, and the
// failures were more likely ours than theirs. The one due soonest goes first
// anyway, so that each retry reaches a peer the last one did not.
func orderPeers(peers []peer.ID, known map[peer.ID]peerInfo, now time.Time) {
	slices.SortStableFunc(peers, func(a, b peer.ID) int {
		ga, la := known[a].rank()
		gb, lb := known[b].rank()
		return cmp.Or(cmp.Compare(ga, gb), cmp.Compare(la, lb))
	})

	allHeld := len(peers) > 0 && known[peers[0]].hold > 0 // held peers sort last
	due := -1
	for i, p := range peers {
		at := known[p].dueAt()
		if (allHeld || !at.After(now)) && (due < 0 || at.Before(known[peers[due]].dueAt())) {
			due = i
		}
	}
	if due > 0 {
		p := peers[due]
		copy(peers[1:due+1], peers[:due])
		peers[0] = p
	}
}

// peerBest remembers, for each peer, the latest best height it has told us of
// and what asking it for a block has cost.  The height is an
// opportunistic heuristic: if we know a peer is at height 10 and we need block
// 20, we can skip querying it.  The cost decides whom to ask first.  Entries
// are evicted by gcPeerCache; if we evict too aggressively we merely sample
// the peer again later.  sync.Map lets hot paths read/write without explicit
// locks; write through updatePeer so that no writer wipes what another
// recorded.
var peerBest sync.Map // map[peer.ID]peerInfo

// updatePeer applies update to what we know of p. Two writers at once, say a
// block announcement arriving as a block request to the same peer ends, both
// keep what they wrote.
func updatePeer(p peer.ID, update func(*peerInfo)) {
	for {
		v, loaded := peerBest.Load(p)
		var pi peerInfo
		if loaded {
			pi = v.(peerInfo)
		}
		update(&pi)
		if loaded {
			if peerBest.CompareAndSwap(p, v, pi) {
				return
			}
		} else if _, loaded = peerBest.LoadOrStore(p, pi); !loaded {
			return
		}
	}
}

// notePeerHeight records height as the best block p has, as of now.
func notePeerHeight(p peer.ID, height int64) {
	updatePeer(p, func(pi *peerInfo) { pi.height, pi.seenAt = height, time.Now() })
}

func (n *Node) blkGetStreamHandler(s network.Stream) {
	defer s.Close()

	s.SetReadDeadline(time.Now().Add(reqRWTimeout))

	var req blockHashReq
	if _, err := req.ReadFrom(s); err != nil {
		n.log.Debug("Bad get block (hash) request", "error", err)
		return
	}
	n.log.Debug("Peer requested block", "hash", req.Hash)

	height, rawBlk, ci, err := n.bki.GetRaw(req.Hash)
	if err != nil || ci == nil {
		s.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		s.Write(noData) // don't have it
		return
	}

	ciBytes, _ := ci.MarshalBinary()
	s.SetWriteDeadline(time.Now().Add(defaultBlkSendTimeout))
	if err := writeBlockByHash(s, height, ciBytes, rawBlk); err != nil {
		n.log.Debug("Failed to send block", "hash", req.Hash, "error", err)
		return
	}

	mets.ServedBlock(context.Background(), height, int64(len(rawBlk)))
}

// writeBlockByHash writes a ProtocolIDBlock response: the height, the commit
// info, then the block.
//
// The pieces go through one buffer, so a block of ordinary size reaches the
// peer as one frame instead of five. bufio keeps the first error and returns it
// from every call after it, so the flush is the only place to check.
func writeBlockByHash(w io.Writer, height int64, ciBytes, rawBlk []byte) error {
	bw := bufio.NewWriterSize(w, blkRespBufSize)
	binary.Write(bw, binary.LittleEndian, height)
	ktypes.WriteCompactBytes(bw, ciBytes)
	ktypes.WriteCompactBytes(bw, rawBlk)
	return bw.Flush()
}

// blockHeightServer is the part of a block store that answering a
// ProtocolIDBlockHeight request needs.
type blockHeightServer interface {
	Best() (height int64, blkHash, appHash types.Hash, stamp time.Time)
	GetRawByHeight(height int64) (types.Hash, []byte, *ktypes.CommitInfo, error)
}

// blkGetHeightStreamHandler is the stream handler for ProtocolIDBlockHeight.
func (n *Node) blkGetHeightStreamHandler(s network.Stream) {
	serveBlockByHeight(s, n.bki, n.log)
}

// serveBlockByHeight answers one ProtocolIDBlockHeight request.
//
// Two services answer this protocol on one node. The state-sync service holds
// it from startup and the node takes it over once it is up, and a peer cannot
// tell which one it reached: it sends one request and runs one parser over the
// reply. So there is one implementation of the reply, and both register it.
//
// They did not share one before. 66d983ec bumped the protocol to 1.1.0 and
// added the leading flag byte and the trailing best height to the node's copy,
// leaving the state-sync copy writing the frame from before it — which a 1.1.0
// client reads as a status flag followed by a block that starts one byte late.
func serveBlockByHeight(s network.Stream, bs blockHeightServer, log log.Logger) {
	defer s.Close()

	s.SetReadDeadline(time.Now().Add(reqRWTimeout))

	var req blockHeightReq
	if _, err := req.ReadFrom(s); err != nil {
		log.Warn("Bad get block (height) request", "error", err) // Debug when we ship
		return
	}
	log.Debug("Peer requested block", "height", req.Height)

	bestHeight, _, _, _ := bs.Best()

	hash, rawBlk, ci, err := bs.GetRawByHeight(req.Height)
	if err != nil || ci == nil {
		s.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		// Don't have it, so say so and tell them how far we have got. That is
		// nine bytes, and two Writes would make it two frames.
		s.Write(binary.LittleEndian.AppendUint64(slices.Clone(noData), uint64(bestHeight)))
		return
	}

	ciBytes, _ := ci.MarshalBinary()
	s.SetWriteDeadline(time.Now().Add(defaultBlkSendTimeout))
	if err := writeBlockByHeight(s, hash, ciBytes, rawBlk, bestHeight); err != nil {
		log.Debug("Failed to send block", "height", req.Height, "error", err)
		return
	}

	mets.ServedBlock(context.Background(), req.Height, int64(len(rawBlk)))
}

// writeBlockByHeight writes a ProtocolIDBlockHeight response: the data flag,
// the block hash, the commit info, the block, then our own best height. As with
// writeBlockByHash, the buffer is what makes that one frame rather than seven.
func writeBlockByHeight(w io.Writer, hash types.Hash, ciBytes, rawBlk []byte, bestHeight int64) error {
	bw := bufio.NewWriterSize(w, blkRespBufSize)
	bw.Write(withData)
	// The hash precedes the block so that a receiver could hang up before
	// reading it. Nothing does yet, and it could leave the protocol if nothing
	// ever will.
	bw.Write(hash[:])
	ktypes.WriteCompactBytes(bw, ciBytes)
	ktypes.WriteCompactBytes(bw, rawBlk)
	binary.Write(bw, binary.LittleEndian, bestHeight)
	return bw.Flush()
}

func (n *Node) blkAnnStreamHandler(s network.Stream) {
	defer s.Close()

	if n.InCatchup() { // we are in catchup, don't accept new blocks
		n.log.Debug("in catchup, not accepting new block announcement messages")
		return
	}

	// Get configurable timeouts
	blkGetTimeout := defaultBlkGetTimeout
	annRespTimeout := defaultAnnRespTimeout
	annWriteTimeout := defaultAnnWriteTimeout
	if n.blockSyncCfg != nil {
		blkGetTimeout = blockSyncTimeout(n.blockSyncCfg.BlockGetTimeout, defaultBlkGetTimeout)
		annRespTimeout = blockSyncTimeout(n.blockSyncCfg.AnnounceRespTimeout, defaultAnnRespTimeout)
		annWriteTimeout = blockSyncTimeout(n.blockSyncCfg.AnnounceWriteTimeout, defaultAnnWriteTimeout)
	}
	s.SetDeadline(time.Now().Add(blkGetTimeout + annRespTimeout + annWriteTimeout)) // combined
	ctx, cancel := context.WithTimeout(context.Background(), blkGetTimeout)
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

	// Update peer height cache with observed announcement height
	notePeerHeight(peerID, height)

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
		blkSendTimeout := defaultBlkSendTimeout
		if n.blockSyncCfg != nil {
			blkSendTimeout = blockSyncTimeout(n.blockSyncCfg.BlockSendTimeout, defaultBlkSendTimeout)
		}
		err = n.advertiseToPeer(ctx, peerID, ProtocolIDBlkAnn, ann, blkSendTimeout)
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
	// ctx only bounds opening the stream. Once it is open, nothing below reads
	// ctx, so a request we have given up on would wait out the response
	// timeout, 20 s by default, on a peer we no longer want an answer from.
	// Resetting the stream ends the write or read under way.
	stopReset := context.AfterFunc(ctx, func() { stream.Reset() })
	defer stopReset()

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
// - the stream goes idle for idleTimeout between two chunks
// - the total bytes read exceed the limit
//
// idleTimeout starts applying at the second read. Before the first byte there
// is no transfer to be idle: that wait covers the request's flight to the peer,
// the peer's own block lookup and encode, and the first byte's flight back. On
// a distant peer a whole round trip is routinely longer than the gap between
// two chunks of a block already on the wire, so holding the first read to
// idleTimeout abandons peers that were about to answer. The first read is
// bounded by deadline instead, which the caller derives from the block sync
// response timeout.
func readAll(s network.Stream, limit int64, deadline time.Time, idleTimeout time.Duration) ([]byte, error) {
	r := io.LimitReader(s, limit)

	const readChunk = 512 // like io.ReadAll
	b := make([]byte, 0, readChunk)

	for first := true; ; first = false {
		// Check absolute deadline for the entire resource.
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout")
		}

		// Set read deadline for this chunk. The first read waits out the round
		// trip; every later one only allows for a gap in a transfer already
		// under way.
		chunkDeadline := deadline
		if !first {
			chunkDeadline = time.Now().Add(idleTimeout)
		}
		s.SetReadDeadline(chunkDeadline)

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

// getBlkHeight fetches the block at height from a sample of peers, trying them
// in turn until one serves it. It returns the block hash, the encoded block,
// its commit info, and the best height reported by any peer that did not have
// it. blockSyncCfg may be nil, in which case the package defaults apply. See
// the peer-sampling notes above for how the sample is chosen.
func getBlkHeight(ctx context.Context, height int64, host host.Host, log log.Logger, blockSyncCfg *config.BlockSyncConfig) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
	allPeers := peerHosts(host)
	if len(allPeers) == 0 {
		return types.Hash{}, nil, nil, 0, types.ErrPeersNotFound
	}

	// Filter out peers we know can't have this block
	now := time.Now()
	known := make(map[peer.ID]peerInfo, len(allPeers))
	var eligiblePeers []peer.ID
	for _, p := range allPeers {
		if v, ok := peerBest.Load(p); ok {
			pi := v.(peerInfo)
			known[p] = pi
			if now.Sub(pi.seenAt) < cacheTTL && pi.height < height {
				continue // definitely behind
			}
		}
		eligiblePeers = append(eligiblePeers, p)
	}

	// If no eligible peers, fall back to all peers (maybe our cache is stale)
	fellBack := len(eligiblePeers) == 0
	if fellBack {
		eligiblePeers = allPeers
	}

	// Smart sampling: query more peers in small networks to avoid single-peer stalls
	var sampleSize int
	switch {
	case len(eligiblePeers) <= 5:
		sampleSize = len(eligiblePeers) // Query all peers in small networks
	case len(eligiblePeers) <= 15:
		sampleSize = max(len(eligiblePeers)/3, 3) // Query at least 3, up to 1/3
	default:
		sampleSize = max(len(eligiblePeers)/5, 3) // Query at least 3, up to 1/5 (original behavior)
	}

	// Ask first the peers that have answered fastest, so the sample is the
	// best of them rather than a random few. peerHosts has already shuffled
	// them, which settles ties.
	//
	// Not when no peer is known to have the block, which is where every
	// catch-up ends. The question then is whether anyone has it yet, and the
	// fastest peers can be the last to: a sentry next to us hears of a block
	// after the validators it hangs off. Asking them first, with more than
	// five peers, would end catch-up a block early. The shuffle asks around.
	if !fellBack {
		orderPeers(eligiblePeers, known, now)
	}
	availablePeers := eligiblePeers[:sampleSize]

	log.Debugf("Querying %d peers for block %d (filtered %d/%d eligible)", sampleSize, height, len(eligiblePeers), len(allPeers))

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
		reqTimeout := defaultBlkReqTimeout
		recvTimeout := defaultBlkRespTimeout
		idleTimeout := defaultBlkIdleTimeout
		if blockSyncCfg != nil {
			reqTimeout = blockSyncTimeout(blockSyncCfg.RequestTimeout, defaultBlkReqTimeout)
			recvTimeout = blockSyncTimeout(blockSyncCfg.ResponseTimeout, defaultBlkRespTimeout)
			idleTimeout = blockSyncTimeout(blockSyncCfg.IdleTimeout, defaultBlkIdleTimeout)
		}
		resp, err := requestBlockHeight(ctx, host, peer, height, blkReadLimit, reqTimeout, recvTimeout, idleTimeout)
		took := time.Since(t0)
		// Once we have given up, the stream is reset under the request and it
		// fails the way a transport error does. That is ours, not the peer's,
		// and not a not-found either: counted as one, a peer that had already
		// said not-found would turn our cancelling into the end of catch-up.
		if err != nil && ctx.Err() != nil {
			return types.Hash{}, nil, nil, 0, ctx.Err()
		}
		// failed counts this request against the peer. Our own cancellation
		// says nothing about it.
		failed := func() {
			if ctx.Err() == nil {
				updatePeer(peer, func(pi *peerInfo) { pi.failed(took, time.Now()) })
			}
		}
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrBlkNotFound) {
			notFoundCount++
			be := new(ErrNotFoundWithBestHeight)
			if errors.As(err, &be) {
				theirBest := be.BestHeight
				if theirBest > bestHeight {
					bestHeight = theirBest
				}

				// Update our cache with this peer's best height
				notePeerHeight(peer, theirBest)

				if theirBest == height-1 {
					bestHCount++
				}
				if theirBest >= height {
					// It has the height but not the block, as when it state
					// synced past it. Behind is no fault; this, asked first
					// every time, would cost a round trip on every block.
					failed()
				}
				log.Infof("block %d not found on peer %s; their best height is %d", height, peer, theirBest)
			} else {
				failed()
				log.Warnf("block not available on %v", peer)
			}
			continue
		}
		if errors.Is(err, ErrNoResponse) {
			failed()
			log.Warnf("no response to block request to %v", peer)
			continue
		}
		if err != nil {
			// e.g. "i/o deadline reached", probably network error
			failed()
			log.Warnf("unexpected error from %v: %v", peer, err)
			continue
		}

		if len(resp) < types.HashLen+1 {
			failed()
			log.Warnf("block response too short")
			continue
		}

		log.Debug("obtained block contents", "height", height, "peer", peer, "elapsed", took)

		rd := bytes.NewReader(resp)
		var hash types.Hash

		if _, err := io.ReadFull(rd, hash[:]); err != nil {
			failed()
			log.Warn("failed to read block hash in the block response", "error", err)
			continue
		}

		ciBts, err := ktypes.ReadCompactBytes(rd)
		if err != nil {
			failed()
			log.Info("failed to read commit info in the block response", "error", err)
			continue
		}

		var ci ktypes.CommitInfo
		if err = ci.UnmarshalBinary(ciBts); err != nil {
			failed()
			log.Warn("failed to unmarshal commit info", "error", err)
			continue
		}

		rawBlk, err := ktypes.ReadCompactBytes(rd)
		if err != nil {
			failed()
			log.Warn("failed to read block in the block response", "error", err)
			continue
		}

		var theirBest int64
		err = binary.Read(rd, binary.LittleEndian, &theirBest)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				failed()
				log.Info("failed to read best block height", "error", err)
				continue
			} // else the peer didn't want to send it (this is backwards compatible)
		} else {
			if theirBest > bestHeight {
				bestHeight = theirBest
			}
			// Update our cache - this peer has at least the requested height
			notePeerHeight(peer, max(theirBest, height))
		}
		updatePeer(peer, func(pi *peerInfo) { pi.served(took, time.Now()) })

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
	_, rawBlk, ci, err := n.bki.GetRaw(hash)
	return rawBlk, ci, err
}

// GetBlockHeader returns the block header by block hash.
func (n *Node) GetBlockHeader(hash ktypes.Hash) (*ktypes.BlockHeader, error) {
	return n.bki.GetBlockHeader(hash)
}

// GetBlockHeaderByHeight returns the block header by height. If height <= 0, the
// latest block header will be returned.
func (n *Node) GetBlockHeaderByHeight(height int64) (*ktypes.BlockHeader, error) {
	if height <= 0 { // I think this is correct since block height starts from 1
		height, _, _, _ = n.bki.Best()
	}
	return n.bki.GetBlockHeaderByHeight(height)
}

// BlockResultByHash returns the block result by block hash.
func (n *Node) BlockResultByHash(hash types.Hash) ([]ktypes.TxResult, error) {
	return n.bki.Results(hash)
}

func gcPeerCache() {
	// gcPeerCache runs from a ticker started in node.Start.
	// It trims the peerBest map by removing entries that are older than
	// cacheTTL or when the map grows beyond maxEntries.
	now := time.Now()
	var count int
	peerBest.Range(func(k, v any) bool { count++; return true })

	peerBest.Range(func(k, v any) bool {
		pi := v.(peerInfo)
		// Keep a peer asked within cacheTTL even if it has stopped announcing.
		// Every hold is shorter than that, and a peer forgotten during its
		// hold would count as never asked, and be asked first.
		stale := now.Sub(pi.seenAt) > cacheTTL && now.Sub(pi.askedAt) > cacheTTL
		// CompareAndDelete, so as not to delete what a request has just written.
		if (stale || count > maxEntries) && peerBest.CompareAndDelete(k, v) {
			count--
		}
		return true
	})
}
