package node

import (
	"bytes"
	"context"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	ktypes "github.com/kwilteam/kwil-db/core/types"
	"github.com/kwilteam/kwil-db/core/utils"
	"github.com/kwilteam/kwil-db/node/peers"
	"github.com/kwilteam/kwil-db/node/types"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const (
	ProtocolIDDiscover = peers.ProtocolIDDiscover
	ProtocolIDCrawler  = peers.ProtocolIDCrawler

	ProtocolIDTx          protocol.ID = "/kwil/tx/1.0.0"
	ProtocolIDTxAnn       protocol.ID = "/kwil/txann/1.0.0"
	ProtocolIDBlockHeight protocol.ID = "/kwil/blkheight/1.1.0"
	ProtocolIDBlock       protocol.ID = "/kwil/blk/1.0.0"
	ProtocolIDBlkAnn      protocol.ID = "/kwil/blkann/1.0.0"
	// ProtocolIDBlockHeader protocol.ID = "/kwil/blkhdr/1.0.0"

	ProtocolIDBlockPropose protocol.ID = "/kwil/blkprop/1.0.0"
	// ProtocolIDACKProposal  protocol.ID = "/kwil/blkack/1.0.0"
	getMsg = "get" // context dependent, in open stream convo
)

func requestFrom(ctx context.Context, host host.Host, peer peer.ID, resID []byte,
	proto protocol.ID, readLimit int64) ([]byte, error) {
	txStream, err := host.NewStream(ctx, peer, proto)
	if err != nil {
		return nil, peers.CompressDialError(err)
	}
	defer txStream.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultTxGetTimeout)
	}

	txStream.SetDeadline(deadline)

	return request(txStream, resID, readLimit)
}

func request(rw io.ReadWriter, reqMsg []byte, readLimit int64) ([]byte, error) {
	_, err := rw.Write(reqMsg)
	if err != nil {
		return nil, fmt.Errorf("resource get request failed: %w", err)
	}

	rawTx, err := readResp(rw, readLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource get response: %w", err)
	}
	return rawTx, nil
}

var (
	noData   = []byte{0}
	withData = []byte{1}
)

// readResp reads a response of unknown length until an EOF is reached when
// reading. As such, this is the end of a protocol.
func readResp(rd io.Reader, limit int64) ([]byte, error) {
	rd = io.LimitReader(rd, limit)
	resp, err := io.ReadAll(rd) // until EOF/hangup
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, ErrNoResponse
	}
	if bytes.Equal(resp, noData) {
		return nil, ErrNotFound
	}
	return resp, nil
}

const (
	defaultAnnWriteTimeout = 5 * time.Second
	defaultAnnRespTimeout  = 5 * time.Second
	defaultTxGetTimeout    = 20 * time.Second
)

var (
	// reqRWTimeout is the timeout for either writing or reading a resource ID,
	// which is generally short and probably a packet or two.
	reqRWTimeout = defaultAnnWriteTimeout
)

type contentAnn struct {
	cType   string
	ann     []byte // may be cType if self-describing
	content []byte
}

func (ca contentAnn) String() string {
	return ca.cType
}

// advertiseToPeer sends a lightweight advertisement to a connected peer.
// The stream remains open in case the peer wants to request the content .
func (n *Node) advertiseToPeer(ctx context.Context, peerID peer.ID, proto protocol.ID,
	ann contentAnn, contentWriteTimeout time.Duration) error {
	s, err := n.host.NewStream(ctx, peerID, proto)
	if err != nil {
		return fmt.Errorf("failed to open stream to peer: %w", peers.CompressDialError(err))
	}

	annWriteTimeout := defaultAnnWriteTimeout
	if n.blockSyncCfg != nil {
		annWriteTimeout = time.Duration(n.blockSyncCfg.AnnounceWriteTimeout)
	}
	s.SetWriteDeadline(time.Now().Add(annWriteTimeout))

	// Send a lightweight advertisement with the object ID
	_, err = s.Write(ann.ann)
	if err != nil {
		return fmt.Errorf("send content ID failed: %w", err) // TODO: close stream?
	}

	mets.Advertised(ctx, string(proto))

	// Keep the stream open for potential content requests
	go func() {
		defer s.Close()

		annRespTimeout := defaultAnnRespTimeout
		if n.blockSyncCfg != nil {
			annRespTimeout = time.Duration(n.blockSyncCfg.AnnounceRespTimeout)
		}
		s.SetReadDeadline(time.Now().Add(annRespTimeout))

		req := make([]byte, len(getMsg))
		nr, err := s.Read(req)
		if err != nil && !errors.Is(err, io.EOF) {
			n.log.Warn("bad advertise response", "error", err)
			return
		}
		if nr == 0 { // they didn't want it
			mets.AdvertiseRejected(ctx, string(proto))
			return
		}
		if getMsg != string(req) {
			n.log.Warn("bad advertise response", "resp", hex.EncodeToString(req))
			return
		}
		s.SetWriteDeadline(time.Now().Add(contentWriteTimeout))
		s.Write(ann.content)
		mets.AdvertiseServed(ctx, string(proto), int64(len(ann.content)))
	}()

	return nil
}

// blockAnnMsg is for ProtocolIDBlkAnn "/kwil/blkann/1.0.0"
type blockAnnMsg struct {
	Hash       types.Hash
	Height     int64
	Header     *ktypes.BlockHeader
	CommitInfo *ktypes.CommitInfo // commit sigs of validators attest to the block and app hash
	LeaderSig  []byte             // to avoid having to get the block to realize if it is fake (spam)
}

var _ encoding.BinaryMarshaler = blockAnnMsg{}
var _ encoding.BinaryMarshaler = (*blockAnnMsg)(nil)

func (m blockAnnMsg) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	_, err := m.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var _ encoding.BinaryUnmarshaler = (*blockAnnMsg)(nil)

func (m *blockAnnMsg) UnmarshalBinary(data []byte) error {
	_, err := m.ReadFrom(bytes.NewReader(data))
	return err
}

var _ io.WriterTo = (*blockAnnMsg)(nil)

func (m *blockAnnMsg) WriteTo(w io.Writer) (int64, error) {
	cw := utils.NewCountingWriter(w)

	if _, err := cw.Write(m.Hash[:]); err != nil {
		return cw.Written(), err
	}

	if err := binary.Write(cw, binary.LittleEndian, uint64(m.Height)); err != nil {
		return cw.Written(), err
	}

	// Block header must be present in the block announcement messages
	if m.Header == nil {
		return cw.Written(), errors.New("nil block header")
	}

	// CommitInfo must be present in the block announcement messages
	if m.CommitInfo == nil {
		return cw.Written(), errors.New("nil commit info")
	}

	// write block header length and bytes
	hBts := ktypes.EncodeBlockHeader(m.Header)
	if err := ktypes.WriteCompactBytes(cw, hBts); err != nil {
		return cw.Written(), err
	}

	ciBts, err := m.CommitInfo.MarshalBinary()
	if err != nil {
		return cw.Written(), err
	}

	// write commit info length and bytes
	if err := ktypes.WriteCompactBytes(cw, ciBts); err != nil {
		return cw.Written(), err
	}

	// write leader sig length and bytes
	if err := ktypes.WriteCompactBytes(cw, m.LeaderSig); err != nil {
		return cw.Written(), err
	}

	return cw.Written(), nil
}

var _ io.ReaderFrom = (*blockAnnMsg)(nil)

func (m *blockAnnMsg) ReadFrom(r io.Reader) (int64, error) {
	cr := utils.NewCountingReader(r)

	if _, err := io.ReadFull(cr, m.Hash[:]); err != nil {
		return cr.ReadCount(), err
	}

	if err := binary.Read(cr, binary.LittleEndian, &m.Height); err != nil {
		return cr.ReadCount(), err
	}

	headerBts, err := ktypes.ReadCompactBytes(cr)
	if err != nil {
		return cr.ReadCount(), err
	}
	hdr, err := ktypes.DecodeBlockHeader(bytes.NewBuffer(headerBts))
	if err != nil {
		return cr.ReadCount(), err
	}
	m.Header = hdr

	ciBts, err := ktypes.ReadCompactBytes(cr)
	if err != nil {
		return cr.ReadCount(), err
	}

	var ci ktypes.CommitInfo
	if err := ci.UnmarshalBinary(ciBts); err != nil {
		return cr.ReadCount(), err
	}
	m.CommitInfo = &ci

	leaderSig, err := ktypes.ReadCompactBytes(cr)
	if err != nil {
		return cr.ReadCount(), err
	}
	m.LeaderSig = leaderSig

	return cr.ReadCount(), nil
}

// blockHeightReq is for ProtocolIDBlockHeight "/kwil/blkheight/1.0.0"
type blockHeightReq struct {
	Height int64
}

var _ encoding.BinaryMarshaler = blockHeightReq{}
var _ encoding.BinaryMarshaler = (*blockHeightReq)(nil)

func (r blockHeightReq) MarshalBinary() ([]byte, error) {
	return binary.LittleEndian.AppendUint64(nil, uint64(r.Height)), nil
}

func (r *blockHeightReq) UnmarshalBinary(data []byte) error {
	if len(data) != 8 {
		return errors.New("unexpected data length")
	}
	r.Height = int64(binary.LittleEndian.Uint64(data))
	return nil
}

var _ io.WriterTo = (*blockHeightReq)(nil)

func (r blockHeightReq) WriteTo(w io.Writer) (int64, error) {
	bts, _ := r.MarshalBinary()
	n, err := w.Write(bts)
	return int64(n), err
}

var _ io.ReaderFrom = (*blockHeightReq)(nil)

func (r *blockHeightReq) ReadFrom(rd io.Reader) (int64, error) {
	hBts := make([]byte, 8)
	n, err := io.ReadFull(rd, hBts)
	if err != nil {
		return int64(n), err
	}
	r.Height = int64(binary.LittleEndian.Uint64(hBts))
	return int64(n), err
}

// blockHashReq is for ProtocolIDBlock "/kwil/blk/1.0.0"
type blockHashReq struct {
	Hash types.Hash
}

var _ encoding.BinaryMarshaler = blockHashReq{}
var _ encoding.BinaryMarshaler = (*blockHashReq)(nil)

func (r blockHashReq) MarshalBinary() ([]byte, error) {
	return r.Hash[:], nil
}

func (r *blockHashReq) UnmarshalBinary(data []byte) error {
	if len(data) != types.HashLen {
		return errors.New("invalid hash length")
	}
	copy(r.Hash[:], data)
	return nil
}

var _ io.WriterTo = (*blockHashReq)(nil)

func (r blockHashReq) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(r.Hash[:])
	return int64(n), err
}

var _ io.ReaderFrom = (*blockHashReq)(nil)

func (r *blockHashReq) ReadFrom(rd io.Reader) (int64, error) {
	n, err := io.ReadFull(rd, r.Hash[:])
	return int64(n), err
}

// txHashReq is for ProtocolIDTx "/kwil/tx/1.0.0"
type txHashReq struct {
	blockHashReq // just embed the methods for the identical block hash request for now
}

func newTxHashReq(hash types.Hash) txHashReq {
	return txHashReq{blockHashReq{Hash: hash}}
}

// txHashAnn is for ProtocolIDTxAnn "/kwil/txann/1.0.0"
type txHashAnn struct {
	blockHashReq
}

func newTxHashAnn(hash types.Hash) txHashAnn {
	return txHashAnn{blockHashReq{Hash: hash}}
}
