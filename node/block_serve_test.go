package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/crypto"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

// countingWriter stands in for a libp2p stream, where one Write is one frame.
type countingWriter struct {
	buf    bytes.Buffer
	writes []int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, len(p))
	return w.buf.Write(p)
}

type failingWriter struct{ err error }

func (w failingWriter) Write(p []byte) (int, error) { return 0, w.err }

// blockResponse is one block ready to be served, as the handlers hold it.
type blockResponse struct {
	hash    types.Hash
	ciBytes []byte
	rawBlk  []byte
}

func testBlockResponse(t *testing.T, height int64, numTxns int) blockResponse {
	t.Helper()
	blk, appHash := createTestBlock(height, numTxns)
	ciBytes, err := (&ktypes.CommitInfo{AppHash: appHash}).MarshalBinary()
	require.NoError(t, err)
	return blockResponse{hash: blk.Hash(), ciBytes: ciBytes, rawBlk: ktypes.EncodeBlock(blk)}
}

// readBlockByHeightResponse parses a ProtocolIDBlockHeight response the way
// getBlkHeight does, so that a change to either side of the frame shows up here.
func readBlockByHeightResponse(t *testing.T, resp []byte) (blockResponse, int64) {
	t.Helper()
	require.Greater(t, len(resp), types.HashLen+1)
	require.Equal(t, withData[0], resp[0], "the data flag leads the response")

	var got blockResponse
	copy(got.hash[:], resp[1:1+types.HashLen])

	r := bytes.NewReader(resp[1+types.HashLen:])
	var err error
	got.ciBytes, err = ktypes.ReadCompactBytes(r)
	require.NoError(t, err)
	got.rawBlk, err = ktypes.ReadCompactBytes(r)
	require.NoError(t, err)

	var bestHeight int64
	require.NoError(t, binary.Read(r, binary.LittleEndian, &bestHeight))
	require.Zero(t, r.Len(), "nothing follows the best height")
	return got, bestHeight
}

func TestWriteBlockByHeightSendsOneFrame(t *testing.T) {
	want := testBlockResponse(t, 1, 1)
	require.Less(t, len(want.rawBlk), blkRespBufSize, "this test needs a block that fits the buffer")

	var w countingWriter
	require.NoError(t, writeBlockByHeight(&w, want.hash, want.ciBytes, want.rawBlk, 42))

	require.Len(t, w.writes, 1, "a block that fits the buffer reaches the peer as one frame")

	got, bestHeight := readBlockByHeightResponse(t, w.buf.Bytes())
	require.Equal(t, want, got)
	require.EqualValues(t, 42, bestHeight)
}

// TestWriteBlockByHeightHoldsALargeBlockToThreeFrames covers the size the
// buffer does not have to be. A response too big for it leaves as a buffer's
// worth, the rest of the block straight to the stream, and the best height, so
// the frame count stops growing where the buffer ends instead of tracking the
// block.
func TestWriteBlockByHeightHoldsALargeBlockToThreeFrames(t *testing.T) {
	for _, numTxns := range []int{8, 24, 48} {
		want := testBlockResponse(t, 2, numTxns)
		require.Greater(t, len(want.rawBlk), blkRespBufSize, "this case needs a block larger than the buffer")

		var w countingWriter
		require.NoError(t, writeBlockByHeight(&w, want.hash, want.ciBytes, want.rawBlk, 42))
		require.LessOrEqual(t, len(w.writes), 3, "a %d byte block took %v", len(want.rawBlk), w.writes)

		got, bestHeight := readBlockByHeightResponse(t, w.buf.Bytes())
		require.Equal(t, want, got)
		require.EqualValues(t, 42, bestHeight)
	}
}

func TestWriteBlockByHashSendsOneFrame(t *testing.T) {
	want := testBlockResponse(t, 3, 1)
	require.Less(t, len(want.rawBlk), blkRespBufSize, "this test needs a block that fits the buffer")

	var w countingWriter
	require.NoError(t, writeBlockByHash(&w, 3, want.ciBytes, want.rawBlk))

	require.Len(t, w.writes, 1, "a block that fits the buffer reaches the peer as one frame")

	r := bytes.NewReader(w.buf.Bytes())
	var height int64
	require.NoError(t, binary.Read(r, binary.LittleEndian, &height))
	require.EqualValues(t, 3, height)

	ciBytes, err := ktypes.ReadCompactBytes(r)
	require.NoError(t, err)
	require.Equal(t, want.ciBytes, ciBytes)

	rawBlk, err := ktypes.ReadCompactBytes(r)
	require.NoError(t, err)
	require.Equal(t, want.rawBlk, rawBlk)
	require.Zero(t, r.Len(), "nothing follows the block")
}

// TestWriteBlockReportsAFailedSend covers what the buffer costs: the writes
// themselves stop reporting errors, so the flush has to. A block that fits the
// buffer fails only at the flush; one that does not fails during the send and
// has to keep the error until then.
func TestWriteBlockReportsAFailedSend(t *testing.T) {
	boom := errors.New("stream reset")

	for _, tc := range []struct {
		name    string
		numTxns int
	}{
		{"block fits the buffer", 1},
		{"block larger than the buffer", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blk := testBlockResponse(t, 5, tc.numTxns)

			err := writeBlockByHeight(failingWriter{boom}, blk.hash, blk.ciBytes, blk.rawBlk, 42)
			require.ErrorIs(t, err, boom)

			err = writeBlockByHash(failingWriter{boom}, 5, blk.ciBytes, blk.rawBlk)
			require.ErrorIs(t, err, boom)
		})
	}
}

// TestServeBlockOverTheWire is the regression guard on the frames themselves.
// Both handlers now send the stored block rather than one they decoded and
// encoded again, and a peer has to be unable to tell.
func TestServeBlockOverTheWire(t *testing.T) {
	nodes, extraHosts, _, mn := makeTestHosts(t, 1, 1, 5*time.Hour, crypto.KeyTypeSecp256k1)
	linkAll(t, mn)

	n1 := nodes[0]
	blk, appHash := createTestBlock(1, 2)
	require.NoError(t, n1.bki.Store(blk, &ktypes.CommitInfo{AppHash: appHash}))

	startNodes(t, nodes)
	h2 := extraHosts[0]
	ctx := context.Background()

	wantBlk := ktypes.EncodeBlock(blk)

	t.Run("by height", func(t *testing.T) {
		// requestBlockHeight has already taken the data flag off the front.
		resp, err := requestBlockHeight(ctx, h2, n1.host.ID(), 1, blkReadLimit,
			2*time.Second, 20*time.Second, 500*time.Millisecond)
		require.NoError(t, err)
		require.Greater(t, len(resp), types.HashLen)

		var hash types.Hash
		copy(hash[:], resp[:types.HashLen])
		require.Equal(t, blk.Hash(), hash)

		r := bytes.NewReader(resp[types.HashLen:])
		ciBytes, err := ktypes.ReadCompactBytes(r)
		require.NoError(t, err)
		var ci ktypes.CommitInfo
		require.NoError(t, ci.UnmarshalBinary(ciBytes))
		require.Equal(t, appHash, ci.AppHash)

		rawBlk, err := ktypes.ReadCompactBytes(r)
		require.NoError(t, err)
		require.Equal(t, wantBlk, rawBlk)

		var bestHeight int64
		require.NoError(t, binary.Read(r, binary.LittleEndian, &bestHeight))
		require.EqualValues(t, 1, bestHeight)
		require.Zero(t, r.Len(), "nothing follows the best height")
	})

	t.Run("by hash", func(t *testing.T) {
		req, err := blockHashReq{Hash: blk.Hash()}.MarshalBinary()
		require.NoError(t, err)
		resp, err := requestFrom(ctx, h2, n1.host.ID(), req, ProtocolIDBlock, blkReadLimit)
		require.NoError(t, err)

		r := bytes.NewReader(resp)
		var height int64
		require.NoError(t, binary.Read(r, binary.LittleEndian, &height))
		require.EqualValues(t, 1, height)

		ciBytes, err := ktypes.ReadCompactBytes(r)
		require.NoError(t, err)
		var ci ktypes.CommitInfo
		require.NoError(t, ci.UnmarshalBinary(ciBytes))
		require.Equal(t, appHash, ci.AppHash)

		rawBlk, err := ktypes.ReadCompactBytes(r)
		require.NoError(t, err)
		require.Equal(t, wantBlk, rawBlk)
		require.Zero(t, r.Len(), "nothing follows the block")
	})

	t.Run("by height, not found, still carries our best height", func(t *testing.T) {
		_, err := requestBlockHeight(ctx, h2, n1.host.ID(), 2, blkReadLimit,
			2*time.Second, 20*time.Second, 500*time.Millisecond)
		require.ErrorIs(t, err, ErrBlkNotFound)

		be := new(ErrNotFoundWithBestHeight)
		require.ErrorAs(t, err, &be)
		require.EqualValues(t, 1, be.BestHeight)
	})
}
