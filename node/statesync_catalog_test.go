package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
)

// TestValidateCatalogEntry pins the shape of a snapshot catalog entry the node
// is willing to admit. The honest snapshotter appends exactly one chunk hash
// per chunk it writes (splitStreamIntoChunks increments the chunk index and
// appends the hash together, with no path that does one without the other), and
// both serving handlers re-establish that on the wire by allocating
// make([][32]byte, snap.ChunkCount). So every case marked valid here is a shape
// a real provider emits, and every case marked invalid is one only a hostile or
// buggy peer can produce.
func TestValidateCatalogEntry(t *testing.T) {
	h := sha256.Sum256([]byte("chunk"))

	tests := []struct {
		name    string
		snap    *snapshotMetadata
		wantErr bool
	}{
		{
			name:    "nil entry",
			snap:    nil,
			wantErr: true,
		},
		{
			name:    "no chunks",
			snap:    &snapshotMetadata{Height: 1, Chunks: 0, Hash: h[:]},
			wantErr: true,
		},
		{
			// Indexes past the end of the provider's slice in VerifySnapshot.
			name:    "more chunk hashes than chunks",
			snap:    &snapshotMetadata{Height: 1, Chunks: 1, Hash: h[:], ChunkHashes: [][32]byte{h, h, h, h, h}},
			wantErr: true,
		},
		{
			// Verifies vacuously, then runs off the end in downloadChunkResumable.
			name:    "fewer chunk hashes than chunks",
			snap:    &snapshotMetadata{Height: 1, Chunks: 5, Hash: h[:], ChunkHashes: [][32]byte{h}},
			wantErr: true,
		},
		{
			name:    "no chunk hashes",
			snap:    &snapshotMetadata{Height: 1, Chunks: 5, Hash: h[:], ChunkHashes: nil},
			wantErr: true,
		},
		{
			name: "chunk count above the ceiling",
			snap: &snapshotMetadata{Height: 1, Chunks: maxSnapshotChunks + 1, Hash: h[:],
				ChunkHashes: make([][32]byte, maxSnapshotChunks+1)},
			wantErr: true,
		},
		{
			// The shape of every snapshot in the existing test fixtures.
			name:    "single chunk",
			snap:    &snapshotMetadata{Height: 1, Chunks: 1, Hash: h[:], ChunkHashes: [][32]byte{h}},
			wantErr: false,
		},
		{
			// A ~823MB snapshot at the snapshotter's ~16MB chunk size, i.e. the
			// measured testnet shape.
			name:    "many chunks",
			snap:    &snapshotMetadata{Height: 1, Chunks: 52, Hash: h[:], ChunkHashes: make([][32]byte, 52)},
			wantErr: false,
		},
		{
			name: "chunk count at the ceiling",
			snap: &snapshotMetadata{Height: 1, Chunks: maxSnapshotChunks, Hash: h[:],
				ChunkHashes: make([][32]byte, maxSnapshotChunks)},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCatalogEntry(tt.snap)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestRequestSnapshotCatalogsDropsMalformedEntries verifies that a malformed
// catalog cannot poison the snapshot pool. A catalog is unauthenticated peer
// input, and three of its malformed shapes each panic a bootstrapping node at a
// different site: a null element faults on snap.Key(), an entry with more chunk
// hashes than chunks indexes past the end of the trusted provider's slice in
// VerifySnapshot, and one with fewer runs off the end during chunk download.
// None of them may reach the pool.
func TestRequestSnapshotCatalogsDropsMalformedEntries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mn := mock.New()
	tmpDir := t.TempDir()

	hU, _, _, _, pkU, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "untrusted"), testSSConfig(false, nil))
	require.NoError(t, err)

	bootPeer := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pkU.Public().Bytes()), pkU.Type())
	_, _, _, ssMe, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "me"), testSSConfig(true, []string{bootPeer}))
	require.NoError(t, err)

	// The malformed entries are built as Go values because the struct places no
	// constraint on Chunks versus len(ChunkHashes) - that is exactly the gap
	// being closed - and json.Marshal reproduces what a hostile peer puts on the
	// wire. The nil entry has to be a literal null, so the array is assembled as
	// raw JSON rather than by encoding a []*snapshotMetadata.
	hash := sha256.Sum256([]byte("catalog"))
	tooMany := &snapshotMetadata{Height: 11, Format: 1, Chunks: 1, Hash: hash[:], Size: 100,
		ChunkHashes: [][32]byte{hash, hash, hash, hash, hash}}
	tooFew := &snapshotMetadata{Height: 12, Format: 1, Chunks: 5, Hash: hash[:], Size: 100,
		ChunkHashes: [][32]byte{hash}}
	noChunks := &snapshotMetadata{Height: 13, Format: 1, Chunks: 0, Hash: hash[:], Size: 100}
	huge := &snapshotMetadata{Height: 14, Format: 1, Chunks: maxSnapshotChunks + 1, Hash: hash[:], Size: 100,
		ChunkHashes: make([][32]byte, maxSnapshotChunks+1)}
	wellFormed := &snapshotMetadata{Height: 10, Format: 1, Chunks: 1, Hash: hash[:], Size: 100,
		ChunkHashes: [][32]byte{hash}}

	parts := []string{"null"}
	for _, snap := range []*snapshotMetadata{tooMany, tooFew, noChunks, huge, wellFormed} {
		b, err := json.Marshal(snap)
		require.NoError(t, err)
		parts = append(parts, string(b))
	}
	catalog := "[" + strings.Join(parts, ",") + "]"

	hU.SetStreamHandler(snapshotter.ProtocolIDSnapshotCatalog, func(s network.Stream) {
		defer s.Close()
		io.WriteString(s, catalog)
	})

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())

	require.NoError(t, ssMe.requestSnapshotCatalogs(ctx, peer.AddrInfo{ID: hU.ID()}))

	snaps := ssMe.snapshotPool.listSnapshots()
	require.Len(t, snaps, 1, "only the well-formed entry may enter the pool")
	require.Equal(t, uint64(10), snaps[0].Height)
}

// TestRequestSnapshotCatalogsRejectsOversizedCatalogs covers the bounds on the
// response as a whole. Per-entry limits do not bound the work a peer can cause
// on their own: every entry that survives validation costs a round trip to the
// trusted providers before it can be blacklisted, so the entry count and the
// bytes behind it have to be capped too.
func TestRequestSnapshotCatalogsRejectsOversizedCatalogs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	mn := mock.New()
	tmpDir := t.TempDir()

	hU, _, _, _, pkU, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "untrusted2"), testSSConfig(false, nil))
	require.NoError(t, err)

	bootPeer := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pkU.Public().Bytes()), pkU.Type())
	_, _, _, ssMe, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "me2"), testSSConfig(true, []string{bootPeer}))
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("oversized"))
	entry := func(height uint64) string {
		b, err := json.Marshal(&snapshotMetadata{Height: height, Format: 1, Chunks: 1,
			Hash: hash[:], Size: 100, ChunkHashes: [][32]byte{hash}})
		require.NoError(t, err)
		return string(b)
	}

	var served string
	hU.SetStreamHandler(snapshotter.ProtocolIDSnapshotCatalog, func(s network.Stream) {
		defer s.Close()
		io.WriteString(s, served)
	})

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())

	t.Run("too many entries", func(t *testing.T) {
		parts := make([]string, 0, maxCatalogEntries+1)
		for i := range maxCatalogEntries + 1 {
			parts = append(parts, entry(uint64(i+1)))
		}
		served = "[" + strings.Join(parts, ",") + "]"

		require.Error(t, ssMe.requestSnapshotCatalogs(ctx, peer.AddrInfo{ID: hU.ID()}))
		require.Empty(t, ssMe.snapshotPool.listSnapshots(), "an over-long catalog must be rejected whole, not truncated")
	})

	t.Run("too many bytes", func(t *testing.T) {
		// One entry, padded past the byte limit. The decoder hits the end of the
		// limited reader mid-value and the whole response is refused.
		padding := strings.Repeat("0", maxCatalogBytes)
		served = `[{"height":1,"format":1,"chunks":1,"hash":"` + padding + `"}]`

		require.Error(t, ssMe.requestSnapshotCatalogs(ctx, peer.AddrInfo{ID: hU.ID()}))
		require.Empty(t, ssMe.snapshotPool.listSnapshots())
	})

	t.Run("an honest catalog still lands", func(t *testing.T) {
		served = "[" + entry(42) + "]"
		require.NoError(t, ssMe.requestSnapshotCatalogs(ctx, peer.AddrInfo{ID: hU.ID()}))
		snaps := ssMe.snapshotPool.listSnapshots()
		require.Len(t, snaps, 1)
		require.Equal(t, uint64(42), snaps[0].Height)
	})
}

// TestVerifySnapshotChunkHashLengthMismatch covers the second half of the same
// invariant. VerifySnapshot ranges the catalog entry's chunk hashes while
// indexing the trusted provider's, and the provider's metadata arrives on its
// own stream that the catalog ingest guard never sees, so a length disagreement
// has to be rejected here as well.
func TestVerifySnapshotChunkHashLengthMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	mn := mock.New()
	tmpDir := t.TempDir()

	hT, _, _, _, pkT, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "trusted"), testSSConfig(false, nil))
	require.NoError(t, err)

	bootPeer := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pkT.Public().Bytes()), pkT.Type())
	_, _, _, ssMe, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "me"), testSSConfig(true, []string{bootPeer}))
	require.NoError(t, err)

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())

	// mocknet has already connected the hosts, so the bare ID is dialable.
	ssMe.trustedProviders = []*peer.AddrInfo{{ID: hT.ID()}}

	hash := sha256.Sum256([]byte("verify"))

	tests := []struct {
		name string
		snap *snapshotMetadata
		meta *snapshotMetadata
		want VerificationResult
	}{
		{
			// This is the panic: before the fix the loop indexes
			// meta.ChunkHashes[1] on a one-element slice.
			name: "entry has extra chunk hashes",
			snap: &snapshotMetadata{Height: 20, Format: 1, Chunks: 1, Hash: hash[:],
				ChunkHashes: [][32]byte{hash, hash, hash, hash, hash}},
			meta: &snapshotMetadata{Height: 20, Format: 1, Chunks: 1, Hash: hash[:],
				ChunkHashes: [][32]byte{hash}},
			want: VerificationInvalid,
		},
		{
			// Before the fix the loop runs once, matches, and returns
			// VerificationValid, sending the download path off the end of
			// ChunkHashes.
			name: "entry has too few chunk hashes",
			snap: &snapshotMetadata{Height: 21, Format: 1, Chunks: 5, Hash: hash[:],
				ChunkHashes: [][32]byte{hash}},
			meta: &snapshotMetadata{Height: 21, Format: 1, Chunks: 5, Hash: hash[:],
				ChunkHashes: [][32]byte{hash, hash, hash, hash, hash}},
			want: VerificationInvalid,
		},
		{
			// The entry is well-formed, so the catalog guard admits it; only
			// this check stops a short metadata reply from panicking the same
			// line.
			name: "provider returned too few chunk hashes",
			snap: &snapshotMetadata{Height: 22, Format: 1, Chunks: 2, Hash: hash[:],
				ChunkHashes: [][32]byte{hash, hash}},
			meta: &snapshotMetadata{Height: 22, Format: 1, Chunks: 2, Hash: hash[:],
				ChunkHashes: [][32]byte{hash}},
			want: VerificationInvalid,
		},
		{
			// The shape the honest snapshotter emits must still verify.
			name: "matching chunk hashes",
			snap: &snapshotMetadata{Height: 23, Format: 1, Chunks: 2, Hash: hash[:],
				ChunkHashes: [][32]byte{hash, hash}},
			meta: &snapshotMetadata{Height: 23, Format: 1, Chunks: 2, Hash: hash[:],
				ChunkHashes: [][32]byte{hash, hash}, AppHash: hash[:]},
			want: VerificationValid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// SetStreamHandler replaces the handler the harness installed, and
			// the subtests run sequentially, so re-registering is safe.
			hT.SetStreamHandler(snapshotter.ProtocolIDSnapshotMeta, func(s network.Stream) {
				defer s.Close()
				var req snapshotter.SnapshotReq
				if _, err := req.ReadFrom(s); err != nil {
					return
				}
				json.NewEncoder(s).Encode(tt.meta)
			})

			got, _ := ssMe.VerifySnapshot(ctx, tt.snap)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestCleanupInvalidSnapshotHonoursCancellation covers the fourth shape a
// malformed catalog entry can take. It does not crash the node, it stalls it:
// the cleanup runs once per claimed chunk with two os.Stat calls each, and it is
// reached from the branch of downloadSnapshot that loops without counting
// against MaxRetries.
func TestCleanupInvalidSnapshotHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mn := mock.New()

	_, _, _, ss, _, err := newTestStatesyncer(ctx, t, mn, t.TempDir(), testSSConfig(false, nil))
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("cleanup"))
	snap := &snapshotMetadata{Height: 1, Format: 1, Chunks: 4, Hash: hash[:], Size: 100,
		ChunkHashes: make([][32]byte, 4)}

	seed := func(t *testing.T) []string {
		t.Helper()
		var paths []string
		for i := range snap.Chunks {
			for _, name := range []string{
				fmt.Sprintf("chunk-%d.sql.gz", i),
				fmt.Sprintf("chunk-%d.sql.gz.tmp", i),
			} {
				path := filepath.Join(ss.snapshotDir, name)
				require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
				paths = append(paths, path)
			}
		}
		return paths
	}

	t.Run("cancelled before the first chunk", func(t *testing.T) {
		paths := seed(t)
		cancelled, stop := context.WithCancel(ctx)
		stop()

		require.ErrorIs(t, ss.cleanupInvalidSnapshot(cancelled, snap), context.Canceled)
		for _, path := range paths {
			require.FileExists(t, path, "cleanup kept working after its context was cancelled")
		}
	})

	t.Run("runs to completion otherwise", func(t *testing.T) {
		paths := seed(t)
		require.NoError(t, ss.cleanupInvalidSnapshot(ctx, snap))
		for _, path := range paths {
			require.NoFileExists(t, path)
		}
	})
}
