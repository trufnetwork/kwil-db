package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/require"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
)

// TestStateSyncFallback verifies that the StateSyncService is able to fall back
// to the latest snapshot that *can* be verified by the trusted providers when a
// newer snapshot advertised by un-trusted peers cannot be verified. Today the
// implementation will keep retrying the un-verifiable snapshot and ultimately
// give up, therefore this test currently FAILS. It should pass after the
// selection logic black-lists unverifiable snapshots and retries with the next
// best candidate.
func TestStateSyncFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mn := mock.New()
	tmpDir := t.TempDir()

	// ---------------------------------------------------------------------
	// 1. Build the TRUSTED provider (hT) – it will have snapshots up to height 4
	// ---------------------------------------------------------------------
	_, dT, stT, _, pkT, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "trusted"), testSSConfig(false, nil))
	require.NoError(t, err)

	// ---------------------------------------------------------------------
	// 2. Build the UNTRUSTED provider (hU) – it advertises a newer snapshot (h=5)
	// ---------------------------------------------------------------------
	_, dU, stU, _, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "untrusted"), testSSConfig(false, nil))
	require.NoError(t, err)

	// ---------------------------------------------------------------------
	// 3. Build the node under test (hMe) with hT as its single trusted provider
	// ---------------------------------------------------------------------
	bootPeer := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pkT.Public().Bytes()), pkT.Type())
	hMe, dMe, _, ssMe, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "me"), testSSConfig(true, []string{bootPeer}))
	require.NoError(t, err)

	// ---------------------------------------------------------------------
	// 4. Inter-connect the mock hosts
	// ---------------------------------------------------------------------
	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())

	// ---------------------------------------------------------------------
	// 5. Prepare snapshots – hT has height 4, hU advertises height 5
	// ---------------------------------------------------------------------
	hashData := sha256.Sum256([]byte("snapshot"))

	snapH4 := &snapshotMetadata{
		Height:      4,
		Format:      1,
		Chunks:      1,
		Hash:        hashData[:],
		Size:        100,
		ChunkHashes: [][32]byte{hashData},
	}
	snapH5 := &snapshotMetadata{
		Height:      5,
		Format:      1,
		Chunks:      1,
		Hash:        hashData[:], // reuse same hash – contents not important for this test
		Size:        100,
		ChunkHashes: [][32]byte{hashData},
	}

	stT.addSnapshot(snapH4)
	stU.addSnapshot(snapH5)

	// ---------------------------------------------------------------------
	// 6. Advertise snapshot-catalog service for discovery
	// ---------------------------------------------------------------------
	advertise(ctx, snapshotCatalogNS, dT)
	advertise(ctx, snapshotCatalogNS, dU)

	time.Sleep(500 * time.Millisecond) // small delay for discovery

	// ---------------------------------------------------------------------
	// 7. Manually request snapshot catalogues and exercise verification logic
	//    without invoking chunk download / DB restore paths. This keeps the
	//    test lightweight and focussed on the selection + verification stage.
	// ---------------------------------------------------------------------

	// Discover peers from the perspective of the test node
	peers, err := discoverProviders(ctx, snapshotCatalogNS, dMe)
	require.NoError(t, err)

	for _, p := range peers {
		// filter out self
		if p.ID == hMe.ID() {
			continue
		}
		require.NoError(t, ssMe.requestSnapshotCatalogs(ctx, p))
	}

	// best snapshot should be height 5 (from untrusted peer)
	bestSnap, err := ssMe.bestSnapshot()
	require.NoError(t, err)
	require.Equal(t, uint64(5), bestSnap.Height)

	// Verification should fail (trusted provider lacks height 5)
	result, _ := ssMe.VerifySnapshot(ctx, bestSnap)
	require.Equal(t, VerificationInvalid, result)

	// Blacklist the invalid snapshot to simulate statesync loop behaviour
	ssMe.snapshotPool.blacklistSnapshot(bestSnap)

	// Next best snapshot should now be height 4
	bestSnap, err = ssMe.bestSnapshot()
	require.NoError(t, err)
	require.Equal(t, uint64(4), bestSnap.Height)

	result, _ = ssMe.VerifySnapshot(ctx, bestSnap)
	require.Equal(t, VerificationValid, result)
}

func TestSnapshotCatalogDedup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mn := mock.New()
	tmpDir := t.TempDir()

	// Trusted provider (no snapshots)
	_, dT, _, _, pkT, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "trusted2"), testSSConfig(false, nil))
	require.NoError(t, err)

	// Untrusted providers U1 and U2 advertising SAME snapshot
	_, dU1, stU1, _, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "untrusted1"), testSSConfig(false, nil))
	require.NoError(t, err)
	_, dU2, stU2, _, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "untrusted2"), testSSConfig(false, nil))
	require.NoError(t, err)

	// Node under test
	bootPeer := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pkT.Public().Bytes()), pkT.Type())
	hMe, dMe, _, ssMe, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "me3"), testSSConfig(true, []string{bootPeer}))
	require.NoError(t, err)

	// Link and connect all hosts
	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())

	// Prepare identical snapshot
	hash := sha256.Sum256([]byte("dupSnap"))
	dupSnap := &snapshotMetadata{
		Height:      10,
		Format:      1,
		Chunks:      1,
		Hash:        hash[:],
		Size:        50,
		ChunkHashes: [][32]byte{hash},
	}
	stU1.addSnapshot(dupSnap)
	stU2.addSnapshot(dupSnap)

	// Advertise snapshot-catalog
	advertise(ctx, snapshotCatalogNS, dT)
	advertise(ctx, snapshotCatalogNS, dU1)
	advertise(ctx, snapshotCatalogNS, dU2)

	time.Sleep(500 * time.Millisecond)

	// Discover peers and request catalogs
	peers, err := discoverProviders(ctx, snapshotCatalogNS, dMe)
	require.NoError(t, err)

	for _, p := range peers {
		if p.ID == hMe.ID() {
			continue
		}
		require.NoError(t, ssMe.requestSnapshotCatalogs(ctx, p))
	}

	snaps := ssMe.snapshotPool.listSnapshots()
	require.Len(t, snaps, 1, "should have exactly one snapshot entry despite duplicates")

	key := dupSnap.Key()
	providers := ssMe.snapshotPool.keyProviders(key)
	require.Len(t, providers, 2, "provider list should contain both untrusted providers")
}

// TestStateSyncFallsBackWhenTrustedProvidersUnreachable is the regression test for
// the statesync loop that never terminated when the snapshot pool was non-empty but
// every trusted provider was unreachable. The VerificationFailed branch deliberately
// does not blacklist the snapshot, so bestSnapshot kept re-selecting it and the
// download loop spun forever, never reaching the block sync fallback.
func TestStateSyncFallsBackWhenTrustedProvidersUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	mn := mock.New()
	tmpDir := t.TempDir()

	// Trusted provider - it will refuse to serve snapshot metadata
	hT, dT, _, _, pkT, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "trusted"), testSSConfig(false, nil))
	require.NoError(t, err)

	// Untrusted provider - it advertises a snapshot, so the pool is not empty
	_, dU, stU, _, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "untrusted"), testSSConfig(false, nil))
	require.NoError(t, err)

	// Node under test, with hT as its single trusted provider
	bootPeer := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pkT.Public().Bytes()), pkT.Type())
	cfgMe := testSSConfig(true, []string{bootPeer})
	cfgMe.MaxRetries = 0 // a single discovery round
	cfgMe.DiscoveryTimeout = ktypes.Duration(200 * time.Millisecond)
	hMe, dMe, _, ssMe, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "me"), cfgMe)
	require.NoError(t, err)
	ssMe.retryBackoff = 10 * time.Millisecond

	// Make the trusted provider unreachable for verification only, so that
	// VerifySnapshot reports VerificationFailed (a network-class failure).
	hT.SetStreamHandler(snapshotter.ProtocolIDSnapshotMeta, func(s network.Stream) { s.Reset() })

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())

	hashData := sha256.Sum256([]byte("snapshot"))
	snapH5 := &snapshotMetadata{
		Height:      5,
		Format:      1,
		Chunks:      1,
		Hash:        hashData[:],
		Size:        100,
		ChunkHashes: [][32]byte{hashData},
	}
	stU.addSnapshot(snapH5)

	advertise(ctx, snapshotCatalogNS, dT)
	advertise(ctx, snapshotCatalogNS, dU)

	time.Sleep(500 * time.Millisecond) // small delay for discovery

	// Populate the snapshot pool deterministically before the discovery loop runs,
	// so the test cannot pass via ErrNoSnapshotsDiscovered.
	peers, err := discoverProviders(ctx, snapshotCatalogNS, dMe)
	require.NoError(t, err)
	for _, p := range peers {
		if p.ID == hMe.ID() {
			continue
		}
		require.NoError(t, ssMe.requestSnapshotCatalogs(ctx, p))
	}

	bestSnap, err := ssMe.bestSnapshot()
	require.NoError(t, err)
	require.Equal(t, uint64(5), bestSnap.Height)

	height, err := ssMe.DiscoverSnapshots(ctx)
	require.NoError(t, err, "DiscoverSnapshots must return cleanly, not via context cancellation")
	require.Equal(t, int64(-1), height)

	// The snapshot only failed for network reasons, so it must survive untouched.
	require.Len(t, ssMe.snapshotPool.listSnapshots(), 1, "a transient network failure must not remove the snapshot")
	ssMe.snapshotPool.mtx.Lock()
	_, blacklisted := ssMe.snapshotPool.blacklist[snapH5.Key()]
	ssMe.snapshotPool.mtx.Unlock()
	require.False(t, blacklisted, "a transient network failure must not blacklist an otherwise-good snapshot")
}

// TestStateSyncFallsBackWhenChunksUnavailable covers the chunk fetch failure path,
// which used to loop on the same snapshot without a backoff or an attempt bound.
func TestStateSyncFallsBackWhenChunksUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	mn := mock.New()
	tmpDir := t.TempDir()

	// Trusted provider - it holds the snapshot, so verification succeeds
	_, dT, stT, _, pkT, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "trusted2"), testSSConfig(false, nil))
	require.NoError(t, err)

	_, dU, stU, _, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "untrusted2"), testSSConfig(false, nil))
	require.NoError(t, err)

	bootPeer := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pkT.Public().Bytes()), pkT.Type())
	cfgMe := testSSConfig(true, []string{bootPeer})
	cfgMe.MaxRetries = 0
	cfgMe.DiscoveryTimeout = ktypes.Duration(200 * time.Millisecond)
	hMe, dMe, _, ssMe, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "me2"), cfgMe)
	require.NoError(t, err)
	ssMe.retryBackoff = 10 * time.Millisecond

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())

	// The chunk hash cannot match what the providers actually serve, so every
	// chunk fetch fails without being retryable.
	badChunk := sha256.Sum256([]byte("not-the-chunk"))
	snapH7 := &snapshotMetadata{
		Height:      7,
		Format:      snapshotter.DefaultSnapshotFormat,
		Chunks:      1,
		Hash:        badChunk[:],
		Size:        100,
		ChunkHashes: [][32]byte{badChunk},
	}
	stT.addSnapshot(snapH7)
	stU.addSnapshot(snapH7)

	advertise(ctx, snapshotCatalogNS, dT)
	advertise(ctx, snapshotCatalogNS, dU)

	time.Sleep(500 * time.Millisecond)

	peers, err := discoverProviders(ctx, snapshotCatalogNS, dMe)
	require.NoError(t, err)
	for _, p := range peers {
		if p.ID == hMe.ID() {
			continue
		}
		require.NoError(t, ssMe.requestSnapshotCatalogs(ctx, p))
	}

	bestSnap, err := ssMe.bestSnapshot()
	require.NoError(t, err)
	require.Equal(t, uint64(7), bestSnap.Height)

	// Verification passes, so the run below exercises the chunk fetch branch.
	result, _ := ssMe.VerifySnapshot(ctx, bestSnap)
	require.Equal(t, VerificationValid, result)

	height, err := ssMe.DiscoverSnapshots(ctx)
	require.NoError(t, err, "DiscoverSnapshots must return cleanly, not via context cancellation")
	require.Equal(t, int64(-1), height)

	require.Len(t, ssMe.snapshotPool.listSnapshots(), 1, "a chunk fetch failure must not remove the snapshot")
	ssMe.snapshotPool.mtx.Lock()
	_, blacklisted := ssMe.snapshotPool.blacklist[snapH7.Key()]
	ssMe.snapshotPool.mtx.Unlock()
	require.False(t, blacklisted, "a chunk fetch failure must not blacklist the snapshot")
}

// TestSnapshotCatalogSkipsBlacklistedEntries verifies that a snapshot the trusted
// providers already rejected cannot re-enter the pool from a catalog that arrives
// later. Catalog requests run on goroutines that outlive the discovery window, so
// without this the download loop could re-select an entry it had just blacklisted.
func TestSnapshotCatalogSkipsBlacklistedEntries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mn := mock.New()
	tmpDir := t.TempDir()

	hU, _, _, _, pkU, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "untrusted3"), testSSConfig(false, nil))
	require.NoError(t, err)

	bootPeer := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pkU.Public().Bytes()), pkU.Type())
	_, _, _, ssMe, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(tmpDir, "me3"), testSSConfig(true, []string{bootPeer}))
	require.NoError(t, err)

	rejectedHash := sha256.Sum256([]byte("rejected"))
	goodHash := sha256.Sum256([]byte("well-formed"))
	rejected := &snapshotMetadata{Height: 99, Format: 1, Chunks: 1, Hash: rejectedHash[:], Size: 100,
		ChunkHashes: [][32]byte{rejectedHash}}
	catalog := []*snapshotMetadata{
		rejected,
		{Height: 97, Format: 1, Chunks: 1, Hash: goodHash[:], Size: 100, ChunkHashes: [][32]byte{goodHash}},
	}

	hU.SetStreamHandler(snapshotter.ProtocolIDSnapshotCatalog, func(s network.Stream) {
		defer s.Close()
		json.NewEncoder(s).Encode(catalog)
	})

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())

	// The trusted providers rejected the taller snapshot on an earlier round.
	ssMe.snapshotPool.blacklistSnapshot(rejected)

	require.NoError(t, ssMe.requestSnapshotCatalogs(ctx, peer.AddrInfo{ID: hU.ID()}))

	snaps := ssMe.snapshotPool.listSnapshots()
	require.Len(t, snaps, 1, "a blacklisted snapshot must not re-enter the pool")
	require.Equal(t, uint64(97), snaps[0].Height)
}
