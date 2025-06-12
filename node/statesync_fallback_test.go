package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/require"
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
