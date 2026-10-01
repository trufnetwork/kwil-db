package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/require"

	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
)

func findTestSnapshot(height uint64) *snapshotMetadata {
	hash := sha256.Sum256(fmt.Appendf(nil, "snapshot %d", height))
	return &snapshotMetadata{
		Height:      height,
		Format:      1,
		Chunks:      1,
		Hash:        hash[:],
		Size:        100,
		ChunkHashes: [][32]byte{hash},
	}
}

// countChunkRequests replaces a provider's chunk handlers with ones that count
// each request and serve nothing.
func countChunkRequests(h host.Host, n *atomic.Int64) {
	count := func(s network.Stream) {
		n.Add(1)
		s.Reset()
	}
	h.SetStreamHandler(snapshotter.ProtocolIDSnapshotChunk, count)
	h.SetStreamHandler(snapshotter.ProtocolIDSnapshotRange, count)
}

type findTestNet struct {
	trusted, untrusted *snapshotStore
	trustedHost        host.Host
	me                 *StateSyncService
	chunkRequests      atomic.Int64
}

// newFindTestNet links a trusted provider, an untrusted provider and the node
// under test, which trusts only the first.
func newFindTestNet(ctx context.Context, t *testing.T) *findTestNet {
	t.Helper()
	mn := mock.New()
	dir := t.TempDir()
	net := &findTestNet{}

	hT, dT, stT, _, pkT, err := newTestStatesyncer(ctx, t, mn, filepath.Join(dir, "trusted"), testSSConfig(false, nil))
	require.NoError(t, err)
	hU, dU, stU, _, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(dir, "untrusted"), testSSConfig(false, nil))
	require.NoError(t, err)

	bootPeer := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pkT.Public().Bytes()), pkT.Type())
	cfg := testSSConfig(true, []string{bootPeer})
	cfg.DiscoveryTimeout = ktypes.Duration(500 * time.Millisecond)
	_, _, _, me, _, err := newTestStatesyncer(ctx, t, mn, filepath.Join(dir, "me"), cfg)
	require.NoError(t, err)

	countChunkRequests(hT, &net.chunkRequests)
	countChunkRequests(hU, &net.chunkRequests)

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())
	advertise(ctx, snapshotCatalogNS, dT)
	advertise(ctx, snapshotCatalogNS, dU)
	time.Sleep(500 * time.Millisecond) // let the advertisements land

	net.trusted, net.untrusted, net.trustedHost, net.me = stT, stU, hT, me
	return net
}

func TestFindVerifiedSnapshotReturnsTheHighestTrustedOne(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	net := newFindTestNet(ctx, t)

	snap5, snap10, snap12 := findTestSnapshot(5), findTestSnapshot(10), findTestSnapshot(12)
	net.trusted.addSnapshot(snap5)
	net.trusted.addSnapshot(snap10)
	net.untrusted.addSnapshot(snap10)
	net.untrusted.addSnapshot(snap12) // the trusted provider does not have it

	height, ok, err := net.me.FindVerifiedSnapshot(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint64(10), height)

	// Nothing was downloaded.
	require.Zero(t, net.chunkRequests.Load())
	entries, err := os.ReadDir(net.me.snapshotDir)
	require.NoError(t, err)
	require.Empty(t, entries)

	// The snapshot the trusted provider rejected is blacklisted.
	net.me.snapshotPool.mtx.Lock()
	_, blacklisted := net.me.snapshotPool.blacklist[snap12.Key()]
	net.me.snapshotPool.mtx.Unlock()
	require.True(t, blacklisted)
}

func TestFindVerifiedSnapshotWhenTheTrustedProviderIsUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	net := newFindTestNet(ctx, t)
	net.trustedHost.SetStreamHandler(snapshotter.ProtocolIDSnapshotMeta, func(s network.Stream) { s.Reset() })

	snap10 := findTestSnapshot(10)
	net.untrusted.addSnapshot(snap10)

	height, ok, err := net.me.FindVerifiedSnapshot(ctx)
	require.NoError(t, err)
	require.False(t, ok)
	require.Zero(t, height)

	// A network failure says nothing about the snapshot, so it is kept.
	net.me.snapshotPool.mtx.Lock()
	_, blacklisted := net.me.snapshotPool.blacklist[snap10.Key()]
	net.me.snapshotPool.mtx.Unlock()
	require.False(t, blacklisted)
	require.Zero(t, net.chunkRequests.Load())
}

func TestFindVerifiedSnapshotWhenNoneIsOffered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	net := newFindTestNet(ctx, t)

	height, ok, err := net.me.FindVerifiedSnapshot(ctx)
	require.NoError(t, err)
	require.False(t, ok)
	require.Zero(t, height)
}

func TestFindVerifiedSnapshotWhenTheTrustedProviderRejectsAll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	net := newFindTestNet(ctx, t)

	net.untrusted.addSnapshot(findTestSnapshot(12)) // the trusted provider has none

	height, ok, err := net.me.FindVerifiedSnapshot(ctx)
	require.NoError(t, err)
	require.False(t, ok)
	require.Zero(t, height)
	require.Zero(t, net.chunkRequests.Load())
}
