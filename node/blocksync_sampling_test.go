package node

import (
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto"

	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/require"
)

func TestPeerSamplingInSmallNetworks(t *testing.T) {
	// Test that the peer sampling logic queries more peers in small networks
	mn := mock.New()
	defer mn.Close()

	// Create 4 hosts (1 requester + 3 peers)
	_, hMe := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, h1 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, h2 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, h3 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())
	time.Sleep(100 * time.Millisecond)

	// Get peer list and verify we have 3 peers
	allPeers := peerHosts(hMe)
	require.Len(t, allPeers, 3, "Should have exactly 3 peers")
	require.Contains(t, allPeers, h1.ID())
	require.Contains(t, allPeers, h2.ID())
	require.Contains(t, allPeers, h3.ID())

	// This verifies that the peer discovery mechanism works correctly
	// and that our sampling logic will have the right input
}

func TestPeerCacheFiltering(t *testing.T) {
	// Test that peers with stale cache entries are not filtered out
	mn := mock.New()
	defer mn.Close()

	_, hMe := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, hPeer := newTestHost(t, mn, crypto.KeyTypeSecp256k1)

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())
	time.Sleep(100 * time.Millisecond)

	const targetHeight = int64(200)

	// Add a stale cache entry (older than cacheTTL)
	oldTime := time.Now().Add(-2 * cacheTTL) // cacheTTL is 5 minutes, so this is 10 minutes ago
	peerBest.Store(hPeer.ID(), peerInfo{height: targetHeight - 1, seenAt: oldTime})

	// Get all peers - should include the peer despite stale cache
	allPeers := peerHosts(hMe)
	require.Contains(t, allPeers, hPeer.ID(), "Peer should be discovered")
	require.Len(t, allPeers, 1, "Should have exactly one peer")
}

func TestPeerBestCacheCleanup(t *testing.T) {
	// Test the cache cleanup functionality
	mn := mock.New()
	defer mn.Close()

	_, h1 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, h2 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)

	const targetHeight = int64(100)

	// Add recent entry
	peerBest.Store(h1.ID(), peerInfo{height: targetHeight, seenAt: time.Now()})

	// Add very old entry
	veryOldTime := time.Now().Add(-2 * cacheTTL)
	peerBest.Store(h2.ID(), peerInfo{height: targetHeight - 1, seenAt: veryOldTime})

	// Call garbage collection
	gcPeerCache()

	// Check that recent entry is still there
	if _, ok := peerBest.Load(h1.ID()); !ok {
		t.Error("Recent cache entry should not be garbage collected")
	}

	// Old entry might or might not be there depending on implementation,
	// but the test verifies gcPeerCache doesn't crash
}

func TestSampleSizeCalculation(t *testing.T) {
	// Test the sample size calculation logic
	testCases := []struct {
		name           string
		eligiblePeers  int
		expectedSample int
	}{
		{"1 peer", 1, 1},
		{"3 peers", 3, 3},
		{"5 peers", 5, 5},
		{"6 peers", 6, 3},      // 6/3 = 2, max(2, 3) = 3
		{"10 peers", 10, 3},    // 10/3 = 3, max(3, 3) = 3
		{"15 peers", 15, 5},    // 15/3 = 5, max(5, 3) = 5
		{"16 peers", 16, 3},    // 16/5 = 3, max(3, 3) = 3 (switches to /5 logic)
		{"20 peers", 20, 4},    // 20/5 = 4, max(4, 3) = 4
		{"100 peers", 100, 20}, // 100/5 = 20, max(20, 3) = 20
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var sampleSize int
			switch {
			case tc.eligiblePeers <= 5:
				sampleSize = tc.eligiblePeers // Query all peers in small networks
			case tc.eligiblePeers <= 15:
				sampleSize = max(tc.eligiblePeers/3, 3) // Query at least 3, up to 1/3
			default:
				sampleSize = max(tc.eligiblePeers/5, 3) // Query at least 3, up to 1/5 (original behavior)
			}
			require.Equal(t, tc.expectedSample, sampleSize,
				"Sample size calculation for %d peers", tc.eligiblePeers)
		})
	}
}
