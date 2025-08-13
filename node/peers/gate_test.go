package peers

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/log"
)

// mockPeerMan implements the IsBlacklisted interface for testing
type mockPeerMan struct {
	blacklistedPeers map[peer.ID]string // peer -> reason
}

func (m *mockPeerMan) IsBlacklisted(p peer.ID) (bool, string) {
	if reason, exists := m.blacklistedPeers[p]; exists {
		return true, reason
	}
	return false, ""
}

func TestWhitelistGaterBlacklistIntegration(t *testing.T) {
	// Create test peer IDs
	whitePeer, err := peer.Decode("16Uiu2HAkuztyBUEcBxXrRRGJ2uBEdoJNpkYwXNQahS7Q6PH7VQHP")
	require.NoError(t, err)

	blackPeer, err := peer.Decode("16Uiu2HAkwWNgvbTRuKi9dRhWJN3cZPJ6LKN2Y3zRF1XkEVJgvVoE")
	require.NoError(t, err)

	normalPeer, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	t.Run("WhitelistedButBlacklistedPeerIsRejected", func(t *testing.T) {
		// Create mock PeerMan with blacklisted peer
		mockPM := &mockPeerMan{
			blacklistedPeers: map[peer.ID]string{
				blackPeer: "manual blacklist",
			},
		}

		// Create gater with both peers on whitelist
		allPeers := []peer.ID{whitePeer, blackPeer}
		gater := NewWhitelistGater(allPeers, WithLogger(log.DiscardLogger), WithPeerMan(mockPM))

		// Whitelisted peer should be allowed
		require.True(t, gater.IsAllowed(whitePeer))
		require.True(t, gater.InterceptPeerDial(whitePeer))
		require.True(t, gater.InterceptSecured(network.DirInbound, whitePeer, nil))

		// Blacklisted peer should be rejected despite being whitelisted
		require.False(t, gater.IsAllowed(blackPeer))
		require.False(t, gater.InterceptPeerDial(blackPeer))
		require.False(t, gater.InterceptSecured(network.DirInbound, blackPeer, nil))
	})

	t.Run("NonWhitelistedNonBlacklistedPeerIsRejected", func(t *testing.T) {
		mockPM := &mockPeerMan{
			blacklistedPeers: map[peer.ID]string{},
		}

		// Create gater with only one peer on whitelist
		gater := NewWhitelistGater([]peer.ID{whitePeer}, WithLogger(log.DiscardLogger), WithPeerMan(mockPM))

		// Normal peer (not whitelisted, not blacklisted) should be rejected
		require.False(t, gater.IsAllowed(normalPeer))
		require.False(t, gater.InterceptPeerDial(normalPeer))
		require.False(t, gater.InterceptSecured(network.DirInbound, normalPeer, nil))
	})

	t.Run("BlacklistTakesPrecedenceOverWhitelist", func(t *testing.T) {
		mockPM := &mockPeerMan{
			blacklistedPeers: map[peer.ID]string{
				blackPeer: "connection exhaustion",
			},
		}

		// Add blacklisted peer to whitelist
		gater := NewWhitelistGater([]peer.ID{blackPeer}, WithLogger(log.DiscardLogger), WithPeerMan(mockPM))

		// Should still be rejected because blacklist takes precedence
		require.False(t, gater.IsAllowed(blackPeer))
		require.False(t, gater.InterceptPeerDial(blackPeer))
		require.False(t, gater.InterceptSecured(network.DirInbound, blackPeer, nil))
	})

	t.Run("GaterWorksWithoutPeerMan", func(t *testing.T) {
		// Create gater without PeerMan reference (legacy behavior)
		gater := NewWhitelistGater([]peer.ID{whitePeer}, WithLogger(log.DiscardLogger))

		// Should work as before - only whitelist checking
		require.True(t, gater.IsAllowed(whitePeer))
		require.False(t, gater.IsAllowed(normalPeer))
	})

	t.Run("NilGaterAllowsEverything", func(t *testing.T) {
		var gater *WhitelistGater // nil gater

		// Nil gater should allow everything (existing behavior)
		require.True(t, gater.IsAllowed(whitePeer))
		require.True(t, gater.IsAllowed(blackPeer))
		require.True(t, gater.IsAllowed(normalPeer))
	})
}

func TestWhitelistGaterBlacklistReasons(t *testing.T) {
	blackPeer, err := peer.Decode("16Uiu2HAkwWNgvbTRuKi9dRhWJN3cZPJ6LKN2Y3zRF1XkEVJgvVoE")
	require.NoError(t, err)

	testCases := []struct {
		name   string
		reason string
	}{
		{"manual_blacklist", "manual blacklist"},
		{"connection_exhaustion", "connection exhaustion"},
		{"bad_behavior", "bad behavior"},
		{"empty_reason", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockPM := &mockPeerMan{
				blacklistedPeers: map[peer.ID]string{
					blackPeer: tc.reason,
				},
			}

			gater := NewWhitelistGater([]peer.ID{blackPeer}, WithLogger(log.DiscardLogger), WithPeerMan(mockPM))

			// Peer should be rejected regardless of reason
			require.False(t, gater.IsAllowed(blackPeer))

			// Verify reason is available (this would be logged in real usage)
			blacklisted, reason := mockPM.IsBlacklisted(blackPeer)
			require.True(t, blacklisted)
			require.Equal(t, tc.reason, reason)
		})
	}
}

func TestWhitelistGaterBlacklistUpdates(t *testing.T) {
	testPeer, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	mockPM := &mockPeerMan{
		blacklistedPeers: map[peer.ID]string{},
	}

	gater := NewWhitelistGater([]peer.ID{testPeer}, WithLogger(log.DiscardLogger), WithPeerMan(mockPM))

	// Initially peer should be allowed (whitelisted, not blacklisted)
	require.True(t, gater.IsAllowed(testPeer))

	// Add peer to blacklist
	mockPM.blacklistedPeers[testPeer] = "newly blacklisted"

	// Now peer should be rejected
	require.False(t, gater.IsAllowed(testPeer))

	// Remove peer from blacklist
	delete(mockPM.blacklistedPeers, testPeer)

	// Peer should be allowed again
	require.True(t, gater.IsAllowed(testPeer))
}

func TestWhitelistGaterAggregateLogging(t *testing.T) {
	// Create test peer IDs
	blackPeer, err := peer.Decode("16Uiu2HAkwWNgvbTRuKi9dRhWJN3cZPJ6LKN2Y3zRF1XkEVJgvVoE")
	require.NoError(t, err)

	t.Run("AggregateLoggingBasicFunctionality", func(t *testing.T) {
		// Create mock PeerMan with blacklisted peer
		mockPM := &mockPeerMan{
			blacklistedPeers: map[peer.ID]string{
				blackPeer: "testing aggregate logging",
			},
		}

		// Create gater with aggregate logging
		gater := NewWhitelistGater([]peer.ID{},
			WithLogger(log.DiscardLogger),
			WithPeerMan(mockPM),
			WithWhitelistEnforcement(false), // Blacklist-only mode
		)
		defer gater.Close()

		// Simulate multiple blocked connection attempts
		for range 5 {
			// These should be blocked and recorded for aggregate logging
			require.False(t, gater.InterceptSecured(network.DirInbound, blackPeer, nil))
			require.False(t, gater.InterceptPeerDial(blackPeer))
		}

		// Verify stats were recorded internally
		gater.statsMtx.Lock()
		statsCount := len(gater.blockedStats)
		gater.statsMtx.Unlock()

		require.Greater(t, statsCount, 0, "Expected blocked connection stats to be recorded")

		// Trigger aggregate logging (this would normally happen every 30 seconds)
		gater.logAggregateStats()

		// Verify stats were cleared after logging
		gater.statsMtx.Lock()
		statsCountAfter := len(gater.blockedStats)
		gater.statsMtx.Unlock()

		require.Equal(t, 0, statsCountAfter, "Expected stats to be cleared after aggregate logging")
	})

	t.Run("AggregateLoggerLifecycle", func(t *testing.T) {
		mockPM := &mockPeerMan{}

		// Create gater
		gater := NewWhitelistGater([]peer.ID{},
			WithLogger(log.DiscardLogger),
			WithPeerMan(mockPM),
		)

		// Verify logger started
		gater.statsMtx.Lock()
		started := gater.loggerStarted
		gater.statsMtx.Unlock()
		require.True(t, started, "Expected aggregate logger to start automatically")

		// Close gater
		gater.Close()

		// Verify logger stopped
		gater.statsMtx.Lock()
		stopped := !gater.loggerStarted
		gater.statsMtx.Unlock()
		require.True(t, stopped, "Expected aggregate logger to stop after Close()")
	})
}
