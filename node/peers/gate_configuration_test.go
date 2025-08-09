package peers

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/log"
)

// TestWhitelistGaterConfigurationMatrix tests all possible configuration combinations
// This would have caught the nil pointer bug in blacklist-only mode
func TestWhitelistGaterConfigurationMatrix(t *testing.T) {
	// Create test peer IDs
	testPeer, err := peer.Decode("16Uiu2HAkuztyBUEcBxXrRRGJ2uBEdoJNpkYwXNQahS7Q6PH7VQHP")
	require.NoError(t, err)

	blacklistedPeer, err := peer.Decode("16Uiu2HAkwWNgvbTRuKi9dRhWJN3cZPJ6LKN2Y3zRF1XkEVJgvVoE")
	require.NoError(t, err)

	unknownPeer, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	// Mock PeerMan with one blacklisted peer
	mockPM := &mockPeerMan{
		blacklistedPeers: map[peer.ID]string{
			blacklistedPeer: "test blacklist",
		},
	}

	testCases := []struct {
		name             string
		whitelist        []peer.ID
		enforceWhitelist bool
		peerMan          interface{ IsBlacklisted(peer.ID) (bool, string) }
		expectedBehavior map[peer.ID]bool // peer -> should be allowed
		description      string
	}{
		{
			name:             "DefaultMode_NoWhitelistNoBlacklist",
			whitelist:        nil,
			enforceWhitelist: true, // Default behavior
			peerMan:          nil,  // No blacklist functionality
			expectedBehavior: map[peer.ID]bool{
				testPeer:        false, // Not whitelisted
				blacklistedPeer: false, // Not whitelisted
				unknownPeer:     false, // Not whitelisted
			},
			description: "Default mode: empty whitelist blocks all peers",
		},
		{
			name:             "PrivateMode_WithWhitelistAndBlacklist",
			whitelist:        []peer.ID{testPeer, blacklistedPeer},
			enforceWhitelist: true,
			peerMan:          mockPM,
			expectedBehavior: map[peer.ID]bool{
				testPeer:        true,  // Whitelisted, not blacklisted
				blacklistedPeer: false, // Whitelisted but blacklisted (blacklist wins)
				unknownPeer:     false, // Not whitelisted
			},
			description: "Private mode: whitelist + blacklist enforcement",
		},
		{
			name:             "BlacklistOnlyMode_NoWhitelistEnforcement", // ← THE CRITICAL TEST
			whitelist:        nil,                                        // Empty whitelist
			enforceWhitelist: false,                                      // Don't enforce whitelist (blacklist-only)
			peerMan:          mockPM,
			expectedBehavior: map[peer.ID]bool{
				testPeer:        true,  // Not blacklisted, whitelist not enforced
				blacklistedPeer: false, // Blacklisted
				unknownPeer:     true,  // Not blacklisted, whitelist not enforced
			},
			description: "Blacklist-only mode: only blacklist is enforced, whitelist ignored",
		},
		{
			name:             "BlacklistOnlyMode_WithSomeWhitelist",
			whitelist:        []peer.ID{testPeer}, // Non-empty whitelist
			enforceWhitelist: false,               // But don't enforce it
			peerMan:          mockPM,
			expectedBehavior: map[peer.ID]bool{
				testPeer:        true,  // Not blacklisted, whitelist not enforced
				blacklistedPeer: false, // Blacklisted
				unknownPeer:     true,  // Not blacklisted, whitelist not enforced
			},
			description: "Blacklist-only mode with existing whitelist: whitelist ignored, only blacklist enforced",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create WhitelistGater with specific configuration
			var opts []GateOpt
			opts = append(opts, WithLogger(log.DiscardLogger))
			opts = append(opts, WithWhitelistEnforcement(tc.enforceWhitelist))
			if tc.peerMan != nil {
				opts = append(opts, WithPeerMan(tc.peerMan))
			}

			gater := NewWhitelistGater(tc.whitelist, opts...)

			// Test all three methods for each peer
			for testPeerID, expectedAllowed := range tc.expectedBehavior {
				t.Run(testPeerID.String()[:8], func(t *testing.T) {
					// Test IsAllowed method
					allowed := gater.IsAllowed(testPeerID)
					require.Equal(t, expectedAllowed, allowed,
						"IsAllowed failed for %s in %s", testPeerID.String()[:8], tc.description)

					// Test InterceptPeerDial method
					dialAllowed := gater.InterceptPeerDial(testPeerID)
					require.Equal(t, expectedAllowed, dialAllowed,
						"InterceptPeerDial failed for %s in %s", testPeerID.String()[:8], tc.description)

					// Test InterceptSecured method
					securedAllowed := gater.InterceptSecured(network.DirInbound, testPeerID, nil)
					require.Equal(t, expectedAllowed, securedAllowed,
						"InterceptSecured failed for %s in %s", testPeerID.String()[:8], tc.description)
				})
			}
		})
	}
}

// TestWhitelistGaterNilPointerSafety tests that the gater handles nil references gracefully
// This specifically tests the scenario that caused the original bug
func TestWhitelistGaterNilPointerSafety(t *testing.T) {
	testPeer, err := peer.Decode("16Uiu2HAkuztyBUEcBxXrRRGJ2uBEdoJNpkYwXNQahS7Q6PH7VQHP")
	require.NoError(t, err)

	t.Run("GaterWithNilPeerManShouldNotPanic", func(t *testing.T) {
		// Create gater without PeerMan (peerMan will be nil)
		gater := NewWhitelistGater(nil,
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(false)) // Blacklist-only mode

		// These should not panic even though peerMan is nil
		require.NotPanics(t, func() {
			gater.IsAllowed(testPeer)
		})
		require.NotPanics(t, func() {
			gater.InterceptPeerDial(testPeer)
		})
		require.NotPanics(t, func() {
			gater.InterceptSecured(network.DirInbound, testPeer, nil)
		})
	})

	t.Run("GaterWithNilPeerManBlacklistOnlyMode", func(t *testing.T) {
		// This is the exact scenario that caused the bug:
		// - Empty whitelist
		// - enforceWhitelist = false (blacklist-only mode)
		// - peerMan = nil initially
		gater := NewWhitelistGater(nil,
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(false))

		// Should allow all peers since blacklist is not available and whitelist not enforced
		require.True(t, gater.IsAllowed(testPeer))
		require.True(t, gater.InterceptPeerDial(testPeer))
		require.True(t, gater.InterceptSecured(network.DirInbound, testPeer, nil))
	})

	t.Run("SetPeerManAfterCreation", func(t *testing.T) {
		// Test the SetPeerMan functionality that caused issues
		mockPM := &mockPeerMan{
			blacklistedPeers: map[peer.ID]string{
				testPeer: "test blacklist",
			},
		}

		// Create gater without PeerMan
		gater := NewWhitelistGater(nil,
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(false))

		// Initially should allow (no blacklist available)
		require.True(t, gater.IsAllowed(testPeer))

		// Set PeerMan after creation (this is done during P2P initialization)
		gater.SetPeerMan(mockPM)

		// Now should reject blacklisted peer
		require.False(t, gater.IsAllowed(testPeer))
	})

	t.Run("SetPeerManOnNilGater", func(t *testing.T) {
		// Test that SetPeerMan handles nil gater gracefully
		var gater *WhitelistGater // nil gater

		// Should not panic
		require.NotPanics(t, func() {
			gater.SetPeerMan(&mockPeerMan{})
		})
	})
}

// TestWhitelistGaterEnforcementTransitions tests changing enforcement modes
func TestWhitelistGaterEnforcementTransitions(t *testing.T) {
	testPeer, err := peer.Decode("16Uiu2HAkuztyBUEcBxXrRRGJ2uBEdoJNpkYwXNQahS7Q6PH7VQHP")
	require.NoError(t, err)

	unknownPeer, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	mockPM := &mockPeerMan{
		blacklistedPeers: map[peer.ID]string{},
	}

	t.Run("PrivateModeToBlacklistOnlyMode", func(t *testing.T) {
		// This would require changing the gater configuration at runtime
		// Currently not supported, but this test documents the expected behavior

		// Private mode: enforce whitelist
		privateGater := NewWhitelistGater([]peer.ID{testPeer},
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(true),
			WithPeerMan(mockPM))

		// In private mode, unknown peer is rejected
		require.False(t, privateGater.IsAllowed(unknownPeer))

		// Blacklist-only mode: don't enforce whitelist
		blacklistGater := NewWhitelistGater([]peer.ID{testPeer},
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(false),
			WithPeerMan(mockPM))

		// In blacklist-only mode, unknown peer is allowed
		require.True(t, blacklistGater.IsAllowed(unknownPeer))
	})
}
