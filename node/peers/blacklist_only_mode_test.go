package peers

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
)

// TestBlacklistOnlyModeIntegration tests the complete blacklist-only mode integration
// This test specifically targets the configuration that caused the nil pointer bug
func TestBlacklistOnlyModeIntegration(t *testing.T) {
	// Create test peer IDs
	testPeer1, err := peer.Decode("16Uiu2HAkuztyBUEcBxXrRRGJ2uBEdoJNpkYwXNQahS7Q6PH7VQHP")
	require.NoError(t, err)

	testPeer2, err := peer.Decode("16Uiu2HAkwWNgvbTRuKi9dRhWJN3cZPJ6LKN2Y3zRF1XkEVJgvVoE")
	require.NoError(t, err)

	blacklistedPeer, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	tempDir := t.TempDir()

	t.Run("BlacklistOnlyModeFullIntegration", func(t *testing.T) {
		// Create a test host
		host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer host.Close()

		// Create blacklist configuration
		blacklistConfig := config.BlacklistConfig{
			Enable: true,
		}

		peerManCfg := &Config{
			PEX:               false,
			AddrBook:          filepath.Join(tempDir, "addrbook.json"),
			Logger:            log.DiscardLogger,
			ChainID:           "blacklist-integration-test",
			Host:              host,
			BlacklistConfig:   blacklistConfig,
			TargetConnections: 5,
		}

		// Create PeerMan (this initializes the blacklist functionality)
		peerMan, err := NewPeerMan(peerManCfg)
		require.NoError(t, err, "PeerMan creation should succeed")
		require.NotNil(t, peerMan)

		// Test blacklist operations
		t.Run("BlacklistOperations", func(t *testing.T) {
			// Add peer to blacklist (BlacklistPeer doesn't return error, it's a void method)
			peerMan.BlacklistPeer(blacklistedPeer, "integration test", time.Hour)

			// Verify peer is blacklisted
			isBlacklisted, reason := peerMan.IsBlacklisted(blacklistedPeer)
			require.True(t, isBlacklisted, "Peer should be blacklisted")
			require.Equal(t, "integration test", reason, "Blacklist reason should match")

			// Other peers should not be blacklisted
			isBlacklisted, _ = peerMan.IsBlacklisted(testPeer1)
			require.False(t, isBlacklisted, "Other peer should not be blacklisted")
		})

		// Test WhitelistGater integration with blacklist-only mode
		t.Run("WhitelistGaterBlacklistOnlyIntegration", func(t *testing.T) {
			// Create WhitelistGater in blacklist-only mode (the configuration that caused the bug)
			gater := NewWhitelistGater(nil, // Empty whitelist
				WithLogger(log.DiscardLogger),
				WithWhitelistEnforcement(false), // Don't enforce whitelist (blacklist-only mode)
				WithPeerMan(peerMan),
			)

			require.NotNil(t, gater, "WhitelistGater should be created successfully")

			// Test that non-blacklisted peers are allowed (key difference from private mode)
			require.True(t, gater.IsAllowed(testPeer1), "Non-blacklisted peer should be allowed in blacklist-only mode")
			require.True(t, gater.IsAllowed(testPeer2), "Non-blacklisted peer should be allowed in blacklist-only mode")

			// Test that blacklisted peer is rejected
			require.False(t, gater.IsAllowed(blacklistedPeer), "Blacklisted peer should be rejected")

			// Test InterceptPeerDial method
			require.True(t, gater.InterceptPeerDial(testPeer1), "Non-blacklisted peer dial should be allowed")
			require.False(t, gater.InterceptPeerDial(blacklistedPeer), "Blacklisted peer dial should be blocked")

			// Test InterceptSecured method
			require.True(t, gater.InterceptSecured(0, testPeer1, nil), "Non-blacklisted peer connection should be allowed")
			require.False(t, gater.InterceptSecured(0, blacklistedPeer, nil), "Blacklisted peer connection should be blocked")
		})

		// Test dynamic blacklist updates
		t.Run("DynamicBlacklistUpdates", func(t *testing.T) {
			gater := NewWhitelistGater(nil,
				WithLogger(log.DiscardLogger),
				WithWhitelistEnforcement(false),
				WithPeerMan(peerMan),
			)

			// Initially, testPeer1 should be allowed
			require.True(t, gater.IsAllowed(testPeer1), "Peer should initially be allowed")

			// Add testPeer1 to blacklist
			peerMan.BlacklistPeer(testPeer1, "dynamic test", time.Hour)

			// Now testPeer1 should be rejected
			require.False(t, gater.IsAllowed(testPeer1), "Peer should be rejected after blacklisting")

			// Note: RemoveBlacklistedPeer might not be available in PeerMan interface
			// For this test, we'll just verify the blacklisting worked
		})
	})
}

// TestBlacklistOnlyVsPrivateModeComparison compares blacklist-only mode with private mode
func TestBlacklistOnlyVsPrivateModeComparison(t *testing.T) {
	// Create test peers
	whitelistedPeer, err := peer.Decode("16Uiu2HAkuztyBUEcBxXrRRGJ2uBEdoJNpkYwXNQahS7Q6PH7VQHP")
	require.NoError(t, err)

	unknownPeer, err := peer.Decode("16Uiu2HAkwWNgvbTRuKi9dRhWJN3cZPJ6LKN2Y3zRF1XkEVJgvVoE")
	require.NoError(t, err)

	blacklistedPeer, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	// Mock PeerMan for testing
	mockPM := &mockPeerMan{
		blacklistedPeers: map[peer.ID]string{
			blacklistedPeer: "test blacklist",
		},
	}

	testCases := []struct {
		name             string
		whitelist        []peer.ID
		enforceWhitelist bool
		testPeer         peer.ID
		expectedAllowed  bool
		description      string
	}{
		// Private Mode Tests (enforceWhitelist = true)
		{
			name:             "PrivateMode_WhitelistedPeer",
			whitelist:        []peer.ID{whitelistedPeer},
			enforceWhitelist: true,
			testPeer:         whitelistedPeer,
			expectedAllowed:  true,
			description:      "Private mode should allow whitelisted peers",
		},
		{
			name:             "PrivateMode_UnknownPeer",
			whitelist:        []peer.ID{whitelistedPeer},
			enforceWhitelist: true,
			testPeer:         unknownPeer,
			expectedAllowed:  false,
			description:      "Private mode should reject non-whitelisted peers",
		},
		{
			name:             "PrivateMode_BlacklistedPeer",
			whitelist:        []peer.ID{whitelistedPeer, blacklistedPeer},
			enforceWhitelist: true,
			testPeer:         blacklistedPeer,
			expectedAllowed:  false,
			description:      "Private mode should reject blacklisted peers even if whitelisted",
		},

		// Blacklist-Only Mode Tests (enforceWhitelist = false)
		{
			name:             "BlacklistOnly_WhitelistedPeer",
			whitelist:        []peer.ID{whitelistedPeer},
			enforceWhitelist: false,
			testPeer:         whitelistedPeer,
			expectedAllowed:  true,
			description:      "Blacklist-only mode should allow whitelisted peers",
		},
		{
			name:             "BlacklistOnly_UnknownPeer", // ← Key difference from private mode
			whitelist:        []peer.ID{whitelistedPeer},
			enforceWhitelist: false,
			testPeer:         unknownPeer,
			expectedAllowed:  true, // ← This is different from private mode!
			description:      "Blacklist-only mode should allow unknown peers (not on whitelist)",
		},
		{
			name:             "BlacklistOnly_BlacklistedPeer",
			whitelist:        []peer.ID{whitelistedPeer, blacklistedPeer},
			enforceWhitelist: false,
			testPeer:         blacklistedPeer,
			expectedAllowed:  false,
			description:      "Blacklist-only mode should reject blacklisted peers",
		},
		{
			name:             "BlacklistOnly_EmptyWhitelist_UnknownPeer", // ← The bug scenario
			whitelist:        nil,                                        // Empty whitelist
			enforceWhitelist: false,
			testPeer:         unknownPeer,
			expectedAllowed:  true, // Should be allowed in blacklist-only mode
			description:      "Blacklist-only mode with empty whitelist should allow unknown peers",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gater := NewWhitelistGater(tc.whitelist,
				WithLogger(log.DiscardLogger),
				WithWhitelistEnforcement(tc.enforceWhitelist),
				WithPeerMan(mockPM),
			)

			result := gater.IsAllowed(tc.testPeer)
			require.Equal(t, tc.expectedAllowed, result, tc.description)

			// Also test the connection methods for consistency
			dialResult := gater.InterceptPeerDial(tc.testPeer)
			require.Equal(t, tc.expectedAllowed, dialResult, "InterceptPeerDial should match IsAllowed")

			securedResult := gater.InterceptSecured(0, tc.testPeer, nil)
			require.Equal(t, tc.expectedAllowed, securedResult, "InterceptSecured should match IsAllowed")
		})
	}
}

// TestBlacklistOnlyModeEdgeCases tests edge cases specific to blacklist-only mode
func TestBlacklistOnlyModeEdgeCases(t *testing.T) {
	testPeer, err := peer.Decode("16Uiu2HAkuztyBUEcBxXrRRGJ2uBEdoJNpkYwXNQahS7Q6PH7VQHP")
	require.NoError(t, err)

	t.Run("BlacklistOnlyWithNilPeerMan", func(t *testing.T) {
		// This tests the scenario where blacklist is enabled but PeerMan is not yet available
		gater := NewWhitelistGater(nil,
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(false),
			// No WithPeerMan - peerMan will be nil
		)

		// Should not panic and should allow peers (no blacklist available, no whitelist enforcement)
		require.NotPanics(t, func() {
			result := gater.IsAllowed(testPeer)
			require.True(t, result, "Should allow peer when peerMan is nil in blacklist-only mode")
		})

		// Test SetPeerMan later (simulating the initialization sequence)
		mockPM := &mockPeerMan{
			blacklistedPeers: map[peer.ID]string{
				testPeer: "late blacklist",
			},
		}

		gater.SetPeerMan(mockPM)

		// Now should reject the blacklisted peer
		result := gater.IsAllowed(testPeer)
		require.False(t, result, "Should reject peer after PeerMan is set and peer is blacklisted")
	})

	t.Run("BlacklistOnlyModeWithEmptyBlacklist", func(t *testing.T) {
		// Test with PeerMan that has no blacklisted peers
		mockPM := &mockPeerMan{
			blacklistedPeers: map[peer.ID]string{}, // Empty blacklist
		}

		gater := NewWhitelistGater(nil,
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(false),
			WithPeerMan(mockPM),
		)

		// Should allow all peers
		require.True(t, gater.IsAllowed(testPeer), "Should allow all peers when blacklist is empty")
	})

	t.Run("BlacklistOnlyModeTransitionFromPrivate", func(t *testing.T) {
		// Test the conceptual transition from private mode to blacklist-only mode
		// (This would require runtime configuration changes, which aren't currently supported,
		// but this test documents the expected behavior)

		testPeer2, err := peer.Decode("16Uiu2HAkwWNgvbTRuKi9dRhWJN3cZPJ6LKN2Y3zRF1XkEVJgvVoE")
		require.NoError(t, err)

		mockPM := &mockPeerMan{blacklistedPeers: map[peer.ID]string{}}

		// Start with private mode
		privateGater := NewWhitelistGater([]peer.ID{testPeer},
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(true), // Private mode
			WithPeerMan(mockPM),
		)

		// In private mode, unknown peer should be rejected
		require.False(t, privateGater.IsAllowed(testPeer2), "Private mode should reject unknown peer")

		// Create new gater with blacklist-only mode (simulating configuration change)
		blacklistGater := NewWhitelistGater([]peer.ID{testPeer},
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(false), // Blacklist-only mode
			WithPeerMan(mockPM),
		)

		// In blacklist-only mode, unknown peer should be allowed
		require.True(t, blacklistGater.IsAllowed(testPeer2), "Blacklist-only mode should allow unknown peer")
	})
}
