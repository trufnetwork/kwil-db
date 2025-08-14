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

// TestBlacklistOnlyModeRegression ensures that nodes in blacklist-only mode
// (private_mode=false, blacklist.enable=true) work correctly.
// This is a regression test to prevent the bug where such nodes would
// incorrectly behave like private nodes due to gater misconfiguration.
func TestBlacklistOnlyModeRegression(t *testing.T) {
	tempDir := t.TempDir()

	// Test peer IDs
	unknownPeer1, err := peer.Decode("16Uiu2HAkuztyBUEcBxXrRRGJ2uBEdoJNpkYwXNQahS7Q6PH7VQHP")
	require.NoError(t, err)

	unknownPeer2, err := peer.Decode("16Uiu2HAkwWNgvbTRuKi9dRhWJN3cZPJ6LKN2Y3zRF1XkEVJgvVoE")
	require.NoError(t, err)

	blacklistedPeer, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	t.Run("BlacklistOnlyModeAllowsUnknownPeers", func(t *testing.T) {
		// Create host
		host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer host.Close()

		// Create gater in blacklist-only mode
		gater := NewWhitelistGater(nil,
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(false)) // Key: no whitelist enforcement
		defer gater.Close()

		// Create PeerMan with blacklist enabled but private mode disabled
		cfg := &Config{
			PEX:               false,
			AddrBook:          filepath.Join(tempDir, "addrbook.json"),
			Logger:            log.DiscardLogger,
			ChainID:           "test-chain",
			Host:              host,
			ConnGater:         gater,
			BlacklistConfig:   config.BlacklistConfig{Enable: true},
			TargetConnections: 5,
		}

		peerMan, err := NewPeerMan(cfg)
		require.NoError(t, err)
		defer func() { require.NoError(t, peerMan.Close()) }()

		// Verify PeerMan reuses the original gater (regression test)
		require.Same(t, gater, peerMan.cg,
			"PeerMan must reuse the original gater to preserve configuration")

		// Test blacklist-only behavior: unknown peers should be allowed
		require.True(t, peerMan.IsAllowed(unknownPeer1),
			"Unknown peers must be allowed in blacklist-only mode")
		require.True(t, peerMan.IsAllowed(unknownPeer2),
			"All unknown peers must be allowed in blacklist-only mode")

		// Blacklist functionality should still work
		peerMan.BlacklistPeer(blacklistedPeer, "test blacklist", time.Hour)
		require.False(t, peerMan.IsAllowed(blacklistedPeer),
			"Blacklisted peers must be blocked")

		// Unknown peers should remain allowed after blacklisting others
		require.True(t, peerMan.IsAllowed(unknownPeer1),
			"Non-blacklisted peers must remain allowed")
	})

	t.Run("PrivateModeStillEnforcesWhitelist", func(t *testing.T) {
		// Ensure private mode still works correctly
		host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer host.Close()

		// Pre-allowed peer
		allowedPeer, err := peer.Decode("16Uiu2HAky9nVkRgFv77jHT3jKZaSnrGHtBmhsrDwJCPiECPpEf6J")
		require.NoError(t, err)

		// Create gater in private mode
		gater := NewWhitelistGater([]peer.ID{allowedPeer},
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(true)) // Private mode: enforce whitelist
		defer gater.Close()

		cfg := &Config{
			PEX:               false,
			AddrBook:          filepath.Join(tempDir, "addrbook_private.json"),
			Logger:            log.DiscardLogger,
			ChainID:           "test-chain-private",
			Host:              host,
			ConnGater:         gater,
			TargetConnections: 5,
		}

		peerMan, err := NewPeerMan(cfg)
		require.NoError(t, err)
		defer func() { require.NoError(t, peerMan.Close()) }()

		// Verify private mode behavior
		require.True(t, peerMan.IsAllowed(allowedPeer),
			"Whitelisted peers must be allowed in private mode")
		require.False(t, peerMan.IsAllowed(unknownPeer1),
			"Unknown peers must be blocked in private mode")
		require.False(t, peerMan.IsAllowed(unknownPeer2),
			"All unknown peers must be blocked in private mode")
	})

	t.Run("MaintainMinPeersWorksInBlacklistOnlyMode", func(t *testing.T) {
		// Verify that the maintainMinPeers loop can connect to unknown peers
		host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer host.Close()

		gater := NewWhitelistGater(nil,
			WithLogger(log.DiscardLogger),
			WithWhitelistEnforcement(false))
		defer gater.Close()

		cfg := &Config{
			PEX:               false,
			AddrBook:          filepath.Join(tempDir, "addrbook_maintain.json"),
			Logger:            log.DiscardLogger,
			ChainID:           "test-chain-maintain",
			Host:              host,
			ConnGater:         gater,
			BlacklistConfig:   config.BlacklistConfig{Enable: true},
			TargetConnections: 5,
		}

		peerMan, err := NewPeerMan(cfg)
		require.NoError(t, err)
		defer func() { require.NoError(t, peerMan.Close()) }()

		// This simulates the check in maintainMinPeers (peers.go:374)
		// if !pm.IsAllowed(pid) { continue }
		// In blacklist-only mode, this should return true for unknown peers
		require.True(t, peerMan.IsAllowed(unknownPeer1),
			"maintainMinPeers must be able to dial unknown peers in blacklist-only mode")
		require.True(t, peerMan.IsAllowed(unknownPeer2),
			"maintainMinPeers must be able to dial any unknown peer in blacklist-only mode")
	})
}

// TestBlacklistOnlyModeWithFullP2PSetup tests the complete P2P service flow
// to ensure Host and PeerMan use the same gater instance
func TestBlacklistOnlyModeWithFullP2PSetup(t *testing.T) {
	tempDir := t.TempDir()

	unknownPeer, err := peer.Decode("16Uiu2HAkuztyBUEcBxXrRRGJ2uBEdoJNpkYwXNQahS7Q6PH7VQHP")
	require.NoError(t, err)

	// Simulate the full P2P service setup pattern from node/p2p.go

	// Step 1: Create gater for blacklist-only mode (like node/p2p.go:70-72)
	wcg := NewWhitelistGater(nil,
		WithLogger(log.DiscardLogger),
		WithWhitelistEnforcement(false))
	defer wcg.Close()

	// Step 2: Create host with the gater (like node/p2p.go:76)
	host, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.ConnectionGater(wcg))
	require.NoError(t, err)
	defer host.Close()

	// Step 3: Create PeerMan config (like node/p2p.go:110-120)
	pmCfg := &Config{
		PEX:               false,
		AddrBook:          filepath.Join(tempDir, "addrbook.json"),
		Logger:            log.DiscardLogger,
		ChainID:           "test-chain",
		Host:              host,
		ConnGater:         wcg, // Pass the same gater
		BlacklistConfig:   config.BlacklistConfig{Enable: true},
		TargetConnections: 5,
	}

	// Step 4: Create PeerMan (like node/p2p.go:121)
	pm, err := NewPeerMan(pmCfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, pm.Close()) }()

	// Step 5: Verify SetPeerMan was called (like node/p2p.go:127-129)
	// This is critical - both Host and PeerMan must use the same gater instance
	require.Same(t, wcg, pm.cg,
		"Host and PeerMan must share the same gater instance")

	// Step 6: Verify consistent behavior between Host gater and PeerMan gater
	require.True(t, wcg.IsAllowed(unknownPeer),
		"Host's gater must allow unknown peers in blacklist-only mode")
	require.True(t, pm.IsAllowed(unknownPeer),
		"PeerMan's gater must allow unknown peers in blacklist-only mode")
}

// TestDynamicWhitelistUpdatesPropagate verifies that dynamic whitelist updates
// from PeerMan propagate to the shared Host gater
func TestDynamicWhitelistUpdatesPropagate(t *testing.T) {
	tempDir := t.TempDir()

	// Decode a test peer
	newPeer, err := peer.Decode("16Uiu2HAkwWNgvbTRuKi9dRhWJN3cZPJ6LKN2Y3zRF1XkEVJgvVoE")
	require.NoError(t, err)

	// Create a WhitelistGater with whitelist enforcement enabled (private mode)
	wcg := NewWhitelistGater(nil, // Start with empty whitelist
		WithLogger(log.DiscardLogger),
		WithWhitelistEnforcement(true)) // Enable whitelist enforcement
	defer wcg.Close()

	// Start a libp2p Host using that gater
	host, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.ConnectionGater(wcg))
	require.NoError(t, err)
	defer host.Close()

	// Construct a PeerMan using the same gater
	cfg := &Config{
		PEX:               false,
		AddrBook:          filepath.Join(tempDir, "addrbook.json"),
		Logger:            log.DiscardLogger,
		ChainID:           "test-chain-dynamic",
		Host:              host,
		ConnGater:         wcg, // Same gater instance
		TargetConnections: 5,
	}

	pm, err := NewPeerMan(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, pm.Close()) }()

	// Verify both gaters are the same instance
	require.Same(t, wcg, pm.cg,
		"Host and PeerMan must share the same gater instance")

	// Assert both wcg.IsAllowed(newPeer) and pm.IsAllowed(newPeer) are false initially
	require.False(t, wcg.IsAllowed(newPeer),
		"New peer should not be allowed initially in private mode")
	require.False(t, pm.IsAllowed(newPeer),
		"New peer should not be allowed initially via PeerMan")

	// Call pm.AllowPersistent(newPeer) to add peer to persistent whitelist
	pm.AllowPersistent(newPeer)

	// Assert both pm.IsAllowed(newPeer) and wcg.IsAllowed(newPeer) are true
	// This verifies that dynamic whitelist updates propagate through the shared gater
	require.True(t, pm.IsAllowed(newPeer),
		"New peer should be allowed after AllowPersistent via PeerMan")
	require.True(t, wcg.IsAllowed(newPeer),
		"New peer should be allowed after AllowPersistent via shared Host gater")
}
