package node

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/peers"
)

// createTestPeerMan creates a test PeerMan for blacklist testing
func createTestPeerMan(t *testing.T) *peers.PeerMan {
	// Create a test host
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	t.Cleanup(func() { host.Close() })

	// Create temporary address book file
	tempDir := t.TempDir()
	addrBookPath := filepath.Join(tempDir, "test_addrbook.json")

	// Create blacklist config
	blacklistConfig := config.BlacklistConfig{
		Enable: true,
	}

	// Create PeerMan config
	cfg := &peers.Config{
		Host:            host,
		AddrBook:        addrBookPath,
		Logger:          log.DiscardLogger,
		BlacklistConfig: blacklistConfig,
	}

	pm, err := peers.NewPeerMan(cfg)
	require.NoError(t, err)
	return pm
}

func TestBlacklistMgr_BlacklistPeer(t *testing.T) {
	pm := createTestPeerMan(t)
	blacklistMgr := &BlacklistMgr{
		pm:     pm,
		logger: log.DiscardLogger,
	}

	tests := []struct {
		name        string
		nodeID      string
		reason      string
		duration    time.Duration
		expectError bool
	}{
		{
			name:        "valid permanent blacklist",
			nodeID:      "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
			reason:      "manual blacklist",
			duration:    0, // permanent
			expectError: false,
		},
		{
			name:        "valid temporary blacklist",
			nodeID:      "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
			reason:      "temporary block",
			duration:    1 * time.Hour,
			expectError: false,
		},
		{
			name:        "invalid node ID",
			nodeID:      "invalid-node-id",
			reason:      "test",
			duration:    0,
			expectError: true,
		},
		{
			name:        "empty reason",
			nodeID:      "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
			reason:      "",
			duration:    0,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := blacklistMgr.BlacklistPeer(tt.nodeID, tt.reason, tt.duration)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify the peer was actually blacklisted
				if tt.nodeID != "invalid-node-id" {
					peerID, parseErr := nodeIDToPeerID(tt.nodeID)
					require.NoError(t, parseErr)

					isBlacklisted, reason := pm.IsBlacklisted(peerID)
					require.True(t, isBlacklisted)

					if tt.reason == "" {
						require.Empty(t, reason)
					} else {
						require.Equal(t, tt.reason, reason)
					}
				}
			}
		})
	}
}

func TestBlacklistMgr_RemoveFromBlacklist(t *testing.T) {
	pm := createTestPeerMan(t)
	blacklistMgr := &BlacklistMgr{
		pm:     pm,
		logger: log.DiscardLogger,
	}

	nodeID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"

	tests := []struct {
		name            string
		nodeID          string
		setupBlacklist  bool
		expectError     bool
		expectedRemoved bool
	}{
		{
			name:            "remove existing blacklisted peer",
			nodeID:          nodeID,
			setupBlacklist:  true,
			expectError:     false,
			expectedRemoved: true,
		},
		{
			name:            "remove non-blacklisted peer",
			nodeID:          nodeID,
			setupBlacklist:  false,
			expectError:     true,
			expectedRemoved: false,
		},
		{
			name:            "invalid node ID",
			nodeID:          "invalid-node-id",
			setupBlacklist:  false,
			expectError:     true,
			expectedRemoved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: blacklist the peer if needed
			if tt.setupBlacklist && tt.nodeID != "invalid-node-id" {
				err := blacklistMgr.BlacklistPeer(tt.nodeID, "test setup", 0)
				require.NoError(t, err)
			}

			// Test removal
			err := blacklistMgr.RemoveFromBlacklist(tt.nodeID)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify the peer was actually removed
				if tt.nodeID != "invalid-node-id" {
					peerID, parseErr := nodeIDToPeerID(tt.nodeID)
					require.NoError(t, parseErr)

					isBlacklisted, _ := pm.IsBlacklisted(peerID)
					require.False(t, isBlacklisted)
				}
			}
		})
	}
}

func TestBlacklistMgr_ListBlacklisted(t *testing.T) {
	pm := createTestPeerMan(t)
	blacklistMgr := &BlacklistMgr{
		pm:     pm,
		logger: log.DiscardLogger,
	}

	nodeID1 := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"
	nodeID2 := "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa#secp256k1"

	t.Run("empty blacklist", func(t *testing.T) {
		entries, err := blacklistMgr.ListBlacklisted()
		require.NoError(t, err)
		require.Empty(t, entries)
	})

	t.Run("single entry", func(t *testing.T) {
		// Add one entry
		err := blacklistMgr.BlacklistPeer(nodeID1, "test reason 1", 0)
		require.NoError(t, err)

		entries, err := blacklistMgr.ListBlacklisted()
		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.Equal(t, "test reason 1", entries[0].Reason)
		require.True(t, entries[0].Permanent)
	})

	t.Run("multiple entries", func(t *testing.T) {
		// Add another entry
		err := blacklistMgr.BlacklistPeer(nodeID2, "test reason 2", 1*time.Hour)
		require.NoError(t, err)

		entries, err := blacklistMgr.ListBlacklisted()
		require.NoError(t, err)
		require.Len(t, entries, 2)

		// Check both entries are present
		reasons := make(map[string]bool)
		permanentCount := 0
		for _, entry := range entries {
			reasons[entry.Reason] = true
			if entry.Permanent {
				permanentCount++
			}
		}
		require.True(t, reasons["test reason 1"])
		require.True(t, reasons["test reason 2"])
		require.Equal(t, 1, permanentCount) // Only first one is permanent
	})
}

func TestBlacklistMgr_NilPeerMan(t *testing.T) {
	blacklistMgr := &BlacklistMgr{
		pm:     nil,
		logger: log.DiscardLogger,
	}

	nodeID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"

	t.Run("blacklist with nil peerman", func(t *testing.T) {
		err := blacklistMgr.BlacklistPeer(nodeID, "test", 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "blacklist functionality unavailable")
	})

	t.Run("remove with nil peerman", func(t *testing.T) {
		err := blacklistMgr.RemoveFromBlacklist(nodeID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "blacklist functionality unavailable")
	})

	t.Run("list with nil peerman", func(t *testing.T) {
		entries, err := blacklistMgr.ListBlacklisted()
		require.Error(t, err)
		require.Nil(t, entries)
		require.Contains(t, err.Error(), "blacklist functionality unavailable")
	})
}

func TestNode_Blacklister(t *testing.T) {
	// Create a test node with actual PeerMan
	pm := createTestPeerMan(t)

	node := &Node{
		P2PService: P2PService{
			pm: pm,
		},
		log: log.DiscardLogger,
	}

	t.Run("valid peerman cast", func(t *testing.T) {
		blacklister := node.Blacklister()
		require.NotNil(t, blacklister)
		require.NotNil(t, blacklister.pm)
		require.Equal(t, pm, blacklister.pm)
	})

	t.Run("blacklister functionality", func(t *testing.T) {
		blacklister := node.Blacklister()
		nodeID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"

		// Test blacklist
		err := blacklister.BlacklistPeer(nodeID, "test", 0)
		require.NoError(t, err)

		// Test list
		entries, err := blacklister.ListBlacklisted()
		require.NoError(t, err)
		require.Len(t, entries, 1)

		// Test remove
		err = blacklister.RemoveFromBlacklist(nodeID)
		require.NoError(t, err)

		// Verify removed
		entries, err = blacklister.ListBlacklisted()
		require.NoError(t, err)
		require.Empty(t, entries)
	})
}

// mockPeerManager implements peerManager but is not a *peers.PeerMan
type mockPeerManager struct{}

// network.Notifiee methods
func (m *mockPeerManager) Listen(network.Network, multiaddr.Multiaddr)      {}
func (m *mockPeerManager) ListenClose(network.Network, multiaddr.Multiaddr) {}
func (m *mockPeerManager) Connected(network.Network, network.Conn)          {}
func (m *mockPeerManager) Disconnected(network.Network, network.Conn)       {}

// peerManager methods
func (m *mockPeerManager) Start(ctx context.Context) error  { return nil }
func (m *mockPeerManager) ConnectedPeers() []peers.PeerInfo { return nil }
func (m *mockPeerManager) KnownPeers() ([]peers.PeerInfo, []peers.PeerInfo, []peers.PeerInfo) {
	return nil, nil, nil
}
func (m *mockPeerManager) Connect(ctx context.Context, info peers.AddrInfo) error { return nil }
func (m *mockPeerManager) Allow(p peer.ID)                                        {}
func (m *mockPeerManager) AllowPersistent(p peer.ID)                              {}
func (m *mockPeerManager) Disallow(p peer.ID)                                     {}
func (m *mockPeerManager) AllowedPersistent() []peer.ID                           { return nil }

func TestNode_Blacklister_InvalidCast(t *testing.T) {
	node := &Node{
		P2PService: P2PService{
			pm: &mockPeerManager{}, // Not a *peers.PeerMan
		},
		log: log.DiscardLogger,
	}

	t.Run("invalid peerman cast", func(t *testing.T) {
		blacklister := node.Blacklister()
		require.NotNil(t, blacklister)
		require.Nil(t, blacklister.pm)

		// Should return errors for all operations
		nodeID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"

		err := blacklister.BlacklistPeer(nodeID, "test", 0)
		require.Error(t, err)

		err = blacklister.RemoveFromBlacklist(nodeID)
		require.Error(t, err)

		entries, err := blacklister.ListBlacklisted()
		require.Error(t, err)
		require.Nil(t, entries)
	})
}
