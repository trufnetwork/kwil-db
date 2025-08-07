package peers

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestBlacklistAPIMethods(t *testing.T) {
	// Create a test host
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer host.Close()

	// Create temporary address book file
	tempDir := t.TempDir()
	addrBookPath := filepath.Join(tempDir, "test_addrbook.json")

	// Create blacklist config
	blacklistConfig := config.BlacklistConfig{
		Enable:                    true,
		AutoBlacklistOnMaxRetries: true,
	}

	// Create PeerMan config
	cfg := &Config{
		Host:            host,
		AddrBook:        addrBookPath,
		Logger:          log.DiscardLogger,
		BlacklistConfig: blacklistConfig,
	}

	pm, err := NewPeerMan(cfg)
	require.NoError(t, err)

	// Create test peer ID
	testPeerID, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	t.Run("BlacklistPeer permanent", func(t *testing.T) {
		// Test permanent blacklisting
		pm.BlacklistPeer(testPeerID, "test reason", 0)

		// Verify peer is blacklisted
		blacklisted, _ := pm.IsBlacklisted(testPeerID)
		require.True(t, blacklisted)

		// Verify blacklist entry
		entries := pm.ListBlacklisted()
		require.Len(t, entries, 1)
		require.Equal(t, testPeerID, entries[0].PeerID)
		require.Equal(t, "test reason", entries[0].Reason)
		require.True(t, entries[0].Permanent)
	})

	t.Run("RemoveFromBlacklist", func(t *testing.T) {
		// Remove from blacklist
		removed := pm.RemoveFromBlacklist(testPeerID)
		require.True(t, removed)

		// Verify peer is no longer blacklisted
		blacklisted, _ := pm.IsBlacklisted(testPeerID)
		require.False(t, blacklisted)

		// Verify blacklist is empty
		entries := pm.ListBlacklisted()
		require.Len(t, entries, 0)

		// Try to remove non-existent entry
		removed = pm.RemoveFromBlacklist(testPeerID)
		require.False(t, removed)
	})

	t.Run("BlacklistPeer temporary", func(t *testing.T) {
		// Test temporary blacklisting (1 second)
		pm.BlacklistPeer(testPeerID, "temporary blacklist", 1*time.Second)

		// Verify peer is blacklisted
		blacklisted, _ := pm.IsBlacklisted(testPeerID)
		require.True(t, blacklisted)

		// Verify entry details
		entries := pm.ListBlacklisted()
		require.Len(t, entries, 1)
		require.False(t, entries[0].Permanent)
		require.True(t, entries[0].ExpiresAt.After(time.Now()))

		// Wait for expiration
		time.Sleep(1100 * time.Millisecond)

		// Verify peer is no longer blacklisted
		isBlacklisted, _ := pm.IsBlacklisted(testPeerID)
		require.False(t, isBlacklisted)

		// List should not include expired entries
		entries = pm.ListBlacklisted()
		require.Len(t, entries, 0)
	})

	t.Run("SelfBlacklistPrevention", func(t *testing.T) {
		// Try to blacklist self
		pm.BlacklistPeer(host.ID(), "self blacklist", 0)

		// Verify self is not blacklisted
		blacklisted, _ := pm.IsBlacklisted(host.ID())
		require.False(t, blacklisted)
		entries := pm.ListBlacklisted()
		require.Len(t, entries, 0)
	})

	t.Run("BlacklistingDisabled", func(t *testing.T) {
		// Disable blacklisting
		pm.blacklistConfig.Enable = false

		// Try to blacklist a peer
		pm.BlacklistPeer(testPeerID, "disabled test", 0)

		// Verify peer is not blacklisted
		blacklisted, _ := pm.IsBlacklisted(testPeerID)
		require.False(t, blacklisted)
		entries := pm.ListBlacklisted()
		require.Len(t, entries, 0)

		// Re-enable for cleanup
		pm.blacklistConfig.Enable = true
	})
}

func TestBlacklistPersistence(t *testing.T) {
	// Create temporary address book file
	tempDir := t.TempDir()
	addrBookPath := filepath.Join(tempDir, "test_addrbook.json")

	// Create test peer IDs and get their node IDs
	testPeerID1, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)
	pk1, err := pubKeyFromPeerID(testPeerID1)
	require.NoError(t, err)
	nid1 := NodeIDFromPubKey(pk1)

	testPeerID2, err := peer.Decode("16Uiu2HAm8iRUsTzYepLP8pdJL3645ACP7VBfZQ7yFbLfdb7WvkL7")
	require.NoError(t, err)
	pk2, err := pubKeyFromPeerID(testPeerID2)
	require.NoError(t, err)
	nid2 := NodeIDFromPubKey(pk2)

	// Create test address
	addr1, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1234")

	// Test direct persistence using PersistentPeerInfo
	blacklistEntry1 := &BlacklistEntry{
		PeerID:    testPeerID1,
		Reason:    "permanent test",
		Timestamp: time.Now(),
		Permanent: true,
	}

	blacklistEntry2 := &BlacklistEntry{
		PeerID:    testPeerID2,
		Reason:    "temporary test",
		Timestamp: time.Now(),
		Permanent: false,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Create PersistentPeerInfo with blacklist data
	testPeers := []PersistentPeerInfo{
		{
			NodeID:      nid1,
			Addrs:       []ma.Multiaddr{addr1},
			Protos:      []protocol.ID{"/test/1.0.0"},
			Whitelisted: false,
			Blacklisted: blacklistEntry1,
		},
		{
			NodeID:      nid2,
			Addrs:       []ma.Multiaddr{addr1},
			Protos:      []protocol.ID{"/test/1.0.0"},
			Whitelisted: false,
			Blacklisted: blacklistEntry2,
		},
	}

	// Persist the data
	err = persistPeers(testPeers, addrBookPath)
	require.NoError(t, err)

	// Load and verify
	loadedPeers, err := loadPeers(addrBookPath)
	require.NoError(t, err)
	require.Len(t, loadedPeers, 2)

	// Verify blacklist data was persisted correctly
	var loaded1, loaded2 *PersistentPeerInfo
	for i, peer := range loadedPeers {
		if peer.NodeID == nid1 {
			loaded1 = &loadedPeers[i]
		} else if peer.NodeID == nid2 {
			loaded2 = &loadedPeers[i]
		}
	}

	require.NotNil(t, loaded1)
	require.NotNil(t, loaded2)

	// Verify blacklist entries
	require.NotNil(t, loaded1.Blacklisted)
	require.Equal(t, "permanent test", loaded1.Blacklisted.Reason)
	require.True(t, loaded1.Blacklisted.Permanent)

	require.NotNil(t, loaded2.Blacklisted)
	require.Equal(t, "temporary test", loaded2.Blacklisted.Reason)
	require.False(t, loaded2.Blacklisted.Permanent)
	require.True(t, loaded2.Blacklisted.ExpiresAt.After(time.Now()))

	// Test loading with PeerMan
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer host.Close()

	cfg := &Config{
		Host:     host,
		AddrBook: addrBookPath,
		Logger:   log.DiscardLogger,
		BlacklistConfig: config.BlacklistConfig{
			Enable:                    true,
			AutoBlacklistOnMaxRetries: true,
		},
	}

	pm, err := NewPeerMan(cfg)
	require.NoError(t, err)

	// Verify blacklist data was loaded into PeerMan
	blacklisted1, _ := pm.IsBlacklisted(testPeerID1)
	require.True(t, blacklisted1, "permanent blacklist should be loaded")
	blacklisted2, _ := pm.IsBlacklisted(testPeerID2)
	require.True(t, blacklisted2, "temporary blacklist should be loaded")

	// Verify details in PeerMan
	entries := pm.ListBlacklisted()
	require.Len(t, entries, 2)
}

func TestBlacklistExpiredEntryHandling(t *testing.T) {
	// Create temporary address book file
	tempDir := t.TempDir()
	addrBookPath := filepath.Join(tempDir, "test_addrbook.json")

	testPeerID, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	// First instance - create expired entry
	{
		host1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer host1.Close()

		cfg1 := &Config{
			Host:     host1,
			AddrBook: addrBookPath,
			Logger:   log.DiscardLogger,
			BlacklistConfig: config.BlacklistConfig{
				Enable:                    true,
				AutoBlacklistOnMaxRetries: true,
			},
		}

		pm1, err := NewPeerMan(cfg1)
		require.NoError(t, err)

		// Note: We don't need to add keys to peerstore for blacklist testing

		// Create a blacklist entry that will expire immediately
		pm1.BlacklistPeer(testPeerID, "expired test", 1*time.Millisecond)

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		// Save peers
		err = pm1.savePeers()
		require.NoError(t, err)
	}

	// Second instance - verify expired entries are not loaded
	{
		host2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		require.NoError(t, err)
		defer host2.Close()

		cfg2 := &Config{
			Host:     host2,
			AddrBook: addrBookPath,
			Logger:   log.DiscardLogger,
			BlacklistConfig: config.BlacklistConfig{
				Enable:                    true,
				AutoBlacklistOnMaxRetries: true,
			},
		}

		pm2, err := NewPeerMan(cfg2)
		require.NoError(t, err)

		// Verify expired entry was not loaded
		blacklisted, _ := pm2.IsBlacklisted(testPeerID)
		require.False(t, blacklisted, "expired blacklist should not be loaded")
		entries := pm2.ListBlacklisted()
		require.Len(t, entries, 0)
	}
}
