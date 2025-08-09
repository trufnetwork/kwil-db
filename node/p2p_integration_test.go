package node

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
)

// TestP2PServiceConfigurationMatrix tests P2P service initialization with different configurations
// This would have caught the WhitelistGater nil pointer bug
func TestP2PServiceConfigurationMatrix(t *testing.T) {
	// Create a temporary directory for tests
	tempDir := t.TempDir()

	// Generate a test private key
	privKey, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)

	testCases := []struct {
		name            string
		privateMode     bool
		blacklistEnable bool
		shouldSucceed   bool
		description     string
	}{
		{
			name:            "DefaultConfiguration",
			privateMode:     false,
			blacklistEnable: false,
			shouldSucceed:   true,
			description:     "Default configuration should work",
		},
		{
			name:            "PrivateModeOnly",
			privateMode:     true,
			blacklistEnable: false,
			shouldSucceed:   true,
			description:     "Private mode without blacklist should work",
		},
		{
			name:            "BlacklistOnlyMode", // ← THE CRITICAL TEST CASE
			privateMode:     false,
			blacklistEnable: true,
			shouldSucceed:   true,
			description:     "Blacklist-only mode should work without nil pointer crashes",
		},
		{
			name:            "PrivateModeWithBlacklist",
			privateMode:     true,
			blacklistEnable: true,
			shouldSucceed:   true,
			description:     "Private mode with blacklist should work",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Create test configuration using default config
			defaultCfg := config.DefaultConfig()
			// Override specific P2P settings for test
			defaultCfg.P2P.PrivateMode = tc.privateMode
			defaultCfg.P2P.Blacklist.Enable = tc.blacklistEnable

			cfg := &P2PServiceConfig{
				PrivKey: privKey,
				RootDir: tempDir,
				ChainID: "test-chain",
				KwilCfg: defaultCfg,
				Logger:  log.DiscardLogger,
			}

			// This is the critical test - P2P service initialization should not panic
			var p2pService *P2PService
			var initErr error

			if tc.shouldSucceed {
				require.NotPanics(t, func() {
					p2pService, initErr = NewP2PService(ctx, cfg, nil)
				}, "P2P service initialization should not panic for %s", tc.description)

				require.NoError(t, initErr, "P2P service should initialize successfully for %s", tc.description)
				require.NotNil(t, p2pService, "P2P service should not be nil for %s", tc.description)

				// Verify the service can be closed without issues
				require.NotPanics(t, func() {
					err := p2pService.Close()
					require.NoError(t, err)
				}, "P2P service should close cleanly")
			} else {
				// For future test cases where we expect failures
				p2pService, initErr = NewP2PService(ctx, cfg, nil)
				require.Error(t, initErr, "P2P service should fail for %s", tc.description)
			}
		})
	}
}

// TestP2PServiceBlacklistOnlyModeSpecific tests the exact scenario that caused the bug
func TestP2PServiceBlacklistOnlyModeSpecific(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tempDir := t.TempDir()

	privKey, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)

	// This is the exact configuration that caused the nil pointer crash
	defaultCfg := config.DefaultConfig()
	defaultCfg.P2P.PrivateMode = false     // ← Critical: private mode disabled
	defaultCfg.P2P.Blacklist.Enable = true // ← Critical: blacklist enabled

	cfg := &P2PServiceConfig{
		PrivKey: privKey,
		RootDir: tempDir,
		ChainID: "blacklist-test-chain",
		KwilCfg: defaultCfg,
		Logger:  log.DiscardLogger,
	}

	t.Run("BlacklistOnlyInitialization", func(t *testing.T) {
		// The original bug would cause a panic during NewP2PService
		require.NotPanics(t, func() {
			service, err := NewP2PService(ctx, cfg, nil)
			require.NoError(t, err, "BlacklistOnly mode should initialize without error")
			require.NotNil(t, service, "P2P service should not be nil")

			// Verify the service has the expected components
			require.NotNil(t, service.Host(), "Host should be initialized")
			require.NotNil(t, service.Discovery(), "Discovery should be initialized")

			// Clean shutdown
			err = service.Close()
			require.NoError(t, err, "Service should close cleanly")
		})
	})

	t.Run("BlacklistOnlyWithStartup", func(t *testing.T) {
		// Test that the service can actually start without panicking
		service, err := NewP2PService(ctx, cfg, nil)
		require.NoError(t, err)
		require.NotNil(t, service)

		// Attempt to start the service (this would trigger peer connections and WhitelistGater usage)
		require.NotPanics(t, func() {
			startErr := service.Start(ctx) // No bootstrap peers
			// Start might fail due to network issues, but should not panic
			if startErr != nil {
				t.Logf("Service start returned error (expected in test): %v", startErr)
			}
		})

		// Clean shutdown
		err = service.Close()
		require.NoError(t, err)
	})
}

// TestP2PServiceWhitelistGaterIntegration tests the WhitelistGater integration specifically
func TestP2PServiceWhitelistGaterIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tempDir := t.TempDir()

	privKey, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)

	t.Run("WhitelistGaterSetPeerManIntegration", func(t *testing.T) {
		// Test the exact sequence that caused the bug:
		// 1. NewP2PService creates WhitelistGater
		// 2. NewPeerMan creates PeerMan
		// 3. SetPeerMan is called on WhitelistGater

		defaultCfg := config.DefaultConfig()
		defaultCfg.P2P.PrivateMode = false
		defaultCfg.P2P.Blacklist.Enable = true

		cfg := &P2PServiceConfig{
			PrivKey: privKey,
			RootDir: tempDir,
			ChainID: "integration-test",
			KwilCfg: defaultCfg,
			Logger:  log.DiscardLogger,
		}

		// This tests the complete initialization sequence
		require.NotPanics(t, func() {
			service, err := NewP2PService(ctx, cfg, nil)
			require.NoError(t, err)
			require.NotNil(t, service)

			// The bug would manifest during service creation when:
			// 1. WhitelistGater is created for blacklist-only mode
			// 2. PeerMan is created
			// 3. wcg.SetPeerMan(pm) is called
			// 4. If wcg was nil, this would panic

			err = service.Close()
			require.NoError(t, err)
		})
	})

	t.Run("WhitelistGaterConnectionAttempts", func(t *testing.T) {
		// Create two P2P services to test actual connection gating
		defaultCfg1 := config.DefaultConfig()
		defaultCfg1.P2P.PrivateMode = false
		defaultCfg1.P2P.Blacklist.Enable = true

		cfg1 := &P2PServiceConfig{
			PrivKey: privKey,
			RootDir: filepath.Join(tempDir, "node1"),
			ChainID: "connection-test",
			KwilCfg: defaultCfg1,
			Logger:  log.DiscardLogger,
		}

		privKey2, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
		require.NoError(t, err)

		defaultCfg2 := config.DefaultConfig()
		defaultCfg2.P2P.PrivateMode = false
		defaultCfg2.P2P.Blacklist.Enable = true

		cfg2 := &P2PServiceConfig{
			PrivKey: privKey2,
			RootDir: filepath.Join(tempDir, "node2"),
			ChainID: "connection-test",
			KwilCfg: defaultCfg2,
			Logger:  log.DiscardLogger,
		}

		// Both services should initialize without panic
		service1, err := NewP2PService(ctx, cfg1, nil)
		require.NoError(t, err)
		require.NotNil(t, service1)

		service2, err := NewP2PService(ctx, cfg2, nil)
		require.NoError(t, err)
		require.NotNil(t, service2)

		// Both should be able to start (connection attempts should not panic)
		require.NotPanics(t, func() {
			_ = service1.Start(ctx)
			_ = service2.Start(ctx)
		})

		// Clean shutdown
		require.NoError(t, service1.Close())
		require.NoError(t, service2.Close())
	})
}

// TestP2PServiceWithMockHost tests P2P service with a provided host
func TestP2PServiceWithMockHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tempDir := t.TempDir()

	privKey, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)

	defaultCfg := config.DefaultConfig()
	defaultCfg.P2P.PrivateMode = false
	defaultCfg.P2P.Blacklist.Enable = true

	cfg := &P2PServiceConfig{
		PrivKey: privKey,
		RootDir: tempDir,
		ChainID: "mock-host-test",
		KwilCfg: defaultCfg,
		Logger:  log.DiscardLogger,
	}

	// Test with nil host (service should create its own)
	t.Run("WithNilHost", func(t *testing.T) {
		require.NotPanics(t, func() {
			service, err := NewP2PService(ctx, cfg, nil)
			require.NoError(t, err)
			require.NotNil(t, service)
			require.NoError(t, service.Close())
		})
	})

	// Note: Testing with a real libp2p host would require more complex setup
	// This test validates that the nil host path (default) works correctly
}
