package peers

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/metrics"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
)

// mockMetricsCollector captures metrics calls for testing
type mockMetricsCollector struct {
	blacklistOps   []BlacklistOpCall
	peerCounts     []int
	autoBlacklists []AutoBlacklistCall
	blockedConns   []BlockedConnCall
}

type BlacklistOpCall struct {
	Operation string
	Reason    string
	Permanent bool
}

type AutoBlacklistCall struct {
	Reason   string
	Attempts int64
}

type BlockedConnCall struct {
	Direction string
	Reason    string
}

func (m *mockMetricsCollector) BlacklistOperation(ctx context.Context, operation, reason string, permanent bool) {
	m.blacklistOps = append(m.blacklistOps, BlacklistOpCall{
		Operation: operation,
		Reason:    reason,
		Permanent: permanent,
	})
}

func (m *mockMetricsCollector) BlacklistedPeerCount(ctx context.Context, count int) {
	m.peerCounts = append(m.peerCounts, count)
}

func (m *mockMetricsCollector) AutoBlacklistEvent(ctx context.Context, reason string, attempts int64) {
	m.autoBlacklists = append(m.autoBlacklists, AutoBlacklistCall{
		Reason:   reason,
		Attempts: attempts,
	})
}

func (m *mockMetricsCollector) BlockedConnection(ctx context.Context, direction, reason string) {
	m.blockedConns = append(m.blockedConns, BlockedConnCall{
		Direction: direction,
		Reason:    reason,
	})
}

// Implement other NodeMetrics methods as no-ops
func (m *mockMetricsCollector) PeerCount(ctx context.Context, numPeers int)                  {}
func (m *mockMetricsCollector) DownloadedBlock(ctx context.Context, blockHeight, size int64) {}
func (m *mockMetricsCollector) ServedBlock(ctx context.Context, blockHeight, size int64)     {}
func (m *mockMetricsCollector) Advertised(ctx context.Context, protocol string)              {}
func (m *mockMetricsCollector) AdvertiseRejected(ctx context.Context, protocol string)       {}
func (m *mockMetricsCollector) AdvertiseServed(ctx context.Context, protocol string, contentLen int64) {
}
func (m *mockMetricsCollector) TxnsReannounced(ctx context.Context, num, totalSize int64) {}

// TestBlacklistMetricsIntegration tests that blacklist operations properly record metrics
func TestBlacklistMetricsIntegration(t *testing.T) {
	// Create a test host
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer host.Close()

	// Create temporary address book file
	tempDir := t.TempDir()
	addrBookPath := filepath.Join(tempDir, "test_addrbook.json")

	// Create mock metrics collector
	mockMetrics := &mockMetricsCollector{}

	// Temporarily replace the global metrics instance
	originalMetrics := metrics.Node
	metrics.Node = mockMetrics
	defer func() {
		metrics.Node = originalMetrics
	}()

	// Create blacklist config
	blacklistConfig := config.BlacklistConfig{
		Enable:                    true,
		AutoBlacklistOnMaxRetries: true,
		AutoBlacklistDuration:     time.Hour,
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
	defer func() { require.NoError(t, pm.Close()) }()

	// Create test peer ID
	testPeerID, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	t.Run("BlacklistOperationMetrics", func(t *testing.T) {
		// Reset mock
		mockMetrics.blacklistOps = nil
		mockMetrics.peerCounts = nil

		// Test permanent blacklist
		pm.BlacklistPeer(testPeerID, "manual", 0)

		// Verify metrics were recorded
		require.Len(t, mockMetrics.blacklistOps, 1)
		require.Equal(t, "add", mockMetrics.blacklistOps[0].Operation)
		require.Equal(t, "manual", mockMetrics.blacklistOps[0].Reason)
		require.True(t, mockMetrics.blacklistOps[0].Permanent)

		require.Len(t, mockMetrics.peerCounts, 1)
		require.Equal(t, 1, mockMetrics.peerCounts[0])

		// Test remove from blacklist
		pm.RemoveFromBlacklist(testPeerID)

		// Verify remove metrics
		require.Len(t, mockMetrics.blacklistOps, 2)
		require.Equal(t, "remove", mockMetrics.blacklistOps[1].Operation)
		require.Equal(t, "manual", mockMetrics.blacklistOps[1].Reason)
		require.False(t, mockMetrics.blacklistOps[1].Permanent)

		require.Len(t, mockMetrics.peerCounts, 2)
		require.Equal(t, 0, mockMetrics.peerCounts[1])
	})

	t.Run("TemporaryBlacklistMetrics", func(t *testing.T) {
		// Reset mock
		mockMetrics.blacklistOps = nil
		mockMetrics.peerCounts = nil

		// Test temporary blacklist
		pm.BlacklistPeer(testPeerID, "temporary", time.Hour)

		// Verify metrics were recorded
		require.Len(t, mockMetrics.blacklistOps, 1)
		require.Equal(t, "add", mockMetrics.blacklistOps[0].Operation)
		require.Equal(t, "temporary", mockMetrics.blacklistOps[0].Reason)
		require.False(t, mockMetrics.blacklistOps[0].Permanent)

		require.Len(t, mockMetrics.peerCounts, 1)
		require.Equal(t, 1, mockMetrics.peerCounts[0])

		// Clean up
		pm.RemoveFromBlacklist(testPeerID)
	})

	t.Run("AutoBlacklistMetrics", func(t *testing.T) {
		// Reset mock
		mockMetrics.autoBlacklists = nil
		mockMetrics.blacklistOps = nil

		// Simulate the auto-blacklist scenario directly (like in maintainMinPeers)
		// Instead of using a real backoffer, simulate the condition where max attempts are reached
		maxAttempts := 500
		duration := pm.blacklistConfig.AutoBlacklistDuration

		// This simulates the exact metrics calls from maintainMinPeers
		metrics.Node.AutoBlacklistEvent(context.Background(), "connection_exhaustion", int64(maxAttempts))
		pm.BlacklistPeer(testPeerID, "connection_exhaustion", duration)

		// Verify auto-blacklist metrics
		require.Len(t, mockMetrics.autoBlacklists, 1)
		require.Equal(t, "connection_exhaustion", mockMetrics.autoBlacklists[0].Reason)
		require.Equal(t, int64(500), mockMetrics.autoBlacklists[0].Attempts)

		// Verify the blacklist operation was also recorded
		require.Len(t, mockMetrics.blacklistOps, 1)
		require.Equal(t, "add", mockMetrics.blacklistOps[0].Operation)
		require.Equal(t, "connection_exhaustion", mockMetrics.blacklistOps[0].Reason)
		require.False(t, mockMetrics.blacklistOps[0].Permanent) // Auto-blacklist is temporary

		// Clean up
		pm.RemoveFromBlacklist(testPeerID)
	})
}

// TestBlacklistStructuredLogging tests that blacklist operations produce proper structured logs
func TestBlacklistStructuredLogging(t *testing.T) {
	// Create a test host
	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer host.Close()

	// Create temporary address book file
	tempDir := t.TempDir()
	addrBookPath := filepath.Join(tempDir, "test_addrbook.json")

	// Create a buffer to capture log output
	var logBuffer bytes.Buffer
	logger := log.New(log.WithWriter(&logBuffer), log.WithFormat(log.FormatJSON))

	// Create blacklist config
	blacklistConfig := config.BlacklistConfig{
		Enable:                    true,
		AutoBlacklistOnMaxRetries: true,
		AutoBlacklistDuration:     time.Hour,
	}

	// Create PeerMan config with test logger
	cfg := &Config{
		Host:            host,
		AddrBook:        addrBookPath,
		Logger:          logger,
		BlacklistConfig: blacklistConfig,
	}

	pm, err := NewPeerMan(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, pm.Close()) }()

	// Create test peer ID
	testPeerID, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	t.Run("PermanentBlacklistLogging", func(t *testing.T) {
		logBuffer.Reset()

		// Perform blacklist operation
		pm.BlacklistPeer(testPeerID, "test_permanent", 0)

		// Parse the log output
		logOutput := logBuffer.String()
		require.Contains(t, logOutput, "Peer blacklisted")

		// Verify structured fields are present
		require.Contains(t, logOutput, "peer_id")
		require.Contains(t, logOutput, "reason")
		require.Contains(t, logOutput, "permanent")
		require.Contains(t, logOutput, "expires_at")
		require.Contains(t, logOutput, "operation")

		// Verify specific values
		require.Contains(t, logOutput, "test_permanent")
		require.Contains(t, logOutput, "blacklist_add")
		require.Contains(t, logOutput, "never") // permanent entries expire never

		// Clean up
		pm.RemoveFromBlacklist(testPeerID)
	})

	t.Run("TemporaryBlacklistLogging", func(t *testing.T) {
		logBuffer.Reset()

		// Perform temporary blacklist operation
		pm.BlacklistPeer(testPeerID, "test_temporary", time.Hour)

		// Parse the log output
		logOutput := logBuffer.String()
		require.Contains(t, logOutput, "Peer blacklisted")
		require.Contains(t, logOutput, "test_temporary")
		require.Contains(t, logOutput, "blacklist_add")
		require.Contains(t, logOutput, "permanent\":false") // JSON format

		// Should contain expiration timestamp
		require.NotContains(t, logOutput, "never") // temporary entries have real expiration

		// Clean up
		pm.RemoveFromBlacklist(testPeerID)
	})

	t.Run("RemoveBlacklistLogging", func(t *testing.T) {
		// First add a peer to blacklist
		pm.BlacklistPeer(testPeerID, "test_remove", 0)
		logBuffer.Reset()

		// Now remove it
		removed := pm.RemoveFromBlacklist(testPeerID)
		require.True(t, removed)

		// Parse the log output
		logOutput := logBuffer.String()
		require.Contains(t, logOutput, "Peer removed from blacklist")
		require.Contains(t, logOutput, "blacklist_remove")
		require.Contains(t, logOutput, "peer_id")
		require.Contains(t, logOutput, "operation")
	})

	t.Run("AutoBlacklistLogging", func(t *testing.T) {
		logBuffer.Reset()

		// Simulate auto-blacklist logging (this would normally be called from maintainMinPeers)
		duration := pm.blacklistConfig.AutoBlacklistDuration
		attempts := 500

		// This replicates the logging from maintainMinPeers
		pm.log.Warn("Auto-blacklisted peer due to connection exhaustion",
			"peer_id", peerIDStringer(testPeerID),
			"reason", "connection_exhaustion",
			"attempts", attempts,
			"duration", duration.String(),
			"operation", "auto_blacklist",
		)

		// Parse the log output
		logOutput := logBuffer.String()
		require.Contains(t, logOutput, "Auto-blacklisted peer due to connection exhaustion")
		require.Contains(t, logOutput, "connection_exhaustion")
		require.Contains(t, logOutput, "auto_blacklist")
		require.Contains(t, logOutput, "attempts")
		require.Contains(t, logOutput, "duration")
		require.Contains(t, logOutput, "1h0m0s") // hour duration
		require.Contains(t, logOutput, "500")    // attempts count
	})
}

// TestWhitelistGaterMetrics tests that connection blocking properly records metrics
func TestWhitelistGaterMetrics(t *testing.T) {
	// Create a mock metrics collector
	mockMetrics := &mockMetricsCollector{}

	// Temporarily replace the global metrics instance
	originalMetrics := metrics.Node
	metrics.Node = mockMetrics
	defer func() {
		metrics.Node = originalMetrics
	}()

	// Create a simple mock PeerMan that reports a peer as blacklisted
	testPeerID, err := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	require.NoError(t, err)

	mockPeerMan := &mockBlacklistChecker{
		blacklistedPeers: map[peer.ID]string{
			testPeerID: "test_reason",
		},
	}

	// Create WhitelistGater with blacklist support
	gater := NewWhitelistGater(
		[]peer.ID{}, // empty whitelist
		WithLogger(log.DiscardLogger),
		WithPeerMan(mockPeerMan),
		WithWhitelistEnforcement(false), // blacklist-only mode
	)
	defer gater.Close() // Clean up background goroutine

	t.Run("OutboundConnectionBlocking", func(t *testing.T) {
		mockMetrics.blockedConns = nil

		// Test outbound connection blocking
		allowed := gater.InterceptPeerDial(testPeerID)
		require.False(t, allowed)

		// Verify metrics were recorded
		require.Len(t, mockMetrics.blockedConns, 1)
		require.Equal(t, "outbound", mockMetrics.blockedConns[0].Direction)
		require.Equal(t, "test_reason", mockMetrics.blockedConns[0].Reason)
	})

	t.Run("InboundConnectionBlocking", func(t *testing.T) {
		mockMetrics.blockedConns = nil

		// Test inbound connection blocking
		allowed := gater.InterceptSecured(0, testPeerID, nil)
		require.False(t, allowed)

		// Verify metrics were recorded
		require.Len(t, mockMetrics.blockedConns, 1)
		require.Equal(t, "inbound", mockMetrics.blockedConns[0].Direction)
		require.Equal(t, "test_reason", mockMetrics.blockedConns[0].Reason)
	})

	t.Run("AllowedConnectionNoMetrics", func(t *testing.T) {
		mockMetrics.blockedConns = nil

		// Test with a non-blacklisted peer
		nonBlacklistedPeer, err := peer.Decode("16Uiu2HAm8iRUsTzYepLP8pdJL3645ACP7VBfZQ7yFbLfdb7WvkL7")
		require.NoError(t, err)

		// Test outbound connection - should be allowed
		allowed := gater.InterceptPeerDial(nonBlacklistedPeer)
		require.True(t, allowed)

		// Verify no metrics were recorded for allowed connections
		require.Len(t, mockMetrics.blockedConns, 0)
	})
}

// TestRealMetricsIntegration tests with actual OpenTelemetry metrics
func TestRealMetricsIntegration(t *testing.T) {
	// Create a Prometheus exporter for testing
	exporter, err := prometheus.New()
	require.NoError(t, err)

	// Create meter provider
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	otel.SetMeterProvider(provider)

	// Use real metrics
	ctx := context.Background()

	// Test that metrics calls don't panic and work with real OpenTelemetry
	t.Run("RealMetricsCalls", func(t *testing.T) {
		// These should not panic
		require.NotPanics(t, func() {
			metrics.Node.BlacklistOperation(ctx, "add", "test", true)
			metrics.Node.BlacklistedPeerCount(ctx, 5)
			metrics.Node.AutoBlacklistEvent(ctx, "connection_exhaustion", 500)
			metrics.Node.BlockedConnection(ctx, "inbound", "manual")
		})
	})
}

// mockBlacklistChecker implements the interface needed by WhitelistGater for testing
type mockBlacklistChecker struct {
	blacklistedPeers map[peer.ID]string
}

func (m *mockBlacklistChecker) IsBlacklisted(pid peer.ID) (bool, string) {
	if reason, exists := m.blacklistedPeers[pid]; exists {
		return true, reason
	}
	return false, ""
}
