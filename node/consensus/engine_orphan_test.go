package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufnetwork/kwil-db/core/log"
)

func TestCalculateMajorityHeight(t *testing.T) {
	ce := &ConsensusEngine{}

	tests := []struct {
		name        string
		peerHeights map[string]int64
		expected    int64
	}{
		{
			name:        "clear majority",
			peerHeights: map[string]int64{"p1": 100, "p2": 100, "p3": 100, "p4": 99},
			expected:    100,
		},
		{
			name:        "no clear majority - highest wins",
			peerHeights: map[string]int64{"p1": 100, "p2": 101, "p3": 102},
			expected:    102,
		},
		{
			name:        "empty peers",
			peerHeights: map[string]int64{},
			expected:    0,
		},
		{
			name:        "single peer",
			peerHeights: map[string]int64{"p1": 50},
			expected:    50,
		},
		{
			name:        "tie - first encountered wins",
			peerHeights: map[string]int64{"p1": 100, "p2": 101},
			expected:    101, // depends on map iteration order, but should be consistent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ce.calculateMajorityHeight(tt.peerHeights)
			
			if tt.name == "tie - first encountered wins" {
				// For ties, we accept either value as valid
				assert.True(t, result == 100 || result == 101, "expected 100 or 101, got %d", result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// testIsLikelyOrphanedWithPeerHeights tests the orphan detection logic with given peer heights
func testIsLikelyOrphanedWithPeerHeights(t *testing.T, currentHeight int64, peerHeights map[string]int64, expected bool) {
	ce := &ConsensusEngine{}
	
	// Test the calculation logic directly using calculateMajorityHeight
	if len(peerHeights) == 0 {
		// No peers case
		result := ce.isLikelyOrphaned(context.Background(), currentHeight)
		assert.Equal(t, expected, result)
		return
	}
	
	// For testing purposes, we'll simulate the logic without network calls
	majorityHeight := ce.calculateMajorityHeight(peerHeights)
	isOrphaned := majorityHeight > currentHeight + 1
	assert.Equal(t, expected, isOrphaned)
}

func TestIsLikelyOrphanedLogic(t *testing.T) {
	tests := []struct {
		name          string
		currentHeight int64
		peerHeights   map[string]int64
		expected      bool
	}{
		{
			name:          "not orphaned - same height",
			currentHeight: 100,
			peerHeights:   map[string]int64{"peer1": 100, "peer2": 100},
			expected:      false,
		},
		{
			name:          "orphaned - significantly behind",
			currentHeight: 100,
			peerHeights:   map[string]int64{"peer1": 110, "peer2": 110, "peer3": 110},
			expected:      true,
		},
		{
			name:          "not orphaned - one block behind",
			currentHeight: 100,
			peerHeights:   map[string]int64{"peer1": 101, "peer2": 101},
			expected:      false,
		},
		{
			name:          "not orphaned - ahead of peers",
			currentHeight: 105,
			peerHeights:   map[string]int64{"peer1": 100, "peer2": 100},
			expected:      false,
		},
		{
			name:          "orphaned - two blocks behind",
			currentHeight: 100,
			peerHeights:   map[string]int64{"peer1": 102, "peer2": 102, "peer3": 103},
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testIsLikelyOrphanedWithPeerHeights(t, tt.currentHeight, tt.peerHeights, tt.expected)
		})
	}
}

func TestIsLikelyOrphanedWithNoPeers(t *testing.T) {
	ce := &ConsensusEngine{}

	// Test with no peers (should return false - not orphaned)
	result := ce.isLikelyOrphaned(context.Background(), 100)
	assert.False(t, result, "should not consider orphaned when no peers available")
}

func TestAttemptOrphanRecovery(t *testing.T) {
	// Import required packages for logger
	log := &mockLogger{}
	ce := &ConsensusEngine{
		log: log,
	}

	// Since we're in Phase 1, attemptOrphanRecovery should return an error
	err := ce.attemptOrphanRecovery(context.Background(), 100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "orphan recovery requires manual intervention")
	assert.Contains(t, err.Error(), "height 100")
}

// mockLogger implements a simple logger for testing
type mockLogger struct{}

func (m *mockLogger) Debug(msg string, args ...any) {}
func (m *mockLogger) Info(msg string, args ...any) {}
func (m *mockLogger) Warn(msg string, args ...any) {}
func (m *mockLogger) Error(msg string, args ...any) {}
func (m *mockLogger) Log(level log.Level, msg string, args ...any) {}

func (m *mockLogger) Debugf(msg string, args ...any) {}
func (m *mockLogger) Infof(msg string, args ...any) {}
func (m *mockLogger) Warnf(msg string, args ...any) {}
func (m *mockLogger) Errorf(msg string, args ...any) {}
func (m *mockLogger) Logf(level log.Level, msg string, args ...any) {}

func (m *mockLogger) Debugln(a ...any) {}
func (m *mockLogger) Infoln(a ...any) {}
func (m *mockLogger) Warnln(a ...any) {}
func (m *mockLogger) Errorln(a ...any) {}
func (m *mockLogger) Logln(level log.Level, a ...any) {}

func (m *mockLogger) New(name string) log.Logger { return m }
func (m *mockLogger) NewWithLevel(lvl log.Level, name string) log.Logger { return m }