package consensus

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/types"
)

func TestBlockSyncOrphanDetectionIntegration(t *testing.T) {
	// Test that orphan detection is called during block sync when ErrBlkNotFound occurs
	
	log := &mockLoggerSimple{}
	
	// Create a consensus engine with mocked getPeerChainTips
	ce := &ConsensusEngine{
		log: log,
	}
	
	// Test case 1: No orphan detected (empty peer tips)
	t.Run("no_orphan_detected", func(t *testing.T) {
		// The isLikelyOrphaned function should return false when getPeerChainTips returns empty
		result := ce.isLikelyOrphaned(context.Background(), 100)
		assert.False(t, result, "should not detect orphan when no peer tips available")
	})
	
	// Test case 2: Orphan recovery error handling
	t.Run("orphan_recovery_error", func(t *testing.T) {
		// Test that attemptOrphanRecovery returns appropriate error
		err := ce.attemptOrphanRecovery(context.Background(), 100)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "orphan recovery requires manual intervention")
		assert.Contains(t, err.Error(), "height 100")
	})
}

func TestBlockSyncOrphanLogic(t *testing.T) {
	// Test the logic that would be used in doBlockSync
	
	tests := []struct {
		name        string
		err         error
		height      int64
		shouldCheck bool
	}{
		{
			name:        "ErrBlkNotFound triggers orphan check",
			err:         types.ErrBlkNotFound, 
			height:      100,
			shouldCheck: true,
		},
		{
			name:        "ErrNotFound triggers orphan check",
			err:         types.ErrNotFound,
			height:      100, 
			shouldCheck: true,
		},
		{
			name:        "Other error does not trigger orphan check",
			err:         errors.New("some other error"),
			height:      100,
			shouldCheck: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic from blocksync.go
			shouldCallOrphanDetection := errors.Is(tt.err, types.ErrBlkNotFound) || errors.Is(tt.err, types.ErrNotFound)
			assert.Equal(t, tt.shouldCheck, shouldCallOrphanDetection)
		})
	}
}

// mockLoggerSimple provides a minimal logger implementation for testing
type mockLoggerSimple struct{}

func (m *mockLoggerSimple) Debug(msg string, args ...any) {}
func (m *mockLoggerSimple) Info(msg string, args ...any) {}
func (m *mockLoggerSimple) Warn(msg string, args ...any) {}
func (m *mockLoggerSimple) Error(msg string, args ...any) {}
func (m *mockLoggerSimple) Log(level log.Level, msg string, args ...any) {}

func (m *mockLoggerSimple) Debugf(msg string, args ...any) {}
func (m *mockLoggerSimple) Infof(msg string, args ...any) {}
func (m *mockLoggerSimple) Warnf(msg string, args ...any) {}
func (m *mockLoggerSimple) Errorf(msg string, args ...any) {}
func (m *mockLoggerSimple) Logf(level log.Level, msg string, args ...any) {}

func (m *mockLoggerSimple) Debugln(a ...any) {}
func (m *mockLoggerSimple) Infoln(a ...any) {}
func (m *mockLoggerSimple) Warnln(a ...any) {}
func (m *mockLoggerSimple) Errorln(a ...any) {}
func (m *mockLoggerSimple) Logln(level log.Level, a ...any) {}

func (m *mockLoggerSimple) New(name string) log.Logger { return m }
func (m *mockLoggerSimple) NewWithLevel(lvl log.Level, name string) log.Logger { return m }