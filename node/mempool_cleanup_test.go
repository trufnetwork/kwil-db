package node

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/trufnetwork/kwil-db/core/crypto"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/consensus"
	"github.com/trufnetwork/kwil-db/node/types"
)

// TestMempoolCleanupFunction tests the mempool cleanup function in isolation
func TestMempoolCleanupFunction(t *testing.T) {
	// Test that the function can be called without panicking
	// and that it respects context cancellation
	
	callCount := 0
	var mu sync.Mutex
	
	// Create a mock consensus engine that tracks calls
	mockCE := &mockConsensusEngine{
		recheckFunc: func(ctx context.Context) error {
			mu.Lock()
			callCount++
			mu.Unlock()
			return nil
		},
	}
	
	node := &Node{
		ce:  mockCE,
		log: &mockLogger{},
	}

	// Test with short cleanup interval
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	cleanupInterval := 50 * time.Millisecond
	node.startMempoolCleanup(ctx, cleanupInterval)

	// Wait for cleanup to run at least twice
	time.Sleep(120 * time.Millisecond)

	// Verify that RecheckMempool was called multiple times
	mu.Lock()
	actualCallCount := callCount
	mu.Unlock()
	
	assert.GreaterOrEqual(t, actualCallCount, 2, "Expected at least 2 cleanup calls")
	
	// Wait for context to be cancelled
	<-ctx.Done()
	
	// Give a moment for cleanup goroutine to exit
	time.Sleep(10 * time.Millisecond)
}

func TestMempoolCleanupContextCancellation(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	
	mockCE := &mockConsensusEngine{
		recheckFunc: func(ctx context.Context) error {
			mu.Lock()
			callCount++
			mu.Unlock()
			return nil
		},
	}
	
	node := &Node{
		ce:  mockCE,
		log: &mockLogger{},
	}

	// Create context and cancel immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Start cleanup
	node.startMempoolCleanup(ctx, time.Second)

	// Give some time for potential execution
	time.Sleep(20 * time.Millisecond)

	// Since context was cancelled immediately, no calls should occur
	mu.Lock()
	actualCallCount := callCount
	mu.Unlock()
	
	assert.Equal(t, 0, actualCallCount, "No cleanup calls should occur when context is cancelled immediately")
}

func TestMempoolCleanupInterval(t *testing.T) {
	callTimes := []time.Time{}
	var mu sync.Mutex
	
	mockCE := &mockConsensusEngine{
		recheckFunc: func(ctx context.Context) error {
			mu.Lock()
			callTimes = append(callTimes, time.Now())
			mu.Unlock()
			return nil
		},
	}
	
	node := &Node{
		ce:  mockCE,
		log: &mockLogger{},
	}

	// Test with precise timing
	cleanupInterval := 40 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	node.startMempoolCleanup(ctx, cleanupInterval)

	// Wait for test to complete
	<-ctx.Done()
	time.Sleep(10 * time.Millisecond)

	// Verify timing intervals
	mu.Lock()
	times := make([]time.Time, len(callTimes))
	copy(times, callTimes)
	mu.Unlock()

	if len(times) >= 2 {
		interval := times[1].Sub(times[0])
		// Allow some tolerance for timing
		assert.InDelta(t, cleanupInterval.Milliseconds(), interval.Milliseconds(), 20, 
			"Cleanup interval should be approximately %v, got %v", cleanupInterval, interval)
	}
}

// mockConsensusEngine provides a minimal implementation for testing
type mockConsensusEngine struct {
	recheckFunc func(ctx context.Context) error
}

func (m *mockConsensusEngine) RecheckMempool(ctx context.Context) error {
	if m.recheckFunc != nil {
		return m.recheckFunc(ctx)
	}
	return nil
}

// Stub implementations for other required methods
func (m *mockConsensusEngine) Status() *ktypes.NodeStatus { return nil }
func (m *mockConsensusEngine) Role() types.Role { return types.RoleValidator }
func (m *mockConsensusEngine) InCatchup() bool { return false }
func (m *mockConsensusEngine) AcceptProposal(height int64, blkID, prevBlkID types.Hash, leaderSig []byte, timestamp int64) bool { return false }
func (m *mockConsensusEngine) NotifyBlockProposal(blk *ktypes.Block, sender []byte, done func()) {}
func (m *mockConsensusEngine) AcceptCommit(height int64, blkID types.Hash, hdr *ktypes.BlockHeader, ci *ktypes.CommitInfo, leaderSig []byte) bool { return false }
func (m *mockConsensusEngine) NotifyBlockCommit(blk *ktypes.Block, ci *ktypes.CommitInfo, blkID types.Hash, doneFn func()) {}
func (m *mockConsensusEngine) NotifyACK(validatorPK []byte, ack types.AckRes) {}
func (m *mockConsensusEngine) NotifyResetState(height int64, txIDs []types.Hash, senderPubKey []byte) {}
func (m *mockConsensusEngine) NotifyDiscoveryMessage(validatorPK []byte, height int64) {}
func (m *mockConsensusEngine) Start(ctx context.Context, fns consensus.BroadcastFns, peerFns consensus.WhitelistFns) error { return nil }
func (m *mockConsensusEngine) QueueTx(ctx context.Context, tx *types.Tx) error { return nil }
func (m *mockConsensusEngine) BroadcastTx(ctx context.Context, tx *types.Tx, sync uint8) (types.Hash, *ktypes.TxResult, error) { return types.Hash{}, nil, nil }
func (m *mockConsensusEngine) ConsensusParams() *ktypes.NetworkParameters { return nil }
func (m *mockConsensusEngine) CancelBlockExecution(height int64, txIDs []types.Hash) error { return nil }
func (m *mockConsensusEngine) PromoteLeader(leader crypto.PublicKey, height int64) error { return nil }

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