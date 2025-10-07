package blockprocessor

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
)

// Mock implementations are in transactions_test.go

// TestNodeStatusConcurrency verifies thread-safe access to nodeStatus
func TestNodeStatusConcurrency(t *testing.T) {
	ns := newNodeStatus()

	// Verify initial state
	assert.False(t, ns.IsSyncing(), "node should not be syncing initially")

	// Concurrent writes and reads
	var wg sync.WaitGroup
	iterations := 100

	// Writers
	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range iterations {
				ns.setSyncing(id%2 == 0) // Alternate true/false
			}
		}(i)
	}

	// Readers
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				_ = ns.IsSyncing()
			}
		}()
	}

	wg.Wait()

	// Should not panic and should have a valid state
	syncing := ns.IsSyncing()
	assert.IsType(t, false, syncing, "IsSyncing should return a boolean")
}

// TestNodeStatusStateTransitions verifies correct state transitions
func TestNodeStatusStateTransitions(t *testing.T) {
	ns := newNodeStatus()

	// Initial state
	assert.False(t, ns.IsSyncing(), "initial state should be not syncing")

	// Transition to syncing
	ns.setSyncing(true)
	assert.True(t, ns.IsSyncing(), "should be syncing after setSyncing(true)")

	// Stay in syncing
	ns.setSyncing(true)
	assert.True(t, ns.IsSyncing(), "should remain syncing")

	// Transition to not syncing
	ns.setSyncing(false)
	assert.False(t, ns.IsSyncing(), "should not be syncing after setSyncing(false)")

	// Stay in not syncing
	ns.setSyncing(false)
	assert.False(t, ns.IsSyncing(), "should remain not syncing")

	// Multiple rapid transitions
	for i := range 10 {
		ns.setSyncing(i%2 == 0)
		expected := i%2 == 0
		assert.Equal(t, expected, ns.IsSyncing(), "state should match last setSyncing call")
	}
}

// TestNodeStatusImplementsInterface verifies nodeStatus implements NodeStatusProvider
func TestNodeStatusImplementsInterface(t *testing.T) {
	ns := newNodeStatus()

	// This will fail to compile if nodeStatus doesn't implement the interface
	var _ interface{ IsSyncing() bool } = ns

	// Verify it works as expected
	assert.False(t, ns.IsSyncing())
	ns.setSyncing(true)
	assert.True(t, ns.IsSyncing())
}

// TestBlockProcessorNodeStatusIntegration verifies BlockProcessor properly manages nodeStatus
func TestBlockProcessorNodeStatusIntegration(t *testing.T) {
	// Create minimal BlockProcessor with nodeStatus
	nodePrivKey, err := crypto.GeneratePrivateKey(crypto.KeyTypeSecp256k1)
	require.NoError(t, err)
	nodeSigner := auth.GetNodeSigner(nodePrivKey)

	chainCtx := &common.ChainContext{
		ChainID: "test",
		NetworkParameters: &ktypes.NetworkParameters{
			MaxBlockSize:     1024 * 1024,
			MaxVotesPerTx:    100,
			DisabledGasCosts: true,
		},
	}

	bp := &BlockProcessor{
		db:         &mockDB{},
		txapp:      &mockTxApp{},
		log:        log.DiscardLogger,
		signer:     nodeSigner,
		chainCtx:   chainCtx,
		nodeStatus: newNodeStatus(),
	}

	// Initially not syncing
	assert.False(t, bp.NodeStatus().IsSyncing(), "initial state should be not syncing")

	// Execute block with syncing=true
	bp.nodeStatus.setSyncing(true)
	assert.True(t, bp.NodeStatus().IsSyncing(), "should be syncing during block sync")

	// Simulate transition to normal operation
	bp.nodeStatus.setSyncing(false)
	assert.False(t, bp.NodeStatus().IsSyncing(), "should not be syncing after sync complete")
}

// TestBlockProcessorNodeStatusExposedViaGetter verifies NodeStatus() returns non-nil provider
func TestBlockProcessorNodeStatusExposedViaGetter(t *testing.T) {
	bp := &BlockProcessor{
		nodeStatus: newNodeStatus(),
	}

	// Verify NodeStatus is accessible
	nodeStatus := bp.NodeStatus()
	require.NotNil(t, nodeStatus, "NodeStatus should not be nil")

	// Verify it implements the interface
	var _ common.NodeStatusProvider = nodeStatus

	// Verify initial state
	assert.False(t, nodeStatus.IsSyncing(), "initial state should be not syncing")

	// Verify state can be queried and changed
	bp.nodeStatus.setSyncing(true)
	assert.True(t, nodeStatus.IsSyncing(), "state should reflect changes")

	bp.nodeStatus.setSyncing(false)
	assert.False(t, nodeStatus.IsSyncing(), "state should reflect changes")
}
