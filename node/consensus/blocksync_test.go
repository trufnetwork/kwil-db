//go:build pglive

package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	blockprocessor "github.com/trufnetwork/kwil-db/node/block_processor"
	"github.com/trufnetwork/kwil-db/node/mempool"
	"github.com/trufnetwork/kwil-db/node/types"

	"github.com/stretchr/testify/require"
)

// Test that RecheckTxs is called when ErrBlkNotFound occurs during block sync
func TestReplayBlockFromNetwork_CallsRecheckTxsOnErrBlkNotFound(t *testing.T) {
	ctx := context.Background()

	// Create a minimal consensus engine with just the required components
	mp := mempool.New(1000000, 100000) // 1MB mempool, 100KB max tx size

	// Track RecheckTxs calls
	recheckCalled := false

	// Create a mock block processor that tracks RecheckTxs calls
	mockBP := &testBlockProcessor{
		recheckTxsFunc: func(ctx context.Context, height int64, timestamp time.Time) error {
			recheckCalled = true
			return nil
		},
	}

	ce := &ConsensusEngine{
		mempool:        mp,
		blockProcessor: mockBP,
		log:            log.DiscardLogger, // Use discard logger for tests
	}

	// Initialize state info for lastBlockInternal
	now := time.Now()
	ce.stateInfo.lastCommit.blk = &ktypes.Block{
		Header: &ktypes.BlockHeader{
			Height:    1,
			Timestamp: now,
		},
	}
	ce.stateInfo.lastCommit.height = 1

	// Initialize state.lc which is needed by lastBlockInternal
	ce.state.lc = &lastCommit{
		blk: &ktypes.Block{
			Header: &ktypes.BlockHeader{
				Height:    1,
				Timestamp: now,
			},
		},
		height: 1,
	}

	// Mock block requester to return ErrBlkNotFound
	ce.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
		return types.Hash{}, nil, nil, 0, types.ErrBlkNotFound
	}

	// Call replayBlockFromNetwork - this should trigger our fix
	err := ce.replayBlockFromNetwork(ctx)
	require.NoError(t, err)

	// Verify RecheckTxs was called
	require.True(t, recheckCalled, "RecheckTxs should be called when ErrBlkNotFound occurs")
}

// Test that RecheckTxs is also called for ErrNotFound
func TestReplayBlockFromNetwork_CallsRecheckTxsOnErrNotFound(t *testing.T) {
	ctx := context.Background()

	mp := mempool.New(1000000, 100000)

	recheckCalled := false
	mockBP := &testBlockProcessor{
		recheckTxsFunc: func(ctx context.Context, height int64, timestamp time.Time) error {
			recheckCalled = true
			return nil
		},
	}

	ce := &ConsensusEngine{
		mempool:        mp,
		blockProcessor: mockBP,
		log:            log.DiscardLogger, // Use discard logger for tests
	}

	now := time.Now()
	ce.stateInfo.lastCommit.blk = &ktypes.Block{
		Header: &ktypes.BlockHeader{
			Height:    1,
			Timestamp: now,
		},
	}
	ce.stateInfo.lastCommit.height = 1

	// Initialize state.lc which is needed by lastBlockInternal
	ce.state.lc = &lastCommit{
		blk: &ktypes.Block{
			Header: &ktypes.BlockHeader{
				Height:    1,
				Timestamp: now,
			},
		},
		height: 1,
	}

	// Mock block requester to return ErrNotFound
	ce.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
		return types.Hash{}, nil, nil, 0, types.ErrNotFound
	}

	err := ce.replayBlockFromNetwork(ctx)
	require.NoError(t, err)

	require.True(t, recheckCalled, "RecheckTxs should be called when ErrNotFound occurs")
}

// Test that with stale transactions in mempool, they get removed by RecheckTxs
func TestReplayBlockFromNetwork_RemovesStaleTransactions(t *testing.T) {
	ctx := context.Background()

	mp := mempool.New(1000000, 100000)

	// Add a test transaction to mempool
	testTx := createTestTransaction()
	err := mp.Store(testTx)
	require.NoError(t, err)

	// Verify transaction is in mempool
	require.True(t, mp.Have(testTx.Hash()))

	// Mock block processor that simulates RecheckTxs removing invalid transactions
	mockBP := &testBlockProcessor{
		recheckTxsFunc: func(ctx context.Context, height int64, timestamp time.Time) error {
			// Simulate removing the stale transaction
			mp.Remove(testTx.Hash())
			return nil
		},
	}

	ce := &ConsensusEngine{
		mempool:        mp,
		blockProcessor: mockBP,
		log:            log.DiscardLogger, // Use discard logger for tests
	}

	now := time.Now()
	ce.stateInfo.lastCommit.blk = &ktypes.Block{
		Header: &ktypes.BlockHeader{
			Height:    1,
			Timestamp: now,
		},
	}
	ce.stateInfo.lastCommit.height = 1

	// Initialize state.lc which is needed by lastBlockInternal
	ce.state.lc = &lastCommit{
		blk: &ktypes.Block{
			Header: &ktypes.BlockHeader{
				Height:    1,
				Timestamp: now,
			},
		},
		height: 1,
	}

	ce.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
		return types.Hash{}, nil, nil, 0, types.ErrBlkNotFound
	}

	// Call replayBlockFromNetwork
	err = ce.replayBlockFromNetwork(ctx)
	require.NoError(t, err)

	// Verify transaction was removed from mempool
	require.False(t, mp.Have(testTx.Hash()), "Stale transaction should be removed from mempool")
}

// Helper function to create a test transaction
func createTestTransaction() *types.Tx {
	tx := &ktypes.Transaction{
		Body: &ktypes.TransactionBody{
			PayloadType: "test",
			Payload:     []byte("test payload"),
			Fee:         big.NewInt(1000),
			Nonce:       1,
		},
		Signature: &auth.Signature{
			Data: []byte("fake signature"),
			Type: "secp256k1",
		},
		Sender: []byte("test sender"),
	}

	return types.NewTx(tx)
}

// Minimal mock block processor that only implements RecheckTxs for testing
type testBlockProcessor struct {
	recheckTxsFunc func(ctx context.Context, height int64, timestamp time.Time) error
}

func (bp *testBlockProcessor) RecheckTxs(ctx context.Context, height int64, timestamp time.Time) error {
	if bp.recheckTxsFunc != nil {
		return bp.recheckTxsFunc(ctx, height, timestamp)
	}
	return nil
}

// Implement other required methods with minimal stubs
func (bp *testBlockProcessor) InitChain(ctx context.Context) (int64, []byte, error) {
	return 0, nil, nil
}
func (bp *testBlockProcessor) SetCallbackFns(applyBlockFn blockprocessor.BroadcastTxFn, addPeer, removePeer func(string) error) {
}
func (bp *testBlockProcessor) PrepareProposal(ctx context.Context, txs []*types.Tx) ([]*ktypes.Transaction, []*ktypes.Transaction, error) {
	return nil, nil, nil
}
func (bp *testBlockProcessor) ExecuteBlock(ctx context.Context, req *ktypes.BlockExecRequest, syncing bool) (*ktypes.BlockExecResult, error) {
	return &ktypes.BlockExecResult{}, nil
}
func (bp *testBlockProcessor) Commit(ctx context.Context, req *ktypes.CommitRequest) error {
	return nil
}
func (bp *testBlockProcessor) Rollback(ctx context.Context, height int64, appHash ktypes.Hash) error {
	return nil
}
func (bp *testBlockProcessor) Close() error { return nil }
func (bp *testBlockProcessor) CheckTx(ctx context.Context, tx *types.Tx, height int64, blockTime time.Time, recheck bool) error {
	return nil
}
func (bp *testBlockProcessor) GetValidators() []*ktypes.Validator { return nil }
func (bp *testBlockProcessor) ConsensusParams() *ktypes.NetworkParameters {
	return &ktypes.NetworkParameters{}
}
func (bp *testBlockProcessor) BlockExecutionStatus() *ktypes.BlockExecutionStatus {
	return &ktypes.BlockExecutionStatus{}
}
func (bp *testBlockProcessor) HasEvents() bool { return false }
func (bp *testBlockProcessor) StateHashes() *blockprocessor.StateHashes {
	return &blockprocessor.StateHashes{}
}

// logLine finds the JSON log record with the given msg in a captured log.
func logLine(t *testing.T, captured, msg string) map[string]any {
	t.Helper()
	for _, raw := range strings.Split(strings.TrimSpace(captured), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			t.Fatalf("log line is not JSON: %s", raw)
		}
		if rec["msg"] == msg {
			return rec
		}
	}
	t.Fatalf("no %q line in the captured log:\n%s", msg, captured)
	return nil
}

// nanos reads a duration field, which the JSON handler writes as nanoseconds.
func nanos(t *testing.T, rec map[string]any, key string) time.Duration {
	t.Helper()
	v, ok := rec[key].(float64)
	if !ok {
		t.Fatalf("%q is %T, not a duration: %v", key, rec[key], rec[key])
	}
	return time.Duration(v)
}

// Test that a catch-up run reports where its time went, rather than one
// combined rate that cannot tell a slow link from a slow apply.
func TestReplayBlockFromNetwork_ReportsWhereTheTimeWent(t *testing.T) {
	ctx := context.Background()

	var captured bytes.Buffer
	ce := &ConsensusEngine{
		mempool:        mempool.New(1000000, 100000),
		blockProcessor: &testBlockProcessor{},
		log:            log.New(log.WithWriter(&captured), log.WithFormat(log.FormatJSON)),
	}

	now := time.Now()
	blk := &ktypes.Block{Header: &ktypes.BlockHeader{Height: 1, Timestamp: now}}
	ce.stateInfo.lastCommit.blk = blk
	ce.stateInfo.lastCommit.height = 1
	ce.state.lc = &lastCommit{blk: blk, height: 1}

	// One slow request, which comes back empty and ends the sync. Nothing is
	// applied, so the whole run is network time and the split has to say so.
	const requestTook = 40 * time.Millisecond
	ce.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
		time.Sleep(requestTook)
		return types.Hash{}, nil, nil, 0, types.ErrBlkNotFound
	}

	require.NoError(t, ce.replayBlockFromNetwork(ctx))

	done := logLine(t, captured.String(), "Block sync completed")
	network, apply, elapsed := nanos(t, done, "network"), nanos(t, done, "apply"), nanos(t, done, "elapsed")

	require.GreaterOrEqual(t, network, requestTook,
		"the request that ended the sync still cost its round trip and has to be counted")
	require.Zero(t, apply, "no block was applied, so no time belongs to apply")
	require.LessOrEqual(t, network, elapsed, "the split cannot exceed the run it is splitting")
}
