//go:build pglive

package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"sync/atomic"
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

// replayEngine is a consensus engine at height 1 with just enough to run
// replayBlockFromNetwork, fetching through fetch.
func replayEngine(prefetchBytes int64, fetch BlkRequester, recheck func()) *ConsensusEngine {
	now := time.Now()
	blk := &ktypes.Block{Header: &ktypes.BlockHeader{Height: 1, Timestamp: now}}
	ce := &ConsensusEngine{
		mempool: mempool.New(1000000, 100000),
		blockProcessor: &testBlockProcessor{
			recheckTxsFunc: func(context.Context, int64, time.Time) error {
				if recheck != nil {
					recheck()
				}
				return nil
			},
		},
		log:           log.DiscardLogger,
		blkRequester:  fetch,
		prefetchBytes: prefetchBytes,
	}
	ce.stateInfo.height = 1 // so replay starts at 2
	ce.stateInfo.lastCommit.blk = blk
	ce.stateInfo.lastCommit.height = 1
	ce.state.lc = &lastCommit{blk: blk, height: 1}
	return ce
}

// replayWithin runs replay, failing the test rather than hanging it if replay
// does not return in time.
func replayWithin(t *testing.T, ce *ConsensusEngine, limit time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- ce.replayBlockFromNetwork(context.Background()) }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("replay did not return within %v", limit)
		return nil
	}
}

// A node already at the tip runs replay on every catch-up tick. With prefetch
// on, the tick has to end the way it did before, on the one request it made.
func TestReplayBlockFromNetwork_PrefetchAsksOnceWhenInSync(t *testing.T) {
	var asked atomic.Int32
	var rechecked bool
	ce := replayEngine(1<<20, func(context.Context, int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
		asked.Add(1)
		return types.Hash{}, nil, nil, 1, types.ErrBlkNotFound
	}, func() { rechecked = true })

	require.NoError(t, replayWithin(t, ce, 10*time.Second))
	require.True(t, rechecked, "the end of sync still rechecks the mempool")
	require.EqualValues(t, 1, asked.Load())
}

// The prefetcher fetches the next blocks while a block applies, and belongs
// to the replay that started it. applyBlock takes ce.state.mtx before anything
// else, so holding it keeps block 2 waiting to apply: the workers have to get
// on without it, which is the spec's rule that they never touch it. Then block
// 2 fails to decode, and when replay returns every request it had out is over.
func TestReplayBlockFromNetwork_PrefetchRunsDuringApplyAndStopsWithIt(t *testing.T) {
	var asked, active atomic.Int32
	ce := replayEngine(1<<20, func(ctx context.Context, h int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
		asked.Add(1)
		if h == 2 {
			// Peers are at 100, so the prefetcher starts on 3 onwards.
			return types.Hash{2}, []byte("not a block"), &ktypes.CommitInfo{}, 100, nil
		}
		active.Add(1)
		defer active.Add(-1)
		<-ctx.Done() // a peer that never answers
		return types.Hash{}, nil, nil, 0, ctx.Err()
	}, nil)

	ce.state.mtx.Lock()
	var sawAll atomic.Bool
	go func() {
		defer ce.state.mtx.Unlock()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			if active.Load() == prefetchWorkers {
				sawAll.Store(true)
				return
			}
		}
	}()

	err := replayWithin(t, ce, 10*time.Second)
	require.ErrorContains(t, err, "failed to apply block at height: 2")
	require.True(t, sawAll.Load(), "the next blocks were on their way while block 2 waited to apply")
	require.Zero(t, active.Load(), "no request outlives the replay")

	sent := asked.Load()
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, sent, asked.Load(), "and none is sent after it")
}
