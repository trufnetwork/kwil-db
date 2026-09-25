//go:build pglive

package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto"
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
	ce.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		return types.Hash{}, nil, nil, 0, nil, types.ErrBlkNotFound
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
	ce.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		return types.Hash{}, nil, nil, 0, nil, types.ErrNotFound
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

	ce.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		return types.Hash{}, nil, nil, 0, nil, types.ErrBlkNotFound
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
	ce.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		time.Sleep(requestTook)
		return types.Hash{}, nil, nil, 0, nil, types.ErrBlkNotFound
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
	ce := replayEngine(1<<20, func(context.Context, int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		asked.Add(1)
		return types.Hash{}, nil, nil, 1, nil, types.ErrBlkNotFound
	}, func() { rechecked = true })

	require.NoError(t, replayWithin(t, ce, 10*time.Second))
	require.True(t, rechecked, "the end of sync still rechecks the mempool")
	require.EqualValues(t, 1, asked.Load())
}

// The prefetcher fetches the next blocks while a block applies, and belongs
// to the replay that started it. applyBlock takes ce.state.mtx before anything
// else, so holding it keeps block 2 waiting to apply: the workers have to get
// on without it, which is the spec's rule that they never touch it. Then block
// 2 turns out not to be a block. Every request out is over before the peer
// that sent it is held back, so no late answer from that peer undoes the hold,
// and when replay returns, having found nobody with block 2 on asking again,
// no request outlives it.
func TestReplayBlockFromNetwork_PrefetchRunsDuringApplyAndStopsWithIt(t *testing.T) {
	var asked, active, rejected atomic.Int32
	activeAtReject := int32(-1)
	ce := replayEngine(1<<20, func(ctx context.Context, h int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		n := asked.Add(1)
		if h == 2 {
			if n > 1 {
				return types.Hash{}, nil, nil, 0, nil, types.ErrBlkNotFound
			}
			// Peers are at 100, so the prefetcher starts on 3 onwards.
			return types.Hash{2}, []byte("not a block"), &ktypes.CommitInfo{}, 100, func() {
				rejected.Add(1)
				activeAtReject = active.Load()
			}, nil
		}
		active.Add(1)
		defer active.Add(-1)
		<-ctx.Done() // a peer that never answers
		return types.Hash{}, nil, nil, 0, nil, ctx.Err()
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

	require.NoError(t, replayWithin(t, ce, 10*time.Second))
	require.True(t, sawAll.Load(), "the next blocks were on their way while block 2 waited to apply")
	require.EqualValues(t, 1, rejected.Load())
	require.Zero(t, activeAtReject, "the prefetcher had stopped when the peer was held back")
	require.Zero(t, active.Load(), "no request outlives the replay")

	sent := asked.Load()
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, sent, asked.Load(), "and none is sent after it")
}

// After a bad block, prefetch starts over from it: the block is asked for
// again, and once it arrives the workers fetch past it as before. Here block 2
// comes back bad twice, and the second time it has to wait to apply until a
// worker is asking for a block past it.
func TestReplayBlockFromNetwork_PrefetchesAgainAfterABadBlock(t *testing.T) {
	var asked, active, rejected atomic.Int32
	var sawWorker atomic.Bool
	var ce *ConsensusEngine
	ce = replayEngine(1<<20, func(ctx context.Context, h int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		if h > 2 {
			active.Add(1)
			defer active.Add(-1)
			<-ctx.Done()
			return types.Hash{}, nil, nil, 0, nil, ctx.Err()
		}
		if asked.Add(1) > 2 {
			return types.Hash{}, nil, nil, 0, nil, types.ErrBlkNotFound
		}
		return types.Hash{2}, []byte("not a block"), &ktypes.CommitInfo{}, 100, func() {
			if rejected.Add(1) > 1 {
				return
			}
			// Before block 2 is asked for again, hold its apply until a worker
			// is out past it.
			ce.state.mtx.Lock()
			go func() {
				defer ce.state.mtx.Unlock()
				for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
					if active.Load() > 0 {
						sawWorker.Store(true)
						return
					}
				}
			}()
		}, nil
	}, nil)

	require.NoError(t, replayWithin(t, ce, 10*time.Second))
	require.EqualValues(t, 2, rejected.Load())
	require.True(t, sawWorker.Load(), "the workers fetched past block 2 again")
}

// badBlockThenNone answers the first bad requests for block 2 with bytes that
// are no block, each with a reject that counts in rejected, and then says
// nobody has it, which ends the replay. It knows of no block past 2.
func badBlockThenNone(bad int32, asked, rejected *atomic.Int32) BlkRequester {
	return func(ctx context.Context, h int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		if h != 2 || asked.Add(1) > bad {
			return types.Hash{}, nil, nil, 0, nil, types.ErrBlkNotFound
		}
		return types.Hash{2}, []byte("not a block"), &ktypes.CommitInfo{}, 0, func() { rejected.Add(1) }, nil
	}
}

// A block that is not the one the validators committed is the peer's doing.
// It holds that peer back, and the block is asked for again, with prefetch
// off and on. None of it runs.
func TestReplayBlockFromNetwork_AsksAgainForABadBlock(t *testing.T) {
	for _, prefetch := range []int64{0, 1 << 20} {
		t.Run(fmt.Sprintf("prefetch %d", prefetch), func(t *testing.T) {
			var asked, rejected atomic.Int32
			ce := replayEngine(prefetch, badBlockThenNone(1, &asked, &rejected), nil)

			require.NoError(t, replayWithin(t, ce, 10*time.Second))
			require.EqualValues(t, 1, rejected.Load())
			require.EqualValues(t, 2, asked.Load(), "block 2 was asked for again")
			require.Zero(t, ce.stateInfo.hasBlock.Load(), "no block reached processing")
		})
	}
}

// Asking again backs off, as a failed request does, so a peer that keeps
// sending bad blocks is not asked in a tight loop.
func TestReplayBlockFromNetwork_BacksOffBetweenBadBlocks(t *testing.T) {
	var asked, rejected atomic.Int32
	ce := replayEngine(0, badBlockThenNone(3, &asked, &rejected), nil)

	t0 := time.Now()
	require.NoError(t, replayWithin(t, ce, 20*time.Second))
	require.EqualValues(t, 3, rejected.Load())
	require.GreaterOrEqual(t, time.Since(t0), 3*250*time.Millisecond, "each of the three waits at least the backoff's minimum")
}

// A block the validators did commit, which does not follow the chain this
// node has, fails on this node's side: asking another peer would get the same
// block. It stays fatal, and no peer is held back for it.
func TestReplayBlockFromNetwork_ABlockThatDoesNotFollowStaysFatal(t *testing.T) {
	key := newKey(t)
	blk := testBlock(2) // PrevHash is not the hash of this node's block 1
	ci := signedBy(t, blk.Hash(), ktypes.Hash{9}, key)
	var rejected atomic.Int32
	ce := replayEngine(0, func(ctx context.Context, h int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		return blk.Hash(), ktypes.EncodeBlock(blk), ci, 2, func() { rejected.Add(1) }, nil
	}, nil)
	ce.validatorSet = committedEngine(key).validatorSet
	ce.stateInfo.hasBlock.Store(1)

	err := replayWithin(t, ce, 10*time.Second)
	require.ErrorContains(t, err, "failed to apply block at height: 2")
	require.ErrorContains(t, err, "prevBlockHash mismatch")
	require.NotErrorIs(t, err, errUncommittedBlock)
	require.Zero(t, rejected.Load())
}

// followingBlock is block 2 as it follows replayEngine's block 1, signed by
// key, whose commit info says the block runs to appHash. testBlockProcessor
// runs every block to the zero app hash with no parameter updates. It also
// gives ce what running a block needs.
func followingBlock(t *testing.T, ce *ConsensusEngine, key crypto.PrivateKey, appHash ktypes.Hash) (*ktypes.Block, *ktypes.CommitInfo) {
	t.Helper()
	ce.stateInfo.hasBlock.Store(ce.state.lc.height)
	ce.catchupTimeout = time.Hour
	ce.catchupTicker = time.NewTicker(ce.catchupTimeout)
	t.Cleanup(ce.catchupTicker.Stop)
	ce.validatorSet = committedEngine(key).validatorSet
	blk := ktypes.NewBlock(2, ce.state.lc.blkHash, ce.state.lc.appHash, ce.validatorSetHash(),
		ce.blockProcessor.ConsensusParams().Hash(), time.Unix(1729723555, 0), nil)
	return blk, signedBy(t, blk.Hash(), appHash, key)
}

// The votes in a commit info are for the app hash, which covers the block's
// parameter updates, but not for the commit info's own list of them. Only
// running the block can check that list. When the app hash comes out right
// and the list does not match, the block is rolled back and asked for again.
func TestReplayBlockFromNetwork_AsksAgainForChangedParameterUpdates(t *testing.T) {
	var asked, rejected atomic.Int32
	var blk *ktypes.Block
	var ci *ktypes.CommitInfo
	ce := replayEngine(0, func(ctx context.Context, h int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		if h != 2 || asked.Add(1) > 1 {
			return types.Hash{}, nil, nil, 0, nil, types.ErrBlkNotFound
		}
		return blk.Hash(), ktypes.EncodeBlock(blk), ci, 2, func() { rejected.Add(1) }, nil
	}, nil)
	blk, ci = followingBlock(t, ce, newKey(t), ktypes.Hash{})
	ci.ParamUpdates = ktypes.ParamUpdates{ktypes.ParamNameMaxBlockSize: int64(5)}

	require.NoError(t, replayWithin(t, ce, 10*time.Second))
	require.EqualValues(t, 1, rejected.Load())
	require.EqualValues(t, 2, asked.Load(), "block 2 was asked for again")
	require.EqualValues(t, 1, ce.stateInfo.hasBlock.Load(), "block 2 was rolled back")
	require.Nil(t, ce.state.blockRes)
}

// A block the validators committed that runs to another app hash is this
// node's divergence, not the peer's doing, and stays fatal, whatever the
// commit info's parameter updates say.
func TestReplayBlockFromNetwork_AnotherAppHashStaysFatal(t *testing.T) {
	var rejected atomic.Int32
	var blk *ktypes.Block
	var ci *ktypes.CommitInfo
	ce := replayEngine(0, func(ctx context.Context, h int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, func(), error) {
		return blk.Hash(), ktypes.EncodeBlock(blk), ci, 2, func() { rejected.Add(1) }, nil
	}, nil)
	blk, ci = followingBlock(t, ce, newKey(t), ktypes.Hash{7})
	ci.ParamUpdates = ktypes.ParamUpdates{ktypes.ParamNameMaxBlockSize: int64(5)}

	err := replayWithin(t, ce, 10*time.Second)
	require.ErrorContains(t, err, "AppHash mismatch")
	require.NotErrorIs(t, err, errUncommittedBlock)
	require.Zero(t, rejected.Load())
}
