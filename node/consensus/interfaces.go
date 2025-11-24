package consensus

import (
	"context"
	"time"

	blockprocessor "github.com/trufnetwork/kwil-db/node/block_processor"
	"github.com/trufnetwork/kwil-db/node/mempool"

	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// DB is the interface for the main SQL database. All queries must be executed
// from within a transaction. A DB can create read transactions or the special
// two-phase outer write transaction.
type DB interface {
	sql.TxMaker // for out-of-consensus writes e.g. setup and meta table writes
	sql.PreparedTxMaker
	sql.ReadTxMaker
	sql.SnapshotTxMaker
}

type Mempool interface {
	PeekN(maxTxns, totalSizeLimit int) []*types.Tx
	Remove(txid types.Hash)
	RecheckTxs(ctx context.Context, checkFn mempool.CheckFn)
	Store(*types.Tx) error
	TxsAvailable() bool
	Size() (totalBytes, numTxns int)
	CapMaxTxSize(maxBytes int64)
}

// BlockStore includes both txns and blocks
type BlockStore interface {
	Best() (height int64, blkHash, appHash types.Hash, stamp time.Time)
	Store(block *ktypes.Block, commitInfo *ktypes.CommitInfo) error
	Get(blkid types.Hash) (*ktypes.Block, *ktypes.CommitInfo, error)
	GetByHeight(height int64) (types.Hash, *ktypes.Block, *ktypes.CommitInfo, error)
	StoreResults(hash types.Hash, results []ktypes.TxResult) error
	Results(hash types.Hash) ([]ktypes.TxResult, error)
	Sync() error
}

type BlockProcessor interface {
	InitChain(ctx context.Context) (int64, []byte, error)
	SetCallbackFns(applyBlockFn blockprocessor.BroadcastTxFn, addPeer, removePeer func(string) error)

	PrepareProposal(ctx context.Context, txs []*types.Tx) (finalTxs []*ktypes.Transaction, invalidTxs []*ktypes.Transaction, err error)
	ExecuteBlock(ctx context.Context, req *ktypes.BlockExecRequest, syncing bool) (*ktypes.BlockExecResult, error)
	Commit(ctx context.Context, req *ktypes.CommitRequest) error
	Rollback(ctx context.Context, height int64, appHash ktypes.Hash) error
	Close() error

	CheckTx(ctx context.Context, tx *types.Tx, height int64, blockTime time.Time, recheck bool) error
	RecheckTxs(ctx context.Context, height int64, blockTime time.Time) error

	GetValidators() []*ktypes.Validator
	ConsensusParams() *ktypes.NetworkParameters

	BlockExecutionStatus() *ktypes.BlockExecutionStatus
	HasEvents() bool
	StateHashes() *blockprocessor.StateHashes
}
