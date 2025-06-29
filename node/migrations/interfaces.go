package migrations

import (
	"context"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/accounts"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// snapshotter creates snapshots of the state at the migration height.
type Snapshotter interface {
	CreateSnapshot(ctx context.Context, height uint64, snapshotID string, schemas, excludedTables []string, excludedTableData []string) error
	LoadSnapshotChunk(height uint64, format uint32, chunkIdx uint32) ([]byte, error)
	ListSnapshots() []*snapshotter.Snapshot
}

// It should connect to the same Postgres database as kwild,
// but should be a different connection pool.
type Database interface {
	sql.TxMaker
	sql.ReadTxMaker
	sql.SnapshotTxMaker
}

// accounts tracks all the spends that have occurred in the block.
type Accounts interface {
	GetBlockSpends() []*accounts.Spend
}

type Validators interface {
	GetValidators() []*types.Validator
}

type NamespaceManager interface {
	ListPostgresSchemasToDump() ([]string, error)
}
