// package user defines the interface for a user client transport.
// the user client is the main service for end users to interact with a Kwil network.
package user

import (
	"context"
	"math/big"

	"github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/types"
)

// TxSvcClient is the interface for a txsvc client.
// The txsvc is the main service for end users to interact with a Kwil network.
type TxSvcClient interface {
	Broadcast(ctx context.Context, tx *types.Transaction, sync client.BroadcastWait) (types.Hash, error)
	Call(ctx context.Context, msg *types.CallMessage, opts ...client.ActionCallOption) (*types.CallResult, error)
	ChainInfo(ctx context.Context) (*types.ChainInfo, error)
	EstimateCost(ctx context.Context, tx *types.Transaction) (*big.Int, error)
	GetAccount(ctx context.Context, identifier *types.AccountID, status types.AccountStatus) (*types.Account, error) // maybe return height too
	Ping(ctx context.Context) (string, error)
	Query(ctx context.Context, query string, params map[string]*types.EncodedValue) (*types.QueryResult, error)
	AuthenticatedQuery(ctx context.Context, msg *types.AuthenticatedQuery) (*types.QueryResult, error)
	TxQuery(ctx context.Context, txHash types.Hash) (*types.TxQueryResponse, error)

	// Migration methods
	ListMigrations(ctx context.Context) ([]*types.Migration, error)

	// Active Migration State
	GenesisState(ctx context.Context) (*types.MigrationMetadata, error)
	GenesisSnapshotChunk(ctx context.Context, height uint64, chunkIdx uint32) ([]byte, error)
	MigrationStatus(ctx context.Context) (*types.MigrationState, error)

	// Changesets
	LoadChangeset(ctx context.Context, height int64, index int64) ([]byte, error)
	ChangesetMetadata(ctx context.Context, height int64) (int64, []int64, error)

	// Challenge
	Challenge(ctx context.Context) ([]byte, error)

	GetNumAccounts(ctx context.Context) (count, height int64, err error)

	Health(ctx context.Context) (*types.Health, error)
}
