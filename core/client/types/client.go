// Package client contains the shared client types, including the options used
// to construct a Client instance, and the records iterator used to represent
// the results of an action call. This package also defines the Client interface
// that should be satisfied by different implementations, such as a gateway
// client.
package client

import (
	"context"
	"math/big"
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
)

// Client defines methods are used to talk to a Kwil provider.
type Client interface {
	Call(ctx context.Context, namespace string, action string, inputs []any) (*types.CallResult, error)
	ChainID() string
	ChainInfo(ctx context.Context) (*types.ChainInfo, error)
	Execute(ctx context.Context, namespace string, action string, tuples [][]any, opts ...TxOpt) (types.Hash, error)
	ExecuteSQL(ctx context.Context, sql string, params map[string]any, opts ...TxOpt) (types.Hash, error)
	GetAccount(ctx context.Context, account *types.AccountID, status types.AccountStatus) (*types.Account, error)
	Ping(ctx context.Context) (string, error)
	Query(ctx context.Context, query string, params map[string]any, auth bool) (*types.QueryResult, error)
	TxQuery(ctx context.Context, txHash types.Hash) (*types.TxQueryResponse, error)
	WaitTx(ctx context.Context, txHash types.Hash, interval time.Duration) (*types.TxQueryResponse, error)
	Transfer(ctx context.Context, to *types.AccountID, amount *big.Int, opts ...TxOpt) (types.Hash, error)
	Signer() auth.Signer
}
