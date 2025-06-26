package chain

import (
	"context"

	"github.com/trufnetwork/kwil-db/core/types"
	chaintypes "github.com/trufnetwork/kwil-db/core/types/chain"
)

type Client interface {
	Version(ctx context.Context) (string, error)
	BlockByHeight(ctx context.Context, height int64) (*chaintypes.Block, *chaintypes.CommitInfo, error)
	BlockByHash(ctx context.Context, hash types.Hash) (*chaintypes.Block, *chaintypes.CommitInfo, error)
	BlockResultByHeight(ctx context.Context, height int64) (*chaintypes.BlockResult, error)
	BlockResultByHash(ctx context.Context, hash types.Hash) (*chaintypes.BlockResult, error)
	UnconfirmedTxs(ctx context.Context) (total int, txs []chaintypes.NamedTx, err error)
	Tx(ctx context.Context, hash types.Hash) (*chaintypes.Tx, error)
	Genesis(ctx context.Context) (*chaintypes.Genesis, error)
	ConsensusParams(ctx context.Context) (*types.NetworkParameters, error)
	Validators(ctx context.Context) (height int64, validators []*types.Validator, err error)
}
