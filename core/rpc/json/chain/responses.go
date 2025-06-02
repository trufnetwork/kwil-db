package chain

import (
	"github.com/kwilteam/kwil-db/core/types"
	chaintypes "github.com/kwilteam/kwil-db/core/types/chain"
)

// HealthResponse is the health check response.
type HealthResponse struct {
	ChainID string `json:"chain_id"`
	Height  int64  `json:"height"`
	Healthy bool   `json:"healthy"`
}

// BlockResponse is the block information. Either the block or raw_block fields
// may be set depending on if the decoded or raw block was requested.
type BlockResponse struct {
	Hash       types.Hash             `json:"hash"`
	Block      *chaintypes.Block      `json:"block,omitempty"`
	RawBlock   []byte                 `json:"raw_block,omitempty"`
	CommitInfo *chaintypes.CommitInfo `json:"commit_info"`
}

type BlockResultResponse chaintypes.BlockResult

type BlockHeaderResponse chaintypes.BlockHeader

type TxResponse chaintypes.Tx

// GenesisResponse is the same as kwil-db/config.GenesisConfig, with JSON tags.
type GenesisResponse = chaintypes.Genesis

type ConsensusParamsResponse = types.NetworkParameters

type ValidatorsResponse struct {
	Height     int64              `json:"height"`
	Validators []*types.Validator `json:"validators"`
}

type UnconfirmedTxsResponse struct {
	Total int                  `json:"total"`
	Txs   []chaintypes.NamedTx `json:"txs"`
}
