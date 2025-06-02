// Package types contains the type used by the chain RPC client and server.
package types

import (
	"github.com/kwilteam/kwil-db/core/types"
)

type Tx struct {
	Hash     types.Hash         `json:"hash"`
	Height   int64              `json:"height"`
	Index    uint32             `json:"index"`
	Tx       *types.Transaction `json:"tx"`
	TxResult *types.TxResult    `json:"tx_result"`
}

type Block = types.Block
type BlockHeader = types.BlockHeader
type CommitInfo = types.CommitInfo

type BlockResult struct {
	Height    int64            `json:"height"`
	Hash      types.Hash       `json:"hash"`
	TxResults []types.TxResult `json:"tx_results"`
}

type GenesisAlloc struct {
	ID      types.HexBytes `json:"id"`
	KeyType string         `json:"key_type"`
	Amount  string         `json:"amount"`
}

// Genesis is like the node's config.Genesis, but flattened, with JSON tags, and
// certain migration fields removed.
type Genesis struct {
	ChainID       string `json:"chain_id"`
	InitialHeight int64  `json:"initial_height"`
	DBOwner       string `json:"db_owner"`
	// Leader is the leader's public key.
	Leader types.PublicKey `json:"leader"`
	// Validators is the list of genesis validators (including the leader).
	Validators []*types.Validator `json:"validators"`

	// StateHash is the hash of the initial state of the chain, used when bootstrapping
	// the chain with a network snapshot during migration.
	StateHash types.HexBytes `json:"state_hash,omitempty"`

	// Alloc is the initial allocation of balances.
	Allocs []GenesisAlloc `json:"alloc,omitempty"`

	// some fields from types.NetworkParameters:

	// MaxBlockSize is the maximum size of a block in bytes.
	MaxBlockSize int64 `json:"max_block_size"`
	// JoinExpiry is the number of blocks after which the validators
	// join request expires if not approved.
	JoinExpiry types.Duration `json:"join_expiry"`
	// DisabledGasCosts dictates whether gas costs are disabled.
	DisabledGasCosts bool `json:"disabled_gas_costs"`
	// MaxVotesPerTx is the maximum number of votes that can be included in a
	// single transaction.
	MaxVotesPerTx int64 `json:"max_votes_per_tx"`
}

// NamedTx pairs a transaction hash with the transaction itself. This is done
// primarily for JSON marshalling, since the Transaction types is capable of
// returning and caching its own hash.
type NamedTx struct {
	Hash types.Hash         `json:"hash"`
	Tx   *types.Transaction `json:"tx"`
}
