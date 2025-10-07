package common

import (
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
)

// ChainContext provides context for all chain operations.
// Fields in ChainContext should never be mutated, except
// NetworkParameters can be deterministically mutated as part
// of block execution.
// TODO: review these contexts and see if all the fields are necessary
type ChainContext struct {
	// ChainID is the unique identifier for the chain.
	ChainID string

	// NetworkParams holds network level parameters that can be evolved
	// over the lifetime of a network.
	NetworkParameters *NetworkParameters

	NetworkUpdates types.ParamUpdates

	// MigrationParams holds the context for all migration operations such as
	// block info to poll for the changesets from the old chain during migration.
	MigrationParams *MigrationContext
}

type NetworkParameters = types.NetworkParameters

// BlockContext provides context for all block operations.
type BlockContext struct {
	// ChainContext contains information about the chain.
	ChainContext *ChainContext
	// Height gets the height of the current block.
	Height int64
	// Hash is the hash of the current block.
	// It can be empty if the block is the genesis block and
	// no initial state hash was specified in the genesis configuration.
	Hash types.Hash
	// Timestamp is a timestamp of the current block, in seconds (UNIX epoch).
	// It is set by the block proposer, and therefore may not be accurate.
	// It should not be used for time-sensitive operations where incorrect
	// timestamps could result in security vulnerabilities.
	Timestamp int64
	// Proposer gets the proposer public key of the current block.
	Proposer crypto.PublicKey
	// InCatchup indicates whether the node is currently catching up
	// with the network (i.e., in block sync mode). Extensions can use
	// this to skip heavy operations during catch-up to reduce resource
	// contention.
	InCatchup bool
}

// MigrationContext provides context for all migration operations.
// Fields in MigrationContext should never be mutated till the migration is completed.
type MigrationContext struct {
	// StartHeight is the height of the first block to start migration.
	StartHeight int64
	// EndHeight is the height of the last block to end migration.
	EndHeight int64
}
