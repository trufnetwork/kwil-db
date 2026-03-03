package node

import (
	"context"

	"github.com/trufnetwork/kwil-db/core/crypto"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/consensus"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
	"github.com/trufnetwork/kwil-db/node/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

type ConsensusEngine interface {
	Status() *ktypes.NodeStatus // includes: role, inCatchup, consensus params, last commit info and block header

	Role() types.Role
	InCatchup() bool

	AcceptProposal(height int64, blkID, prevBlkID types.Hash, leaderSig []byte, timestamp int64) bool
	NotifyBlockProposal(blk *ktypes.Block, sender []byte, done func())

	AcceptCommit(height int64, blkID types.Hash, hdr *ktypes.BlockHeader, ci *ktypes.CommitInfo, leaderSig []byte) bool
	NotifyBlockCommit(blk *ktypes.Block, ci *ktypes.CommitInfo, blkID types.Hash, doneFn func())

	NotifyACK(validatorPK []byte, ack types.AckRes)

	NotifyResetState(height int64, txIDs []types.Hash, senderPubKey []byte)

	NotifyDiscoveryMessage(validatorPK []byte, height int64)

	Start(ctx context.Context, fns consensus.BroadcastFns, peerFns consensus.WhitelistFns) error

	QueueTx(ctx context.Context, tx *types.Tx) error
	BroadcastTx(ctx context.Context, tx *types.Tx, sync uint8) (ktypes.Hash, *ktypes.TxResult, error)

	ConsensusParams() *ktypes.NetworkParameters
	CancelBlockExecution(height int64, txIDs []types.Hash) error

	// PromoteLeader is used to promote a validator to leader starting from the specified height
	PromoteLeader(leader crypto.PublicKey, height int64) error

	// CanReannounce returns true if it's safe to re-announce transactions from the mempool.
	// Returns false if a block is currently being executed to avoid re-announcing transactions
	// with nonces that will be invalidated once the block commits.
	CanReannounce() bool
}

type BlockProcessor interface {
	GetValidators() []*ktypes.Validator
	SubscribeValidators() <-chan []*ktypes.Validator
}

type SnapshotStore interface {
	Enabled() bool
	GetSnapshot(height uint64, format uint32) *snapshotter.Snapshot
	ListSnapshots() []*snapshotter.Snapshot
	LoadSnapshotChunk(height uint64, format uint32, chunk uint32) ([]byte, error)
}

type DB interface {
	sql.ReadTxMaker
}
