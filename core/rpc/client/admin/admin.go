// package admin specifies the interface for the admin service client.
package admin

import (
	"context"

	"github.com/trufnetwork/kwil-db/core/crypto"
	adminjson "github.com/trufnetwork/kwil-db/core/rpc/json/admin"
	"github.com/trufnetwork/kwil-db/core/types"
	adminTypes "github.com/trufnetwork/kwil-db/core/types/admin"
)

type AdminClient interface {
	Approve(ctx context.Context, publicKey []byte, pubKeyType crypto.KeyType) (types.Hash, error)
	Join(ctx context.Context) (types.Hash, error)
	JoinStatus(ctx context.Context, pubkey []byte, pubKeyType crypto.KeyType) (*types.JoinRequest, error)
	Leave(ctx context.Context) (types.Hash, error)
	Promote(ctx context.Context, publicKey []byte, pubKeyType crypto.KeyType, height int64) error
	ListValidators(ctx context.Context) ([]*types.Validator, error)
	Peers(ctx context.Context) ([]*adminTypes.PeerInfo, error)
	Remove(ctx context.Context, publicKey []byte, pubKeyType crypto.KeyType) (types.Hash, error)
	Status(ctx context.Context) (*adminTypes.Status, error)
	Version(ctx context.Context) (string, error)
	ListPendingJoins(ctx context.Context) ([]*types.JoinRequest, error)

	// GetConfig gets the current config from the node.
	// It returns the config serialized as JSON.
	GetConfig(ctx context.Context) ([]byte, error)

	AddPeer(ctx context.Context, peerID string) error
	RemovePeer(ctx context.Context, peerID string) error
	ListPeers(ctx context.Context) ([]string, error)

	// Blacklist management
	BlacklistPeer(ctx context.Context, peerID string, reason string, duration string) error
	RemoveBlacklistedPeer(ctx context.Context, peerID string) error
	ListBlacklistedPeers(ctx context.Context) ([]adminjson.BlacklistEntryJSON, error)

	// Resolutions
	CreateResolution(ctx context.Context, resolution []byte, resolutionType string) (types.Hash, error)
	ApproveResolution(ctx context.Context, resolutionID *types.UUID) (types.Hash, error)
	// DeleteResolution(ctx context.Context, resolutionID *types.UUID) (types.Hash, error)
	ResolutionStatus(ctx context.Context, resolutionID *types.UUID) (*types.PendingResolution, error)

	// Block Execution
	BlockExecStatus(ctx context.Context) (*adminTypes.BlockExecutionStatus, error)
	AbortBlockExecution(ctx context.Context, height int64, discardTxs []string) error
}
