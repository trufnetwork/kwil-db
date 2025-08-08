package adminclient

import (
	"context"
	"net/url"
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto"
	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/rpc/client/admin"
	userClient "github.com/trufnetwork/kwil-db/core/rpc/client/chain/jsonrpc"
	"github.com/trufnetwork/kwil-db/core/rpc/client/user"
	adminjson "github.com/trufnetwork/kwil-db/core/rpc/json/admin"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	"github.com/trufnetwork/kwil-db/core/types"
	adminTypes "github.com/trufnetwork/kwil-db/core/types/admin"
)

// Client is an admin RPC client. It provides all methods of the user RPC
// service, plus methods that are specific to the admin service.
type Client struct {
	*userClient.Client // expose all user service methods, and CallMethod for admin svc
}

// NewClient constructs a new admin Client.
func NewClient(u *url.URL, opts ...rpcclient.RPCClientOpts) *Client {
	// alt: jsonclient.NewBaseClient() ... WrapBaseClient() ...
	userClient := userClient.NewClient(u, opts...)
	return WrapUserClient(userClient)
}

// WrapUserClient can be used to construct a new admin Client from an existing
// user RPC client.
func WrapUserClient(cl *userClient.Client) *Client {
	return &Client{
		Client: cl,
	}
}

var _ user.TxSvcClient = (*Client)(nil)  // via embedded userClient.Client
var _ admin.AdminClient = (*Client)(nil) // with extra methods

// Approve approves a validator join request for the validator identified by a
// public key. The transaction hash for the broadcasted approval transaction is
// returned.
func (cl *Client) Approve(ctx context.Context, publicKey []byte, pubKeyType crypto.KeyType) (types.Hash, error) {
	cmd := &adminjson.ApproveRequest{
		PubKey:     publicKey,
		PubKeyType: pubKeyType,
	}
	res := &userjson.BroadcastResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodValApprove), cmd, res)
	if err != nil {
		return types.Hash{}, err
	}
	return res.TxHash, err
}

// Join makes a validator join request for the node being administered. The
// transaction hash for the broadcasted join transaction is returned.
func (cl *Client) Join(ctx context.Context) (types.Hash, error) {
	cmd := &adminjson.JoinRequest{}
	res := &userjson.BroadcastResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodValJoin), cmd, res)
	if err != nil {
		return types.Hash{}, err
	}
	return res.TxHash, err
}

// JoinStatus returns the status of an active join request for the validator
// identified by the public key.
func (cl *Client) JoinStatus(ctx context.Context, pubkey []byte, pubkeyType crypto.KeyType) (*types.JoinRequest, error) {
	cmd := &adminjson.JoinStatusRequest{
		PubKey:     pubkey,
		PubKeyType: pubkeyType,
	}
	res := &adminjson.JoinStatusResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodValJoinStatus), cmd, res)
	if err != nil {
		return nil, err
	}
	return res.JoinRequest, nil
}

// Leave makes a validator leave request for the node being administered. The
// transaction hash for the broadcasted leave transaction is returned.
func (cl *Client) Leave(ctx context.Context) (types.Hash, error) {
	cmd := &adminjson.LeaveRequest{}
	res := &userjson.BroadcastResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodValLeave), cmd, res)
	if err != nil {
		return types.Hash{}, err
	}
	return res.TxHash, err
}

// ListValidators gets the current validator set.
func (cl *Client) ListValidators(ctx context.Context) ([]*types.Validator, error) {
	cmd := &adminjson.ListValidatorsRequest{}
	res := &adminjson.ListValidatorsResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodValList), cmd, res)
	if err != nil {
		return nil, err
	}
	return res.Validators, err
}

// Peers lists the nodes current peers (p2p node connections).
func (cl *Client) Peers(ctx context.Context) ([]*adminTypes.PeerInfo, error) {
	cmd := &adminjson.PeersRequest{}
	res := &adminjson.PeersResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodPeers), cmd, res)
	if err != nil {
		return nil, err
	}
	return res.Peers, err
}

// Remove votes to remove the validator specified by the given public key.
func (cl *Client) Remove(ctx context.Context, publicKey []byte, pubKeyType crypto.KeyType) (types.Hash, error) {
	cmd := &adminjson.RemoveRequest{
		PubKey:     publicKey,
		PubKeyType: pubKeyType,
	}
	res := &userjson.BroadcastResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodValRemove), cmd, res)
	if err != nil {
		return types.Hash{}, err
	}
	return res.TxHash, err
}

// Promote promotes a validator to a leader at the specified height.
func (cl *Client) Promote(ctx context.Context, publicKey []byte, pubKeyType crypto.KeyType, height int64) error {
	cmd := &adminjson.PromoteRequest{
		PubKey:     publicKey,
		PubKeyType: pubKeyType,
		Height:     height,
	}
	res := &adminjson.PromoteResponse{}
	return cl.CallMethod(ctx, string(adminjson.MethodValPromote), cmd, res)
}

// Status gets the node's status, such as it's name, chain ID, versions, sync
// status, best block info, and validator identity.
func (cl *Client) Status(ctx context.Context) (*adminTypes.Status, error) {
	cmd := &adminjson.StatusRequest{}
	res := &adminjson.StatusResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodStatus), cmd, res)
	if err != nil {
		return nil, err
	}

	return &adminTypes.Status{
		Node: res.Node,
		Sync: &adminTypes.SyncInfo{
			AppHash:         res.Sync.AppHash,
			BestBlockHash:   res.Sync.BestBlockHash,
			BestBlockHeight: res.Sync.BestBlockHeight,
			BestBlockTime:   time.UnixMilli(res.Sync.BestBlockTime),
			Syncing:         res.Sync.Syncing,
		},
		Validator: &adminTypes.ValidatorInfo{
			AccountID: types.AccountID{
				Identifier: res.Validator.Identifier,
				KeyType:    res.Validator.KeyType,
			},
			Power: res.Validator.Power,
		},
	}, nil
}

// Version reports the version of the running node.
func (cl *Client) Version(ctx context.Context) (string, error) {
	cmd := &userjson.VersionRequest{}
	res := &userjson.VersionResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodVersion), cmd, res)
	if err != nil {
		return "", err
	}
	return res.KwilVersion, err
}

// ListPendingJoins lists all active validator join requests.
func (cl *Client) ListPendingJoins(ctx context.Context) ([]*types.JoinRequest, error) {
	cmd := &adminjson.ListJoinRequestsRequest{}
	res := &adminjson.ListJoinRequestsResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodValListJoins), cmd, res)
	if err != nil {
		return nil, err
	}
	return res.JoinRequests, err
}

// GetConfig gets the current config from the node.
// It returns the config serialized as JSON.
func (cl *Client) GetConfig(ctx context.Context) ([]byte, error) {
	cmd := &adminjson.GetConfigRequest{}
	res := &adminjson.GetConfigResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodConfig), cmd, res)
	if err != nil {
		return nil, err
	}
	return res.Config, err
}

// Ping just tests RPC connectivity. The expected response is "pong".
func (cl *Client) Ping(ctx context.Context) (string, error) {
	cmd := &userjson.PingRequest{
		Message: "ping",
	}
	res := &userjson.PingResponse{}
	err := cl.CallMethod(ctx, string(userjson.MethodPing), cmd, res)
	if err != nil {
		return "", err
	}
	return res.Message, nil
}

// AddPeer adds a new peer to the node's peer list.
func (cl *Client) AddPeer(ctx context.Context, peerID string) error {
	cmd := &adminjson.PeerRequest{
		PeerID: peerID,
	}
	res := &adminjson.PeerResponse{}
	return cl.CallMethod(ctx, string(adminjson.MethodAddPeer), cmd, res)
}

// RemovePeer adds a new peer to the node's peer list.
func (cl *Client) RemovePeer(ctx context.Context, peerID string) error {
	cmd := &adminjson.PeerRequest{
		PeerID: peerID,
	}
	res := &adminjson.PeerResponse{}
	return cl.CallMethod(ctx, string(adminjson.MethodRemovePeer), cmd, res)
}

// ListPeers lists all peers in the node's whitelist.
func (cl *Client) ListPeers(ctx context.Context) ([]string, error) {
	cmd := &adminjson.ListPeersRequest{}
	res := &adminjson.ListPeersResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodListPeers), cmd, res)
	if err != nil {
		return nil, err
	}
	return res.Peers, err
}

// BlacklistPeer adds a peer to the node's blacklist.
func (cl *Client) BlacklistPeer(ctx context.Context, peerID string, reason string, duration time.Duration) error {
	// Convert time.Duration to string format for JSON transport
	var durationStr string
	if duration > 0 {
		durationStr = duration.String()
	}

	cmd := &adminjson.BlacklistPeerRequest{
		PeerID:   peerID,
		Reason:   reason,
		Duration: durationStr,
	}
	res := &adminjson.BlacklistPeerResponse{}
	return cl.CallMethod(ctx, string(adminjson.MethodBlacklistPeer), cmd, res)
}

// RemoveBlacklistedPeer removes a peer from the node's blacklist.
func (cl *Client) RemoveBlacklistedPeer(ctx context.Context, peerID string) error {
	cmd := &adminjson.RemoveBlacklistedPeerRequest{
		PeerID: peerID,
	}
	res := &adminjson.RemoveBlacklistedPeerResponse{}
	return cl.CallMethod(ctx, string(adminjson.MethodRemoveBlacklistedPeer), cmd, res)
}

// ListBlacklistedPeers lists all peers in the node's blacklist.
func (cl *Client) ListBlacklistedPeers(ctx context.Context) ([]*adminTypes.BlacklistEntry, error) {
	cmd := &adminjson.ListBlacklistedPeersRequest{}
	res := &adminjson.ListBlacklistedPeersResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodListBlacklistedPeers), cmd, res)
	if err != nil {
		return nil, err
	}

	// Convert from JSON types to domain types
	entries := make([]*adminTypes.BlacklistEntry, len(res.BlacklistedPeers))
	for i, jsonEntry := range res.BlacklistedPeers {
		entry := &adminTypes.BlacklistEntry{
			PeerID:    jsonEntry.PeerID,
			Reason:    jsonEntry.Reason,
			Permanent: jsonEntry.Permanent,
		}

		// Parse timestamp with fallback to handle both RFC3339 and RFC3339Nano
		if jsonEntry.Timestamp != "" {
			if timestamp, err := time.Parse(time.RFC3339, jsonEntry.Timestamp); err == nil {
				entry.Timestamp = timestamp
			} else if timestamp, err := time.Parse(time.RFC3339Nano, jsonEntry.Timestamp); err == nil {
				entry.Timestamp = timestamp
			}
		}

		// Parse expiry time for temporary entries with fallback precision
		if !jsonEntry.Permanent && jsonEntry.ExpiresAt != "" {
			if expiresAt, err := time.Parse(time.RFC3339, jsonEntry.ExpiresAt); err == nil {
				entry.ExpiresAt = &expiresAt
			} else if expiresAt, err := time.Parse(time.RFC3339Nano, jsonEntry.ExpiresAt); err == nil {
				entry.ExpiresAt = &expiresAt
			}
		}

		entries[i] = entry
	}

	return entries, nil
}

// Create Resolution broadcasts a resolution to the network.
func (cl *Client) CreateResolution(ctx context.Context, resolution []byte, resolutionType string) (types.Hash, error) {
	cmd := &adminjson.CreateResolutionRequest{
		Resolution:     resolution,
		ResolutionType: resolutionType,
	}
	res := &userjson.BroadcastResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodCreateResolution), cmd, res)
	if err != nil {
		return types.Hash{}, err
	}
	return res.TxHash, nil
}

// ApproveResolution approves a resolution.
func (cl *Client) ApproveResolution(ctx context.Context, resolutionID *types.UUID) (types.Hash, error) {
	cmd := &adminjson.ApproveResolutionRequest{
		ResolutionID: resolutionID,
	}
	res := &userjson.BroadcastResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodApproveResolution), cmd, res)
	if err != nil {
		return types.Hash{}, err
	}
	return res.TxHash, nil
}

/* DeleteResolution deletes a resolution. This is disabled until the tx route is tested.
func (cl *Client) DeleteResolution(ctx context.Context, resolutionID *types.UUID) (types.Hash, error) {
	cmd := &adminjson.DeleteResolutionRequest{
		ResolutionID: resolutionID,
	}
	res := &userjson.BroadcastResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodDeleteResolution), cmd, res)
	if err != nil {
		return nil, err
	}
	return res.TxHash, nil
}*/

func (cl *Client) ResolutionStatus(ctx context.Context, resolutionID *types.UUID) (*types.PendingResolution, error) {
	cmd := &adminjson.ResolutionStatusRequest{
		ResolutionID: resolutionID,
	}
	res := &adminjson.ResolutionStatusResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodResolutionStatus), cmd, res)
	if err != nil {
		return nil, err
	}
	return res.Status, nil
}

func (cl *Client) BlockExecStatus(ctx context.Context) (*adminTypes.BlockExecutionStatus, error) {
	cmd := &adminjson.BlockExecStatusRequest{}
	res := &adminjson.BlockExecStatusResponse{}
	err := cl.CallMethod(ctx, string(adminjson.MethodBlockExecStatus), cmd, res)
	if err != nil {
		return nil, err
	}
	return res.Status, nil
}

func (cl *Client) AbortBlockExecution(ctx context.Context, height int64, discardTxs []string) error {
	cmd := &adminjson.AbortBlockExecRequest{
		Height: height,
		Txs:    discardTxs,
	}
	res := &adminjson.AbortBlockExecResponse{}
	return cl.CallMethod(ctx, string(adminjson.MethodAbortBlockExecution), cmd, res)
}
