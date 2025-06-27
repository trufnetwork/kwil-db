package adminjson

import (
	"github.com/trufnetwork/kwil-db/core/types"
	adminTypes "github.com/trufnetwork/kwil-db/core/types/admin"
)

// type StatusResponse = adminTypes.Status

type StatusResponse struct {
	Node      *NodeInfo             `json:"node,omitempty"`
	Sync      *SyncInfo             `json:"sync,omitempty"`
	Validator *Validator            `json:"validator,omitempty"`
	Migration *types.MigrationState `json:"migration,omitempty"`
}

type NodeInfo = adminTypes.NodeInfo

// type NodeInfo struct {
// 	adminTypes.NodeInfo
// 	RPCAddr string `json:"rpc_addr"`
// }

// type SyncInfo = adminTypes.SyncInfo
// type Validator = adminTypes.ValidatorInfo
type Validator = types.Validator

// type NodeInfo struct {
// 	ChainID         string `json:"chain_id,omitempty"`
// 	NodeName        string `json:"node_name,omitempty"`
// 	NodeID          string `json:"node_id,omitempty"`
// 	ProtocolVersion uint64 `json:"protocol_version,omitempty"`
// 	AppVersion      uint64 `json:"app_version,omitempty"`
// 	BlockVersion    uint64 `json:"block_version,omitempty"`
// 	ListenAddr      string `json:"listen_addr,omitempty"`
// 	RPCAddr         string `json:"rpc_addr,omitempty"`
// }

// SyncInfo is modified from adminTypes to have BestBlockTime be a unix epoch in
// milliseconds.
type SyncInfo struct {
	AppHash         types.Hash `json:"app_hash,omitempty"`
	BestBlockHash   types.Hash `json:"best_block_hash,omitempty"`
	BestBlockHeight int64      `json:"best_block_height,omitempty"`
	BestBlockTime   int64      `json:"best_block_time,omitempty"` // epoch *milliseconds*
	Syncing         bool       `json:"syncing,omitempty"`
}

// HealthResponse is the health check response.
type HealthResponse struct {
	Version       string         `json:"version"`
	Healthy       bool           `json:"healthy"`
	PubKey        types.HexBytes `json:"pubkey"`
	NumValidators int            `json:"num_validators"`
}

type PeersResponse struct {
	Peers []*adminTypes.PeerInfo `json:"peers"`
}

// type Peer = adminTypes.PeerInfo

// type Peer struct {
// 	Node       *NodeInfo `json:"node,omitempty"`
// 	Inbound    bool      `json:"inbound,omitempty"`
// 	RemoteAddr string    `json:"remote_addr,omitempty"`
// }

type JoinStatusResponse struct {
	JoinRequest *PendingJoin `json:"join_request,omitempty"`
}

type PendingJoin = types.JoinRequest

// type PendingJoin struct {
// 	Candidate []byte   `json:"candidate,omitempty"`
// 	Power     int64    `json:"power,omitempty"`
// 	ExpiresAt int64    `json:"expires_at,omitempty"`
// 	Board     [][]byte `json:"board,omitempty"`    // all validators
// 	Approved  []bool   `json:"approved,omitempty"` // whether each validator has approved
// }

type ListValidatorsResponse struct {
	Validators []*Validator `json:"validators,omitempty"`
}

type ListJoinRequestsResponse struct {
	JoinRequests []*PendingJoin `json:"join_requests,omitempty"`
}

type GetConfigResponse struct {
	Config []byte `json:"config,omitempty"`
}

type PeerResponse struct{}

// List of peers in the node's whitelist.
// These are the peers the node will accept connections from.
type ListPeersResponse struct {
	Peers []string `json:"peers,omitempty"`
}

type ResolutionStatusResponse struct {
	Status *types.PendingResolution `json:"status,omitempty"`
}

type BlockExecStatusResponse struct {
	Status *adminTypes.BlockExecutionStatus `json:"status,omitempty"`
}

type AbortBlockExecResponse struct{}

type PromoteResponse struct{}
