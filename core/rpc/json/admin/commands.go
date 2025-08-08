// Package adminjson defines the admin service's method names, request objects,
// and response objects.
package adminjson

import (
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
)

type StatusRequest struct{}
type PeersRequest struct{}
type GetConfigRequest struct{}
type ApproveRequest struct {
	PubKey     []byte         `json:"pubkey"`
	PubKeyType crypto.KeyType `json:"pubkey_type"`
}
type JoinRequest struct{}
type LeaveRequest struct{}
type RemoveRequest struct {
	PubKey     []byte         `json:"pubkey"`
	PubKeyType crypto.KeyType `json:"pubkey_type"`
}
type JoinStatusRequest struct {
	PubKey     []byte         `json:"pubkey"`
	PubKeyType crypto.KeyType `json:"pubkey_type"`
}
type ListValidatorsRequest struct{}
type ListJoinRequestsRequest struct{}

type PeerRequest struct {
	PeerID string `json:"peerid"`
}

type ListPeersRequest struct{}

type BlacklistPeerRequest struct {
	PeerID   string `json:"peerid"`
	Reason   string `json:"reason,omitempty"`   // optional, defaults to "manual"
	Duration string `json:"duration,omitempty"` // optional, format: "1h30m", empty = permanent
}

type RemoveBlacklistedPeerRequest struct {
	PeerID string `json:"peerid"`
}

type ListBlacklistedPeersRequest struct{}

type CreateResolutionRequest struct {
	Resolution     []byte `json:"resolution"`
	ResolutionType string `json:"resolution_type"`
}

type ApproveResolutionRequest struct {
	ResolutionID *types.UUID `json:"resolution_id"` // Id is the resolution ID
}

// type DeleteResolutionRequest struct {
// 	ResolutionID *types.UUID `json:"resolution_id"` // Id is the resolution ID
// }

type ResolutionStatusRequest struct {
	ResolutionID *types.UUID `json:"resolution_id"` // Id is the resolution ID
}

type BlockExecStatusRequest struct{}

type AbortBlockExecRequest struct {
	Height int64    `json:"height"`
	Txs    []string `json:"txs"`
}

type PromoteRequest struct {
	PubKey     []byte         `json:"pubkey"`
	PubKeyType crypto.KeyType `json:"pubkey_type"`
	Height     int64          `json:"height"`
}
