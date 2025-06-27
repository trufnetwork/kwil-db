package userjson

import (
	"github.com/trufnetwork/kwil-db/core/types"
)

// This file defines the structured parameter types used in the "params" field
// of the request. Many of them build on or alias the types in core/types and to
// avoid duplication and make conversion nearly transparent. Those types MUST
// remain json tagged. If the RPC API must diverge from the Go APIs that use
// those types, they can be cloned and versioned here.

// NOTE: Any field of type []byte will marshal to/from base64 strings. This is
// established by the convention of the encoding/json standard library packages.
// For values that we would like to marshal as hexadecimal, a type such as
// HexBytes should be used, or the field should be a string and converted by the
// application. For instance, "owner" would be friendlier as hexadecimal so that
// it can look like an address if the signature type permits it (e.g. secp256k1).

type VersionRequest struct{}

// SchemaRequest contains the request parameters for MethodSchema.
type SchemaRequest struct {
	Namespace string `json:"namespace"`
}

// AccountRequest contains the request parameters for MethodAccount.
type AccountRequest struct {
	ID     *types.AccountID `json:"id" desc:"account identifier"`
	Status *AccountStatus   `json:"status,omitempty" desc:"blockchain status (confirmed or unconfirmed)"` // Mapped to URL query parameter `status`.
}

type NumAccountsRequest struct{}

// AccountStatus is the type used to enumerate the different account status
// options recognized in AccountRequest.
type AccountStatus = types.AccountStatus

// These are the recognized AccountStatus values used with AccountRequest.
// AccountStatusLatest reflects confirmed state, while AccountStatusPending
// includes changes in mempool.
var (
	AccountStatusLatest  = types.AccountStatusLatest
	AccountStatusPending = types.AccountStatusPending
)

// BroadcastRequest contains the request parameters for MethodBroadcast.
type BroadcastRequest struct {
	Tx   *types.Transaction `json:"tx"`
	Sync *BroadcastSync     `json:"sync,omitempty"`
}

// BroadcastSync is the type used to enumerate the broadcast request
// synchronization options available to BroadcastRequest.
type BroadcastSync uint8

// These are the recognized BroadcastSync values used with BroadcastRequest.
const (
	// BroadcastSyncAccept ensures the transaction is accepted to mempool before
	// responding. This is the default behavior.
	BroadcastSyncAccept BroadcastSync = 0
	// BroadcastSyncCommit will wait for the transaction to be included in a
	// block.
	BroadcastSyncCommit BroadcastSync = 1
)

// CallRequest contains the request parameters for MethodCall.
type CallRequest = types.CallMessage

// AuthenticatedQueryRequest contains the request parameters for MethodAuthenticatedQuery.
type AuthenticatedQueryRequest = types.AuthenticatedQuery

// ChainInfoRequest contains the request parameters for MethodChainInfo.
type ChainInfoRequest struct{}

// ListDatabasesRequest contains the request parameters for MethodDatabases.
type ListDatabasesRequest struct {
	Owner types.HexBytes `json:"owner,omitempty"`
}

// PingRequest contains the request parameters for MethodPing.
type PingRequest struct {
	Message string `json:"message"`
}

// EstimatePriceRequest contains the request parameters for MethodPrice.
type EstimatePriceRequest struct {
	Tx *types.Transaction `json:"tx"`
}

// QueryRequest contains the request parameters for MethodQuery.
type QueryRequest struct {
	Query  string                         `json:"query"`
	Params map[string]*types.EncodedValue `json:"params"`
}

// TxQueryRequest contains the request parameters for MethodTxQuery.
type TxQueryRequest struct {
	TxHash types.Hash `json:"tx_hash"`
}

// LoadChangesetsRequest contains the request parameters for MethodLoadChangesets.
type ChangesetMetadataRequest struct {
	Height int64 `json:"height"`
}

type ChangesetRequest struct {
	Height int64 `json:"height"`
	Index  int64 `json:"index"`
}

type MigrationSnapshotChunkRequest struct {
	Height     uint64 `json:"height"`
	ChunkIndex uint32 `json:"chunk_index"`
}

type MigrationMetadataRequest struct{}
type ListMigrationsRequest struct{}

type ListPendingConsensusUpdatesRequest struct{}

type MigrationStatusRequest struct{}

type ChallengeRequest struct{}
type HealthRequest struct{}
