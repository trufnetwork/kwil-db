// Package types contains the type used by the administrative RPC client and
// servers.
package types

import (
	"time"

	"github.com/trufnetwork/kwil-db/core/types"
)

// NodeInfo describes the administered node.
type NodeInfo struct {
	ChainID    string `json:"chain_id"`
	NodeID     string `json:"node_id"`
	AppVersion uint64 `json:"app_ver"`
	ListenAddr string `json:"listen_addr"`
	Role       string `json:"role"`
	RPCAddr    string `json:"rpc_addr"`
}

// SyncInfo describes the sync state of a node.
type SyncInfo struct {
	AppHash         types.Hash `json:"app_hash"`
	BestBlockHash   types.Hash `json:"best_block_hash"`
	BestBlockHeight int64      `json:"best_block_height"`
	BestBlockTime   time.Time  `json:"best_block_time"`

	Syncing bool `json:"syncing"`
}

// ValidatorInfo describes a validator node.
type ValidatorInfo = types.Validator

// Status includes a comprehensive summary of a nodes status, including if the
// service is running, its best block and if it is syncing, its identity on
// the network, and the node's validator identity if it is one. Note that our
// validator is part of the node rather than an external signer.
type Status struct {
	Node      *NodeInfo      `json:"node"`
	Sync      *SyncInfo      `json:"sync"`
	Validator *ValidatorInfo `json:"validator"`
}

// PeerInfo describes a connected peer node.
type PeerInfo struct {
	RemoteAddr string `json:"remote_addr"`
	LocalAddr  string `json:"local_addr"`
	Inbound    bool   `json:"inbound"`
}

type MigrationInfo struct {
	Status        string `json:"status"`
	StartHeight   int64  `json:"start_height"`
	EndHeight     int64  `json:"end_height"`
	CurrentHeight int64  `json:"current_height"`
}

type BlockExecutionStatus struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Height    int64     `json:"height"`
	TxInfo    []*TxInfo `json:"tx_info"`
}

type TxInfo struct {
	ID     types.Hash `json:"id"`
	Status bool       `json:"status"`
}

// BlacklistEntry represents a blacklisted peer in the domain model
type BlacklistEntry struct {
	PeerID    string
	Reason    string
	Timestamp time.Time
	Permanent bool
	ExpiresAt *time.Time // nil for permanent blacklists
}
