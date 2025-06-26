package types

import (
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto"
)

// This file contains the messages exchanged between the consensus engine and the block processor.

type BlockExecRequest struct {
	Height   int64
	Block    *Block
	BlockID  Hash
	Proposer crypto.PublicKey
}

type BlockExecResult struct {
	TxResults        []TxResult
	AppHash          Hash
	ValidatorUpdates []*Validator
	ParamUpdates     ParamUpdates
}

type CommitRequest struct {
	Height  int64
	AppHash Hash
	Syncing bool
}

type BlockExecutionStatus struct {
	StartTime time.Time
	EndTime   time.Time
	Height    int64
	TxIDs     []Hash
	TxStatus  map[Hash]bool
}
