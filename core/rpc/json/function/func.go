package function

import (
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	"github.com/trufnetwork/kwil-db/core/types"
)

// Methods

const (
	MethodVersion   jsonrpc.Method = "function.version"
	MethodVerifySig jsonrpc.Method = "function.verify_sig"
)

// Requests

type VerifySignatureRequest struct {
	Signature *TxSignature   `json:"signature,omitempty"`
	Sender    types.HexBytes `json:"sender,omitempty"`
	Msg       []byte         `json:"msg,omitempty"`
}

type TxSignature struct {
	SignatureBytes []byte `json:"sig,omitempty"`
	SignatureType  string `json:"type,omitempty"`
}

// Responses

type VerifySignatureResponse struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

type HealthResponse struct {
	Healthy bool   `json:"healthy"`
	Version string `json:"version"`
}
