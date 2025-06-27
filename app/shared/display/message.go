package display

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trufnetwork/kwil-db/core/types"
)

// TxHashAndExecResponse is meant to combine the "tx_hash" marshalling of
// RespTxHash with a RespTxQuery in an "exec_result" field.
type TxHashAndExecResponse struct {
	Res *types.TxQueryResponse
}

// NewTxHashAndExecResponse makes a TxHashAndExecResponse from a TcTxQueryResponse.
func NewTxHashAndExecResponse(resp *types.TxQueryResponse) *TxHashAndExecResponse {
	return &TxHashAndExecResponse{
		Res: resp,
	}
}

func (h *TxHashAndExecResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.Res)
}

func (h *TxHashAndExecResponse) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &h.Res)
}

// MarshalText deduplicates the tx hash for a compact readable output, unlike
// the JSON marshalling that is meant to be a composition of both RespTxHash and
// RespTxQuery.
func (h TxHashAndExecResponse) MarshalText() ([]byte, error) {
	return []byte(formatTxQueryResponseToText(h.Res)), nil
}

var _ MsgFormatter = (*TxHashAndExecResponse)(nil)
var _ MsgFormatter = (*RespTxQuery)(nil)

type TxHashResponse struct {
	TxHash types.Hash `json:"tx_hash"`
}

// RespTxHash is used to represent a transaction hash in cli
// NOTE: it's different from types.TxHash, this is for display purpose.
// It implements the MsgFormatter interface
type RespTxHash types.Hash

func (h RespTxHash) Hex() string {
	return hex.EncodeToString(h[:])
}

func (h RespTxHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(TxHashResponse{TxHash: types.Hash(h)})
}

func (h RespTxHash) MarshalText() ([]byte, error) {
	return []byte("TxHash: " + h.Hex()), nil
}

func (h *RespTxHash) UnmarshalJSON(b []byte) error {
	var res TxHashResponse
	if err := json.Unmarshal(b, &res); err != nil {
		return err
	}
	*h = RespTxHash(res.TxHash)
	return nil
}

// RespString is used to represent a string in cli
// It implements the MsgFormatter interface
type RespString string

func (s RespString) MarshalJSON() ([]byte, error) {
	return []byte(`"` + string(s) + `"`), nil
}

func (s RespString) MarshalText() ([]byte, error) {
	return []byte(s), nil
}

// RespResolutionBroadcast is used to represent the result of creating a new
// resolution with the CLI. This includes the transaction hash and the ID of the
// resolution as computed from the resolution body and resolution type. This
// does not mean it is a unique resolution, and it is important to check that
// the transaction referenced by the returned hash was executed without error.
type RespResolutionBroadcast struct {
	TxHash types.Hash `json:"tx_hash"`
	ID     types.UUID `json:"id"`
}

func (r *RespResolutionBroadcast) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf(`Transaction Hash: %s
Resolution ID: %s`, r.TxHash, r.ID)), nil
}

func (r *RespResolutionBroadcast) MarshalJSON() ([]byte, error) {
	type alias RespResolutionBroadcast
	return json.Marshal((*alias)(r))
}

// RespTxQuery is used to represent a transaction response in cli
type RespTxQuery struct {
	Msg     *types.TxQueryResponse
	WithRaw bool
}

func (r *RespTxQuery) MarshalJSON() ([]byte, error) {
	out := &struct {
		Hash   string             `json:"hash"` // HEX
		Height int64              `json:"height"`
		Tx     *types.Transaction `json:"tx"`
		Result types.TxResult     `json:"tx_result"`
		Raw    string             `json:"raw,omitempty"`
		Warn   string             `json:"warning,omitempty"`
	}{
		Hash:   r.Msg.Hash.String(),
		Height: r.Msg.Height,
		Tx:     r.Msg.Tx,
	}
	if r.Msg.Result != nil {
		out.Result = *r.Msg.Result
	}

	// Always try to serialize to verify hash, but only show raw if requested.
	if r.Msg.Tx != nil {
		raw := r.Msg.Tx.Bytes()
		if r.WithRaw {
			out.Raw = hex.EncodeToString(raw)
		}
		hash := types.HashBytes(raw)
		if hash != r.Msg.Hash {
			out.Warn = fmt.Sprintf("HASH MISMATCH: requested %s; received %s",
				r.Msg.Hash, hash)
		}
	}
	return json.Marshal(out)
}

func heightStatus(res *types.TxQueryResponse) string {
	status := "failed"
	if res.Height == -1 {
		status = "pending"
	} else if res.Result.Code == uint32(types.CodeOk) {
		status = "success"
	}
	return status
}

func (r *RespTxQuery) MarshalText() ([]byte, error) {
	msg := formatTxQueryResponseToText(r.Msg)

	// Always try to serialize to verify hash, but only show raw if requested.
	if r.Msg.Tx == nil {
		return []byte(msg), nil
	}

	raw := r.Msg.Tx.Bytes()

	if r.WithRaw {
		msg += "\nRaw: " + hex.EncodeToString(raw)
	}
	hash := types.HashBytes(raw)
	if hash != r.Msg.Hash {
		msg += fmt.Sprintf("\nWARNING! HASH MISMATCH:\n\tRequested %s\n\tReceived  %s",
			r.Msg.Hash, hash)
	}

	return []byte(msg), nil
}

func formatTxQueryResponseToText(r *types.TxQueryResponse) string {
	msg := fmt.Sprintf(`Transaction ID: %s
Status: %s
Height: %d`,
		r.Hash.String(),
		heightStatus(r),
		r.Height,
	)

	// result can be nil if it is still pending
	if r.Result != nil && r.Result.Log != "" {
		msg += "\nLogs:"
		msg += "\n  " + strings.ReplaceAll(r.Result.Log, "\n", "\n  ")
	}

	return msg
}
