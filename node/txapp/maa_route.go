package txapp

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/consensus"
	"github.com/trufnetwork/kwil-db/node/engine"
)

// maaExecRoute handles PayloadTypeMAAExec: it lets an authorized signer run a
// single allow-listed action AS a Modular Agent Address (MAA), with @caller
// rewritten to the MAA for the inner call.
//
// Security model ("operate the wallet within limits"):
//   - The MAA must be a known, joined instance (created by maa_join, issue #1).
//   - The OUTER signer must be the rule's restricted address (the agent) OR the
//     instance's unrestricted address (the owner); otherwise the signer has no
//     authority over this MAA. The signer is read WHILE @caller is still the
//     signer's own identity, before any rewrite.
//   - The inner (namespace, action) must be in the rule's allow-list. This holds
//     for BOTH roles (plan lifecycle 4a: the unrestricted owner acts "as the MAA
//     [for] any allow-listed action"). Raw value-moving primitives are never
//     allow-listed, so neither role can move funds out via this route. The
//     owner's withdraw-with-commission is a separate action (issue #4); the
//     restricted role's hard no-exit guarantee at any depth is the token
//     boundary (issue #3).
//   - The inner call is TOP-LEVEL, so SYSTEM-only ops (mint/issue/lock_admin/
//     unlock) stay blocked even though @caller is now the MAA.
//
// Gas/nonce are paid by the OUTER signer; the MAA never pays gas. The MAA's
// identity is assumed only for the duration of the inner action.
type maaExecRoute struct {
	maaAddress []byte
	namespace  string
	action     string
	args       []any
}

var _ consensus.Route = (*maaExecRoute)(nil)

func (d *maaExecRoute) Name() string {
	return types.PayloadTypeMAAExec.String()
}

func (d *maaExecRoute) Price(ctx context.Context, app *common.App, tx *types.Transaction) (*big.Int, error) {
	// The inner call does the real work, so price it like an action execution.
	return big.NewInt(2000000000000000), nil
}

func (d *maaExecRoute) PreTx(ctx *common.TxContext, svc *common.Service, tx *types.Transaction) (types.TxCode, error) {
	// ACTIVATION CHOKEPOINT (issue #7): once fork-height infrastructure lands,
	// reject MAAExec before its activation height here, mirroring the
	// MigrationStatus guards in transferRoute.PreTx. Until then availability is
	// "this binary is deployed", which the coordinated rollout (#7) flag-days.

	payload := &types.MAAExec{}
	if err := payload.UnmarshalBinary(tx.Body.Payload); err != nil {
		return types.CodeEncodingError, err
	}
	if len(payload.MAAAddress) != 20 {
		return types.CodeEncodingError, fmt.Errorf("maa_address must be 20 bytes, got %d", len(payload.MAAAddress))
	}
	if payload.Action == "" {
		return types.CodeEncodingError, fmt.Errorf("inner action must not be empty")
	}

	d.maaAddress = payload.MAAAddress
	d.namespace = payload.Namespace
	if d.namespace == "" {
		d.namespace = engine.DefaultNamespace
	}
	d.action = payload.Action

	// Decode the inner-action arguments once (mirrors executeActionRoute.PreTx).
	d.args = make([]any, len(payload.Arguments))
	for i, val := range payload.Arguments {
		v, err := val.Decode()
		if err != nil {
			return types.CodeEncodingError, err
		}
		d.args[i] = v
	}
	return 0, nil
}

func (d *maaExecRoute) InTx(ctx *common.TxContext, app *common.App, tx *types.Transaction) (types.TxCode, string, error) {
	// The outer signer's identity, as raw 20 address bytes. Compared by bytes (not
	// strings) because the engine identifier is EIP-55 checksummed while the rule
	// store emits lowercase hex — a string compare would be a consensus bug.
	if !ethcommon.IsHexAddress(ctx.Caller) {
		return types.CodeInvalidSender, "", fmt.Errorf("maa_exec requires an ethereum-address signer, got %q", ctx.Caller)
	}
	signer := ethcommon.HexToAddress(ctx.Caller).Bytes()

	// 1) Resolve the MAA instance and its rule's restricted/unrestricted keys.
	//    maa_get_instance JOINs the instance to its rule (issue #1 getter); a
	//    missing row means this address was never joined -> not a known MAA.
	var ruleID, restricted, unrestricted []byte
	found := false
	res, err := app.Engine.Call(makeEngineCtx(ctx), app.DB, engine.DefaultNamespace, "maa_get_instance",
		[]any{d.maaAddress}, func(r *common.Row) error {
			// columns: maa_address, rule_id, restricted_addr, unrestricted_addr, created_at
			var derr error
			if ruleID, derr = hexColumnToBytes(r, 1); derr != nil {
				return derr
			}
			if restricted, derr = hexColumnToBytes(r, 2); derr != nil {
				return derr
			}
			if unrestricted, derr = hexColumnToBytes(r, 3); derr != nil {
				return derr
			}
			found = true
			return nil
		})
	if err != nil {
		return codeForEngineError(err), "", err
	}
	if res.Error != nil {
		return types.CodeUnknownError, "", res.Error
	}
	if !found {
		return types.CodeInvalidSender, "", fmt.Errorf("unknown MAA 0x%x: no joined instance", d.maaAddress)
	}

	// 2) Authorize the signer and determine its role (restricted vs unrestricted).
	var role string
	switch {
	case bytes.Equal(signer, restricted):
		role = "restricted"
	case bytes.Equal(signer, unrestricted):
		role = "unrestricted"
	default:
		return types.CodeInvalidSender, "", fmt.Errorf(
			"signer 0x%x is neither the restricted nor the unrestricted key of MAA 0x%x", signer, d.maaAddress)
	}
	_ = role // role is recorded/used by issues #3/#4; allow-list below applies to both.

	// 3) Enforce the allow-list (applies to both roles). The getter orders rows
	//    deterministically; we only test membership, so there is no map iteration
	//    or order dependence in the consensus path.
	allowed := false
	res, err = app.Engine.Call(makeEngineCtx(ctx), app.DB, engine.DefaultNamespace, "maa_get_allowed_actions",
		[]any{ruleID}, func(r *common.Row) error {
			ns, _ := r.Values[0].(string)
			act, _ := r.Values[1].(string)
			if ns == d.namespace && act == d.action {
				allowed = true
			}
			return nil
		})
	if err != nil {
		return codeForEngineError(err), "", err
	}
	if res.Error != nil {
		return types.CodeUnknownError, "", res.Error
	}
	if !allowed {
		return types.CodeInvalidSender, "", fmt.Errorf(
			"action %s.%s is not in the allow-list for MAA 0x%x", d.namespace, d.action, d.maaAddress)
	}

	// 4) Re-enter the engine AS the MAA. Clone the tx context and rewrite @caller
	//    to the MAA's checksummed address (the same format a real signer's
	//    identifier takes). This is a TOP-LEVEL call, so the SYSTEM gate stays
	//    active and SYSTEM-only ops remain unreachable.
	childTx := *ctx
	childTx.Caller = ethcommon.BytesToAddress(d.maaAddress).Hex()
	childEngineCtx := &common.EngineContext{TxContext: &childTx, OverrideAuthz: false}

	var logs string
	res, err = app.Engine.Call(childEngineCtx, app.DB, d.namespace, d.action, d.args, func(r *common.Row) error {
		return nil // results are discarded, like executeActionRoute
	})
	if res != nil && len(res.Logs) > 0 {
		logs = res.FormatLogs()
	}
	if err != nil {
		return codeForEngineError(err), logs, err
	}
	if res.Error != nil {
		return types.CodeUnknownError, logs, res.Error
	}
	return 0, logs, nil
}

// hexColumnToBytes reads a "0x"-prefixed hex string column from a getter row and
// decodes it to raw bytes. The MAA getters project addresses/ids as
// '0x' || encode(col,'hex'), so this is the inverse.
func hexColumnToBytes(r *common.Row, idx int) ([]byte, error) {
	if idx >= len(r.Values) {
		return nil, fmt.Errorf("row has %d columns, want index %d", len(r.Values), idx)
	}
	s, ok := r.Values[idx].(string)
	if !ok {
		return nil, fmt.Errorf("column %d is %T, want a hex string", idx, r.Values[idx])
	}
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}
