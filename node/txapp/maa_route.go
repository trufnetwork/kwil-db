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
//   - The MAA must be a known, joined instance (created by maa_join).
//   - The OUTER signer must be the rule's restricted address (the agent) OR the
//     instance's unrestricted address (the owner); otherwise the signer has no
//     authority over this MAA. The signer is read WHILE @caller is still the
//     signer's own identity, before any rewrite.
//   - The inner (namespace, action) must be in the rule's allow-list. This holds
//     for BOTH roles: the unrestricted owner, too, acts as the MAA only through
//     allow-listed actions. Raw value-moving primitives are never allow-listed,
//     so neither role can move funds out via an allow-listed action; the
//     restricted role's hard no-exit guarantee at any depth is the erc20 token
//     boundary (see below).
//   - EXCEPTION — the dedicated owner-exit (withdrawal) actions are role-gated
//     INSTEAD of allow-list-gated: the UNRESTRICTED owner may always run them,
//     whether or not a rule lists them (rules are immutable, so an
//     allow-list-bound exit would permanently lock an owner out of their own
//     funds the moment a rule forgot to include it — the owner's control of
//     their funds must not depend on how well a rule was curated), and the
//     RESTRICTED key may never run them, not even when a rule lists them
//     (withdrawing is the owner's act).
//   - When the signer is the RESTRICTED key, the child context carries
//     TxContext.MAARestricted, which the erc20 token boundary checks at ANY
//     call depth to reject out-movement of the MAA's funds (transfer/bridge)
//     and privileged token ops (issue/lock_admin). The allow-list alone
//     cannot give that guarantee: it sees only the top-level action name.
//     Nor can the top-level call: it blocks only a BARE SYSTEM target —
//     a SYSTEM precompile wrapped inside an action body runs in a subscope
//     and is not stopped by the SYSTEM gate.
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
	// ACTIVATION CHOKEPOINT: MAAExec is height-gated by the
	// maa_activation_height network parameter, mirroring the
	// MigrationStatus guards in transferRoute.PreTx. The mempool applies
	// the same gate at admission (applyTransaction), keeping pre-activation
	// transactions out of blocks entirely; this execution-time check makes
	// a block that nonetheless carries one fail deterministically on every
	// upgraded node.
	if code, err := maaExecActivationGate(ctx); err != nil {
		return code, err
	}

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
	//    maa_get_instance JOINs the instance to its rule (rule-store getter); a
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
	// The role decides the no-exit flag set on the child context in step 4.

	// 3) Gate the inner action. The dedicated owner-exit (withdrawal) actions are
	//    role-gated INSTEAD of allow-list-gated; everything else must be in the
	//    rule's allow-list, for both roles.
	if d.isOwnerExitAction() {
		// Rejecting the restricted key here is defense-in-depth — even reached
		// through a wrapper action, its exit legs are stopped at the erc20 token
		// boundary by MAARestricted — but failing fast, before re-entry, gives a
		// clear error with zero side effects. The unrestricted owner proceeds to
		// re-entry without an allow-list test: the owner can always exit.
		if role == "restricted" {
			return types.CodeInvalidSender, "", fmt.Errorf(
				"action %s.%s withdraws the agent wallet's funds and is reserved for the unrestricted owner of MAA 0x%x",
				d.namespace, d.action, d.maaAddress)
		}
	} else {
		// Enforce the allow-list (applies to both roles). The getter orders rows
		// deterministically; we only test membership, so there is no map iteration
		// or order dependence in the consensus path.
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
	}

	// 4) Re-enter the engine AS the MAA. Clone the tx context and rewrite @caller
	//    to the MAA's checksummed address (the same format a real signer's
	//    identifier takes). The call is top-level, which rejects a bare SYSTEM
	//    target — but SYSTEM precompiles wrapped inside an action body run in
	//    subscopes and ARE reachable, so the restricted role's hard no-exit
	//    guarantee is the MAARestricted flag, enforced at the erc20 token
	//    boundary at any call depth. The flag is set ONLY on the child
	//    context: the getters above ran under the outer signer's unflagged
	//    context, and the unrestricted owner's executions stay unflagged so
	//    the owner's withdrawal flow keeps working.
	childTx := *ctx
	childTx.Caller = ethcommon.BytesToAddress(d.maaAddress).Hex()
	childTx.MAARestricted = role == "restricted"
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

// maaExecActivationGate rejects MAAExec until the network's scheduled
// activation height, read from the consensus-agreed maa_activation_height
// network parameter. Zero means MAA was never activated on this network;
// a missing context is treated the same way — the gate fails closed. The
// wrapped ErrUnknownPayloadType makes the rejection read (and broadcast-map,
// via BroadcastErrorToCode) like the route does not exist, which is exactly
// what a pre-MAA binary reports for this payload type.
func maaExecActivationGate(ctx *common.TxContext) (types.TxCode, error) {
	if ctx == nil || ctx.BlockContext == nil || ctx.BlockContext.ChainContext == nil ||
		ctx.BlockContext.ChainContext.NetworkParameters == nil {
		return types.CodeInvalidTxType, fmt.Errorf("%w: maa_exec activation height unavailable", types.ErrUnknownPayloadType)
	}
	activation := ctx.BlockContext.ChainContext.NetworkParameters.MAAActivationHeight
	if activation == 0 {
		return types.CodeInvalidTxType, fmt.Errorf("%w: maa_exec is not activated on this network", types.ErrUnknownPayloadType)
	}
	if ctx.BlockContext.Height < activation {
		return types.CodeInvalidTxType, fmt.Errorf("%w: maa_exec activates at height %d, current height %d",
			types.ErrUnknownPayloadType, activation, ctx.BlockContext.Height)
	}
	return 0, nil
}

// isOwnerExitAction reports whether the requested inner action is one of the
// dedicated owner-exit (withdrawal) actions in the engine's default namespace.
// These move the agent wallet's funds out with the agreed commission and are
// role-gated rather than allow-list-gated (see the type doc). The names are
// normalized with the SAME strings.ToLower the engine applies when resolving a
// Call, so any spelling that would execute a withdrawal action is classified as
// one — an exact-case test here could be dodged by a case variant. The list
// must stay in sync with the dedicated withdrawal actions the network's
// migrations define.
func (d *maaExecRoute) isOwnerExitAction() bool {
	if strings.ToLower(d.namespace) != engine.DefaultNamespace {
		return false
	}
	action := strings.ToLower(d.action)
	return action == "maa_withdraw" || action == "maa_bridge_out"
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
