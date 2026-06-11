package txapp

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// These tests exercise the consensus-critical decisions of maaExecRoute in
// isolation, against a fake engine: who may act as a MAA (role resolution by
// RAW BYTES, since identifiers are checksummed but the rule store emits
// lowercase hex), what they may run (the allow-list, plus the role-gated
// owner-exit actions that bypass it for the owner and reject the restricted
// key), and that the inner call is re-entered with @caller rewritten to the
// MAA. A real-engine end-to-end test (create_rule -> join -> maa_exec an
// order-book action) belongs in the node integration suite; here we pin the
// branch logic deterministically.

var (
	maaRestricted   = bytes.Repeat([]byte{0x11}, 20)
	maaUnrestricted = bytes.Repeat([]byte{0x22}, 20)
	maaAddr20       = bytes.Repeat([]byte{0x33}, 20)
	maaRuleID32     = bytes.Repeat([]byte{0x55}, 32)
	maaStranger     = bytes.Repeat([]byte{0x44}, 20)
)

func hexAddr0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

// fakeMAAEngine answers the two getter calls the route makes and captures the
// inner action call so the test can assert it ran as the MAA.
type fakeMAAEngine struct {
	// instance config; if instanceKnown is false, maa_get_instance returns no rows.
	instanceKnown bool
	ruleID        []byte
	restricted    []byte
	unrestricted  []byte
	// allow-list rows the rule exposes, as {namespace, action}.
	allow [][2]string

	// captured inner call
	innerCalled    bool
	innerCaller    string
	innerNamespace string
	innerAction    string
	innerArgs      []any
	// innerRestricted is TxContext.MAARestricted as seen by the inner action —
	// the no-exit flag the erc20 token boundary enforces.
	innerRestricted bool
	// getterRestricted records whether ANY of the route's own getter lookups
	// (maa_get_instance / maa_get_allowed_actions) ran with MAARestricted set.
	// They must not: they run under the outer signer's unflagged context.
	getterRestricted bool
}

func (f *fakeMAAEngine) Call(ctx *common.EngineContext, db sql.DB, namespace, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error) {
	switch action {
	case "maa_get_instance":
		f.getterRestricted = f.getterRestricted || ctx.TxContext.MAARestricted
		if f.instanceKnown {
			row := &common.Row{Values: []any{
				hexAddr0x(maaAddr20),      // 0 maa_address
				hexAddr0x(f.ruleID),       // 1 rule_id
				hexAddr0x(f.restricted),   // 2 restricted_addr
				hexAddr0x(f.unrestricted), // 3 unrestricted_addr
				int64(100),                // 4 created_at
			}}
			if err := resultFn(row); err != nil {
				return nil, err
			}
		}
		return &common.CallResult{}, nil
	case "maa_get_allowed_actions":
		f.getterRestricted = f.getterRestricted || ctx.TxContext.MAARestricted
		for _, a := range f.allow {
			row := &common.Row{Values: []any{a[0], a[1], nil}}
			if err := resultFn(row); err != nil {
				return nil, err
			}
		}
		return &common.CallResult{}, nil
	default:
		// the inner action, re-entered as the MAA
		f.innerCalled = true
		f.innerCaller = ctx.TxContext.Caller
		f.innerNamespace = namespace
		f.innerAction = action
		f.innerArgs = args
		f.innerRestricted = ctx.TxContext.MAARestricted
		return &common.CallResult{}, nil
	}
}

func (f *fakeMAAEngine) CallWithoutEngineCtx(ctx context.Context, db sql.DB, namespace, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error) {
	return &common.CallResult{}, nil
}
func (f *fakeMAAEngine) Execute(ctx *common.EngineContext, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error) error {
	return nil
}
func (f *fakeMAAEngine) ExecuteWithoutEngineCtx(ctx context.Context, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error) error {
	return nil
}

// runMAAExec builds the payload, decodes it via PreTx, and runs InTx against the
// fake engine. signer is the raw 20-byte address of the outer tx signer.
func runMAAExec(t *testing.T, eng *fakeMAAEngine, signer []byte, namespace, action string, args ...any) (types.TxCode, error) {
	t.Helper()

	encArgs := make([]*types.EncodedValue, len(args))
	for i, a := range args {
		ev, err := types.EncodeValue(a)
		require.NoError(t, err)
		encArgs[i] = ev
	}
	payloadBytes, err := (types.MAAExec{
		MAAAddress: maaAddr20,
		Namespace:  namespace,
		Action:     action,
		Arguments:  encArgs,
	}).MarshalBinary()
	require.NoError(t, err)

	tx := &types.Transaction{Body: &types.TransactionBody{Payload: payloadBytes}}
	ctx := maaActivatedTxContext(signer)
	app := &common.App{Engine: eng}

	route := &maaExecRoute{}
	if code, err := route.PreTx(ctx, nil, tx); err != nil {
		return code, err
	}
	code, _, err := route.InTx(ctx, app, tx)
	return code, err
}

// maaActivatedTxContext builds a TxContext whose network has MAAExec
// activated (maa_activation_height = 1, at height 1), so route tests
// exercise the post-activation behavior. signer is the raw 20-byte address
// of the outer tx signer.
func maaActivatedTxContext(signer []byte) *common.TxContext {
	return &common.TxContext{
		Ctx:    context.Background(),
		Caller: ethcommon.BytesToAddress(signer).Hex(), // checksummed, like a real signer
		BlockContext: &common.BlockContext{
			Height: 1,
			ChainContext: &common.ChainContext{
				NetworkParameters: &types.NetworkParameters{MAAActivationHeight: 1},
			},
		},
	}
}

func newKnownEngine() *fakeMAAEngine {
	return &fakeMAAEngine{
		instanceKnown: true,
		ruleID:        maaRuleID32,
		restricted:    maaRestricted,
		unrestricted:  maaUnrestricted,
		allow:         [][2]string{{"main", "ob_place_order"}},
	}
}

func TestMAAExecRoute_RestrictedRunsAllowlistedAction(t *testing.T) {
	eng := newKnownEngine()
	code, err := runMAAExec(t, eng, maaRestricted, "main", "ob_place_order", "0xabc")
	require.NoError(t, err)
	require.Equal(t, types.CodeOk, code)

	require.True(t, eng.innerCalled, "inner action must run")
	// @caller must be rewritten to the MAA (checksummed form of the 20-byte addr).
	assert.Equal(t, ethcommon.BytesToAddress(maaAddr20).Hex(), eng.innerCaller)
	// rewritten caller must decode back to the MAA's bytes.
	assert.True(t, bytes.Equal(ethcommon.HexToAddress(eng.innerCaller).Bytes(), maaAddr20))
	assert.Equal(t, "main", eng.innerNamespace)
	assert.Equal(t, "ob_place_order", eng.innerAction)
	require.Len(t, eng.innerArgs, 1)
	// The engine decodes a text arg to *string (nullable-scalar convention); the
	// route passes it through unchanged.
	gotArg, ok := eng.innerArgs[0].(*string)
	require.Truef(t, ok, "arg should decode to *string, got %T", eng.innerArgs[0])
	assert.Equal(t, "0xabc", *gotArg)

	// The restricted signer's inner execution must carry the no-exit flag the
	// token boundary enforces — and ONLY the inner execution; the route's own
	// getter lookups run under the outer signer's unflagged ctx.
	assert.True(t, eng.innerRestricted, "inner ctx must carry MAARestricted for the restricted signer")
	assert.False(t, eng.getterRestricted, "the route's getter lookups must run unflagged")
}

func TestMAAExecRoute_UnrestrictedOwnerAlsoLimitedToAllowlist(t *testing.T) {
	// The owner (unrestricted) may act as the MAA for allow-listed actions too.
	eng := newKnownEngine()
	code, err := runMAAExec(t, eng, maaUnrestricted, "main", "ob_place_order")
	require.NoError(t, err)
	require.Equal(t, types.CodeOk, code)
	require.True(t, eng.innerCalled)
	assert.Equal(t, ethcommon.BytesToAddress(maaAddr20).Hex(), eng.innerCaller)
	// The owner's execution must stay unflagged: the owner's withdrawal flow
	// moves funds out and must not trip the token boundary.
	assert.False(t, eng.innerRestricted, "the unrestricted owner's inner ctx must NOT carry MAARestricted")
}

func TestMAAExecRoute_DefaultsEmptyNamespaceToMain(t *testing.T) {
	eng := newKnownEngine()
	// Empty payload namespace must normalize to "main" for both the allow-list
	// check and the inner call.
	code, err := runMAAExec(t, eng, maaRestricted, "", "ob_place_order")
	require.NoError(t, err)
	require.Equal(t, types.CodeOk, code)
	require.True(t, eng.innerCalled)
	assert.Equal(t, "main", eng.innerNamespace)
}

func TestMAAExecRoute_UnknownMAARejected(t *testing.T) {
	eng := newKnownEngine()
	eng.instanceKnown = false // maa_get_instance returns no rows
	code, err := runMAAExec(t, eng, maaRestricted, "main", "ob_place_order")
	require.Error(t, err)
	assert.Equal(t, types.CodeInvalidSender, code)
	assert.False(t, eng.innerCalled, "inner action must NOT run for an unknown MAA")
}

func TestMAAExecRoute_UnauthorizedSignerRejected(t *testing.T) {
	eng := newKnownEngine()
	code, err := runMAAExec(t, eng, maaStranger, "main", "ob_place_order")
	require.Error(t, err)
	assert.Equal(t, types.CodeInvalidSender, code)
	assert.False(t, eng.innerCalled, "a non-restricted, non-unrestricted signer must be rejected")
}

func TestMAAExecRoute_NonAllowlistedActionRejected(t *testing.T) {
	eng := newKnownEngine()
	// erc20.transfer is the canonical exit primitive: it is NOT allow-listed, so
	// even the restricted agent cannot reach it through this route.
	code, err := runMAAExec(t, eng, maaRestricted, "main", "transfer")
	require.Error(t, err)
	assert.Equal(t, types.CodeInvalidSender, code)
	assert.False(t, eng.innerCalled, "a non-allow-listed action must NOT run")
}

func TestMAAExecRoute_OwnerExitBypassesAllowlist(t *testing.T) {
	// The dedicated owner-exit (withdrawal) actions are role-gated, not
	// allow-list-gated: the unrestricted owner can always exit, even though no
	// rule lists them (rules are immutable — an allow-list-bound exit would
	// permanently lock an owner out of their own funds). Case variants and the
	// empty namespace resolve to the same action in the engine, so they get the
	// same treatment.
	for _, tc := range []struct {
		name, namespace, action string
	}{
		{"maa_withdraw", "main", "maa_withdraw"},
		{"maa_bridge_out", "main", "maa_bridge_out"},
		{"action case variant", "main", "MAA_WITHDRAW"},
		{"empty namespace defaults to main", "", "maa_withdraw"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := newKnownEngine() // allow-list contains only ob_place_order
			code, err := runMAAExec(t, eng, maaUnrestricted, tc.namespace, tc.action)
			require.NoError(t, err)
			require.Equal(t, types.CodeOk, code)
			require.True(t, eng.innerCalled, "the owner's exit must run without being allow-listed")
			assert.Equal(t, ethcommon.BytesToAddress(maaAddr20).Hex(), eng.innerCaller,
				"the exit must run as the MAA so it debits the MAA's funds")
			assert.False(t, eng.innerRestricted, "the owner's exit must run unflagged or its transfer legs would be blocked")
			assert.False(t, eng.getterRestricted, "the route's getter lookups must run unflagged")
		})
	}
}

func TestMAAExecRoute_RestrictedCannotTriggerOwnerExit(t *testing.T) {
	// Withdrawing is the owner's act: the restricted key must be rejected BEFORE
	// re-entry — even when a rule (mistakenly) allow-lists the exit action, and
	// regardless of name casing (the engine resolves namespace and action names
	// case-insensitively, so a case variant would execute the same action). The
	// allow-listed rows double as dodge detectors: if the role gate missed the
	// spelling, the allow-list path would let the call through to re-entry.
	for _, tc := range []struct {
		name, namespace, action string
		allow                   [][2]string
	}{
		{"not allow-listed", "main", "maa_withdraw", nil},
		{"even when allow-listed", "main", "maa_withdraw", [][2]string{{"main", "maa_withdraw"}}},
		{"bridge out", "main", "maa_bridge_out", nil},
		{"action case variant", "main", "MAA_WITHDRAW", [][2]string{{"main", "MAA_WITHDRAW"}}},
		{"namespace case variant", "MAIN", "maa_withdraw", [][2]string{{"MAIN", "maa_withdraw"}}},
		{"empty namespace defaults to main", "", "maa_withdraw", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := newKnownEngine()
			if tc.allow != nil {
				eng.allow = append(eng.allow, tc.allow...)
			}
			code, err := runMAAExec(t, eng, maaRestricted, tc.namespace, tc.action)
			require.Error(t, err)
			require.ErrorContains(t, err, "reserved for the unrestricted owner",
				"the rejection must come from the owner-exit role gate, not the allow-list")
			assert.Equal(t, types.CodeInvalidSender, code)
			assert.False(t, eng.innerCalled, "the restricted key's exit attempt must not reach re-entry")
		})
	}
}

func TestMAAExecRoute_OwnerExitGatingIsDefaultNamespaceOnly(t *testing.T) {
	// An action that merely SHARES the withdrawal name in another namespace is a
	// normal action: allow-list-gated for both roles, no owner bypass and no
	// restricted-reject at the route (a real exit nested inside it would still be
	// stopped at the erc20 token boundary for the restricted role).
	eng := newKnownEngine()
	code, err := runMAAExec(t, eng, maaUnrestricted, "other", "maa_withdraw")
	require.Error(t, err, "outside the default namespace the owner gets no allow-list bypass")
	assert.Equal(t, types.CodeInvalidSender, code)
	assert.False(t, eng.innerCalled)

	eng = newKnownEngine()
	eng.allow = append(eng.allow, [2]string{"other", "maa_withdraw"})
	code, err = runMAAExec(t, eng, maaRestricted, "other", "maa_withdraw")
	require.NoError(t, err, "an allow-listed same-named action in another namespace follows the normal path")
	require.Equal(t, types.CodeOk, code)
	require.True(t, eng.innerCalled)
	assert.True(t, eng.innerRestricted, "the restricted role's normal-path execution stays flagged for the boundary")
}

func TestMAAExecRoute_BadAddressLengthRejectedInPreTx(t *testing.T) {
	// A payload whose maa_address is not 20 bytes must be rejected at decode time.
	payloadBytes, err := (types.MAAExec{
		MAAAddress: bytes.Repeat([]byte{0x33}, 19),
		Namespace:  "main",
		Action:     "ob_place_order",
	}).MarshalBinary()
	require.NoError(t, err)
	tx := &types.Transaction{Body: &types.TransactionBody{Payload: payloadBytes}}
	ctx := maaActivatedTxContext(maaRestricted)

	route := &maaExecRoute{}
	code, err := route.PreTx(ctx, nil, tx)
	require.Error(t, err)
	assert.Equal(t, types.CodeEncodingError, code)
}

func TestMAAExecRoute_EmptyActionRejectedInPreTx(t *testing.T) {
	// A payload with no inner action must be rejected at decode time, before any
	// state lookups.
	payloadBytes, err := (types.MAAExec{
		MAAAddress: maaAddr20,
		Namespace:  "main",
		Action:     "",
	}).MarshalBinary()
	require.NoError(t, err)
	tx := &types.Transaction{Body: &types.TransactionBody{Payload: payloadBytes}}
	ctx := maaActivatedTxContext(maaRestricted)

	route := &maaExecRoute{}
	code, err := route.PreTx(ctx, nil, tx)
	require.Error(t, err)
	assert.Equal(t, types.CodeEncodingError, code)
}

func TestMAAExecActivationGate(t *testing.T) {
	gateCtx := func(activation, height int64) *common.TxContext {
		return &common.TxContext{
			Ctx: context.Background(),
			BlockContext: &common.BlockContext{
				Height: height,
				ChainContext: &common.ChainContext{
					NetworkParameters: &types.NetworkParameters{MAAActivationHeight: activation},
				},
			},
		}
	}

	t.Run("fails closed without context", func(t *testing.T) {
		for name, ctx := range map[string]*common.TxContext{
			"nil ctx":           nil,
			"nil block context": {Ctx: context.Background()},
			"nil chain context": {Ctx: context.Background(), BlockContext: &common.BlockContext{}},
			"nil params":        {Ctx: context.Background(), BlockContext: &common.BlockContext{ChainContext: &common.ChainContext{}}},
		} {
			code, err := maaExecActivationGate(ctx)
			require.Error(t, err, name)
			assert.Equal(t, types.CodeInvalidTxType, code, name)
			assert.ErrorIs(t, err, types.ErrUnknownPayloadType, name)
		}
	})

	t.Run("zero means never activated", func(t *testing.T) {
		code, err := maaExecActivationGate(gateCtx(0, 1_000_000))
		require.Error(t, err)
		assert.Equal(t, types.CodeInvalidTxType, code)
		assert.ErrorContains(t, err, "not activated")
	})

	t.Run("rejected below the activation height", func(t *testing.T) {
		code, err := maaExecActivationGate(gateCtx(100, 99))
		require.Error(t, err)
		assert.Equal(t, types.CodeInvalidTxType, code)
		assert.ErrorContains(t, err, "activates at height 100")
	})

	t.Run("active at and after the activation height", func(t *testing.T) {
		for _, h := range []int64{100, 101, 1 << 40} {
			code, err := maaExecActivationGate(gateCtx(100, h))
			require.NoError(t, err)
			assert.Equal(t, types.TxCode(0), code)
		}
	})
}

func TestMAAExecRoute_RejectedBeforeActivation(t *testing.T) {
	// A well-formed MAAExec is rejected in PreTx when the network has not
	// reached (or never scheduled) activation. The rejection wraps
	// ErrUnknownPayloadType so it reads exactly like a pre-MAA binary's
	// response to this payload type.
	payloadBytes, err := (types.MAAExec{
		MAAAddress: maaAddr20,
		Namespace:  "main",
		Action:     "ob_place_order",
	}).MarshalBinary()
	require.NoError(t, err)
	tx := &types.Transaction{Body: &types.TransactionBody{Payload: payloadBytes}}

	route := &maaExecRoute{}

	// Not scheduled at all.
	ctx := maaActivatedTxContext(maaRestricted)
	ctx.BlockContext.ChainContext.NetworkParameters.MAAActivationHeight = 0
	code, err := route.PreTx(ctx, nil, tx)
	require.Error(t, err)
	assert.Equal(t, types.CodeInvalidTxType, code)
	assert.ErrorIs(t, err, types.ErrUnknownPayloadType)

	// Scheduled, not yet reached.
	ctx.BlockContext.ChainContext.NetworkParameters.MAAActivationHeight = ctx.BlockContext.Height + 10
	code, err = route.PreTx(ctx, nil, tx)
	require.Error(t, err)
	assert.Equal(t, types.CodeInvalidTxType, code)
	assert.ErrorIs(t, err, types.ErrUnknownPayloadType)
}
