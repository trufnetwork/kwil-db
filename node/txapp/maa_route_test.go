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
// lowercase hex), what they may run (allow-list), and that the inner call is
// re-entered with @caller rewritten to the MAA. A real-engine end-to-end test
// (create_rule -> join -> maa_exec an order-book action) belongs in the node
// integration suite; here we pin the branch logic deterministically.

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
}

func (f *fakeMAAEngine) Call(ctx *common.EngineContext, db sql.DB, namespace, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error) {
	switch action {
	case "maa_get_instance":
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
	ctx := &common.TxContext{
		Ctx:    context.Background(),
		Caller: ethcommon.BytesToAddress(signer).Hex(), // checksummed, like a real signer
	}
	app := &common.App{Engine: eng}

	route := &maaExecRoute{}
	if code, err := route.PreTx(ctx, nil, tx); err != nil {
		return code, err
	}
	code, _, err := route.InTx(ctx, app, tx)
	return code, err
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
}

func TestMAAExecRoute_UnrestrictedOwnerAlsoLimitedToAllowlist(t *testing.T) {
	// The owner (unrestricted) may act as the MAA for allow-listed actions too.
	eng := newKnownEngine()
	code, err := runMAAExec(t, eng, maaUnrestricted, "main", "ob_place_order")
	require.NoError(t, err)
	require.Equal(t, types.CodeOk, code)
	require.True(t, eng.innerCalled)
	assert.Equal(t, ethcommon.BytesToAddress(maaAddr20).Hex(), eng.innerCaller)
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

func TestMAAExecRoute_BadAddressLengthRejectedInPreTx(t *testing.T) {
	// A payload whose maa_address is not 20 bytes must be rejected at decode time.
	payloadBytes, err := (types.MAAExec{
		MAAAddress: bytes.Repeat([]byte{0x33}, 19),
		Namespace:  "main",
		Action:     "ob_place_order",
	}).MarshalBinary()
	require.NoError(t, err)
	tx := &types.Transaction{Body: &types.TransactionBody{Payload: payloadBytes}}
	ctx := &common.TxContext{Ctx: context.Background(), Caller: ethcommon.BytesToAddress(maaRestricted).Hex()}

	route := &maaExecRoute{}
	code, err := route.PreTx(ctx, nil, tx)
	require.Error(t, err)
	assert.Equal(t, types.CodeEncodingError, code)
}
