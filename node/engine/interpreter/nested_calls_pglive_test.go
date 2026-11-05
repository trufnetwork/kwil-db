//go:build pglive

package interpreter_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// readOnlyTx is a transaction that reports itself as read-only, as the
// transaction of a read-only RPC call does.
type readOnlyTx struct {
	sql.Tx
}

func (readOnlyTx) AccessMode() sql.AccessMode { return sql.ReadOnly }

func (r readOnlyTx) QueryScanFn(ctx context.Context, stmt string, scans []any, fn func() error, args ...any) error {
	return r.Tx.(sql.QueryScanner).QueryScanFn(ctx, stmt, scans, fn, args...)
}

const (
	nestedCallTestChain  = "nested-call-test-chain"
	nestedCallTestHeight = 100
)

var registerNestedCallPrecompile sync.Once

// nestedCallPrecompile has methods that call, through their engine, the action
// or method named in their arguments, and methods to be called.
func nestedCallPrecompile() precompiles.Precompile {
	callByName := func(withoutEngineCtx bool) precompiles.HandlerFunc {
		return func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
			namespace, action := inputs[0].(string), inputs[1].(string)

			var res *common.CallResult
			var err error
			if withoutEngineCtx {
				res, err = app.Engine.CallWithoutEngineCtx(ctx.TxContext.Ctx, app.DB, namespace, action, nil, nil)
			} else {
				res, err = app.Engine.Call(ctx, app.DB, namespace, action, nil, nil)
			}
			if err != nil {
				return err
			}
			return res.Error
		}
	}
	params := []precompiles.PrecompileValue{
		precompiles.NewPrecompileValue("namespace", types.TextType, false),
		precompiles.NewPrecompileValue("action", types.TextType, false),
	}
	noop := func(*common.EngineContext, *common.App, []any, func([]any) error) error { return nil }

	return precompiles.Precompile{
		Methods: []precompiles.Method{
			{Name: "call_public", Parameters: params, AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC}, Handler: callByName(false)},
			{Name: "call_public_view", Parameters: params, AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW}, Handler: callByName(false)},
			{Name: "call_system", Parameters: params, AccessModifiers: []precompiles.Modifier{precompiles.SYSTEM}, Handler: callByName(false)},
			{Name: "call_public_without_ctx", Parameters: params, AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC}, Handler: callByName(true)},
			{Name: "private_method", AccessModifiers: []precompiles.Modifier{precompiles.PRIVATE}, Handler: noop},
			{Name: "system_method", AccessModifiers: []precompiles.Modifier{precompiles.SYSTEM}, Handler: noop},
		},
	}
}

// Test_NestedCallsFromPrecompiles checks that, from the height set for the
// chain, an action or method that a precompile method calls by name must be
// one that method may call, and that below it nothing changes.
func Test_NestedCallsFromPrecompiles(t *testing.T) {
	registerNestedCallPrecompile.Do(func() {
		require.NoError(t, precompiles.RegisterPrecompile("nested_call_test", nestedCallPrecompile()))
	})
	precompiles.SetNestedCallChecksHeight(nestedCallTestChain, nestedCallTestHeight)
	t.Cleanup(func() { precompiles.SetNestedCallChecksHeight(nestedCallTestChain, 0) })

	db := newTestDB(t, nil, nil)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	interp := newTestInterp(t, tx, []string{
		`USE nested_call_test AS ext_a;`,
		`USE nested_call_test AS ext_b;`,
		`CREATE ACTION private_target() private {}`,
		`CREATE ACTION system_target() system {}`,
		`CREATE ACTION public_target() public {}`,
		`CREATE ACTION public_view_target() public view {}`,
		`CREATE ACTION private_view_target() private view {}`,
		`CREATE ACTION system_view_target() system view {}`,
		// a public action that hands a name to a public method of an extension
		`CREATE ACTION via_public_method($ns text, $action text) public { ext_a.call_public_view($ns, $action); }`,
		// a public action that hands a name to a system method of an extension
		`CREATE ACTION via_system_method($ns text, $action text) public { ext_a.call_system($ns, $action); }`,
		// a public action that hands a system action to a public method
		`CREATE ACTION relay_system_target() public { ext_a.call_public('main', 'system_target'); }`,
	}, false)

	type call struct {
		namespace, action string
		args              []any
	}
	tests := []struct {
		name string
		call call
		// err is the result from the activation height; below it, every call succeeds.
		err error
	}{
		{"public method calls a public action", call{"ext_a", "call_public", []any{"main", "public_target"}}, nil},
		{"public view method calls a public view action", call{"ext_a", "call_public_view", []any{"main", "public_view_target"}}, nil},
		{"public method calls a private action of another namespace", call{"ext_a", "call_public", []any{"main", "private_target"}}, engine.ErrActionPrivate},
		{"public method calls a system action", call{"ext_a", "call_public", []any{"main", "system_target"}}, engine.ErrActionSystemOnly},
		{"public method calls a private method of its own namespace", call{"ext_a", "call_public", []any{"ext_a", "private_method"}}, nil},
		{"public method calls a system method of its own namespace", call{"ext_a", "call_public", []any{"ext_a", "system_method"}}, engine.ErrActionSystemOnly},
		{"public method calls a private method of another extension", call{"ext_a", "call_public", []any{"ext_b", "private_method"}}, engine.ErrActionPrivate},
		{"public method without an engine context calls a private action", call{"ext_a", "call_public_without_ctx", []any{"main", "private_target"}}, engine.ErrActionPrivate},
		{"public method without an engine context calls a system action", call{"ext_a", "call_public_without_ctx", []any{"main", "system_target"}}, engine.ErrActionSystemOnly},
		{"public method without an engine context calls a public action", call{"ext_a", "call_public_without_ctx", []any{"main", "public_target"}}, nil},
		// the action reached without an engine context still runs with the checks of the top-level call
		{"public method without an engine context reaches a public method that calls a system action", call{"ext_a", "call_public_without_ctx", []any{"main", "relay_system_target"}}, engine.ErrActionSystemOnly},
		{"action passes a private action to a public method", call{"main", "via_public_method", []any{"main", "private_target"}}, engine.ErrActionPrivate},
		{"action passes a system action to a public method", call{"main", "via_public_method", []any{"main", "system_target"}}, engine.ErrActionSystemOnly},
		{"action passes a public view action to a public method", call{"main", "via_public_method", []any{"main", "public_view_target"}}, nil},
		{"system method calls a system action", call{"main", "via_system_method", []any{"main", "system_target"}}, nil},
		{"system method calls a system method of another extension", call{"main", "via_system_method", []any{"ext_b", "system_method"}}, nil},
		{"system method calls a private action of another namespace", call{"main", "via_system_method", []any{"main", "private_target"}}, engine.ErrActionPrivate},
		{"system method calls a private method of another extension", call{"main", "via_system_method", []any{"ext_b", "private_method"}}, engine.ErrActionPrivate},
	}

	callWith := func(db sql.DB, chainID string, height int64, c call) error {
		engCtx := newEngineCtx(defaultCaller)
		engCtx.TxContext.BlockContext.Height = height
		engCtx.TxContext.BlockContext.ChainContext.ChainID = chainID

		res, err := interp.Call(engCtx, db, c.namespace, c.action, c.args, nil)
		if err != nil {
			return err
		}
		return res.Error
	}
	callAt := func(height int64, c call) error {
		return callWith(tx, nestedCallTestChain, height, c)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, callAt(nestedCallTestHeight-1, tt.call), "below the activation height")

			err := callAt(nestedCallTestHeight, tt.call)
			if tt.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.err)
			}
		})
	}

	t.Run("chain without a height", func(t *testing.T) {
		engCtx := newEngineCtx(defaultCaller)
		engCtx.TxContext.BlockContext.Height = nestedCallTestHeight * 10
		engCtx.TxContext.BlockContext.ChainContext.ChainID = nestedCallTestChain + "-other"

		_, err := interp.Call(engCtx, tx, "ext_a", "call_public", []any{"main", "system_target"}, nil)
		require.NoError(t, err)
	})

	t.Run("read-only calls below the height", func(t *testing.T) {
		ro := readOnlyTx{tx}
		viaPublicViewMethod := func(action string) call {
			return call{"ext_a", "call_public_view", []any{"main", action}}
		}

		// a read-only call never reaches consensus, so it is checked below the
		// height too, including on a syncing node, which gives RPC calls height -1
		for _, height := range []int64{-1, nestedCallTestHeight - 1} {
			require.ErrorIs(t, callWith(ro, nestedCallTestChain, height, viaPublicViewMethod("private_view_target")), engine.ErrActionPrivate)
			require.ErrorIs(t, callWith(ro, nestedCallTestChain, height, viaPublicViewMethod("system_view_target")), engine.ErrActionSystemOnly)
			require.NoError(t, callWith(ro, nestedCallTestChain, height, viaPublicViewMethod("public_view_target")))

			// a call that can change state still follows the height
			require.NoError(t, callWith(tx, nestedCallTestChain, height, viaPublicViewMethod("private_view_target")))
		}

		// a chain without a height keeps read-only calls unchecked too
		require.NoError(t, callWith(ro, nestedCallTestChain+"-other", -1, viaPublicViewMethod("private_view_target")))
	})
}
