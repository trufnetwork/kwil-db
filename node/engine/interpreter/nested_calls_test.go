package interpreter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// writerDB is a database stub for building execution contexts. Only its
// access mode is used.
type writerDB struct {
	sql.DB
}

func (writerDB) AccessMode() sql.AccessMode { return sql.ReadWrite }

func blockEngineCtx(chainID string, height int64) *common.EngineContext {
	return &common.EngineContext{TxContext: &common.TxContext{
		Ctx: context.Background(),
		BlockContext: &common.BlockContext{
			ChainContext: &common.ChainContext{ChainID: chainID},
			Height:       height,
		},
	}}
}

func setNestedCallChecksHeight(t *testing.T, chainID string, height int64) {
	t.Helper()
	precompiles.SetNestedCallChecksHeight(chainID, height)
	t.Cleanup(func() { precompiles.SetNestedCallChecksHeight(chainID, 0) })
}

func TestCanExecute_CallsFromPrecompileMethods(t *testing.T) {
	mods := func(m ...precompiles.Modifier) precompiles.Modifiers { return m }

	tests := []struct {
		name      string
		method    *callingMethod // nil: not made by a precompile method
		namespace string         // namespace of the called action
		modifiers precompiles.Modifiers
		err       error
	}{
		{
			name:      "unchecked call reaches a private action",
			namespace: "main",
			modifiers: mods(precompiles.PRIVATE),
		},
		{
			name:      "unchecked call reaches a system action",
			namespace: "main",
			modifiers: mods(precompiles.SYSTEM),
		},
		{
			name:      "public method reaches a public action",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.PUBLIC)},
			namespace: "main",
			modifiers: mods(precompiles.PUBLIC),
		},
		{
			name:      "public view method reaches a public view action",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.PUBLIC, precompiles.VIEW)},
			namespace: "main",
			modifiers: mods(precompiles.PUBLIC, precompiles.VIEW),
		},
		{
			name:      "public method cannot reach a private action of another namespace",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.PUBLIC)},
			namespace: "main",
			modifiers: mods(precompiles.PRIVATE),
			err:       engine.ErrActionPrivate,
		},
		{
			name:      "system method cannot reach a private action of another namespace",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.SYSTEM)},
			namespace: "main",
			modifiers: mods(precompiles.PRIVATE),
			err:       engine.ErrActionPrivate,
		},
		{
			name:      "method reaches a private method of its own namespace",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.PUBLIC)},
			namespace: "ext",
			modifiers: mods(precompiles.PRIVATE),
		},
		{
			name:      "public method cannot reach a system action",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.PUBLIC)},
			namespace: "main",
			modifiers: mods(precompiles.SYSTEM),
			err:       engine.ErrActionSystemOnly,
		},
		{
			name:      "public view method cannot reach a system view action",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.PUBLIC, precompiles.VIEW)},
			namespace: "main",
			modifiers: mods(precompiles.SYSTEM, precompiles.VIEW),
			err:       engine.ErrActionSystemOnly,
		},
		{
			name:      "public method cannot reach a system method of its own namespace",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.PUBLIC)},
			namespace: "ext",
			modifiers: mods(precompiles.SYSTEM),
			err:       engine.ErrActionSystemOnly,
		},
		{
			name:      "system method reaches a system method of another namespace",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.SYSTEM)},
			namespace: "meta",
			modifiers: mods(precompiles.SYSTEM),
		},
		{
			name:      "private method reaches a system action",
			method:    &callingMethod{namespace: "ext", modifiers: mods(precompiles.PRIVATE)},
			namespace: "main",
			modifiers: mods(precompiles.SYSTEM),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// a nested call runs in the namespace of the called action, as call() sets it up.
			// OverrideAuthz is set so that only the access modifiers decide the result.
			eng := blockEngineCtx("chain", 1)
			eng.OverrideAuthz = true
			exec := &executionContext{
				engineCtx:      eng,
				scope:          newScope(tt.namespace),
				canMutateState: true,
				callingMethod:  tt.method,
			}

			err := exec.canExecute(tt.namespace, "target", tt.modifiers)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNestedCallChecksActive(t *testing.T) {
	setNestedCallChecksHeight(t, "nested-checks-ctx-chain", 10)
	setNestedCallChecksHeight(t, "nested-checks-node-chain", 20)

	i := &baseInterpreter{service: &common.Service{
		GenesisConfig: &config.GenesisConfig{ChainID: "nested-checks-node-chain"},
	}}

	require.False(t, i.nestedCallChecksActive(nil))
	require.False(t, i.nestedCallChecksActive(&common.EngineContext{}))
	require.False(t, i.nestedCallChecksActive(&common.EngineContext{TxContext: &common.TxContext{}}))

	// the chain named in the context
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 9)))
	require.True(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 10)))
	require.True(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 11)))

	// a chain with no height keeps the checks off
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-other-chain", 1_000_000)))

	// a context that names no chain, like a read-only RPC call, uses the node's chain
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("", 19)))
	require.True(t, i.nestedCallChecksActive(blockEngineCtx("", 20)))
	noChain := blockEngineCtx("", 20)
	noChain.TxContext.BlockContext.ChainContext = nil
	require.True(t, i.nestedCallChecksActive(noChain))

	// a context made without a block has no height
	require.False(t, i.nestedCallChecksActive(newInvalidEngineCtx(context.Background())))

	// removing the height turns the checks off again
	precompiles.SetNestedCallChecksHeight("nested-checks-ctx-chain", 0)
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 11)))
}

func TestNestedCallChecksFollowTheTopLevelCall(t *testing.T) {
	setNestedCallChecksHeight(t, "nested-checks-chain", 5)
	i := &baseInterpreter{}

	// below the height, methods get no calling method
	before, err := i.newExecCtx(blockEngineCtx("nested-checks-chain", 4), writerDB{}, "main", nil)
	require.NoError(t, err)
	require.True(t, before.scope.isTopLevel)
	require.False(t, before.checkNestedCalls)
	r := before.subscope("ext").methodApp(precompiles.Modifiers{precompiles.PUBLIC}).Engine.(*recursiveInterpreter)
	require.False(t, r.checkNestedCalls)
	require.Nil(t, r.callingMethod)

	// from the height, a method gets its namespace and modifiers
	top, err := i.newExecCtx(blockEngineCtx("nested-checks-chain", 5), writerDB{}, "main", nil)
	require.NoError(t, err)
	require.True(t, top.checkNestedCalls)

	method := top.subscope("ext")
	require.True(t, method.checkNestedCalls)
	r = method.methodApp(precompiles.Modifiers{precompiles.PUBLIC, precompiles.VIEW}).Engine.(*recursiveInterpreter)
	require.True(t, r.checkNestedCalls)
	require.Equal(t, &callingMethod{namespace: "ext", modifiers: precompiles.Modifiers{precompiles.PUBLIC, precompiles.VIEW}}, r.callingMethod)

	// lifecycle hooks get no calling method
	require.Nil(t, method.app().Engine.(*recursiveInterpreter).callingMethod)

	// a nested call keeps the top-level decision, even when the extension
	// passes an engine context without a block
	nested, err := i.newExecCtx(newInvalidEngineCtx(context.Background()), writerDB{}, "main", r)
	require.NoError(t, err)
	require.False(t, nested.scope.isTopLevel)
	require.True(t, nested.checkNestedCalls)
	require.True(t, nested.subscope("main").checkNestedCalls)
}
