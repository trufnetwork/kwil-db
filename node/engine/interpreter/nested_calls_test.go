package interpreter

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
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

// readerDB is the read-only counterpart of writerDB.
type readerDB struct {
	sql.DB
}

func (readerDB) AccessMode() sql.AccessMode { return sql.ReadOnly }

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

	const readWrite, readOnly = true, false

	// a context without a block has no height, so only a read-only call is checked
	require.False(t, i.nestedCallChecksActive(nil, readWrite))
	require.False(t, i.nestedCallChecksActive(&common.EngineContext{}, readWrite))
	require.False(t, i.nestedCallChecksActive(&common.EngineContext{TxContext: &common.TxContext{}}, readWrite))
	require.True(t, i.nestedCallChecksActive(nil, readOnly))
	require.True(t, i.nestedCallChecksActive(&common.EngineContext{TxContext: &common.TxContext{}}, readOnly))

	// the chain named in the context
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 9), readWrite))
	require.True(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 10), readWrite))
	require.True(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 11), readWrite))

	// a chain with no height keeps the checks off
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-other-chain", 1_000_000), readWrite))
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-other-chain", 1_000_000), readOnly))

	// a context that names no chain, like a read-only RPC call, uses the node's chain
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("", 19), readWrite))
	require.True(t, i.nestedCallChecksActive(blockEngineCtx("", 20), readWrite))
	noChain := blockEngineCtx("", 20)
	noChain.TxContext.BlockContext.ChainContext = nil
	require.True(t, i.nestedCallChecksActive(noChain, readWrite))

	// a read-only call never reaches consensus, so it is checked below the
	// height too, including on a syncing node, which gives RPC calls height -1
	require.True(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 9), readOnly))
	require.True(t, i.nestedCallChecksActive(blockEngineCtx("", -1), readOnly))
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("", -1), readWrite))

	// a context made by CallWithoutEngineCtx has height 0, so only a read-only call is checked
	require.False(t, i.nestedCallChecksActive(newInvalidEngineCtx(context.Background()), readWrite))
	require.True(t, i.nestedCallChecksActive(newInvalidEngineCtx(context.Background()), readOnly))

	// removing the height turns the checks off again
	precompiles.SetNestedCallChecksHeight("nested-checks-ctx-chain", 0)
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 11), readWrite))
	require.False(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-ctx-chain", 11), readOnly))
}

func TestNestedCallChecksLogChainWithoutHeight(t *testing.T) {
	setNestedCallChecksHeight(t, "nested-checks-listed-chain", 10)
	const message = "no height is set for nested-call checks on this chain"

	var logs bytes.Buffer
	i := &baseInterpreter{service: &common.Service{
		Logger:        log.New(log.WithWriter(&logs)),
		GenesisConfig: &config.GenesisConfig{ChainID: "nested-checks-unlisted-chain"},
	}}

	// a chain with a height is not logged
	require.True(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-listed-chain", 10), true))
	require.Empty(t, logs.String())

	// the first call on a chain with no height is logged, and only that one
	for range 3 {
		require.False(t, i.nestedCallChecksActive(blockEngineCtx("", 5), true))
		require.False(t, i.nestedCallChecksActive(blockEngineCtx("nested-checks-unlisted-chain", 6), false))
	}
	require.Equal(t, 1, strings.Count(logs.String(), message), logs.String())
	require.Contains(t, logs.String(), "nested-checks-unlisted-chain")

	// a context that names no chain, on an engine with no chain of its own, is not logged
	var quiet bytes.Buffer
	noChain := &baseInterpreter{service: &common.Service{Logger: log.New(log.WithWriter(&quiet))}}
	require.False(t, noChain.nestedCallChecksActive(blockEngineCtx("", 5), true))
	require.Empty(t, quiet.String())
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

	// a read-only call is checked below the height, since it never reaches consensus
	readOnly, err := i.newExecCtx(blockEngineCtx("nested-checks-chain", -1), readerDB{}, "main", nil)
	require.NoError(t, err)
	require.True(t, readOnly.checkNestedCalls)
	r = readOnly.subscope("ext").methodApp(precompiles.Modifiers{precompiles.PUBLIC, precompiles.VIEW}).Engine.(*recursiveInterpreter)
	require.Equal(t, &callingMethod{namespace: "ext", modifiers: precompiles.Modifiers{precompiles.PUBLIC, precompiles.VIEW}}, r.callingMethod)

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
