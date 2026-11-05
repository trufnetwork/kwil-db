package erc20

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// noBalanceEngine answers the balances lookup with no rows, which is what
// Postgres returns for an account that never held the token. Every other
// statement fails, so a handler cannot reach a write without the test noticing.
type noBalanceEngine struct{}

func (noBalanceEngine) Call(*common.EngineContext, sql.DB, string, string, []any, func(*common.Row) error) (*common.CallResult, error) {
	return nil, errors.New("unexpected call")
}

func (noBalanceEngine) CallWithoutEngineCtx(context.Context, sql.DB, string, string, []any, func(*common.Row) error) (*common.CallResult, error) {
	return nil, errors.New("unexpected call")
}

func (noBalanceEngine) Execute(*common.EngineContext, sql.DB, string, map[string]any, func(*common.Row) error) error {
	return errors.New("unexpected statement")
}

func (noBalanceEngine) ExecuteWithoutEngineCtx(_ context.Context, _ sql.DB, stmt string, _ map[string]any, _ func(*common.Row) error) error {
	if strings.Contains(stmt, "FROM balances") {
		return nil
	}
	return fmt.Errorf("unexpected statement: %s", stmt)
}

// registeredMetaMethod returns a method of the registered kwil_erc20_meta
// precompile, so the test runs the real handler.
func registeredMetaMethod(t *testing.T, name string) precompiles.Method {
	t.Helper()
	init, ok := precompiles.RegisteredPrecompiles()[RewardMetaExtensionName]
	require.True(t, ok, "meta extension must be registered")
	p, err := init(context.Background(), nil, nil, RewardMetaExtensionName, nil)
	require.NoError(t, err)
	for _, m := range p.Methods {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("method %q not found on %s", name, RewardMetaExtensionName)
	return precompiles.Method{}
}

// TestMetaMethodsWithoutBalanceRow: every method that reads the caller's
// balance must treat a missing balances row as zero and return an error,
// never dereference the nil balance.
func TestMetaMethodsWithoutBalanceRow(t *testing.T) {
	id := uuidForChainAndEscrow("sepolia", "0x00000000000000000000000000000000000000cc")
	caller := "0x5555555555555555555555555555555555555555"
	other := "0x6666666666666666666666666666666666666666"
	one := types.MustParseDecimalExplicit("1", 78, 0)

	app := &common.App{Engine: noBalanceEngine{}}
	ctx := &common.EngineContext{TxContext: &common.TxContext{
		Ctx:          context.Background(),
		TxID:         "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Caller:       caller,
		BlockContext: &common.BlockContext{Height: 1},
	}}

	for _, tc := range []struct {
		name   string
		method string
		inputs []any
		want   string
	}{
		{"lock", "lock", []any{&id, one}, "insufficient balance"},
		{"lock_admin", "lock_admin", []any{&id, caller, one}, "insufficient balance"},
		{"transfer", "transfer", []any{&id, other, one}, "insufficient balance: have 0, need 1"},
		{"bridge", "bridge", []any{&id, other, one}, "insufficient balance"},
		{"bridge whole balance", "bridge", []any{&id, other, nil}, "amount needs to be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := registeredMetaMethod(t, tc.method)
			var err error
			require.NotPanics(t, func() {
				err = method.Handler(ctx, app, tc.inputs, func([]any) error { return nil })
			})
			require.EqualError(t, err, tc.want)
		})
	}

	t.Run("balance", func(t *testing.T) {
		var got []any
		err := registeredMetaMethod(t, "balance").Handler(ctx, app, []any{&id, caller}, func(v []any) error {
			got = v
			return nil
		})
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, "0", got[0].(*types.Decimal).String())
	})
}
