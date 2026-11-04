package pggenerate_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
	pggenerate "github.com/trufnetwork/kwil-db/node/engine/pg_generate"
)

// Test_LegacySQL checks that the legacy generator writes SQL as releases
// before the generator upgrade did, and where its output differs from the
// current generator's.
func Test_LegacySQL(t *testing.T) {
	getVar := func(varName string) (*types.DataType, error) {
		return types.TextType, nil
	}

	tests := []struct {
		name   string
		sql    string
		legacy string
		// current is the output of GenerateSQL, if it differs from legacy
		current string
	}{
		{
			name:   "aggregate with ORDER BY",
			sql:    "SELECT array_agg(name ORDER BY id DESC) FROM users;",
			legacy: "\nSELECT array_agg(name ORDER BY id DESC)\nFROM users\n;",
		},
		{
			name:   "aggregate with DISTINCT and ORDER BY",
			sql:    "SELECT array_agg(DISTINCT name ORDER BY name) FROM users;",
			legacy: "\nSELECT array_agg(DISTINCT name ORDER BY name)\nFROM users\n;",
		},
		{
			name:   "aggregate with a literal and ORDER BY",
			sql:    "SELECT string_agg(name, ', ' ORDER BY id) FROM users;",
			legacy: "\nSELECT string_agg(name, ', ' ORDER BY id)\nFROM users\n;",
		},
		{
			name:   "array_agg default ordering",
			sql:    "SELECT array_agg(name) FROM users;",
			legacy: "\nSELECT array_agg(name ORDER BY name)\nFROM users\n;",
		},
		// aggregates with DISTINCT and no ORDER BY of their own
		{
			name:   "count with DISTINCT",
			sql:    "SELECT count(DISTINCT id) FROM users;",
			legacy: "\nSELECT count(DISTINCT id)\nFROM users\n;",
		},
		{
			name:   "sum with DISTINCT",
			sql:    "SELECT sum(DISTINCT id) FROM users;",
			legacy: "\nSELECT sum(DISTINCT id)\nFROM users\n;",
		},
		{
			name:   "min with DISTINCT",
			sql:    "SELECT min(DISTINCT id) FROM users;",
			legacy: "\nSELECT min(DISTINCT id)\nFROM users\n;",
		},
		{
			name:   "max with DISTINCT",
			sql:    "SELECT max(DISTINCT id) FROM users;",
			legacy: "\nSELECT max(DISTINCT id)\nFROM users\n;",
		},
		{
			name:   "avg with DISTINCT",
			sql:    "SELECT avg(DISTINCT id) FROM users;",
			legacy: "\nSELECT avg(DISTINCT id)\nFROM users\n;",
		},
		{
			name:   "string_agg with DISTINCT",
			sql:    "SELECT string_agg(DISTINCT name, ',') FROM users;",
			legacy: "\nSELECT string_agg(DISTINCT name, ',')\nFROM users\n;",
		},
		{
			name:   "array_agg with DISTINCT has no default ordering",
			sql:    "SELECT array_agg(DISTINCT name) FROM users;",
			legacy: "\nSELECT array_agg(DISTINCT name)\nFROM users\n;",
		},
		{
			name:    "literal with an open parenthesis",
			sql:     "SELECT array_agg('(' ORDER BY id) FROM users;",
			legacy:  "\nSELECT array_agg('(' ORDER BY '(' ORDER BY id)\nFROM users\n;",
			current: "\nSELECT array_agg('(' ORDER BY id)\nFROM users\n;",
		},
		{
			name:    "literal with a close parenthesis",
			sql:     "SELECT array_agg(')' ORDER BY id) FROM users;",
			legacy:  "\nSELECT array_agg(')' ORDER BY ')' ORDER BY id)\nFROM users\n;",
			current: "\nSELECT array_agg(')' ORDER BY id)\nFROM users\n;",
		},
		{
			name:    "reserved word identifier",
			sql:     "SELECT user FROM (SELECT 'a' AS user) AS s;",
			legacy:  "\nSELECT user\nFROM (SELECT 'a' AS user\n) AS s\n;",
			current: "\nSELECT \"user\"\nFROM (SELECT 'a' AS \"user\"\n) AS s\n;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			require.Len(t, stmts, 1)

			got, params, err := pggenerate.GenerateLegacySQL(stmts[0], "kwil", getVar)
			require.NoError(t, err)
			require.Equal(t, tt.legacy, got)
			require.Empty(t, params)

			current := tt.current
			if current == "" {
				current = tt.legacy
			}
			got, params, err = pggenerate.GenerateSQL(stmts[0], "kwil", getVar)
			require.NoError(t, err)
			require.Equal(t, current, got)
			require.Empty(t, params)
		})
	}
}

// Test_LegacyOrderByFallbackInsertion checks how the legacy generator places
// an aggregate's ORDER BY when the formatted call has no matching
// parentheses.
func Test_LegacyOrderByFallbackInsertion(t *testing.T) {
	const (
		unmatchedParenFn = "test_order_by_unmatched_paren"
		noClosingParenFn = "test_order_by_no_closing_paren"
	)

	engine.Functions[unmatchedParenFn] = &engine.AggregateFunctionDefinition{
		ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
			return types.TextType, nil
		},
		PGFormatFunc: func(inputs []string, distinct bool, orderBy []string) (string, error) {
			return "test_aggregate)", nil
		},
	}
	engine.Functions[noClosingParenFn] = &engine.AggregateFunctionDefinition{
		ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
			return types.TextType, nil
		},
		PGFormatFunc: func(inputs []string, distinct bool, orderBy []string) (string, error) {
			return "test_aggregate", nil
		},
	}
	defer delete(engine.Functions, unmatchedParenFn)
	defer delete(engine.Functions, noClosingParenFn)

	tests := []struct {
		name string
		sql  string
		want string
	}{
		{
			name: "unmatched closing parenthesis",
			sql:  "SELECT " + unmatchedParenFn + "(name ORDER BY id) FROM users;",
			want: "\nSELECT test_aggregate ORDER BY id)\nFROM users\n;",
		},
		{
			name: "no closing parenthesis",
			sql:  "SELECT " + noClosingParenFn + "(name ORDER BY id) FROM users;",
			want: "\nSELECT test_aggregate ORDER BY id\nFROM users\n;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			require.Len(t, stmts, 1)

			got, params, err := pggenerate.GenerateLegacySQL(stmts[0], "kwil", func(varName string) (*types.DataType, error) {
				return types.TextType, nil
			})
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Empty(t, params)
		})
	}
}

// Test_LegacyOrderByAfterFormat checks that the legacy generator renders an
// aggregate's ORDER BY terms only once the call has been formatted, so that
// a call that cannot be formatted reports the format error.
func Test_LegacyOrderByAfterFormat(t *testing.T) {
	stmts, err := parse.Parse("SELECT string_agg(name ORDER BY $unknown) FROM users;")
	require.NoError(t, err)

	getVar := func(varName string) (*types.DataType, error) {
		return nil, engine.ErrUnknownVariable
	}

	_, _, err = pggenerate.GenerateLegacySQL(stmts[0], "kwil", getVar)
	require.ErrorContains(t, err, "string_agg requires exactly 2 arguments")

	_, _, err = pggenerate.GenerateSQL(stmts[0], "kwil", getVar)
	require.ErrorIs(t, err, engine.ErrUnknownVariable)
}

func Test_UpgradeHeights(t *testing.T) {
	t.Cleanup(func() { pggenerate.SetUpgradeHeights(nil) })

	// with no heights set, every block uses the legacy generator
	require.True(t, pggenerate.LegacyAt("some-chain", 1))
	require.True(t, pggenerate.LegacyAt("some-chain", math.MaxInt64))

	pggenerate.SetUpgradeHeights(func(chainID string) int64 {
		if chainID == "upgraded-chain" {
			return 10
		}
		return math.MaxInt64
	})

	require.True(t, pggenerate.LegacyAt("upgraded-chain", 9))
	require.False(t, pggenerate.LegacyAt("upgraded-chain", 10))
	require.False(t, pggenerate.LegacyAt("upgraded-chain", 11))
	require.True(t, pggenerate.LegacyAt("some-chain", 1_000_000))
	// a statement executed outside a block has no chain ID
	require.True(t, pggenerate.LegacyAt("", 10))

	pggenerate.SetUpgradeHeights(nil)
	require.True(t, pggenerate.LegacyAt("upgraded-chain", 10))
}

// Test_LegacyAndCurrentSQLMatch checks which statements the legacy and
// current generators write the same way. Such a statement runs the same in
// blocks below the upgrade height and from it on.
func Test_LegacyAndCurrentSQLMatch(t *testing.T) {
	getVar := func(varName string) (*types.DataType, error) {
		return types.TextType, nil
	}

	tests := []struct {
		sql  string
		same bool
	}{
		{"SELECT id, name FROM users WHERE name = 'a' ORDER BY id;", true},
		{"SELECT string_agg(name, ', ' ORDER BY id) FROM users;", true},
		{`INSERT INTO users (id, name) VALUES ($id, 'it\'s');`, true},
		{"CREATE TABLE t (id INT PRIMARY KEY, name TEXT);", true},
		// literals outside aggregate calls, and literals without
		// parentheses or ORDER BY inside them, are written the same way
		{"SELECT 'a) ORDER BY (b', id FROM users WHERE name = '; -- $$';", true},
		{`SELECT string_agg(name || 'a\\', '; -- ' ORDER BY id) FROM users;`, true},
		{`SELECT array_agg('\' $$ /*' ORDER BY id DESC) FROM users;`, true},
		{"SELECT array_agg('(' ORDER BY id) FROM users;", false},
		{"SELECT string_agg(name, ' ORDER BY ' ORDER BY id) FROM users;", false},
		{"SELECT count(*) FROM (SELECT 'a' AS current_user) AS s;", false},
	}

	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			stmts, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			require.Len(t, stmts, 1)

			current, currentParams, err := pggenerate.GenerateSQL(stmts[0], "kwil", getVar)
			require.NoError(t, err)
			legacy, legacyParams, err := pggenerate.GenerateLegacySQL(stmts[0], "kwil", getVar)
			require.NoError(t, err)

			require.Equal(t, currentParams, legacyParams)
			require.Equal(t, tt.same, current == legacy, "current: %q\nlegacy: %q", current, legacy)
		})
	}
}
