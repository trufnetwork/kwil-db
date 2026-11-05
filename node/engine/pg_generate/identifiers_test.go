package pggenerate_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
	pggenerate "github.com/trufnetwork/kwil-db/node/engine/pg_generate"
	"github.com/trufnetwork/kwil-db/node/engine/planner/logical"
)

// Test_ReservedWordIdentifiers checks that an identifier that Postgres
// reserves is written quoted, so that it keeps its meaning as a name and is
// not read as a keyword or a built-in value.
func Test_ReservedWordIdentifiers(t *testing.T) {
	users := &engine.Table{
		Name: "users",
		Columns: []*engine.Column{
			{Name: "id", DataType: types.IntType, IsPrimaryKey: true},
			{Name: "name", DataType: types.TextType, Nullable: true},
		},
	}
	getVar := func(varName string) (*types.DataType, error) {
		return nil, engine.ErrUnknownVariable
	}

	tests := []struct {
		name     string
		sql      string
		contains []string // quoted names expected in the output
	}{
		{
			name:     "current_timestamp",
			sql:      "SELECT current_timestamp FROM (SELECT 'a' AS current_timestamp) AS s;",
			contains: []string{`SELECT "current_timestamp"`, `AS "current_timestamp"`},
		},
		{
			name:     "localtimestamp in an expression",
			sql:      "SELECT length(localtimestamp) FROM (SELECT 'a' AS localtimestamp) AS s;",
			contains: []string{`length("localtimestamp")`},
		},
		{
			name:     "user",
			sql:      "SELECT user FROM (SELECT 'a' AS user) AS s;",
			contains: []string{`SELECT "user"`},
		},
		{
			name:     "current_schema",
			sql:      "SELECT current_schema FROM (SELECT 'a' AS current_schema) AS s;",
			contains: []string{`SELECT "current_schema"`},
		},
		{
			name:     "expanded wildcard",
			sql:      "SELECT * FROM (SELECT 'a' AS current_user) AS s;",
			contains: []string{`SELECT "current_user"`},
		},
		{
			name:     "default in SET",
			sql:      "UPDATE users SET name = default FROM (SELECT 'a' AS default) AS s WHERE users.id = 1;",
			contains: []string{`SET name = "default"`},
		},
		{
			name:     "ORDER BY an output column",
			sql:      "SELECT 'a' AS current_date FROM users ORDER BY current_date;",
			contains: []string{`ORDER BY "current_date"`},
		},
		{
			name:     "common table expression",
			sql:      "WITH user AS (SELECT 'a' AS x) SELECT x FROM user;",
			contains: []string{`WITH "user" AS`, `FROM "user"`},
		},
		{
			name:     "common table expression columns",
			sql:      "WITH s (session_user) AS (SELECT 'a') SELECT session_user FROM s;",
			contains: []string{`WITH s ("session_user")`, `SELECT "session_user"`},
		},
		{
			name:     "relation alias",
			sql:      "SELECT current_role.name FROM users AS current_role;",
			contains: []string{`SELECT "current_role".name`, `AS "current_role"`},
		},
		{
			name:     "named window",
			sql:      "SELECT row_number() OVER localtime FROM users WINDOW localtime AS (ORDER BY id);",
			contains: []string{`OVER "localtime"`, `WINDOW "localtime" AS`},
		},
		{
			name:     "group by",
			sql:      "SELECT current_catalog, count(*) FROM (SELECT 'a' AS current_catalog) AS s GROUP BY current_catalog;",
			contains: []string{`SELECT "current_catalog"`, `GROUP BY "current_catalog"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			stmt := stmts[0].(*parse.SQLStatement)

			_, err = logical.CreateLogicalPlan(stmt,
				func(namespace, tableName string) (*engine.Table, error) {
					if tableName != users.Name {
						return nil, fmt.Errorf("table %s not found", tableName)
					}
					return users, nil
				},
				getVar,
				func(objName string) (map[string]*types.DataType, error) {
					return nil, engine.ErrUnknownVariable
				},
				func(fnName string) bool { return false },
				false,
				"kwil",
			)
			require.NoError(t, err)

			got, _, err := pggenerate.GenerateSQL(stmt, "kwil", getVar)
			require.NoError(t, err)
			for _, want := range tt.contains {
				require.Contains(t, got, want)
			}
		})
	}
}

// Test_UnreservedIdentifiersUnquoted checks that names Postgres does not
// reserve are written as they are.
func Test_UnreservedIdentifiersUnquoted(t *testing.T) {
	stmts, err := parse.Parse("SELECT u.name, count(*) AS total FROM users AS u WHERE u.id > 1 GROUP BY u.name;")
	require.NoError(t, err)

	got, _, err := pggenerate.GenerateSQL(stmts[0], "kwil", func(varName string) (*types.DataType, error) {
		return types.TextType, nil
	})
	require.NoError(t, err)
	require.Equal(t, "\nSELECT u.name, count(*) AS total\nFROM users AS u\nWHERE u.id > 1\nGROUP BY u.name\n;", got)
}
