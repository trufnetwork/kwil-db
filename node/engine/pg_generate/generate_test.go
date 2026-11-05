package pggenerate_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
	pggenerate "github.com/trufnetwork/kwil-db/node/engine/pg_generate"
	"github.com/trufnetwork/kwil-db/node/engine/planner/logical"
)

func Test_PgGenerate(t *testing.T) {
	type testcase struct {
		name      string
		sql       string
		want      string
		params    []string
		variables map[string]*types.DataType
		wantErr   bool
	}

	tests := []testcase{
		{
			name: "Simple Insert with two params",
			sql:  "INSERT INTO tbl VALUES ($a, $b);",
			want: "INSERT INTO kwil.tbl VALUES ($1::INT8, $2::INT8);",
			variables: map[string]*types.DataType{
				"$a": types.IntType,
				"$b": types.IntType,
			},
			params: []string{"$a", "$b"},
		},
		{
			name: "array_agg with order by",
			sql:  "SELECT array_agg(name ORDER BY id ASC) FROM users;",
			want: "SELECT array_agg(name ORDER BY id ASC) FROM users;",
		},
		{
			name: "array_agg with multiple order by terms",
			sql:  "SELECT array_agg(name ORDER BY age DESC, name ASC) FROM users;",
			want: "SELECT array_agg(name ORDER BY age DESC, name ASC) FROM users;",
		},
		{
			name: "array_agg without order by (default behavior)",
			sql:  "SELECT array_agg(name) FROM users;",
			want: "SELECT array_agg(name ORDER BY name) FROM users;",
		},
		{
			name: "select with @caller",
			sql:  "SELECT * FROM tbl WHERE col = @caller;",
			want: "SELECT * FROM tbl WHERE col = $1::TEXT;",
			variables: map[string]*types.DataType{
				"@caller": types.TextType,
			},
			params: []string{"@caller"},
		},
		{
			name: "Insert with named columns and params",
			sql:  "INSERT INTO tbl (col1, col2) VALUES ($foo, $bar);",
			want: "INSERT INTO kwil.tbl (col1, col2) VALUES ($1::INT8, $2::INT8);",
			variables: map[string]*types.DataType{
				"$foo": types.IntType,
				"$bar": types.IntType,
			},
			params: []string{"$foo", "$bar"},
		},
		{
			name: "Update statement",
			sql:  "UPDATE tbl SET col1 = $x, col2 = $y WHERE col3 = $z;",
			want: "UPDATE kwil.tbl SET col1 = $1::INT8, col2 = $2::INT8 WHERE col3 = $3::INT8;",
			variables: map[string]*types.DataType{
				"$x": types.IntType,
				"$y": types.IntType,
				"$z": types.IntType,
			},
			params: []string{"$x", "$y", "$z"},
		},
		{
			name: "Select with one param",
			sql:  "SELECT * FROM tbl WHERE col = $param;",
			want: "SELECT * FROM tbl WHERE col = $1::INT8;",
			variables: map[string]*types.DataType{
				"$param": types.IntType,
			},
			params: []string{"$param"},
		},
		{
			name: "Delete with a param",
			sql:  "DELETE FROM tbl WHERE id = $id;",
			want: "DELETE FROM kwil.tbl WHERE id = $1::UUID;",
			variables: map[string]*types.DataType{
				"$id": types.UUIDType,
			},
			params: []string{"$id"},
		},
		{
			name: "Complex select with multiple params",
			sql:  "SELECT col1, col2 FROM tbl WHERE col1 = $foo AND col2 IN ($bar, $baz);",
			want: "SELECT col1, col2 FROM tbl WHERE col1 = $1::INT8 AND col2 IN ($2::INT8, $3::INT8);",
			variables: map[string]*types.DataType{
				"$foo": types.IntType,
				"$bar": types.IntType,
				"$baz": types.IntType,
			},
			params: []string{"$foo", "$bar", "$baz"},
		},
		{
			name: "Repeated parameter name",
			sql:  "SELECT * FROM tbl WHERE col1 = $foo AND col2 = $foo;",
			want: "SELECT * FROM tbl WHERE col1 = $1::INT8 AND col2 = $1::INT8;",
			variables: map[string]*types.DataType{
				"$foo": types.IntType,
			},
			params: []string{"$foo"},
		},
		{
			name: "Mixed case parameter name",
			sql:  "SELECT * FROM tbl WHERE UserId = $UserId;",
			want: "SELECT * FROM tbl WHERE userid = $1::INT8;",
			variables: map[string]*types.DataType{
				"$userid": types.IntType,
			},
			params: []string{"$userid"},
		},
		{
			name: "Parameter name with underscore",
			sql:  "SELECT * FROM tbl WHERE col = $some_param_name;",
			want: "SELECT * FROM tbl WHERE col = $1::INT8;",
			variables: map[string]*types.DataType{
				"$some_param_name": types.IntType,
			},
			params: []string{"$some_param_name"},
		},
		{
			name: "Multiple parameters used in multiple places",
			sql:  "UPDATE tbl SET col1 = $a, col2 = $b WHERE col3 = $a;",
			want: "UPDATE kwil.tbl SET col1 = $1::INT8, col2 = $2::TEXT WHERE col3 = $1::INT8;",
			variables: map[string]*types.DataType{
				"$a": types.IntType,
				"$b": types.TextType,
			},
			params: []string{"$a", "$b"},
		},
		{
			name: "No parameters",
			sql:  "SELECT * FROM tbl;",
			want: "SELECT * FROM tbl;",
		},
		{
			name: "Parameter in function call",
			sql:  "SELECT * FROM tbl WHERE col = abs($pwd);",
			want: "SELECT * FROM tbl WHERE col = abs($1::INT8);",
			variables: map[string]*types.DataType{
				"$pwd": types.IntType,
			},
			params: []string{"$pwd"},
		},
		{
			name: "Parameter in JOIN condition",
			sql:  "SELECT t1.col, t2.col FROM t1 JOIN t2 ON t1.id = t2.id AND t1.name = $name;",
			want: "SELECT t1.col, t2.col FROM t1 INNER JOIN t2 ON t1.id = t2.id AND t1.name = $1::TEXT;",
			variables: map[string]*types.DataType{
				"$name": types.TextType,
			},
			params: []string{"$name"},
		},
		{
			name: "window function",
			sql:  "SELECT col1, col2, SUM(col3) OVER (PARTITION BY col1 ORDER BY col2) FROM tbl;",
			want: "SELECT col1, col2, sum(col3) OVER (PARTITION BY col1 ORDER BY col2) FROM tbl;",
		},
		{
			name: "array access",
			sql:  "SELECT col1[1], col2[2] FROM tbl;",
			want: "SELECT col1[1], col2[2] FROM tbl;",
		},
		{
			name: "array slice",
			sql:  "SELECT col1[1:2], col2[2:], col3[:3] FROM tbl;",
			want: "SELECT col1[1:2], col2[2:], col3[:3] FROM tbl;",
		},
		{
			name: "make array",
			sql:  "SELECT ARRAY[col1, col2] FROM tbl;",
			want: "SELECT ARRAY[col1, col2] FROM tbl;",
		},
		{
			name: "type cast",
			sql:  "SELECT col1::INT8, (col2::TEXT)::INT8 FROM tbl;",
			want: "SELECT col1::INT8, (col2::TEXT)::INT8 FROM tbl;",
		},
		{
			name: "arithmetics",
			sql:  "SELECT col1 + col2, col1 - col2, col1 * col2, col1 / col2 FROM tbl;",
			want: "SELECT col1 + col2, col1 - col2, col1 * col2, col1 / col2 FROM tbl;",
		},
		{
			name: "comparison",
			sql:  "SELECT col1 = col2, col1 <> col2, col1 < col2, col1 <= col2, col1 > col2, col1 >= col2 FROM tbl;",
			want: "SELECT col1 = col2, col1 <> col2, col1 < col2, col1 <= col2, col1 > col2, col1 >= col2 FROM tbl;",
		},
		{
			name: "unary",
			sql:  "SELECT +col1, -col2 FROM tbl;",
			want: "SELECT +col1, -col2 FROM tbl;",
		},
		{
			name: "logical",
			sql:  "SELECT col1 AND col2, col1 OR col2, NOT col1 FROM tbl;",
			want: "SELECT col1 AND col2, col1 OR col2, NOT col1 FROM tbl;",
		},
		{
			name: "case",
			sql:  "SELECT CASE WHEN col1 = 1 THEN 'one' ELSE 'other' END FROM tbl;",
			want: "SELECT CASE WHEN col1 = 1 THEN 'one' ELSE 'other' END FROM tbl;",
		},
		{
			name: "collate",
			sql:  "SELECT col1 from tbl where name = 'foo' collate nocase;",
			want: "SELECT col1 FROM tbl WHERE name = 'foo' COLLATE nocase;",
		},
		{
			name: "is null",
			sql:  "SELECT col1 IS NULL, col2 IS NOT NULL FROM tbl;",
			want: "SELECT col1 IS NULL, col2 IS NOT NULL FROM tbl;",
		},
		{
			name: "between",
			sql:  "SELECT col1 BETWEEN 1 AND 10 FROM tbl;",
			want: "SELECT col1 BETWEEN 1 AND 10 FROM tbl;",
		},
		{
			name: "in",
			sql:  "SELECT col1 IN (1, 2, 3) FROM tbl;",
			want: "SELECT col1 IN (1, 2, 3) FROM tbl;",
		},
		{
			name: "like",
			sql:  "SELECT col1 LIKE 'foo%' FROM tbl WHERE col2 NOT LIKE '%bar' AND col3 ILIKE 'baz%';",
			want: "SELECT col1 LIKE 'foo%' FROM tbl WHERE col2 NOT LIKE '%bar' AND col3 ILIKE 'baz%';",
		},
		{
			name: "exists",
			sql:  "SELECT EXISTS (SELECT 1 FROM tbl WHERE col1 = 1);",
			want: "SELECT EXISTS (SELECT 1 FROM tbl WHERE col1 = 1);",
		},
		{
			name: "subquery",
			sql:  "SELECT (SELECT col1 FROM tbl WHERE col2 = 1) FROM tbl2;",
			want: "SELECT (SELECT col1 FROM tbl WHERE col2 = 1) FROM tbl2;",
		},
		{
			name: "common table expression",
			sql:  "WITH cte AS (SELECT * FROM tbl) SELECT * FROM cte;",
			want: "WITH cte AS (SELECT * FROM tbl) SELECT * FROM cte;",
		},
		{
			name: "recursive common table expression",
			sql:  "WITH RECURSIVE cte AS (SELECT * FROM tbl) SELECT * FROM cte;",
			want: "WITH RECURSIVE cte AS (SELECT * FROM tbl) SELECT * FROM cte;",
		},
		// ddl
		{
			name: "Create table",
			sql: `CREATE TABLE departments (
    department_id   UUID,
    department_code TEXT NOT NULL,
    department_name TEXT NOT NULL,
    location_id     INT8 DEFAULT 1,
    created_at      INT8,
    PRIMARY KEY (department_id, department_code),
    UNIQUE (department_name),
    CHECK (department_name <> ''),
	FOREIGN KEY (location_id) REFERENCES locations(location_id)
);`,
			want: `CREATE TABLE kwil.departments (
				department_id   UUID,
				department_code TEXT NOT NULL,
				department_name TEXT NOT NULL,
				location_id     INT8 DEFAULT 1,
				created_at      INT8,
				PRIMARY KEY (department_id, department_code),
				UNIQUE (department_name),
				CHECK (department_name <> ''),
				FOREIGN KEY (location_id) REFERENCES kwil.locations(location_id)
			);`,
		},
		{
			name: "Create table if not exists",
			sql: `CREATE TABLE IF NOT EXISTS departments (
				department_id   UUID PRIMARY KEY
		);`,
			want: `CREATE TABLE IF NOT EXISTS kwil.departments (
				department_id   UUID PRIMARY KEY
			);`,
		},
		{
			name: "add column",
			sql:  `ALTER TABLE departments ADD COLUMN department_head UUID;`,
			want: `ALTER TABLE kwil.departments ADD COLUMN department_head UUID;`,
		},
		{
			// Regression: the SQL generator used to drop the IF NOT EXISTS
			// flag, so a re-run of an idempotent column-add migration
			// failed with PostgreSQL SQLSTATE 42701.
			name: "add column if not exists",
			sql:  `ALTER TABLE departments ADD COLUMN IF NOT EXISTS department_head UUID;`,
			want: `ALTER TABLE kwil.departments ADD COLUMN IF NOT EXISTS department_head UUID;`,
		},
		{
			name: "drop column",
			sql:  `ALTER TABLE departments DROP COLUMN department_head;`,
			want: `ALTER TABLE kwil.departments DROP COLUMN department_head;`,
		},
		{
			// Symmetric regression to "add column if not exists".
			name: "drop column if exists",
			sql:  `ALTER TABLE departments DROP COLUMN IF EXISTS department_head;`,
			want: `ALTER TABLE kwil.departments DROP COLUMN IF EXISTS department_head;`,
		},
		{
			name: "rename column",
			sql:  `ALTER TABLE departments RENAME COLUMN department_head TO head_department;`,
			want: `ALTER TABLE kwil.departments RENAME COLUMN department_head TO head_department;`,
		},
		{
			name: "rename table",
			sql:  `ALTER TABLE departments RENAME TO division;`,
			want: `ALTER TABLE kwil.departments RENAME TO division;`,
		},
		{
			name: "add table constraint",
			sql:  `ALTER TABLE departments ADD PRIMARY KEY (department_id);`,
			want: `ALTER TABLE kwil.departments ADD PRIMARY KEY (department_id);`,
		},
		{
			name: "drop table constraint",
			sql:  `ALTER TABLE departments DROP CONSTRAINT department_id;`,
			want: `ALTER TABLE kwil.departments DROP CONSTRAINT department_id;`,
		},
		{
			name: "add column constraint",
			sql:  `ALTER TABLE departments ALTER COLUMN department_head SET NOT NULL;`,
			want: `ALTER TABLE kwil.departments ALTER COLUMN department_head SET NOT NULL;`,
		},
		{
			name: "drop column constraint",
			sql:  `ALTER TABLE departments ALTER COLUMN department_head DROP NOT NULL;`,
			want: `ALTER TABLE kwil.departments ALTER COLUMN department_head DROP NOT NULL;`,
		},
		{
			name: "drop table",
			sql:  `DROP TABLE departments;`,
			want: `DROP TABLE kwil.departments;`,
		},
		{
			name: "drop table if exists cascade",
			sql:  `DROP TABLE IF EXISTS departments CASCADE;`,
			want: `DROP TABLE IF EXISTS kwil.departments CASCADE;`,
		},
		{
			name: "create index",
			sql:  `CREATE INDEX IF NOT EXISTS idx_department_name_id ON departments (department_name, department_id);`,
			want: `CREATE INDEX IF NOT EXISTS idx_department_name_id ON kwil.departments (department_name, department_id);`,
		},
		{
			name: "drop index",
			sql:  `DROP INDEX IF EXISTS idx_department_name_id;`,
			want: `DROP INDEX IF EXISTS kwil.idx_department_name_id;`,
		},
		{
			name: "window function",
			sql:  `SELECT col1, col2, row_number() OVER (PARTITION BY col1 ORDER BY col2) FROM tbl;`,
			want: `SELECT col1, col2, row_number() OVER (PARTITION BY col1 ORDER BY col2) FROM tbl;`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			require.Len(t, parsed, 1)

			got, ps, err := pggenerate.GenerateSQL(parsed[0], "kwil", func(varName string) (dataType *types.DataType, err error) {
				v, ok := tt.variables[varName]
				if !ok {
					return nil, fmt.Errorf("variable %s not found", varName)
				}

				return v, nil
			})
			if err != nil {
				if !tt.wantErr {
					require.NoError(t, err)
				}
				return
			} else {
				require.Equal(t, tt.wantErr, false)
			}

			require.Equal(t, removeWhitespace(tt.want), removeWhitespace(got))
			require.EqualValues(t, tt.params, ps)
		})
	}
}

func removeWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1 // skip this rune
		}
		return r
	}, s)
}

func Test_OrderByScalarFunctionRejection(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "scalar function with ORDER BY should be rejected",
			sql:     "SELECT lower(name ORDER BY id) FROM users;",
			wantErr: true,
			errMsg:  "ORDER BY is only supported inside aggregate function calls (got lower)",
		},
		{
			name:    "scalar function with multiple ORDER BY terms should be rejected",
			sql:     "SELECT upper(name ORDER BY age DESC, id ASC) FROM users;",
			wantErr: true,
			errMsg:  "ORDER BY is only supported inside aggregate function calls (got upper)",
		},
		{
			name:    "scalar function without ORDER BY should work",
			sql:     "SELECT lower(name) FROM users;",
			wantErr: false,
		},
		{
			name:    "aggregate function with ORDER BY should work",
			sql:     "SELECT array_agg(name ORDER BY id) FROM users;",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			require.Len(t, stmts, 1)

			_, _, err = pggenerate.GenerateSQL(stmts[0], "kwil", func(varName string) (*types.DataType, error) {
				return types.TextType, nil
			})

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func Test_OrderBySafeInsertion(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want string
	}{
		{
			name: "aggregate with explicit ORDER BY replaces default",
			sql:  "SELECT array_agg(name ORDER BY id DESC) FROM users;",
			want: "\nSELECT array_agg(name ORDER BY id DESC)\nFROM users\n;",
		},
		{
			name: "aggregate with multiple ORDER BY terms",
			sql:  "SELECT array_agg(name ORDER BY age DESC, name ASC) FROM users;",
			want: "\nSELECT array_agg(name ORDER BY age DESC, name ASC)\nFROM users\n;",
		},
		{
			name: "aggregate without explicit ORDER BY uses default",
			sql:  "SELECT array_agg(name) FROM users;",
			want: "\nSELECT array_agg(name ORDER BY name)\nFROM users\n;",
		},
		{
			name: "count aggregate with query-level ORDER BY",
			sql:  "SELECT count(*) FROM users ORDER BY id;",
			want: "\nSELECT count(*)\nFROM users\nORDER BY id;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			require.Len(t, stmts, 1)

			got, params, err := pggenerate.GenerateSQL(stmts[0], "kwil", func(varName string) (*types.DataType, error) {
				return types.TextType, nil
			})
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, []string(nil), params)
		})
	}
}

// Test_OrderByPassedToAggregateFormat checks that the ORDER BY terms of an
// aggregate call are rendered from the AST and passed to the aggregate's
// format function, and that the generator uses its result as is.
func Test_OrderByPassedToAggregateFormat(t *testing.T) {
	const fnName = "test_order_by_terms"

	var gotInputs, gotOrderBy []string
	var gotDistinct bool
	engine.Functions[fnName] = &engine.AggregateFunctionDefinition{
		ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
			return types.TextType, nil
		},
		PGFormatFunc: func(inputs []string, distinct bool, orderBy []string) (string, error) {
			gotInputs, gotDistinct, gotOrderBy = inputs, distinct, orderBy
			return "test_aggregate", nil
		},
	}
	defer delete(engine.Functions, fnName)

	generate := func(t *testing.T, sql string) (string, []string) {
		stmts, err := parse.Parse(sql)
		require.NoError(t, err)
		require.Len(t, stmts, 1)

		got, params, err := pggenerate.GenerateSQL(stmts[0], "kwil", func(varName string) (*types.DataType, error) {
			return types.TextType, nil
		})
		require.NoError(t, err)
		return got, params
	}

	t.Run("with ORDER BY", func(t *testing.T) {
		got, params := generate(t, "SELECT "+fnName+"(DISTINCT $a, 'x' ORDER BY $b DESC NULLS LAST, lower(name)) FROM users;")
		require.Equal(t, "\nSELECT test_aggregate\nFROM users\n;", got)
		require.True(t, gotDistinct)
		require.Equal(t, []string{"$1::TEXT", "'x'"}, gotInputs)
		require.Equal(t, []string{"$2::TEXT DESC NULLS LAST", "lower(name)"}, gotOrderBy)
		// the arguments are numbered before the ORDER BY terms
		require.Equal(t, []string{"$a", "$b"}, params)
	})

	t.Run("without ORDER BY", func(t *testing.T) {
		got, params := generate(t, "SELECT "+fnName+"(name) FROM users;")
		require.Equal(t, "\nSELECT test_aggregate\nFROM users\n;", got)
		require.False(t, gotDistinct)
		require.Equal(t, []string{"name"}, gotInputs)
		require.Empty(t, gotOrderBy)
		require.Empty(t, params)
	})
}

// Test_OrderByStringLiteralArgs checks that an explicit ORDER BY inside an
// aggregate call leaves string literal arguments intact when their text
// contains the words ORDER BY, a quote or a parenthesis.
func Test_OrderByStringLiteralArgs(t *testing.T) {
	getVar := func(varName string) (*types.DataType, error) {
		return types.TextType, nil
	}

	tests := []struct {
		name string
		sql  string
		want string
	}{
		{
			name: "array_agg literal containing ORDER BY",
			sql:  "SELECT array_agg('a ORDER BY b' ORDER BY id) FROM users;",
			want: "\nSELECT array_agg('a ORDER BY b' ORDER BY id)\nFROM users\n;",
		},
		{
			name: "array_agg literal containing ORDER BY followed by another literal",
			sql:  "SELECT array_agg('a ORDER BY b' ORDER BY id) FROM users WHERE name = 'c';",
			want: "\nSELECT array_agg('a ORDER BY b' ORDER BY id)\nFROM users\nWHERE name = 'c'\n;",
		},
		{
			name: "string_agg literal containing ORDER BY",
			sql:  "SELECT string_agg('a ORDER BY b', ', ' ORDER BY id) FROM users;",
			want: "\nSELECT string_agg('a ORDER BY b', ', ' ORDER BY id)\nFROM users\n;",
		},
		{
			name: "array_agg literal containing an open parenthesis",
			sql:  "SELECT array_agg('(' ORDER BY id) FROM users;",
			want: "\nSELECT array_agg('(' ORDER BY id)\nFROM users\n;",
		},
		{
			name: "array_agg literal containing a close parenthesis",
			sql:  "SELECT array_agg(')' ORDER BY id) FROM users;",
			want: "\nSELECT array_agg(')' ORDER BY id)\nFROM users\n;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			require.Len(t, stmts, 1)

			got, params, err := pggenerate.GenerateSQL(stmts[0], "kwil", getVar)
			require.NoError(t, err)
			// Each literal is written with its inner quotes doubled, so a
			// complete statement always holds an even number of quotes.
			require.Zero(t, strings.Count(got, "'")%2, "unterminated string literal in %q", got)
			require.Equal(t, tt.want, got)
			require.Empty(t, params)
		})
	}

	// A literal whose value holds a quote is written with that quote doubled.
	t.Run("array_agg literal containing a quote and ORDER BY", func(t *testing.T) {
		call := &parse.ExpressionFunctionCall{
			Name: "array_agg",
			Args: []parse.Expression{
				&parse.ExpressionLiteral{Type: types.TextType, Value: "it's ORDER BY b"},
			},
			OrderBy: []*parse.OrderingTerm{
				{Expression: &parse.ExpressionColumn{Column: "id"}},
			},
		}

		got, params, err := pggenerate.GenerateSQL(call, "kwil", getVar)
		require.NoError(t, err)
		require.Zero(t, strings.Count(got, "'")%2, "unterminated string literal in %q", got)
		require.Equal(t, "array_agg('it''s ORDER BY b' ORDER BY id);", got)
		require.Empty(t, params)
	})
}

// Test_StringLiteralTextStaysInLiteral checks that SQL text inside a string
// literal stays inside that literal in the generated SQL, in a plain select
// list and in aggregate calls with and without their own ORDER BY.
func Test_StringLiteralTextStaysInLiteral(t *testing.T) {
	getVar := func(varName string) (*types.DataType, error) {
		return types.TextType, nil
	}

	literals := []struct {
		name string
		kwil string // the literal as written in the statement
		pg   string // the literal as written in the generated SQL
	}{
		{name: "quote", kwil: `'it\'s'`, pg: `'it\''s'`},
		{name: "ORDER BY", kwil: "'a ORDER BY b'", pg: "'a ORDER BY b'"},
		{name: "GROUP BY", kwil: "'a GROUP BY b'", pg: "'a GROUP BY b'"},
		{name: "SQL keywords", kwil: "'SELECT a FROM b WHERE c UNION SELECT d'", pg: "'SELECT a FROM b WHERE c UNION SELECT d'"},
		{name: "ORDER BY inside parentheses", kwil: "'x) ORDER BY (y'", pg: "'x) ORDER BY (y'"},
		{name: "semicolon", kwil: "'a; b'", pg: "'a; b'"},
		{name: "dollar quotes", kwil: "'$$ a $$'", pg: "'$$ a $$'"},
		{name: "tagged dollar quotes", kwil: "'$tag$ a $tag$'", pg: "'$tag$ a $tag$'"},
		{name: "parameter marker", kwil: "'$1'", pg: "'$1'"},
		{name: "line comment", kwil: "'a -- b'", pg: "'a -- b'"},
		{name: "line comment after a newline", kwil: "'a\n-- b'", pg: "'a\n-- b'"},
		{name: "block comment", kwil: "'a /* b */'", pg: "'a /* b */'"},
		{name: "unclosed block comment", kwil: "'a /* b'", pg: "'a /* b'"},
		{name: "parentheses", kwil: "') ('", pg: "') ('"},
		{name: "quotes around ORDER BY", kwil: `'\' ORDER BY \''`, pg: `'\'' ORDER BY \'''`},
		{name: "trailing backslashes", kwil: `'a\\'`, pg: `'a\\'`},
		{name: "backslashes before a quote", kwil: `'a\\\' b'`, pg: `'a\\\'' b'`},
		{name: "backslashes, a quote and ORDER BY", kwil: `'\\\' ORDER BY id) --'`, pg: `'\\\'' ORDER BY id) --'`},
		{name: "double quotes", kwil: `'"a" b'`, pg: `'"a" b'`},
		{name: "empty", kwil: "''", pg: "''"},
	}

	contexts := []struct {
		name string
		sql  string // %[1]s is the literal as written in the statement
		want string // %[1]s is the literal as written in the generated SQL
	}{
		{
			name: "select list",
			sql:  "SELECT %[1]s, id FROM users WHERE name = 'c';",
			want: "\nSELECT %[1]s, id\nFROM users\nWHERE name = 'c'\n;",
		},
		{
			name: "array_agg",
			sql:  "SELECT array_agg(%[1]s) FROM users WHERE name = 'c';",
			want: "\nSELECT array_agg(%[1]s ORDER BY %[1]s)\nFROM users\nWHERE name = 'c'\n;",
		},
		{
			name: "array_agg with ORDER BY",
			sql:  "SELECT array_agg(%[1]s ORDER BY id) FROM users WHERE name = 'c';",
			want: "\nSELECT array_agg(%[1]s ORDER BY id)\nFROM users\nWHERE name = 'c'\n;",
		},
		{
			name: "array_agg DISTINCT with ORDER BY",
			sql:  "SELECT array_agg(DISTINCT name || %[1]s ORDER BY name || %[1]s DESC) FROM users;",
			want: "\nSELECT array_agg(DISTINCT name || %[1]s ORDER BY name || %[1]s DESC)\nFROM users\n;",
		},
		{
			name: "string_agg with ORDER BY",
			sql:  "SELECT string_agg(name || %[1]s, %[1]s ORDER BY id, name) FROM users WHERE name = 'c';",
			want: "\nSELECT string_agg(name || %[1]s, %[1]s ORDER BY id, name)\nFROM users\nWHERE name = 'c'\n;",
		},
		{
			name: "count with ORDER BY",
			sql:  "SELECT count(%[1]s ORDER BY id) FROM users;",
			want: "\nSELECT count(%[1]s ORDER BY id)\nFROM users\n;",
		},
		{
			name: "max with ORDER BY and a cast",
			sql:  "SELECT max(coalesce(name, %[1]s) ORDER BY id)::TEXT FROM users;",
			want: "\nSELECT max(coalesce(name, %[1]s) ORDER BY id)::TEXT\nFROM users\n;",
		},
		{
			name: "aggregate ORDER BY term",
			sql:  "SELECT array_agg(name ORDER BY %[1]s) FROM users;",
			want: "\nSELECT array_agg(name ORDER BY %[1]s)\nFROM users\n;",
		},
	}

	for _, lit := range literals {
		for _, c := range contexts {
			t.Run(lit.name+"/"+c.name, func(t *testing.T) {
				stmts, err := parse.Parse(fmt.Sprintf(c.sql, lit.kwil))
				require.NoError(t, err)
				require.Len(t, stmts, 1)

				got, params, err := pggenerate.GenerateSQL(stmts[0], "kwil", getVar)
				require.NoError(t, err)
				require.Equal(t, fmt.Sprintf(c.want, lit.pg), got)
				require.Empty(t, params)
				requireLiteralsIntact(t, got, lit.pg, "'c'")
			})
		}
	}

	// A literal value built in the AST can hold a bare quote, which is
	// written doubled, and a single backslash, which is written as is.
	for _, value := range []string{"it's", "a' ORDER BY b", "') ORDER BY ('", "a'; b", `a\`, `\' ORDER BY ('`, `$$') -- `} {
		pg := "'" + strings.ReplaceAll(value, "'", "''") + "'"
		lit := func() parse.Expression {
			return &parse.ExpressionLiteral{Type: types.TextType, Value: value}
		}
		orderByID := []*parse.OrderingTerm{{Expression: &parse.ExpressionColumn{Column: "id"}}}

		calls := []struct {
			name string
			call parse.Node
			want string
		}{
			{
				name: "array_agg with ORDER BY",
				call: &parse.ExpressionFunctionCall{Name: "array_agg", Args: []parse.Expression{lit()}, OrderBy: orderByID},
				want: "array_agg(" + pg + " ORDER BY id);",
			},
			{
				name: "string_agg with ORDER BY",
				call: &parse.ExpressionFunctionCall{Name: "string_agg", Args: []parse.Expression{lit(), lit()}, OrderBy: orderByID},
				want: "string_agg(" + pg + ", " + pg + " ORDER BY id);",
			},
			{
				name: "array_agg",
				call: &parse.ExpressionFunctionCall{Name: "array_agg", Args: []parse.Expression{lit()}},
				want: "array_agg(" + pg + " ORDER BY " + pg + ");",
			},
			{
				name: "literal",
				call: lit(),
				want: pg + ";",
			},
		}
		for _, c := range calls {
			t.Run(fmt.Sprintf("value %q/%s", value, c.name), func(t *testing.T) {
				got, params, err := pggenerate.GenerateSQL(c.call, "kwil", getVar)
				require.NoError(t, err)
				require.Equal(t, c.want, got)
				require.Empty(t, params)
				requireLiteralsIntact(t, got, pg)
			})
		}
	}
}

// Test_PlannedAggregateKeepsLiterals plans statements the way the engine does
// before it generates their SQL, with the default ordering that is applied
// when a statement may change state, and checks the generated SQL.
func Test_PlannedAggregateKeepsLiterals(t *testing.T) {
	users := &engine.Table{
		Name: "users",
		Columns: []*engine.Column{
			{Name: "id", DataType: types.IntType, IsPrimaryKey: true},
			{Name: "name", DataType: types.TextType},
		},
	}
	getVar := func(varName string) (*types.DataType, error) {
		return nil, engine.ErrUnknownVariable
	}

	tests := []struct {
		name string
		sql  string
		want string
	}{
		{
			name: "array_agg",
			sql:  "SELECT array_agg('a ORDER BY b' ORDER BY id) FROM users WHERE name = 'c';",
			want: "\nSELECT array_agg('a ORDER BY b' ORDER BY id)\nFROM kwil.users\nWHERE name = 'c'\nORDER BY 1;",
		},
		{
			name: "string_agg with GROUP BY",
			sql:  "SELECT name, string_agg(name || '; -- ', ' ORDER BY ' ORDER BY id DESC) FROM users GROUP BY name;",
			want: "\nSELECT name, string_agg(name || '; -- ', ' ORDER BY ' ORDER BY id DESC)\nFROM kwil.users\nGROUP BY name\nORDER BY 1, 2;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			require.Len(t, stmts, 1)
			stmt, ok := stmts[0].(*parse.SQLStatement)
			require.True(t, ok)

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
				true,
				"kwil",
			)
			require.NoError(t, err)

			got, params, err := pggenerate.GenerateSQL(stmt, "kwil", getVar)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Empty(t, params)
		})
	}
}

// requireLiteralsIntact splits generated SQL into its string literals and the
// text between them. It checks that every literal is closed and is one of
// the allowed literals, and that no statement separator or comment marker
// appears between literals, other than the final semicolon.
func requireLiteralsIntact(t *testing.T, sql string, allowed ...string) {
	t.Helper()

	var outside strings.Builder
	for i := 0; i < len(sql); i++ {
		if sql[i] != '\'' {
			outside.WriteByte(sql[i])
			continue
		}

		// the literal ends at the next quote that is not doubled
		end := -1
		for j := i + 1; j < len(sql); j++ {
			if sql[j] != '\'' {
				continue
			}
			if j+1 < len(sql) && sql[j+1] == '\'' {
				j++
				continue
			}
			end = j
			break
		}
		require.NotEqual(t, -1, end, "unterminated string literal in %q", sql)
		require.Contains(t, allowed, sql[i:end+1], "unexpected string literal in %q", sql)
		outside.WriteString("?")
		i = end
	}

	between := strings.TrimSuffix(outside.String(), ";")
	for _, marker := range []string{";", "--", "/*", "*/", "$$"} {
		require.NotContains(t, between, marker, "%q outside string literals in %q", marker, sql)
	}
}
