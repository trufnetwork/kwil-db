package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
	pggenerate "github.com/trufnetwork/kwil-db/node/engine/pg_generate"
)

func TestUNNESTIntegration(t *testing.T) {
	tests := []struct {
		name             string
		sql              string
		expectedContains []string
	}{
		{
			name:             "basic UNNEST with column aliases",
			sql:              "SELECT * FROM UNNEST($stream_ids, $stream_types) AS t(stream_id, stream_type)",
			expectedContains: []string{"UNNEST(", "AS t(stream_id, stream_type)"},
		},
		{
			name:             "UNNEST with WHERE clause",
			sql:              "SELECT id, type FROM UNNEST($ids, $types) AS t(id, type) WHERE id > 10",
			expectedContains: []string{"UNNEST(", "WHERE id > 10"},
		},
		{
			name:             "single array UNNEST",
			sql:              "SELECT value FROM UNNEST($array) AS t(value)",
			expectedContains: []string{"UNNEST(", "AS t(value)"},
		},
		{
			name:             "UNNEST with JOIN",
			sql:              "SELECT u.id, u.name, p.value FROM users u JOIN UNNEST($values) AS p(value) ON u.id = p.value",
			expectedContains: []string{"UNNEST(", "JOIN", "ON"},
		},
		{
			name:             "complex UNNEST replacing recursive CTE pattern",
			sql:              "SELECT stream_id, stream_type FROM UNNEST($stream_ids, $stream_types) AS t(stream_id, stream_type) WHERE stream_type = 'active'",
			expectedContains: []string{"UNNEST($1::INT8[], $2::TEXT[])", "AS t(stream_id, stream_type)", "WHERE stream_type = 'active'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the SQL
			stmts, err := parse.Parse(tt.sql)
			assert.NoError(t, err, "Failed to parse SQL: %s", tt.sql)
			assert.Len(t, stmts, 1, "Should parse exactly one statement")

			stmt := stmts[0]

			// Mock variable types for SQL generation
			getVar := func(varName string) (*types.DataType, error) {
				switch varName {
				case "$stream_ids", "$ids", "$array", "$values":
					return &types.DataType{Name: "int8", IsArray: true}, nil
				case "$stream_types", "$types":
					return &types.DataType{Name: "text", IsArray: true}, nil
				default:
					return &types.DataType{Name: "text"}, nil
				}
			}

			// Generate PostgreSQL SQL
			generatedSQL, params, err := pggenerate.GenerateSQL(stmt, "test_schema", getVar)
			assert.NoError(t, err, "Failed to generate SQL")
			assert.NotEmpty(t, generatedSQL, "Generated SQL should not be empty")
			assert.NotEmpty(t, params, "Should have parameters")

			// Verify the generated SQL contains expected components
			for _, expected := range tt.expectedContains {
				assert.Contains(t, generatedSQL, expected,
					"Generated SQL should contain '%s'.\nOriginal: %s\nGenerated: %s",
					expected, tt.sql, generatedSQL)
			}

			t.Logf("✅ Original: %s", tt.sql)
			t.Logf("✅ Generated: %s", generatedSQL)
			t.Logf("✅ Parameters: %v", params)
		})
	}
}

func TestUNNESTASTStructure(t *testing.T) {
	sql := "SELECT * FROM UNNEST($ids, $types) AS t(id, type_name)"

	stmts, err := parse.Parse(sql)
	assert.NoError(t, err)
	assert.Len(t, stmts, 1)

	stmt := stmts[0]

	// Navigate to the FROM clause to find the table function
	sqlStmt, ok := stmt.(*parse.SQLStatement)
	assert.True(t, ok, "Should be SQLStatement")

	selectStmt, ok := sqlStmt.SQL.(*parse.SelectStatement)
	assert.True(t, ok, "Should be SelectStatement")

	selectCore := selectStmt.SelectCores[0]
	assert.NotNil(t, selectCore.From, "Should have FROM clause")

	// Check if the FROM clause contains our table function
	tableFuncRel, ok := selectCore.From.(*parse.RelationTableFunction)
	assert.True(t, ok, "Should be RelationTableFunction")

	// Verify function details
	assert.Equal(t, "unnest", tableFuncRel.FunctionCall.Name, "Function name should be 'unnest'")
	assert.Len(t, tableFuncRel.FunctionCall.Args, 2, "Should have 2 arguments")
	assert.Equal(t, "t", tableFuncRel.Alias, "Table alias should be 't'")
	assert.Len(t, tableFuncRel.ColumnAliases, 2, "Should have 2 column aliases")
	assert.Equal(t, "id", tableFuncRel.ColumnAliases[0], "First column alias should be 'id'")
	assert.Equal(t, "type_name", tableFuncRel.ColumnAliases[1], "Second column alias should be 'type_name'")
}

func TestUNNESTErrorHandling(t *testing.T) {
	// Test syntax errors that should fail at parse time
	syntaxErrorCases := []struct {
		name string
		sql  string
	}{
		{
			name: "UNNEST with no arguments",
			sql:  "SELECT * FROM UNNEST() AS t",
		},
	}

	for _, tc := range syntaxErrorCases {
		t.Run("syntax_error_"+tc.name, func(t *testing.T) {
			_, err := parse.Parse(tc.sql)
			// Should fail during parsing due to syntax error
			assert.Error(t, err, "Should fail with syntax error for: %s", tc.sql)
		})
	}

	// Test valid syntax that would fail during semantic analysis
	validSyntaxCases := []struct {
		name string
		sql  string
	}{
		{
			name: "UNNEST with non-array variable",
			sql:  "SELECT * FROM UNNEST($not_an_array) AS t",
		},
	}

	for _, tc := range validSyntaxCases {
		t.Run("valid_syntax_"+tc.name, func(t *testing.T) {
			stmts, err := parse.Parse(tc.sql)
			// Should parse successfully - type errors happen during planning
			assert.NoError(t, err, "Should parse successfully: %s", tc.sql)
			assert.Len(t, stmts, 1, "Should have one statement")
		})
	}
}

func TestUNNESTRealWorldScenarios(t *testing.T) {
	// Test the exact use case from the GitHub issue
	t.Run("github_issue_use_case", func(t *testing.T) {
		// This is the complex recursive CTE that UNNEST should replace
		complexSQL := `WITH RECURSIVE
		indexes AS (
		    SELECT 1 AS idx
		    UNION ALL
		    SELECT idx + 1 FROM indexes
		    WHERE idx < array_length($stream_ids)
		),
		stream_arrays AS (
		    SELECT
		        $stream_ids AS stream_ids,
		        $stream_types AS stream_types
		),
		arguments AS (
		  SELECT
		      idx,
		      stream_arrays.stream_ids[idx] AS stream_id,
		      stream_arrays.stream_types[idx] AS stream_type
		  FROM indexes
		  JOIN stream_arrays ON 1=1
		)
		SELECT stream_id, stream_type FROM arguments`

		// This is the simple UNNEST replacement
		simpleSQL := "SELECT stream_id, stream_type FROM UNNEST($stream_ids, $stream_types) AS t(stream_id, stream_type)"

		// Both should parse successfully
		complexStmts, err := parse.Parse(complexSQL)
		assert.NoError(t, err, "Complex recursive CTE should parse")
		assert.Len(t, complexStmts, 1)

		simpleStmts, err := parse.Parse(simpleSQL)
		assert.NoError(t, err, "Simple UNNEST should parse")
		assert.Len(t, simpleStmts, 1)

		// Generate SQL for both
		getVar := func(varName string) (*types.DataType, error) {
			switch varName {
			case "$stream_ids":
				return &types.DataType{Name: "int8", IsArray: true}, nil
			case "$stream_types":
				return &types.DataType{Name: "text", IsArray: true}, nil
			default:
				return &types.DataType{Name: "text"}, nil
			}
		}

		complexGenerated, _, err := pggenerate.GenerateSQL(complexStmts[0], "test", getVar)
		assert.NoError(t, err, "Complex SQL should generate")

		simpleGenerated, _, err := pggenerate.GenerateSQL(simpleStmts[0], "test", getVar)
		assert.NoError(t, err, "Simple SQL should generate")

		t.Logf("📊 Complex recursive CTE length: %d characters", len(complexSQL))
		t.Logf("🚀 Simple UNNEST length: %d characters", len(simpleSQL))
		t.Logf("💡 Code reduction: %.1f%%", float64(len(complexSQL)-len(simpleSQL))/float64(len(complexSQL))*100)

		// The simple version should be much shorter and more readable
		assert.True(t, len(simpleSQL) < len(complexSQL)/3, "UNNEST should be significantly shorter than recursive CTE")
		assert.Contains(t, simpleGenerated, "UNNEST(", "Generated SQL should use UNNEST")

		t.Logf("✅ Complex generated: %s", complexGenerated)
		t.Logf("✅ Simple generated: %s", simpleGenerated)
	})
}
