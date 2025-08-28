package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
	pggenerate "github.com/trufnetwork/kwil-db/node/engine/pg_generate"
)

func TestGenerateSubscriptsIntegration(t *testing.T) {
	tests := []struct {
		name             string
		sql              string
		expectedContains []string
	}{
		{
			name:             "basic generate_subscripts",
			sql:              "SELECT * FROM generate_subscripts($stream_ids) AS t(idx)",
			expectedContains: []string{"generate_subscripts(", "AS t(idx)"},
		},
		{
			name:             "generate_subscripts with WHERE clause",
			sql:              "SELECT idx FROM generate_subscripts($ids) AS t(idx) WHERE idx > 2",
			expectedContains: []string{"generate_subscripts(", "WHERE idx > 2"},
		},
		{
			name:             "generate_subscripts with JOIN",
			sql:              "SELECT u.id, gs.idx FROM users u JOIN generate_subscripts($values) AS gs(idx) ON u.id = gs.idx",
			expectedContains: []string{"generate_subscripts(", "JOIN", "ON"},
		},
		{
			name:             "generate_subscripts replacing row_number pattern",
			sql:              "SELECT LOWER($input_array[idx]) FROM generate_subscripts($input_array) AS t(idx)",
			expectedContains: []string{"generate_subscripts(", "AS t(idx)"},
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
				case "$stream_ids", "$ids", "$values", "$input_array":
					return &types.DataType{Name: "int8", IsArray: true}, nil
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

func TestGenerateSubscriptsASTStructure(t *testing.T) {
	sql := "SELECT * FROM generate_subscripts($ids) AS t(idx)"

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
	assert.Equal(t, "generate_subscripts", tableFuncRel.FunctionCall.Name, "Function name should be 'generate_subscripts'")
	assert.Len(t, tableFuncRel.FunctionCall.Args, 1, "Should have 1 argument")
	assert.Equal(t, "t", tableFuncRel.Alias, "Table alias should be 't'")
	assert.Len(t, tableFuncRel.ColumnAliases, 1, "Should have 1 column alias")
	assert.Equal(t, "idx", tableFuncRel.ColumnAliases[0], "Column alias should be 'idx'")
}

func TestGenerateSubscriptsErrorHandling(t *testing.T) {
	// Test syntax errors that should fail at parse time
	syntaxErrorCases := []struct {
		name string
		sql  string
	}{
		{
			name: "generate_subscripts with no arguments",
			sql:  "SELECT * FROM generate_subscripts() AS t",
		},
	}

	for _, tc := range syntaxErrorCases {
		t.Run("syntax_error_"+tc.name, func(t *testing.T) {
			_, err := parse.Parse(tc.sql)
			// Should fail during parsing due to syntax error
			assert.Error(t, err, "Should fail with syntax error for: %s", tc.sql)
		})
	}

	// Note: Semantic validation (like argument count) happens during planning phase,
	// which is not triggered by our current test setup. We focus on syntax validation here.

	// Test valid syntax that would fail during semantic analysis
	validSyntaxCases := []struct {
		name string
		sql  string
	}{
		{
			name: "generate_subscripts with non-array variable",
			sql:  "SELECT * FROM generate_subscripts($not_an_array) AS t",
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

func TestGenerateSubscriptsRealWorldScenarios(t *testing.T) {
	// Test the exact use case from the GitHub issue - replacing row_number patterns
	t.Run("array_processing_replacement", func(t *testing.T) {
		// This is the simple generate_subscripts replacement
		newPattern := "SELECT LOWER($input_array[idx]) FROM generate_subscripts($input_array) AS t(idx)"

		newStmts, err := parse.Parse(newPattern)
		assert.NoError(t, err, "New pattern should parse")
		assert.Len(t, newStmts, 1)

		// Generate SQL for the new pattern
		getVar := func(varName string) (*types.DataType, error) {
			switch varName {
			case "$input_array":
				return &types.DataType{Name: "text", IsArray: true}, nil
			default:
				return &types.DataType{Name: "text"}, nil
			}
		}

		newGenerated, _, err := pggenerate.GenerateSQL(newStmts[0], "test", getVar)
		assert.NoError(t, err, "New pattern should generate")

		// Verify the generated SQL contains the expected components
		assert.Contains(t, newGenerated, "generate_subscripts(", "Generated SQL should use generate_subscripts")
		assert.Contains(t, newGenerated, "lower(", "Generated SQL should use lower function")
		assert.Contains(t, newGenerated, "[idx]", "Generated SQL should use array indexing")

		t.Logf("✅ New pattern: %s", newPattern)
		t.Logf("✅ New pattern generated: %s", newGenerated)
	})

	// Test the actual refactoring from 018-fix-array-ordering-get-stream-ids.sql
	t.Run("get_stream_ids_refactoring", func(t *testing.T) {
		// This is the refactored version using generate_subscripts
		refactoredPattern := `
		WITH joined AS (
			SELECT gs.idx, s.id AS stream_id_resolved
			FROM generate_subscripts($data_providers) AS gs(idx)
			LEFT JOIN data_providers d ON d.address = LOWER($data_providers[gs.idx])
			LEFT JOIN streams s ON s.data_provider_id = d.id AND s.stream_id = $stream_ids[gs.idx]
			ORDER BY gs.idx
		)
		SELECT array_agg(stream_id_resolved)
		FROM joined`

		stmts, err := parse.Parse(refactoredPattern)
		assert.NoError(t, err, "Refactored pattern should parse")
		assert.Len(t, stmts, 1)

		// Generate SQL for the refactored pattern
		getVar := func(varName string) (*types.DataType, error) {
			switch varName {
			case "$data_providers", "$stream_ids":
				return &types.DataType{Name: "text", IsArray: true}, nil
			default:
				return &types.DataType{Name: "text"}, nil
			}
		}

		generated, _, err := pggenerate.GenerateSQL(stmts[0], "test", getVar)
		assert.NoError(t, err, "Refactored pattern should generate")

		// Verify the generated SQL contains the expected components
		assert.Contains(t, generated, "generate_subscripts(", "Generated SQL should use generate_subscripts")
		assert.Contains(t, generated, "array_agg(", "Generated SQL should use array_agg")
		assert.Contains(t, generated, "[gs.idx]", "Generated SQL should use array indexing")

		t.Logf("✅ Refactored pattern generated:")
		t.Logf("%s", generated)
	})

	// Test the refactoring from 901-utilities.sql helper_lowercase_array
	t.Run("helper_lowercase_array_refactoring", func(t *testing.T) {
		// This is the refactored version of helper_lowercase_array using subquery with explicit ordering
		refactoredPattern := `SELECT array_agg(lowered ORDER BY row_num) FROM (
			SELECT
				LOWER($input_array[gs.idx]) AS lowered,
				gs.idx AS row_num
			FROM generate_subscripts($input_array) AS gs(idx)
			ORDER BY gs.idx
		) t`

		stmts, err := parse.Parse(refactoredPattern)
		assert.NoError(t, err, "Refactored pattern should parse")
		assert.Len(t, stmts, 1)

		// Generate SQL for the refactored pattern
		getVar := func(varName string) (*types.DataType, error) {
			switch varName {
			case "$input_array":
				return &types.DataType{Name: "text", IsArray: true}, nil
			default:
				return &types.DataType{Name: "text"}, nil
			}
		}

		generated, _, err := pggenerate.GenerateSQL(stmts[0], "test", getVar)
		assert.NoError(t, err, "Refactored pattern should generate")

		// Verify the generated SQL contains the expected components
		assert.Contains(t, generated, "generate_subscripts(", "Generated SQL should use generate_subscripts")
		assert.Contains(t, generated, "array_agg(", "Generated SQL should use array_agg")
		assert.Contains(t, generated, "lower(", "Generated SQL should use lower function")
		assert.Contains(t, generated, "[gs.idx]", "Generated SQL should use array indexing")
		assert.Contains(t, generated, "ORDER BY row_num", "Generated SQL should preserve order by row_num")
		assert.Contains(t, generated, "ORDER BY gs.idx", "Generated SQL should have subquery ordering")

		t.Logf("✅ helper_lowercase_array refactored:")
		t.Logf("%s", generated)
	})
}
