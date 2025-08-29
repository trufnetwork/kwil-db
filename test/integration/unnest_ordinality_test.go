package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
	pggenerate "github.com/trufnetwork/kwil-db/node/engine/pg_generate"
)

func TestUNNESTWithOrdinalityIntegration(t *testing.T) {
	tests := []struct {
		name             string
		sql              string
		expectedContains []string
	}{
		{
			name:             "single array UNNEST with ordinality",
			sql:              "SELECT * FROM UNNEST($items) WITH ORDINALITY AS t(item, ord)",
			expectedContains: []string{"UNNEST(", "WITH ORDINALITY", "AS t(item, ord)"},
		},
		{
			name:             "single array UNNEST with ordinality, no aliases",
			sql:              "SELECT * FROM UNNEST($items) WITH ORDINALITY AS t",
			expectedContains: []string{"UNNEST(", "WITH ORDINALITY", "AS t"},
		},
		{
			name:             "multiple arrays UNNEST with ordinality",
			sql:              "SELECT * FROM UNNEST($names, $ages) WITH ORDINALITY AS t(name, age, ord)",
			expectedContains: []string{"UNNEST(", "WITH ORDINALITY", "AS t(name, age, ord)"},
		},
		{
			name:             "UNNEST with ordinality and WHERE clause",
			sql:              "SELECT item, ord FROM UNNEST($array) WITH ORDINALITY AS t(item, ord) WHERE ord > 2",
			expectedContains: []string{"UNNEST(", "WITH ORDINALITY", "WHERE ord > 2"},
		},
		{
			name:             "UNNEST with ordinality and JOIN",
			sql:              "SELECT u.id, u.name, p.item, p.ord FROM users u JOIN UNNEST($values) WITH ORDINALITY AS p(item, ord) ON u.id = p.ord",
			expectedContains: []string{"UNNEST(", "WITH ORDINALITY", "JOIN", "ON"},
		},
		{
			name:             "UNNEST without ordinality (regression test)",
			sql:              "SELECT * FROM UNNEST($items) AS t(item)",
			expectedContains: []string{"UNNEST(", "AS t(item)"},
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
				case "$items", "$array", "$values":
					return &types.DataType{Name: "text", IsArray: true}, nil
				case "$names":
					return &types.DataType{Name: "text", IsArray: true}, nil
				case "$ages":
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

			// For ordinality tests, ensure WITH ORDINALITY is NOT in non-ordinality tests
			if !contains(tt.expectedContains, "WITH ORDINALITY") {
				assert.NotContains(t, generatedSQL, "WITH ORDINALITY",
					"Generated SQL should NOT contain 'WITH ORDINALITY' for non-ordinality test: %s", tt.name)
			}

			t.Logf("✅ Original: %s", tt.sql)
			t.Logf("✅ Generated: %s", generatedSQL)
			t.Logf("✅ Parameters: %v", params)
		})
	}
}

func TestUNNESTWithOrdinalityASTStructure(t *testing.T) {
	tests := []struct {
		name                   string
		sql                    string
		expectedWithOrdinality bool
		expectedColumnCount    int
		expectedAlias          string
	}{
		{
			name:                   "single array with ordinality and aliases",
			sql:                    "SELECT * FROM UNNEST($items) WITH ORDINALITY AS t(item, ord)",
			expectedWithOrdinality: true,
			expectedColumnCount:    2,
			expectedAlias:          "t",
		},
		{
			name:                   "multiple arrays with ordinality",
			sql:                    "SELECT * FROM UNNEST($names, $ages) WITH ORDINALITY AS t(name, age, ord)",
			expectedWithOrdinality: true,
			expectedColumnCount:    3,
			expectedAlias:          "t",
		},
		{
			name:                   "without ordinality",
			sql:                    "SELECT * FROM UNNEST($items) AS t(item)",
			expectedWithOrdinality: false,
			expectedColumnCount:    1,
			expectedAlias:          "t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts, err := parse.Parse(tt.sql)
			require.NoError(t, err)
			require.Len(t, stmts, 1)

			stmt := stmts[0]

			// Navigate to the FROM clause to find the table function
			sqlStmt, ok := stmt.(*parse.SQLStatement)
			require.True(t, ok, "Should be SQLStatement")

			selectStmt, ok := sqlStmt.SQL.(*parse.SelectStatement)
			require.True(t, ok, "Should be SelectStatement")

			selectCore := selectStmt.SelectCores[0]
			require.NotNil(t, selectCore.From, "Should have FROM clause")

			// Check if the FROM clause contains our table function
			tableFuncRel, ok := selectCore.From.(*parse.RelationTableFunction)
			require.True(t, ok, "Should be RelationTableFunction")

			// Verify ordinality flag
			assert.Equal(t, tt.expectedWithOrdinality, tableFuncRel.WithOrdinality,
				"WithOrdinality flag should match expected value")

			// Verify function details
			assert.Equal(t, "unnest", tableFuncRel.FunctionCall.Name, "Function name should be 'unnest'")
			// Check number of arguments based on the SQL
			expectedArgs := 1 // default for single array
			if tt.name == "multiple arrays with ordinality" {
				expectedArgs = 2 // multiple arrays
			}
			assert.Len(t, tableFuncRel.FunctionCall.Args, expectedArgs, "Should have correct number of arguments")
			assert.Equal(t, tt.expectedAlias, tableFuncRel.Alias, "Table alias should match")

			if tt.expectedWithOrdinality {
				assert.Len(t, tableFuncRel.ColumnAliases, tt.expectedColumnCount, "Should have correct number of column aliases")
				assert.Equal(t, "ord", tableFuncRel.ColumnAliases[tt.expectedColumnCount-1], "Last column alias should be 'ord'")
			} else {
				assert.Len(t, tableFuncRel.ColumnAliases, tt.expectedColumnCount, "Should have correct number of column aliases")
			}
		})
	}
}

func TestUNNESTWithOrdinalityErrorHandling(t *testing.T) {
	// Test that the parser correctly handles WITH ORDINALITY syntax
	validSyntaxCases := []struct {
		name string
		sql  string
	}{
		{
			name: "UNNEST with WITH ORDINALITY",
			sql:  "SELECT * FROM UNNEST($array) WITH ORDINALITY AS t",
		},
		{
			name: "UNNEST with WITH ORDINALITY and column aliases",
			sql:  "SELECT * FROM UNNEST($array) WITH ORDINALITY AS t(item, ord)",
		},
		{
			name: "Multiple UNNEST with WITH ORDINALITY",
			sql:  "SELECT * FROM UNNEST($a, $b) WITH ORDINALITY AS t(a, b, ord)",
		},
	}

	for _, tc := range validSyntaxCases {
		t.Run("valid_syntax_"+tc.name, func(t *testing.T) {
			stmts, err := parse.Parse(tc.sql)
			assert.NoError(t, err, "Should parse successfully: %s", tc.sql)
			assert.Len(t, stmts, 1, "Should have one statement")
		})
	}
}

func TestUNNESTWithOrdinalityRealWorldScenarios(t *testing.T) {
	t.Run("ordinality_for_array_indexing", func(t *testing.T) {
		// Use case: Get array elements with their positions
		sql := "SELECT item, ord FROM UNNEST($fruits) WITH ORDINALITY AS t(item, ord)"

		stmts, err := parse.Parse(sql)
		assert.NoError(t, err, "Should parse successfully")
		assert.Len(t, stmts, 1)

		getVar := func(varName string) (*types.DataType, error) {
			if varName == "$fruits" {
				return &types.DataType{Name: "text", IsArray: true}, nil
			}
			return &types.DataType{Name: "text"}, nil
		}

		generatedSQL, _, err := pggenerate.GenerateSQL(stmts[0], "test", getVar)
		assert.NoError(t, err, "Should generate SQL successfully")

		// Should contain WITH ORDINALITY in the generated SQL
		assert.Contains(t, generatedSQL, "WITH ORDINALITY", "Generated SQL should contain WITH ORDINALITY")
		assert.Contains(t, generatedSQL, "UNNEST($1::TEXT[])", "Should generate proper UNNEST call")
	})

	t.Run("ordinality_with_multiple_arrays", func(t *testing.T) {
		// Use case: Process multiple related arrays with position tracking
		sql := "SELECT name, age, ord FROM UNNEST($names, $ages) WITH ORDINALITY AS t(name, age, ord) WHERE ord <= 3"

		stmts, err := parse.Parse(sql)
		assert.NoError(t, err, "Should parse successfully")

		getVar := func(varName string) (*types.DataType, error) {
			switch varName {
			case "$names":
				return &types.DataType{Name: "text", IsArray: true}, nil
			case "$ages":
				return &types.DataType{Name: "int8", IsArray: true}, nil
			default:
				return &types.DataType{Name: "text"}, nil
			}
		}

		generatedSQL, _, err := pggenerate.GenerateSQL(stmts[0], "test", getVar)
		assert.NoError(t, err, "Should generate SQL successfully")

		assert.Contains(t, generatedSQL, "WITH ORDINALITY", "Should contain WITH ORDINALITY")
		assert.Contains(t, generatedSQL, "UNNEST($1::TEXT[], $2::INT8[])", "Should generate proper multi-array UNNEST")
		assert.Contains(t, generatedSQL, "WHERE ord <= 3", "Should include ordinality in WHERE clause")
	})
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
