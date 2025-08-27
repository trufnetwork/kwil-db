package interpreter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeQueryType(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		expected QueryType
	}{
		{
			name:     "simple select",
			sql:      "SELECT * FROM users",
			expected: QueryTypeSelect,
		},
		{
			name:     "with clause",
			sql:      "WITH RECURSIVE cte AS (SELECT 1) SELECT * FROM cte",
			expected: QueryTypeWith,
		},
		{
			name:     "insert statement",
			sql:      "INSERT INTO users (name) VALUES ('test')",
			expected: QueryTypeInsert,
		},
		{
			name:     "update statement",
			sql:      "UPDATE users SET name = 'test' WHERE id = 1",
			expected: QueryTypeUpdate,
		},
		{
			name:     "delete statement",
			sql:      "DELETE FROM users WHERE id = 1",
			expected: QueryTypeDelete,
		},
		{
			name:     "case insensitive select",
			sql:      "select * from users",
			expected: QueryTypeSelect,
		},
		{
			name:     "with leading whitespace",
			sql:      "   WITH cte AS (SELECT 1) SELECT * FROM cte",
			expected: QueryTypeWith,
		},
		{
			name:     "unknown query type",
			sql:      "EXPLAIN SELECT * FROM users",
			expected: QueryTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzeQueryType(tt.sql)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasTechnicalViolations(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		expected bool
	}{
		{
			name:     "simple query - safe",
			sql:      "SELECT * FROM users",
			expected: false,
		},
		{
			name:     "complex nesting - now safe",
			sql:      "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE amount > 100)",
			expected: false,
		},
		{
			name:     "with recursive pattern - safe",
			sql:      "WITH RECURSIVE cte AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM cte WHERE n < 10) SELECT * FROM cte",
			expected: false,
		},
		{
			name:     "deep nesting - now allowed",
			sql:      "SELECT * FROM t1 WHERE id IN (SELECT id FROM t2 WHERE id IN (SELECT id FROM t3 WHERE id IN (SELECT id FROM t4 WHERE id IN (SELECT id FROM t5 WHERE id IN (SELECT id FROM t6 WHERE id IN (SELECT id FROM t7))))))",
			expected: false,
		},
		{
			name:     "sql injection - blocked",
			sql:      "SELECT * FROM users; DROP TABLE important;",
			expected: true,
		},
		{
			name:     "system function call - blocked",
			sql:      "SELECT system('dangerous command')",
			expected: true,
		},
		{
			name:     "malformed parentheses - blocked",
			sql:      "SELECT * FROM users WHERE (id = 1 AND name = 'test'",
			expected: true,
		},
		{
			name:     "multi-statement injection - blocked",
			sql:      "SELECT 1; SELECT 2",
			expected: true,
		},
		{
			name:     "multi-statement with WITH - blocked",
			sql:      "WITH x AS (SELECT 1); SELECT x FROM x",
			expected: true,
		},
		{
			name:     "psql copy meta-command - blocked",
			sql:      "\\copy users from 'file.csv'",
			expected: true,
		},
		{
			name:     "single statement with trailing semicolon - allowed",
			sql:      "SELECT 1;",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasTechnicalViolations(tt.sql)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExecutionContext_IsSafeForNesting(t *testing.T) {
	// Create a minimal execution context for testing
	execCtx := &executionContext{
		queryState: QueryExecutionState{
			active:    false,
			queryType: QueryTypeUnknown,
		},
	}

	tests := []struct {
		name     string
		sql      string
		expected bool
	}{
		{
			name: "safe with recursive insert",
			sql: `WITH RECURSIVE
				indexes AS (SELECT 1 AS idx UNION ALL SELECT idx + 1 FROM indexes WHERE idx <= 5)
				INSERT INTO table1 SELECT * FROM indexes`,
			expected: true,
		},
		{
			name: "safe with recursive delete",
			sql: `WITH RECURSIVE
				cleanup_targets AS (SELECT id FROM items WHERE status = 'deleted')
				DELETE FROM items WHERE id IN (SELECT id FROM cleanup_targets)`,
			expected: true,
		},
		{
			name:     "safe simple delete with subquery",
			sql:      "DELETE FROM users WHERE id IN (SELECT user_id FROM inactive_users)",
			expected: true,
		},
		{
			name:     "safe simple update with subquery",
			sql:      "UPDATE users SET status = 'inactive' WHERE last_login < (SELECT date_cutoff FROM system_config)",
			expected: true,
		},
		{
			name: "complex with recursive - now allowed",
			sql: `WITH RECURSIVE
				deep_hierarchy AS (
					SELECT id FROM departments 
					UNION ALL 
					SELECT d.id FROM departments d 
					WHERE EXISTS (SELECT 1 FROM employees e WHERE e.dept_id = d.id AND EXISTS (SELECT 1 FROM orders o WHERE o.user_id = e.id))
				)
				DELETE FROM departments WHERE id IN (SELECT id FROM deep_hierarchy)`,
			expected: true,
		},
		{
			name:     "complex nested query - now allowed",
			sql:      "DELETE FROM users WHERE id IN (SELECT user_id FROM orders WHERE product_id IN (SELECT id FROM products WHERE category IN (SELECT id FROM categories WHERE active IN (SELECT status FROM config))))",
			expected: true,
		},
		{
			name:     "regular select query - now allowed",
			sql:      "SELECT * FROM users",
			expected: true,
		},
		{
			name:     "simple insert - now allowed",
			sql:      "INSERT INTO users (name) VALUES ('test')",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := execCtx.isSafeForNesting(tt.sql)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExecutionContext_CanAllowThisQuery(t *testing.T) {
	tests := []struct {
		name        string
		queryActive bool
		currentSQL  string
		newSQL      string
		expected    bool
		description string
	}{
		{
			name:        "no active query",
			queryActive: false,
			newSQL:      "SELECT * FROM users",
			expected:    true,
			description: "Should allow any query when no query is active",
		},
		{
			name:        "active query with safe nested with recursive",
			queryActive: true,
			currentSQL:  "SELECT * FROM orders",
			newSQL: `WITH RECURSIVE
				indexes AS (SELECT 1 AS idx UNION ALL SELECT idx + 1 FROM indexes WHERE idx <= 10)
				INSERT INTO log_entries SELECT * FROM indexes`,
			expected:    true,
			description: "Should allow safe WITH RECURSIVE patterns even when query is active",
		},
		{
			name:        "active query with safe delete subquery",
			queryActive: true,
			currentSQL:  "SELECT * FROM users",
			newSQL:      "DELETE FROM temp_data WHERE created_at < (SELECT cleanup_date FROM system_config)",
			expected:    true,
			description: "Should allow safe DELETE with simple subquery when query is active",
		},
		{
			name:        "active query with complex nesting - now allowed",
			queryActive: true,
			currentSQL:  "SELECT * FROM users",
			newSQL:      "DELETE FROM users WHERE id IN (SELECT user_id FROM orders WHERE product_id IN (SELECT id FROM products WHERE category IN (SELECT id FROM categories WHERE active IN (SELECT status FROM config))))",
			expected:    true,
			description: "Complex nested queries now allowed when query is active (simplified logic)",
		},
		{
			name:        "active query with regular select - now allowed",
			queryActive: true,
			currentSQL:  "SELECT * FROM orders",
			newSQL:      "SELECT * FROM users",
			expected:    true,
			description: "Regular queries now allowed when query is active (simplified logic)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execCtx := &executionContext{
				queryState: QueryExecutionState{
					active:    tt.queryActive,
					queryType: QueryTypeSelect,
					sql:       tt.currentSQL,
				},
			}

			result := execCtx.canAllowThisQuery(tt.newSQL)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestQueryExecutionStateTransitions(t *testing.T) {
	execCtx := &executionContext{
		queryState: QueryExecutionState{
			active:    false,
			queryType: QueryTypeUnknown,
			sql:       "",
		},
	}

	// Test initial state
	assert.False(t, execCtx.queryState.active)
	assert.True(t, execCtx.canAllowThisQuery("SELECT * FROM users"))

	// Test state after activation
	execCtx.queryState.active = true
	execCtx.queryState.sql = "SELECT * FROM orders"

	// Should now allow normal queries when active (simplified logic)
	assert.True(t, execCtx.canAllowThisQuery("INSERT INTO users (name) VALUES ('test')"))

	// Should allow all PostgreSQL patterns including WITH RECURSIVE
	assert.True(t, execCtx.canAllowThisQuery("WITH RECURSIVE cte AS (SELECT 1) DELETE FROM temp WHERE id = 1"))

	// But should still block technical violations
	assert.False(t, execCtx.canAllowThisQuery("SELECT * FROM users; DROP TABLE sensitive;"))
}

// Test edge cases and regression scenarios
func TestQueryAnalysisEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		function    string
		expected    interface{}
		description string
	}{
		{
			name:        "empty query",
			sql:         "",
			function:    "analyzeQueryType",
			expected:    QueryTypeUnknown,
			description: "Should handle empty query gracefully",
		},
		{
			name:        "whitespace only query",
			sql:         "   \t\n  ",
			function:    "analyzeQueryType",
			expected:    QueryTypeUnknown,
			description: "Should handle whitespace-only query",
		},
		{
			name:        "query with comments - technical violations check",
			sql:         "/* comment */ WITH RECURSIVE cte AS (SELECT 1) INSERT INTO table1 SELECT * FROM cte",
			function:    "hasTechnicalViolations",
			expected:    false,
			description: "Should allow WITH RECURSIVE queries with comments",
		},
		{
			name:        "mixed case sql patterns",
			sql:         "With Recursive cte As (Select 1) Insert Into table1 Select * From cte",
			function:    "hasTechnicalViolations",
			expected:    false,
			description: "Should handle mixed case SQL",
		},
		{
			name:        "keywords in string literals",
			sql:         "SELECT 'WITH RECURSIVE' as description FROM table1",
			function:    "hasTechnicalViolations",
			expected:    false,
			description: "Should not be fooled by keywords in string literals",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result interface{}

			switch tt.function {
			case "analyzeQueryType":
				result = analyzeQueryType(tt.sql)
			case "hasTechnicalViolations":
				result = hasTechnicalViolations(tt.sql)
			default:
				t.Fatalf("Unknown function: %s", tt.function)
			}

			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

// TestQueryAnalysisIntegration tests the complete flow of our query analysis functionality
func TestQueryAnalysisIntegration(t *testing.T) {
	// Create execution context
	execCtx := &executionContext{
		queryState: QueryExecutionState{
			active:    false,
			queryType: QueryTypeUnknown,
			sql:       "",
		},
	}

	testCases := []struct {
		name           string
		setupQuery     string
		nestedQuery    string
		expectedResult bool
		description    string
	}{
		{
			name:           "Allow WITH RECURSIVE DELETE when no query active",
			setupQuery:     "",
			nestedQuery:    "WITH RECURSIVE cte AS (SELECT 1 AS n) DELETE FROM table1 WHERE id IN (SELECT n FROM cte)",
			expectedResult: true,
			description:    "Should allow WITH RECURSIVE DELETE when no active query",
		},
		{
			name:           "Allow WITH RECURSIVE INSERT during active query",
			setupQuery:     "SELECT * FROM users",
			nestedQuery:    "WITH RECURSIVE indexes AS (SELECT 1 AS idx UNION ALL SELECT idx + 1 FROM indexes WHERE idx <= 10) INSERT INTO log_entries SELECT * FROM indexes",
			expectedResult: true,
			description:    "Should allow WITH RECURSIVE INSERT even during active query (simplified logic)",
		},
		{
			name:           "Allow complex nested query during active query",
			setupQuery:     "SELECT * FROM orders",
			nestedQuery:    "DELETE FROM users WHERE id IN (SELECT user_id FROM orders WHERE product_id IN (SELECT id FROM products WHERE category IN (SELECT id FROM categories)))",
			expectedResult: true,
			description:    "Should allow complex nested query during active query (performance restrictions removed)",
		},
		{
			name:           "Allow regular query during active query",
			setupQuery:     "SELECT * FROM table1",
			nestedQuery:    "SELECT * FROM table2",
			expectedResult: true,
			description:    "Should allow regular query during active query (simplified logic allows PostgreSQL patterns)",
		},
		{
			name:           "Block SQL injection during active query",
			setupQuery:     "UPDATE users SET status = 'active'",
			nestedQuery:    "SELECT * FROM users; DROP TABLE sensitive_data;",
			expectedResult: false,
			description:    "Should block SQL injection attempts during active query",
		},
		{
			name:           "Block system calls during active query",
			setupQuery:     "SELECT * FROM table1",
			nestedQuery:    "SELECT system('rm -rf /')",
			expectedResult: false,
			description:    "Should block dangerous system function calls during active query",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup the execution context state
			if tc.setupQuery != "" {
				execCtx.queryState.active = true
				execCtx.queryState.sql = tc.setupQuery
				execCtx.queryState.queryType = analyzeQueryType(tc.setupQuery)
			} else {
				execCtx.queryState.active = false
				execCtx.queryState.sql = ""
				execCtx.queryState.queryType = QueryTypeUnknown
			}

			// Test the nested query
			result := execCtx.canAllowThisQuery(tc.nestedQuery)

			assert.Equal(t, tc.expectedResult, result, tc.description)
		})
	}
}

// TestQueryAnalysisSafeguards verifies that our analysis maintains security
func TestQueryAnalysisSafeguards(t *testing.T) {
	// Test patterns that should still be blocked for technical safety
	dangerousQueries := []string{
		// SQL injection attempts
		"SELECT * FROM users; DROP TABLE sensitive_data;",

		// System function calls
		"SELECT system('rm -rf /')",

		// PostgreSQL file operations
		"COPY users TO '/tmp/stolen_data.csv'",
	}

	for i, query := range dangerousQueries {
		// Capture loop variables for the closure
		testIndex := i
		testQuery := query
		t.Run(fmt.Sprintf("dangerous_query_%d", testIndex), func(t *testing.T) {
			// Create fresh execCtx for each subtest
			execCtx := &executionContext{
				queryState: QueryExecutionState{
					active:    true,
					queryType: QueryTypeSelect,
					sql:       "SELECT * FROM sensitive_table",
				},
			}
			result := execCtx.canAllowThisQuery(testQuery)
			assert.False(t, result, "Dangerous query should be blocked: %s", testQuery)
		})
	}
}

// TestQueryAnalysisRealWorldScenarios tests scenarios based on our actual use case
func TestQueryAnalysisRealWorldScenarios(t *testing.T) {
	// Test the exact patterns we use in our digest operations
	realWorldQueries := []struct {
		query    string
		expected bool
		name     string
	}{
		{
			name: "bulk_delete_with_recursive",
			query: `WITH RECURSIVE
				delete_indexes AS (SELECT 1 AS idx UNION ALL SELECT idx + 1 FROM delete_indexes WHERE idx <= 5),
				delete_arrays AS (SELECT ARRAY[1,2,3] AS stream_refs_array),
				delete_targets AS (SELECT delete_arrays.stream_refs_array[idx] AS stream_ref FROM delete_indexes JOIN delete_arrays ON 1=1)
				DELETE FROM primitive_events WHERE EXISTS (SELECT 1 FROM delete_targets dt WHERE primitive_events.stream_ref = dt.stream_ref)`,
			expected: true,
		},
		{
			name: "bulk_insert_with_recursive",
			query: `WITH RECURSIVE
				marker_indexes AS (SELECT 1 AS idx UNION ALL SELECT idx + 1 FROM marker_indexes WHERE idx <= 10),
				marker_arrays AS (SELECT ARRAY[1,2,3] AS stream_refs_array, ARRAY[100,200,300] AS times_array)
				INSERT INTO primitive_event_type (stream_ref, event_time, type)
				SELECT marker_arrays.stream_refs_array[idx], marker_arrays.times_array[idx], 1
				FROM marker_indexes JOIN marker_arrays ON 1=1`,
			expected: true,
		},
		{
			name: "ohlc_calculation_with_unnest",
			query: `WITH stream_days AS (
				SELECT u.stream_ref, u.day_index FROM UNNEST(ARRAY[1,2,3], ARRAY[10,20,30]) AS u(stream_ref, day_index)
			)
			SELECT stream_ref, day_index FROM stream_days`,
			expected: true, // Now allowed with simplified logic - PostgreSQL compatible
		},
	}

	for _, tc := range realWorldQueries {
		// Capture loop variables for the closure
		testCase := tc
		t.Run(testCase.name, func(t *testing.T) {
			// Create fresh execCtx for each subtest
			execCtx := &executionContext{
				queryState: QueryExecutionState{
					active:    true,
					queryType: QueryTypeSelect,
					sql:       "SELECT * FROM primitive_events WHERE stream_ref = 1",
				},
			}
			result := execCtx.canAllowThisQuery(testCase.query)
			assert.Equal(t, testCase.expected, result, "Real-world query result mismatch for %s", testCase.name)
		})
	}
}

// TestQueryAnalysisNegativeCases focuses on comprehensive negative testing
func TestQueryAnalysisNegativeCases(t *testing.T) {
	// Test patterns that should still be blocked (only technical violations)
	negativeTests := []struct {
		name        string
		query       string
		description string
		shouldBlock bool // New field to indicate if this should actually be blocked
	}{
		{
			name:        "regular_select_during_active_query",
			query:       "SELECT * FROM orders",
			description: "Regular SELECT now allowed during active query (simplified logic)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "regular_insert_during_active_query",
			query:       "INSERT INTO logs (message) VALUES ('test')",
			description: "Regular INSERT now allowed during active query (simplified logic)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "regular_update_during_active_query",
			query:       "UPDATE users SET status = 'inactive' WHERE id = 1",
			description: "Regular UPDATE now allowed during active query (simplified logic)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "regular_delete_during_active_query",
			query:       "DELETE FROM temp_files WHERE id = 1",
			description: "Regular DELETE now allowed during active query (simplified logic)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "with_clause_without_recursive",
			query:       "WITH temp AS (SELECT 1) INSERT INTO table1 SELECT * FROM temp",
			description: "WITH without RECURSIVE now allowed during active query (simplified logic)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "recursive_without_dml",
			query:       "WITH RECURSIVE series AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM series WHERE n < 10) SELECT * FROM series",
			description: "WITH RECURSIVE without DML now allowed during active query (simplified logic)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "complex_subquery_in_select",
			query:       "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE product_id IN (SELECT id FROM products WHERE price > (SELECT AVG(price) FROM products)))",
			description: "Complex nested subqueries now allowed (PostgreSQL compatible)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "sql_injection_attempt",
			query:       "DELETE FROM users WHERE id = 1; DROP TABLE sensitive_data; --",
			description: "SQL injection attempts should still be blocked",
			shouldBlock: true, // Still blocked
		},
		{
			name:        "stored_procedure_call",
			query:       "CALL dangerous_procedure()",
			description: "Stored procedure calls now allowed (PostgreSQL compatible)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "create_table_attempt",
			query:       "CREATE TABLE malicious_table AS SELECT * FROM sensitive_data",
			description: "DDL operations now allowed (PostgreSQL compatible)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "alter_table_attempt",
			query:       "ALTER TABLE users ADD COLUMN backdoor TEXT",
			description: "Schema modification now allowed (PostgreSQL compatible)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "drop_table_attempt",
			query:       "DROP TABLE IF EXISTS important_data",
			description: "Table dropping now allowed (PostgreSQL compatible)",
			shouldBlock: false, // Now allowed
		},
		{
			name:        "transaction_control",
			query:       "BEGIN; DELETE FROM users; COMMIT;",
			description: "Transaction control should still be blocked (multi-statement)",
			shouldBlock: true, // Still blocked
		},
		{
			name:        "system_function_calls",
			query:       "SELECT system('rm -rf /')",
			description: "System function calls should still be blocked",
			shouldBlock: true, // Still blocked
		},
		{
			name:        "file_operations",
			query:       "COPY users TO '/tmp/stolen_data.csv'",
			description: "File operations should still be blocked",
			shouldBlock: true, // Still blocked
		},
	}

	for _, tt := range negativeTests {
		// Capture loop variables for the closure
		testCase := tt
		t.Run(testCase.name, func(t *testing.T) {
			// Create fresh execCtx for each subtest
			execCtx := &executionContext{
				queryState: QueryExecutionState{
					active:    true,
					queryType: QueryTypeSelect,
					sql:       "SELECT * FROM users",
				},
			}
			result := execCtx.canAllowThisQuery(testCase.query)
			expectedResult := !testCase.shouldBlock // shouldBlock=true means result should be false
			assert.Equal(t, expectedResult, result, testCase.description+" - Query: %s", testCase.query)
		})
	}
}

// TestQueryAnalysisSecurityBoundaries tests security boundary conditions
func TestQueryAnalysisSecurityBoundaries(t *testing.T) {
	tests := []struct {
		name            string
		activeQuery     string
		testQuery       string
		expectedAllowed bool
		description     string
	}{
		{
			name:            "safe_with_recursive_boundary",
			activeQuery:     "SELECT count(*) FROM users",
			testQuery:       "WITH RECURSIVE simple AS (SELECT 1) DELETE FROM temp WHERE id = 1",
			expectedAllowed: true,
			description:     "Simple WITH RECURSIVE DELETE should be allowed",
		},
		{
			name:            "complex_with_recursive_now_allowed",
			activeQuery:     "SELECT count(*) FROM users",
			testQuery:       "WITH RECURSIVE complex AS (SELECT 1 UNION ALL SELECT n+1 FROM complex WHERE EXISTS (SELECT 1 FROM sensitive WHERE secret = complex.n)) DELETE FROM users WHERE id IN (SELECT n FROM complex)",
			expectedAllowed: true,
			description:     "Complex WITH RECURSIVE now allowed with simplified logic",
		},
		{
			name:            "deep_nesting_now_allowed",
			activeQuery:     "SELECT * FROM table1",
			testQuery:       "DELETE FROM users WHERE id IN (SELECT id FROM t1 WHERE id IN (SELECT id FROM t2 WHERE id IN (SELECT id FROM t3 WHERE id IN (SELECT id FROM t4))))",
			expectedAllowed: true,
			description:     "Deep nesting now allowed - PostgreSQL compatible",
		},
		{
			name:            "keyword_case_sensitivity",
			activeQuery:     "SELECT * FROM users",
			testQuery:       "with recursive cte as (select 1) delete from temp where id = 1",
			expectedAllowed: true,
			description:     "Lowercase keywords should work the same as uppercase",
		},
		{
			name:            "mixed_case_boundary",
			activeQuery:     "SELECT * FROM users",
			testQuery:       "WiTh ReCuRsIvE cte As (SeLeCt 1) DeLeTe FrOm temp WhErE id = 1",
			expectedAllowed: true,
			description:     "Mixed case keywords should work the same",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execCtx := &executionContext{
				queryState: QueryExecutionState{
					active:    true,
					queryType: analyzeQueryType(tt.activeQuery),
					sql:       tt.activeQuery,
				},
			}

			result := execCtx.canAllowThisQuery(tt.testQuery)
			assert.Equal(t, tt.expectedAllowed, result, tt.description+" - Query: %s", tt.testQuery)
		})
	}
}

// TestQueryAnalysisErrorConditions tests error and edge conditions
func TestQueryAnalysisErrorConditions(t *testing.T) {
	execCtx := &executionContext{
		queryState: QueryExecutionState{
			active:    false,
			queryType: QueryTypeUnknown,
		},
	}

	errorTests := []struct {
		name        string
		query       string
		expectPanic bool
		description string
	}{
		{
			name:        "nil_query",
			query:       "",
			expectPanic: false,
			description: "Empty query should not panic",
		},
		{
			name:        "malformed_sql",
			query:       "SELE CT * FRO M users WHER E",
			expectPanic: false,
			description: "Malformed SQL should not panic",
		},
		{
			name:        "very_long_query",
			query:       strings.Repeat("SELECT * FROM table", 1000),
			expectPanic: false,
			description: "Very long query should not panic",
		},
		{
			name:        "unicode_characters",
			query:       "SELECT * FROM 用户表 WHERE 名字 = '测试'",
			expectPanic: false,
			description: "Unicode characters should not panic",
		},
		{
			name:        "special_characters",
			query:       "SELECT * FROM `table-name` WHERE `field@name` = '$value'",
			expectPanic: false,
			description: "Special characters should not panic",
		},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if !tt.expectPanic {
						t.Errorf("Query analysis panicked unexpectedly: %v - Query: %s", r, tt.query)
					}
				} else if tt.expectPanic {
					t.Errorf("Expected panic but none occurred - Query: %s", tt.query)
				}
			}()

			// Test all analysis functions don't panic
			_ = analyzeQueryType(tt.query)
			_ = hasTechnicalViolations(tt.query)
			_ = execCtx.canAllowThisQuery(tt.query)
		})
	}
}

// TestPreprocessSQL_DollarQuotedStrings tests dollar-quoted PostgreSQL literals
func TestPreprocessSQL_DollarQuotedStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple dollar quotes",
			input:    "SELECT $$ WITH RECURSIVE malicious $$ FROM table",
			expected: "SELECT   FROM table",
		},
		{
			name:     "tagged dollar quotes",
			input:    "SELECT $tag$ INSERT INTO users VALUES ('hacker') $tag$ FROM table",
			expected: "SELECT   FROM table",
		},
		{
			name:     "multiline dollar quotes",
			input:    "SELECT $$\nWITH RECURSIVE evil\nINSERT INTO system\n$$ FROM table",
			expected: "SELECT  \n \n  FROM table",
		},
		{
			name:     "nested tags different",
			input:    "SELECT $outer$ content $inner$ more content $inner$ end $outer$ FROM table",
			expected: "SELECT   FROM table",
		},
		{
			name:     "dollar in regular context",
			input:    "SELECT price FROM products WHERE price > 100",
			expected: "SELECT price FROM products WHERE price > 100",
		},
		{
			name:     "incomplete dollar quote",
			input:    "SELECT $ incomplete FROM table",
			expected: "SELECT $ incomplete FROM table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := preprocessSQL(tt.input)
			// Normalize whitespace for comparison
			expected := strings.Join(strings.Fields(tt.expected), " ")
			actual := strings.Join(strings.Fields(result), " ")
			assert.Equal(t, expected, actual)
		})
	}
}

// TestPreprocessSQL_DoubleQuoteEscapes tests double-quoted identifiers with escaped quotes
func TestPreprocessSQL_DoubleQuoteEscapes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple double quotes",
			input:    `SELECT "column name" FROM table`,
			expected: "SELECT   FROM table",
		},
		{
			name:     "escaped double quotes",
			input:    `SELECT "He said ""Hello""" FROM table`,
			expected: "SELECT   FROM table",
		},
		{
			name:     "multiple escaped quotes",
			input:    `SELECT "column""with""quotes" FROM table`,
			expected: "SELECT   FROM table",
		},
		{
			name:     "mixed quotes",
			input:    `SELECT "quoted", 'string', "more""quotes" FROM table`,
			expected: "SELECT   ,   ,   FROM table",
		},
		{
			name:     "malicious content in double quotes",
			input:    `SELECT "WITH RECURSIVE evil INSERT" FROM table`,
			expected: "SELECT   FROM table",
		},
		{
			name:     "incomplete escape",
			input:    `SELECT "incomplete escape" FROM table`,
			expected: "SELECT   FROM table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := preprocessSQL(tt.input)
			// Normalize whitespace for comparison
			expected := strings.Join(strings.Fields(tt.expected), " ")
			actual := strings.Join(strings.Fields(result), " ")
			assert.Equal(t, expected, actual)
		})
	}
}

// TestPreprocessSQL_ComplexCombinations tests complex combinations of string types
func TestPreprocessSQL_ComplexCombinations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "all quote types combined",
			input:    `SELECT 'single', "double""escaped", $tag$dollar$tag$, /* comment */ FROM table -- line comment`,
			expected: "SELECT   ,   ,   ,   FROM table  ",
		},
		{
			name:     "nested quote types",
			input:    `SELECT $outer$ 'single in dollar' "double in dollar" $outer$ FROM table`,
			expected: "SELECT   FROM table",
		},
		{
			name:     "malicious keywords in all quote types",
			input:    `SELECT 'WITH RECURSIVE', "INSERT INTO", $tag$DELETE FROM$tag$ FROM table`,
			expected: "SELECT   ,   ,   FROM table",
		},
		{
			name:     "semicolons in quotes should be stripped",
			input:    `WITH RECURSIVE cte AS (SELECT 1) SELECT 'statement1; DELETE FROM users;' FROM table`,
			expected: "WITH RECURSIVE cte AS (SELECT 1) SELECT   FROM table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := preprocessSQL(tt.input)
			// Normalize whitespace for comparison
			expected := strings.Join(strings.Fields(tt.expected), " ")
			actual := strings.Join(strings.Fields(result), " ")
			assert.Equal(t, expected, actual)
		})
	}
}
