//go:build pglive

package interpreter_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/common"
)

// TestNestedQueries tests that function calls inside FOR loops now work with savepoints
func TestNestedQueries(t *testing.T) {
	type testcase struct {
		name        string
		sql         []string // setup SQL (tables, procedures, initial data)
		execAction  string   // action to execute that has nested queries
		verifySQL   string   // SQL to verify the result
		expected    [][]any
		errContains string
	}

	tests := []testcase{
		{
			name: "basic nested query - INSERT in FOR loop",
			sql: []string{
				`CREATE TABLE IF NOT EXISTS source (id INT PRIMARY KEY, value INT);`,
				`CREATE TABLE IF NOT EXISTS dest (id INT PRIMARY KEY, value INT);`,
				`INSERT INTO source (id, value) VALUES (1, 10), (2, 20);`,
				`CREATE ACTION copy_data() PUBLIC {
					for $row in SELECT id, value FROM source ORDER BY id {
						$id int := $row.id;
						$val int := $row.value;
						INSERT INTO dest (id, value) VALUES ($id, $val);
					}
				};`,
			},
			execAction: "copy_data",
			verifySQL:  "SELECT id, value FROM dest ORDER BY id;",
			expected: [][]any{
				{int64(1), int64(10)},
				{int64(2), int64(20)},
			},
		},
		{
			name: "simple nested query - function call inside FOR loop",
			sql: []string{
				`CREATE TABLE IF NOT EXISTS users (
					id INT PRIMARY KEY,
					name TEXT NOT NULL
				);`,
				`CREATE TABLE IF NOT EXISTS log (
					id INT PRIMARY KEY,
					user_id INT NOT NULL,
					message TEXT NOT NULL
				);`,
				// Insert test users
				`INSERT INTO users (id, name) VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie');`,
				// Create helper action that logs (will be called inside loop)
				`CREATE ACTION log_user($user_id int, $message text) PRIVATE {
					$next_id int;
					for $row in SELECT COALESCE(MAX(id), 0) + 1 as next_id FROM log {
						$next_id := $row.next_id;
					}
					INSERT INTO log (id, user_id, message) VALUES ($next_id, $user_id, $message);
				};`,
				// Create main action that calls log_user inside a FOR loop
				`CREATE ACTION process_users() PUBLIC {
					for $user in SELECT id, name FROM users ORDER BY id {
						log_user($user.id, 'Processed: ' || $user.name);
					}
				};`,
			},
			execAction: "process_users",
			verifySQL:  "SELECT user_id, message FROM log ORDER BY id;",
			expected: [][]any{
				{int64(1), "Processed: Alice"},
				{int64(2), "Processed: Bob"},
				{int64(3), "Processed: Charlie"},
			},
		},
		{
			name: "double nested - action calling action inside loop",
			sql: []string{
				`CREATE TABLE IF NOT EXISTS items (id INT PRIMARY KEY, name TEXT);`,
				`CREATE TABLE IF NOT EXISTS audit (id INT PRIMARY KEY, item_id INT, action TEXT);`,
				`INSERT INTO items (id, name) VALUES (1, 'Item A'), (2, 'Item B');`,
				`CREATE ACTION audit_item($item_id int, $action text) PRIVATE {
					$next_id int;
					for $row in SELECT COALESCE(MAX(id), 0) + 1 as next_id FROM audit {
						$next_id := $row.next_id;
					}
					INSERT INTO audit (id, item_id, action) VALUES ($next_id, $item_id, $action);
				};`,
				`CREATE ACTION process_items() PUBLIC {
					for $item in SELECT id FROM items ORDER BY id {
						audit_item($item.id, 'processed');
					}
				};`,
			},
			execAction: "process_items",
			verifySQL:  "SELECT item_id, action FROM audit ORDER BY id;",
			expected: [][]any{
				{int64(1), "processed"},
				{int64(2), "processed"},
			},
		},
	}

	db := newTestDB(t, nil, nil)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)

			// Create interpreter with setup SQL
			interp := newTestInterp(t, tx, test.sql, false)

			// Execute the action that has nested queries
			_, err = interp.Call(newEngineCtx("owner"), tx, "", test.execAction, nil, nil)
			if test.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.errContains)
				return
			}
			require.NoError(t, err, "Action with nested queries should succeed")

			// Verify results
			var values [][]any
			err = interp.Execute(newEngineCtx("owner"), tx, test.verifySQL, nil, func(v *common.Row) error {
				values = append(values, v.Values)
				return nil
			})
			require.NoError(t, err)

			require.Equal(t, len(test.expected), len(values), "Result row count should match")
			for i, row := range values {
				require.Equal(t, len(test.expected[i]), len(row), "Column count should match")
				for j, val := range row {
					colEq(t, test.expected[i][j], val)
				}
			}
		})
	}
}

// TestNestedQuerySavepoints tests that errors in nested queries propagate correctly
func TestNestedQuerySavepoints(t *testing.T) {
	db := newTestDB(t, nil, nil)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	sql := []string{
		`CREATE TABLE IF NOT EXISTS source (id INT PRIMARY KEY, value INT);`,
		`CREATE TABLE IF NOT EXISTS dest (id INT PRIMARY KEY, value INT);`,
		`INSERT INTO source (id, value) VALUES (1, 10), (2, 20);`,
		`INSERT INTO dest (id, value) VALUES (1, 100);`, // Pre-existing row with id=1
		// This will error on second iteration due to PRIMARY KEY conflict
		`CREATE ACTION copy_with_conflict() PUBLIC {
			for $row in SELECT id, value FROM source ORDER BY id {
				$id int := $row.id;
				$val int := $row.value;
				INSERT INTO dest (id, value) VALUES ($id, $val);
			}
		};`,
	}

	interp := newTestInterp(t, tx, sql, false)

	// Execute action that will fail due to PRIMARY KEY conflict
	callRes, err := interp.Call(newEngineCtx("owner"), tx, "", "copy_with_conflict", nil, nil)
	require.NoError(t, err, "Call() should not return top-level error")
	require.NotNil(t, callRes, "CallResult should not be nil")
	require.Error(t, callRes.Error, "CallResult.Error should contain PRIMARY KEY conflict error")
	require.Contains(t, callRes.Error.Error(), "duplicate key", "Error should mention duplicate key")

	// Verify that dest table still has only the original row
	var rowCount int
	err = interp.Execute(newEngineCtx("owner"), tx, "SELECT COUNT(*) as count FROM dest;", nil, func(v *common.Row) error {
		count, ok := v.Values[0].(int64)
		require.True(t, ok, "Expected int64 type for count")
		rowCount = int(count)
		return nil
	})
	require.NoError(t, err)
	// Should still have just 1 row (the original), transaction rolled back
	require.Equal(t, 1, rowCount, "Transaction should rollback on error, keeping only original row")
}
