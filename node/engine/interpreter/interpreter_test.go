//go:build pglive

package interpreter_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/kwilteam/kwil-db/common"
	"github.com/kwilteam/kwil-db/core/types"
	"github.com/kwilteam/kwil-db/extensions/precompiles"
	"github.com/kwilteam/kwil-db/node/engine"
	"github.com/kwilteam/kwil-db/node/engine/interpreter"
	"github.com/kwilteam/kwil-db/node/pg"
	pgtest "github.com/kwilteam/kwil-db/node/pg/test"
	"github.com/kwilteam/kwil-db/node/types/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// func TestMain(m *testing.M) {
// 	pg.UseLogger(log.New(log.WithName("PG"), log.WithFormat(log.FormatUnstructured),
// 		log.WithLevel(log.LevelDebug)))
// 	m.Run()
// }

const (
	defaultCaller    = "owner"
	createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
	id INT PRIMARY KEY,
	name TEXT,
	age INT
);
	`

	createPostsTable = `
CREATE TABLE IF NOT EXISTS posts (
	id INT PRIMARY KEY,
	owner_id INT NOT NULL REFERENCES users(id),
	content TEXT,
	created_at INT
);`
)

func Test_SQL(t *testing.T) {
	type testcase struct {
		name string // name of the test
		// array of sql statements, first element is the namespace, second is the sql statement
		// they can begin with {namespace}sql, or just sql
		sql            []string
		execSQL        string         // sql to return the results. Either this or execAction must be set
		execVars       map[string]any // variables to pass to the execSQL
		results        [][]any        // table of results
		err            error          // expected error, can be nil. Errors _MUST_ occur on the exec. This is a direct match
		errContains    string         // expected error message, can be empty. Errors _MUST_ occur on the exec. This is a substring match
		caller         string         // caller to use for the action, will default to defaultCaller
		skipInitTables bool           // skip the creation of the users and posts tables
	}

	tests := []testcase{
		{
			name: "insert and select",
			sql: []string{
				"INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
			},
			execSQL: "SELECT name, age FROM users;",
			results: [][]any{
				{"Alice", int64(30)},
			},
		},
		{
			// this is a bug that previously existed where the composite
			// unique constraint caused an issue when querying views
			name: "create table with multi-dimensional constraint",
			execSQL: `CREATE TABLE IF NOT EXISTS erc20rw_contracts (
				id UUID PRIMARY KEY,
				chain_id INT8 NOT NULL,
				address TEXT NOT NULL,
				nonce INT8 NOT NULL,
				threshold INT8 NOT NULL,
				safe_address TEXT NOT NULL,
				safe_nonce INT8 NOT NULL,
				unique (chain_id, address)
		);`,
		},
		{
			name: "create namespace, add table, add record, alter table, select",
			sql: []string{
				"CREATE NAMESPACE test;",
				"{test}CREATE TABLE users (id INT PRIMARY KEY, name TEXT, age INT);",
				"{test}INSERT INTO users (id, name, age) VALUES (1, 'Bob', 30);",
				"{test}ALTER TABLE users DROP COLUMN age;",
			},
			execSQL: "{test}SELECT * FROM users;",
			results: [][]any{
				{int64(1), "Bob"},
			},
		},
		{
			name: "foreign key across namespaces",
			sql: []string{
				"CREATE NAMESPACE test1;",
				"CREATE NAMESPACE test2;",
				"{test1}CREATE TABLE users (id INT PRIMARY KEY, name TEXT);",
				`{test2}CREATE TABLE posts (id INT PRIMARY KEY,
				owner_id INT NOT NULL REFERENCES test1.users(id) ON UPDATE CASCADE ON DELETE CASCADE,
				content TEXT, created_at INT);`,
				"{test1}INSERT INTO users (id, name) VALUES (1, 'Alice'), (2, 'Bob');",
				"{test2}INSERT INTO posts (id, owner_id, content, created_at) VALUES (1, 1, 'Hello', @height), (2, 2, 'World', @height);",
				"{test1}DELETE FROM users WHERE id = 1;",
			},
			execSQL: `{test2}SELECT * FROM posts;`,
			results: [][]any{
				{int64(2), int64(2), "World", int64(1)},
			},
		},
		{
			name: "alter table create composite foreign key",
			sql: []string{
				// pretty non-sensical schema, but it tests the logic I want
				"CREATE TABLE cars (id INT PRIMARY KEY, make TEXT, model TEXT, UNIQUE(make, model));",
				"CREATE TABLE drivers (id INT PRIMARY KEY, name TEXT, car_make TEXT, car_model TEXT);",
			},
			execSQL: `ALTER TABLE drivers ADD CONSTRAINT fk_car FOREIGN KEY (car_make, car_model) REFERENCES cars (make, model);`,
		},
		{
			name: "update and delete",
			sql: []string{
				"INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30), (2, 'Bob', 40);",
				"UPDATE users SET age = 50 WHERE name = 'Alice';",
				"DELETE FROM users WHERE age = 40;",
			},
			execSQL: "SELECT name, age FROM users;",
			results: [][]any{
				{"Alice", int64(50)},
			},
		},
		{
			name: "recursive common table expression",
			execSQL: `
			with recursive r as (
				select 1 as n
				union all
				select n+1 from r where n < 6
			)
			select * from r;
			`,
			results: [][]any{
				{int64(1)}, {int64(2)}, {int64(3)}, {int64(4)}, {int64(5)}, {int64(6)},
			},
		},
		{
			name: "alter table add column",
			sql: []string{
				"ALTER TABLE users ADD COLUMN email TEXT;",
				"INSERT INTO users (id, name, age, email) VALUES (1, 'Alice', 30, 'alice@kwil.com');",
			},
			execSQL: "SELECT name, age, email FROM users;",
			results: [][]any{
				{"Alice", int64(30), "alice@kwil.com"},
			},
		},
		{
			name: "alter table drop column",
			sql: []string{
				"INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
				"ALTER TABLE users DROP COLUMN age;",
			},
			execSQL: "SELECT * FROM users;",
			results: [][]any{
				{1, "Alice"},
			},
		},

		// Setting a column to be NOT NULL
		{
			name: "alter table set column not null",
			sql: []string{
				"ALTER TABLE users ALTER COLUMN name SET NOT NULL;",
			},
			execSQL:     "INSERT INTO users (id, name, age) VALUES (1, null, 30);",
			errContains: "violates not-null constraint (SQLSTATE 23502)",
		},

		// Setting a default on a column
		{
			name: "alter table set column default",
			sql: []string{
				"ALTER TABLE users ALTER COLUMN age SET DEFAULT 25;",
				"INSERT INTO users (id, name) VALUES (1, 'Alice');",
			},
			execSQL: "SELECT id, name, age FROM users;",
			results: [][]any{
				{int64(1), "Alice", int64(25)},
			},
		},

		// Removing a default from a column
		{
			name: "alter table drop column default",
			sql: []string{
				"ALTER TABLE users ALTER COLUMN age SET DEFAULT 25;",
				"ALTER TABLE users ALTER COLUMN age DROP DEFAULT;",
				"INSERT INTO users (id, name) VALUES (1, 'Alice');",
			},
			execSQL: "SELECT id, name, age FROM users;",
			results: [][]any{
				{int64(1), "Alice", nil}, // Age will be NULL since the default is removed
			},
		},

		// Removing NOT NULL from a column
		{
			name: "alter table drop column not null",
			sql: []string{
				"ALTER TABLE users ALTER COLUMN name SET NOT NULL;",
				"ALTER TABLE users ALTER COLUMN name DROP NOT NULL;",
				"INSERT INTO users (id, age) VALUES (1, 30);",
			},
			execSQL: "SELECT id, name, age FROM users;",
			results: [][]any{
				{int64(1), nil, int64(30)},
			},
		},

		// Renaming a column
		{
			name: "alter table rename column",
			sql: []string{
				"ALTER TABLE users RENAME COLUMN name TO full_name;",
				"INSERT INTO users (id, full_name, age) VALUES (1, 'Alice', 30);",
			},
			execSQL: "SELECT full_name, age FROM users;",
			results: [][]any{
				{"Alice", int64(30)},
			},
		},

		// Renaming a table
		{
			name: "alter table rename table",
			sql: []string{
				"ALTER TABLE users RENAME TO app_users;",
				"INSERT INTO app_users (id, name, age) VALUES (1, 'Alice', 30);",
			},
			execSQL: "SELECT name, age FROM app_users;",
			results: [][]any{
				{"Alice", int64(30)},
			},
		},
		{
			name:    "drop default namespace",
			execSQL: "DROP NAMESPACE main;",
			err:     engine.ErrCannotDropBuiltinNamespace,
		},
		{
			name:    "drop info namespace",
			execSQL: "DROP NAMESPACE info;",
			err:     engine.ErrCannotDropBuiltinNamespace,
		},
		{
			name:    "drop non-existent namespace",
			execSQL: "DROP NAMESPACE some_ns;",
			err:     engine.ErrNamespaceNotFound,
		},
		{
			name: "global select permission - failure",
			sql: []string{
				// test_role starts with select b/c of default, but then loses it.
				"CREATE ROLE test_role;",
				"REVOKE select FROM default;",
				"GRANT test_role TO 'user'",
			},
			execSQL:     "SELECT * FROM users;",
			errContains: "permission denied for table users",
			caller:      "user",
			err:         engine.ErrDoesNotHavePrivilege,
		},
		{
			name: "global select permission - success",
			sql: []string{
				"CREATE ROLE test_role;",
				"REVOKE select FROM default;",
				"GRANT test_role TO 'user'",
				"GRANT select TO test_role;",
			},
			execSQL: "SELECT * FROM users;",
			results: [][]any{},
			caller:  "user",
		},
		{
			name: "namespaced select permission - failure",
			sql: []string{
				"CREATE NAMESPACE test;",
				"CREATE ROLE test_role;",
				"REVOKE select FROM default;",
				"GRANT test_role TO 'user'",
				"GRANT select ON test TO test_role;",
			},
			// they do not have permission to select from the users table, which is in the main namespace
			execSQL: "SELECT * FROM users;",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "user",
		},
		{
			name: "namespaced select permission - success",
			sql: []string{
				"CREATE NAMESPACE test;",
				"CREATE ROLE test_role;",
				"REVOKE select FROM default;",
				"GRANT test_role TO 'user'",
				"GRANT select ON test TO test_role;",
				"{test}CREATE TABLE users (id INT PRIMARY KEY, name TEXT, age INT);",
			},
			execSQL: "{test}SELECT * FROM users;",
			results: [][]any{},
			caller:  "user",
		},
		{
			name:    "global insert permission - failure",
			execSQL: "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "user",
		},
		{
			name: "global insert permission - success",
			sql: []string{
				"CREATE ROLE test_role;",
				"GRANT test_role TO 'user'",
				"GRANT insert TO test_role;",
			},
			execSQL: "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
			results: [][]any{},
			caller:  "user",
		},
		// I wont test other namespace-able perms because they use the same logic
		{
			name: "drop role",
			sql: []string{
				"CREATE ROLE test_role;",
				"GRANT test_role TO 'user';",
				"GRANT iNSert TO test_role;",
				"DROP ROLE test_role;",
			},
			execSQL: "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "user",
		},
		{
			name: "drop and recreate namespace",
			sql: []string{
				"CREATE NAMESPACE test;",
				"CREATE ROLE test_role;",
				"GRANT INSERT ON test TO test_role;",
				"GRANT test_role TO 'user';",
				"DROP NAMESPACE test;",
				"CREATE NAMESPACE test;",
			},
			execSQL: "{test}INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "user",
		},
		{
			name: "revoking global permission",
			sql: []string{
				"CREATE ROLE test_role;",
				"GRANT test_role TO 'user';",
				"GRANT insert TO test_role;",
				"REVOKE insert FROM test_role;",
			},
			execSQL: "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "user",
		},
		{
			name: "revoking namespaced permission",
			sql: []string{
				"CREATE NAMESPACE test;",
				"CREATE ROLE test_role;",
				"GRANT test_role TO 'user';",
				"GRANT insert ON test TO test_role;",
				"REVOKE insert ON test FROM test_role;",
				"{test}CREATE TABLE users (id INT PRIMARY KEY, name TEXT, age INT);",
			},
			execSQL: "{test}INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "user",
		},
		{
			name: "revoke role",
			sql: []string{
				"CREATE ROLE test_role;",
				"GRANT test_role TO 'user';",
				"GRANT insert TO test_role;",
				"REVOKE test_role FROM 'user';",
			},
			execSQL: "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "user",
		},
		{
			name: "transfer owner role to user",
			sql: []string{
				"TRANSFER OWNERSHIP TO 'user';",
			},
			execSQL: "TRANSFER OWNERSHIP TO 'user2';",
			caller:  "user",
		},
		{
			name:    "grant role to user, parameterized",
			sql:     []string{"CREATE ROLE test_role;"},
			execSQL: `grant test_role to $user;`,
			execVars: map[string]any{
				"user": "new_user",
			},
		},
		{
			name:    "cannot grant default role",
			execSQL: `GRANT default TO 'user';`,
			err:     engine.ErrBuiltInRole,
		},
		{
			name:    "cannot revoke default role",
			execSQL: `REVOKE default FROM 'user';`,
			err:     engine.ErrBuiltInRole,
		},
		// here we test that privileges are correctly enforced.
		// We do this by relying on the default role, which has no privileges
		// except for select and call.
		{
			name:    "default role cannot be dropped",
			execSQL: "DROP ROLE default;",
			err:     engine.ErrBuiltInRole,
		},
		{
			name:    "default role cannot create tables",
			execSQL: `CREATE TABLE tbl (col int primary key);`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot alter tables",
			execSQL: "ALTER TABLE users ADD COLUMN email TEXT;",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot drop tables",
			execSQL: "DROP TABLE users;",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot create roles",
			execSQL: `CREATE ROLE test_role;`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot drop roles",
			execSQL: `DROP ROLE test_role;`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot create namespaces",
			execSQL: `CREATE NAMESPACE ns;`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name: "default role cannot drop namespaces",
			sql: []string{
				"CREATE NAMESPACE ns;",
			},
			execSQL: `DROP NAMESPACE ns;`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot create actions",
			execSQL: `CREATE ACTION act() public {};`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name: "default role cannot drop actions",
			sql: []string{
				"CREATE ACTION act() public {};",
			},
			execSQL: `DROP ACTION act;`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name: "default role cannot assign roles",
			sql: []string{
				"CREATE ROLE test_role;",
			},
			execSQL: `GRANT test_role TO 'default_user';`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name: "default role cannot revoke roles",
			sql: []string{
				"CREATE ROLE test_role;",
				"GRANT test_role TO 'default_user';",
			},
			execSQL: `REVOKE test_role FROM 'default_user';`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name: "default role cannot assign privileges",
			sql: []string{
				"CREATE ROLE test_role;",
			},
			execSQL: `GRANT select ON users TO test_role;`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name: "default role cannot revoke privileges",
			sql: []string{
				"CREATE ROLE test_role;",
				"GRANT select ON main TO test_role;",
			},
			execSQL: `REVOKE select ON main FROM test_role;`,
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot use extensions",
			execSQL: "USE test AS test_ext;",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot unuse extensions",
			execSQL: "UNUSE test_ext;",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot insert",
			execSQL: "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30);",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot update",
			execSQL: "UPDATE users SET age = 50 WHERE name = 'Alice';",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		{
			name:    "default role cannot delete",
			execSQL: "DELETE FROM users WHERE age = 40;",
			err:     engine.ErrDoesNotHavePrivilege,
			caller:  "default",
		},
		// testing that the admin cannot perform disallowed operations
		// (e.g. dropping the info namespace)
		{
			name:    "admin cannot drop info namespace",
			execSQL: "DROP NAMESPACE info;",
			err:     engine.ErrCannotDropBuiltinNamespace,
		},
		{
			name:    "admin cannot drop main namespace",
			execSQL: `DROP NAMESPACE main;`,
			err:     engine.ErrCannotDropBuiltinNamespace,
		},
		{
			name:    "admin cannot add table to info namespace",
			execSQL: `{info}CREATE TABLE tbl (col int primary key);`,
			err:     engine.ErrCannotMutateInfoNamespace,
		},
		{
			name:    "admin cannot add action to info namespace",
			execSQL: `{info}CREATE ACTION act() public {};`,
			err:     engine.ErrCannotMutateInfoNamespace,
		},
		{
			name:    "admin cannot drop table from info namespace",
			execSQL: `{info}DROP TABLE namespaces;`,
			err:     engine.ErrCannotMutateInfoNamespace,
		},
		{
			// this should always fail because it is a postgres view, but I want to make sure
			// the error is correctly caught by the engine
			name:    "admin cannot insert into info namespace",
			execSQL: `{info}INSERT INTO namespaces (name, type) VALUES ('test', 'SYSTEM');`,
			err:     engine.ErrCannotMutateInfoNamespace,
		},
		// testing info schema
		// I only have one test here because sql_test.go tests all of the info schema,
		// this is simply to ensure that it can be accessed by the engine.
		{
			name:    "read namespaces",
			execSQL: "SELECT name, type FROM info.namespaces;",
			results: [][]any{
				{"info", "SYSTEM"},
				{"main", "SYSTEM"},
			},
		},
		{
			name: "cannot grant roles privileges on a namespace",
			sql: []string{
				"CREATE ROLE test_role;",
			},
			execSQL: `GRANT ROLES ON main TO test_role;`,
			err:     engine.ErrCannotBeNamespaced,
		},
		{
			name: "cannot grant use privileges on a namespace",
			sql: []string{
				"CREATE ROLE test_role;",
			},
			execSQL: `GRANT USE ON main TO test_role;`,
			err:     engine.ErrCannotBeNamespaced,
		},
		{
			name:    "2d array",
			execSQL: `SELECT ARRAY[ARRAY[1,2], ARRAY[3,4]];`,
			err:     engine.ErrArrayDimensionality,
		},
		{
			// this tests for a bug gavin found where foreign keys are read as columns
			// from the info schema, and then incorrectly create ambiguous column errors
			// in the query planner
			name: "select against foreign key",
			sql: []string{
				`CREATE TABLE IF NOT EXISTS erc20rw_contracts (
					id UUID PRIMARY KEY,
					chain_id INT8 NOT NULL, -- the chain ID of the contract.
					address TEXT NOT NULL, -- the reward escrow contract address.
					nonce INT8 NOT NULL, -- the last known nonce of the contract
					threshold INT8 NOT NULL,
					safe_address TEXT NOT NULL, -- the GnosisSafe address.
					safe_nonce INT8 NOT NULL, -- the last known nonce of the safe. NOTE: unless we force the safe can only be updated through KWIL, which is not practical, so the nonce may change without the ext knowing.
					unique (chain_id, address) -- unique per chain and address
				);`,
				`CREATE TABLE IF NOT EXISTS erc20rw_signers (
					id UUID PRIMARY KEY,
					address TEXT NOT NULL, -- eth address
					contract_id UUID NOT NULL REFERENCES erc20rw_contracts(id) ON UPDATE CASCADE ON DELETE CASCADE,
					UNIQUE (address, contract_id)
				);`,
			},
			execSQL: `SELECT * FROM erc20rw_signers WHERE contract_id = $contract_id;`,
			execVars: map[string]any{
				"contract_id": mustUUID("d3b3b3b3-3b3b-3b3b-3b3b-3b3b3b3b3b3b"),
			},
		},
		{
			// this is testing that, even though we send pgtype.Array[pgtype.Text] as all nils,
			// it works for int[]
			name: "insert array of nulls",
			sql: []string{
				`CREATE TABLE IF NOT EXISTS tbl (id INT PRIMARY KEY, arr INT[]);`,
			},
			execSQL: `INSERT INTO tbl (id, arr) VALUES (1, $a);`,
			execVars: map[string]any{
				"$a": []any{nil, nil},
			},
		},
		{
			name:    "cannot use reserved namespace prefix",
			execSQL: `CREATE NAMESPACE kwil_hello;`,
			err:     engine.ErrReservedNamespacePrefix,
		},
		{
			// this is a regression test
			// https://github.com/kwilteam/kwil-db/issues/1352
			name: "alter table add and remove column",
			sql: []string{
				"CREATE TABLE users2 (id INT PRIMARY KEY, name TEXT);",
			},
			execSQL: `ALTER TABLE users2 ADD COLUMN age INT, DROP COLUMN name;`,
		},
		{
			name: "default ordering of complex group",
			sql: []string{
				`CREATE TABLE wallets (id int primary key, address text)`,
			},
			execSQL: `SELECT lower(address) FROM wallets GROUP BY lower(address);`,
		},
		{
			name:    "namespace with hyphen",
			execSQL: `CREATE NAMESPACE "test-hyphen";`,
			err:     engine.ErrParse,
		},
		{
			name:    "namespace with period",
			execSQL: `CREATE NAMESPACE "test.hyphen";`,
			err:     engine.ErrParse,
		},
		{
			name: "drop primary key",
			sql: []string{
				`CREATE TABLE tbl (id INT PRIMARY KEY, name TEXT);`,
			},
			execSQL: `ALTER TABLE tbl DROP column id;`,
			err:     engine.ErrCannotAlterPrimaryKey,
		},
		{
			name:           "select empty array (untyped)",
			execSQL:        `SELECT ARRAY[];`,
			err:            engine.ErrQueryPlanner,
			skipInitTables: true,
		},
		{
			name:           "select empty array (type casted)",
			execSQL:        `SELECT ARRAY[]::TEXT[];`,
			results:        [][]any{{[]*string{}}},
			skipInitTables: true,
		},
		{
			// a regression test that tests for a few cases.
			// 1. it tests for ERROR working properly within queries.
			// 2. it tests that we can order by ERROR. Since ERROR returns void,
			// Postgres cannot order it, so we cast it to text.
			// 3. Since the result is casted to text, Postgres complains that it cannot
			// return either text or int, so we type cast it.
			name:        "select error",
			execSQL:     `SELECT case when false then 1 else error('a')::INT end;`,
			errContains: "ERROR: a (SQLSTATE P0001)",
		},
		{
			// this is a regression test for a bug where default ordering
			// applied to aggregates in windows actually changed the intent of the query
			name: "aggregate window function ordering",
			execSQL: `WITH data AS (
					    SELECT 'key1' AS key, 1 AS val
					    UNION ALL SELECT 'key1', 2
					)
					SELECT
					    max(val) OVER (
					        PARTITION BY key
					    ) AS max_key
					FROM data;`,
			results: [][]any{
				{int64(2)},
				{int64(2)},
			},
		},
		{
			// this is the same test as above, but with ordering applied
			// to make sure that we match the intent of the query
			name: "aggregate window function explicit ordering",
			execSQL: `WITH data AS (
					    SELECT 'key1' AS key, 1 AS val
					    UNION ALL SELECT 'key1', 2
					)
					SELECT
					    max(val) OVER (
					        PARTITION BY key ORDER BY key, val
					    ) AS max_key
					FROM data;`,
			results: [][]any{
				{int64(1)},
				{int64(2)},
			},
		},
		{
			// testing that default ordering DOES apply to windows
			name: "window function ordering",
			execSQL: `WITH data AS (
				SELECT 'key1' AS key, 1 AS val
				UNION ALL SELECT 'key1', 2
			)
			SELECT
				lag(val) OVER (
					PARTITION BY key
				) AS max_key
			FROM data
			ORDER BY 1 NULLS FIRST;`,
			results: [][]any{
				{nil},
				{int64(1)},
			},
		},
		{
			// explicit ordering of the above
			name: "window function explicit ordering",
			execSQL: `WITH data AS (
				SELECT 'key1' AS key, 1 AS val
				UNION ALL SELECT 'key1', 2
			)
			SELECT
				lag(val) OVER (
					PARTITION BY key ORDER BY key desc, val desc
				) AS max_key
			FROM data
			ORDER BY 1 NULLS FIRST;`,
			results: [][]any{
				{nil},
				{int64(2)},
			},
		},
		{
			// this is a regression test for a previous bug
			// https://github.com/trufnetwork/kwil-db/issues/1503
			name: "insert with select, without all columns",
			sql: []string{
				`CREATE TABLE info (id int primary key, name text);`,
			},
			execSQL: `INSERT INTO info (id) SELECT 1;`,
		},
	}

	db := newTestDB(t, nil, nil)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx) // always rollback

			interp := newTestInterp(t, tx, test.sql, !test.skipInitTables)

			var values [][]any
			err = interp.Execute(newEngineCtx(test.caller), tx, test.execSQL, test.execVars, func(v *common.Row) error {
				values = append(values, v.Values)
				return nil
			})
			if test.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, test.err)
			} else if test.errContains != "" {
				require.Contains(t, err.Error(), test.errContains)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, len(test.results), len(values))
			for i, row := range values {
				require.Equal(t, len(test.results[i]), len(row))
				for j, val := range row {
					colEq(t, test.results[i][j], val)
				}
			}
		})
	}
}

func colEq(t *testing.T, a, b any) {
	// if it is a numeric, we should do a special comparison
	if a != nil {
		if decVal, ok := a.(*types.Decimal); ok {
			cmp, err := decVal.Cmp(b.(*types.Decimal))
			require.NoError(t, err)

			require.Equal(t, 0, cmp)
		}
	}

	require.EqualValues(t, a, b)
}

func ptrArr[T any](a ...T) []*T {
	var res []*T
	for _, v := range a {
		res = append(res, &v)
	}
	return res
}

// Test_Roundtrip tries roundtripping each data type
// to the database
func Test_Roundtrip(t *testing.T) {
	type testcase struct {
		name     string
		datatype string
		value    any
	}

	tests := []testcase{
		{
			name:     "int",
			datatype: "INT",
			value:    int64(100),
		},
		{
			name:     "text",
			datatype: "TEXT",
			value:    "hello",
		},
		{
			name:     "bool",
			datatype: "BOOL",
			value:    true,
		},
		{
			name:     "numeric",
			datatype: "numeric(70,5)",
			value:    mustExplicitDecimal("100.101", 70, 5),
		},
		{
			name:     "uuid",
			datatype: "UUID",
			value:    mustUUID("d3b3b3b3-3b3b-3b3b-3b3b-3b3b3b3b3b3b"),
		},
		{
			name:     "bytea",
			datatype: "BYTEA",
			value:    []byte("hello"),
		},
		{
			name:     "int_array",
			datatype: "INT[]",
			value:    append(ptrArr[int64](1, 2), nil),
		},
		{
			name:     "text_array",
			datatype: "TEXT[]",
			value:    append(ptrArr("hello", "", `"actualquotes"`, "world", "NULL"), nil),
		},
		{
			name:     "bool_array",
			datatype: "BOOL[]",
			value:    append(ptrArr(true, false), nil),
		},
		{
			name:     "numeric_array",
			datatype: "numeric(70,5)[]",
			value:    append([]*types.Decimal{mustExplicitDecimal("100.101", 70, 5), mustExplicitDecimal("200.202", 70, 5)}, nil),
		},
		{
			name:     "uuid_array",
			datatype: "UUID[]",
			value:    append([]*types.UUID{mustUUID("d3b3b3b3-3b3b-3b3b-3b3b-3b3b3b3b3b3b"), mustUUID("d3b3b3b3-3b3b-3b3b-3b3b-3b3b3b3b3b3b")}, nil),
		},
		{
			name:     "bytea_array",
			datatype: "BYTEA[]",
			value:    [][]byte{[]byte("hello"), {}, []byte("world"), nil}, //  append(ptrArr([]byte("hello"), []byte{}, []byte("world")), nil),
		},
	}

	db := newTestDB(t, func(db *pg.DB) {
		d := db.Pool() // direct, don't worry about commit ID or anything
		_, err := d.Execute(context.Background(), `DROP SCHEMA IF EXISTS main CASCADE;`)
		assert.NoError(t, err)
		_, err = d.Execute(context.Background(), `DROP SCHEMA IF EXISTS info CASCADE;`)
		assert.NoError(t, err)
		_, err = d.Execute(context.Background(), `DROP SCHEMA IF EXISTS kwild_engine CASCADE;`)
		assert.NoError(t, err)
	}, func(s string) bool {
		return s == "main"
	})

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	interp := newTestInterp(t, tx, nil, false)
	err = tx.Commit(ctx)
	if err != nil {
		t.Errorf("failed to commit tx: %v", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx, err := db.BeginPreparedTx(ctx)
			require.NoError(t, err)
			t.Cleanup(func() {
				tx.Rollback(ctx)
			})

			// we will create a table with the datatype
			// and then insert the value into the table
			err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf("CREATE TABLE tbl_%s (id int primary key, val %s);", test.name, test.datatype), nil, nil)
			require.NoError(t, err)

			// insert the value
			err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf("INSERT INTO tbl_%s (id, val) VALUES (1, $val);", test.name), map[string]any{"$val": test.value}, nil)
			require.NoError(t, err)

			// select the value
			var value any
			err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf("SELECT val FROM tbl_%s;", test.name), nil, func(r *common.Row) error {
				value = r.Values[0]
				return nil
			})
			require.NoError(t, err)

			require.EqualValues(t, test.value, value)
			// roundtrip nulls as well
			err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf("INSERT INTO tbl_%s (id, val) VALUES (2, NULL);", test.name), nil, nil)
			require.NoError(t, err)

			err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf("SELECT val FROM tbl_%s WHERE id = 2;", test.name), nil, func(r *common.Row) error {
				assert.True(t, r.Values[0] == nil)
				return nil
			})
			require.NoError(t, err)

			// create actions
			err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf("CREATE ACTION act_%s($id int, $a %s) public { INSERT INTO tbl_%s (id, val) VALUES ($id, $a); };", test.name, test.datatype, test.name), nil, nil)
			require.NoError(t, err)

			// call the action
			_, err = interp.Call(newEngineCtx(defaultCaller), tx, "", fmt.Sprintf("act_%s", test.name), []any{3, test.value}, nil)
			require.NoError(t, err)

			// select the value
			err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf("SELECT val FROM tbl_%s WHERE id = 3;", test.name), nil, func(r *common.Row) error {
				assert.EqualValues(t, test.value, r.Values[0])
				return nil
			})
			require.NoError(t, err)

			// roundtrip nulls to the action as well
			_, err = interp.Call(newEngineCtx(defaultCaller), tx, "", fmt.Sprintf("act_%s", test.name), []any{4, nil}, nil)
			require.NoError(t, err)

			err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf("SELECT val FROM tbl_%s WHERE id = 4;", test.name), nil, func(r *common.Row) error {
				assert.True(t, r.Values[0] == nil)
				return nil
			})
			require.NoError(t, err)

			csChan := make(chan any, 1)
			go func() {
				for range csChan {
				} // discard whatever precommit sends
			}()
			_, err = tx.Precommit(ctx, csChan)
			require.NoError(t, err)

			// err = tx.Commit(ctx)
			// require.NoError(t, err)

			// and we rollback
		})

		// If DB failed, stop all tests
		if dbErr := db.Err(); dbErr != nil && !errors.Is(dbErr, context.Canceled) {
			t.Fatalf("db error: %v", dbErr)
		}
	}
}

func Test_RoundtripNull(t *testing.T) {

	db := newTestDB(t, nil, nil)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	interp := newTestInterp(t, tx, nil, false)

	err = interp.ExecuteWithoutEngineCtx(ctx, tx, "CREATE TABLE tbl (id int primary key, val int);", nil, nil)
	require.NoError(t, err)

	err = interp.ExecuteWithoutEngineCtx(ctx, tx, "INSERT INTO tbl (id, val) VALUES (1, $a);", map[string]any{
		"$a": nil,
	}, nil)
	require.NoError(t, err)

	err = interp.ExecuteWithoutEngineCtx(ctx, tx, "SELECT val FROM tbl WHERE id = 1;", nil, exact(nil))
	require.NoError(t, err)

	// action
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, "CREATE ACTION act($a int) public { INSERT INTO tbl (id, val) VALUES (2, $a); };", nil, nil)
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "", "act", []any{nil}, nil)
	require.NoError(t, err)

	err = interp.ExecuteWithoutEngineCtx(ctx, tx, "SELECT val FROM tbl WHERE id = 2;", nil, exact(nil))
	require.NoError(t, err)
}

// Test_CreateAndDelete tests creating and dropping different objects,
// as well as how created objects are read from the database on startup.
func Test_CreateAndDelete(t *testing.T) {
	type testcase struct {
		name   string // name of the test
		create string
		drop   string
		verify string // must return 0 rows
	}

	tests := []testcase{
		{
			name:   "create and drop table",
			create: "CREATE TABLE tbl (col INT PRIMARY KEY);",
			drop:   "DROP TABLE tbl;",
			verify: "SELECT * FROM info.tables where name = 'tbl' AND namespace = 'main';",
		},
		{
			name:   "create and drop role",
			create: "CREATE ROLE test_role;",
			drop:   "DROP ROLE test_role;",
			verify: "SELECT * FROM info.roles where name = 'test_role';",
		},
		{
			name:   "create and drop namespace",
			create: "CREATE NAMESPACE test;",
			drop:   "DROP NAMESPACE test;",
			verify: "SELECT * FROM info.namespaces where name = 'test';",
		},
		{
			name:   "create and drop index",
			create: "CREATE INDEX idx ON users (name, age);",
			drop:   "DROP INDEX idx;",
			verify: "SELECT * FROM info.indexes where name = 'idx' AND namespace = 'main';",
		},
		{
			name:   "create and drop action with no parameters",
			create: "CREATE ACTION act() public {};",
			drop:   "DROP ACTION act;",
			verify: "SELECT * FROM info.actions where name = 'act' AND namespace = 'main';",
		},
	}

	db := newTestDB(t, nil, nil)

	for _, test := range tests {
		// the first run through, we will test creating and dropping tables
		t.Run(test.name+"_1", func(t *testing.T) {
			ctx := context.Background()
			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx) // always rollback

			interp := newTestInterp(t, tx, nil, true)

			err = interp.Execute(newEngineCtx(defaultCaller), tx, test.create, nil, nil)
			require.NoError(t, err)

			err = interp.Execute(newEngineCtx(defaultCaller), tx, test.drop, nil, nil)
			require.NoError(t, err)

			count := 0
			err = interp.Execute(newEngineCtx(defaultCaller), tx, test.verify, nil, func(r *common.Row) error {
				count++
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, 0, count)
		})

		// the second run through, we will test creating, mocking a restart, dropping, and verifying
		t.Run(test.name+"_2", func(t *testing.T) {
			ctx := context.Background()
			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx) // always rollback

			interp := newTestInterp(t, tx, nil, true)

			err = interp.Execute(newEngineCtx(defaultCaller), tx, test.create, nil, nil)
			require.NoError(t, err)

			interp = newTestInterp(t, tx, nil, true)

			err = interp.Execute(newEngineCtx(defaultCaller), tx, test.drop, nil, nil)
			require.NoError(t, err)

			count := 0
			err = interp.Execute(newEngineCtx(defaultCaller), tx, test.verify, nil, func(v *common.Row) error {
				count++
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, 0, count)
		})
	}
}

func newEngineCtx(caller string) *common.EngineContext {
	if caller == "" {
		caller = defaultCaller
	}
	return &common.EngineContext{
		TxContext: &common.TxContext{
			Ctx: context.Background(),
			BlockContext: &common.BlockContext{
				Height: 1,
				ChainContext: &common.ChainContext{
					NetworkParameters: &common.NetworkParameters{},
					MigrationParams:   &common.MigrationContext{},
				},
			},
			Caller:        caller,
			Signer:        []byte(caller),
			Authenticator: "test_authenticator",
		}}
}

func adminCtx() *common.EngineContext {
	return &common.EngineContext{
		TxContext: &common.TxContext{
			Ctx: context.Background(),
			BlockContext: &common.BlockContext{
				Height: 1,
				ChainContext: &common.ChainContext{
					NetworkParameters: &common.NetworkParameters{},
					MigrationParams:   &common.MigrationContext{},
				},
			},
			Caller:        "",
			Signer:        []byte(""),
			Authenticator: "test_authenticator",
		},
		OverrideAuthz: true,
	}
}

func Test_Actions(t *testing.T) {
	type testcase struct {
		name string // name of the test
		// array of sql statements, first element is the namespace, second is the sql statement
		// they can begin with {namespace}sql, or just sql
		stmt []string
		// namespace in which the action is defined
		namespace string
		// action to execute
		action string
		// values to pass to the action
		values []any
		// expected results
		results [][]any
		// expected error
		err error
		// errContains is a string that should be contained in the error message
		errContains string
		// executionErrContains is a string that should be contained in the error message
		// raised by the action execution (e.g. from ERROR(), a primary key violation, etc.)
		executionErrContains string
		// caller to use for the action, will default to defaultCaller
		caller string
	}

	// rawTest is a helper that allows us to write test logic purely in Kuneiform.
	rawTest := func(name string, body string, err ...error) testcase {
		var err1 error
		if len(err) > 0 {
			err1 = err[0]
		}
		if len(err) > 1 {
			panic("too many errors")
		}
		return testcase{
			name:   name,
			stmt:   []string{`CREATE ACTION raw_test() public {` + body + `}`},
			action: "raw_test",
			err:    err1,
		}
	}
	_ = rawTest

	tests := []testcase{
		{
			name: "insert and select",
			stmt: []string{`
			CREATE ACTION create_user($name text, $age int) public returns (count int) {
				INSERT INTO users (id, name, age)
				VALUES (1, $name, $age);

				for $row in SELECT count(*) as count FROM users WHERE name = $name {
					RETURN $row.count;
				};

				error('user not found');
			}
			`},
			action: "create_user",
			values: []any{"Alice", int64(30)},
			results: [][]any{
				{int64(1)},
			},
		},
		{
			name: "read values out of the db, perform arithmetic and conditionals",
			stmt: []string{`INSERT INTO users(id, name, age) VALUES (1, 'satoshi', 42), (2, 'hal finney', 50), (3, 'craig wright', 45)`, `
			CREATE ACTION do_something() public view returns (result int) {
				$total int8;
				$sum int8;
				for $row in SELECT count(*) as count, sum(age) as sum FROM users WHERE age >= 45 {
					$total := $row.count::int8;
					$sum := $row.sum::int8;
				}
				if $total is null {
					error('no users found');
				}

				-- random arithmetic
				$result := ($total * 2 + $sum)/3; -- (2 * 2 + 95)/3 = 33

				if $result < 33 {
					error('result is less than 33');
				}
				if $result > 33 {
					error('result is greater than 33');
				}

				RETURN $result;
			}
			`},
			action: "do_something",
			results: [][]any{
				{int64(33)},
			},
		},
		{
			name: "return next from another action",
			stmt: []string{
				`INSERT INTO users(id, name, age) VALUES (1, 'satoshi', 42), (2, 'hal finney', 50), (3, 'craig wright', 45)`,
				`CREATE NAMESPACE test;`,
				`{test}CREATE ACTION get_users() public view returns table(name text, age int) {
					return SELECT name, age FROM main.users ORDER BY id;
				}`,
				`CREATE ACTION get_next_user($d int) public view returns table(name text, age int) {
					for $row in test.get_users() {
						RETURN NEXT $row.name, $row.age/$d;
					}
				}`,
			},
			values: []any{int64(2)},
			action: "get_next_user",
			results: [][]any{
				{"satoshi", int64(21)},
				{"hal finney", int64(25)},
				{"craig wright", int64(22)},
			},
		},
		{
			name: "calling an action that returns several variables",
			stmt: []string{
				`CREATE ACTION get_several_values($i int) public view returns (value1 int, value2 int, value3 int) {
					RETURN $i, $i + 1, $i + 2;
				}`,
				`CREATE ACTION call_get_several_values() public view {
					$value1, $value2, $value3 := get_several_values(1);

					_, $value2Again, _ := get_several_values(1);
					$value1Again := get_several_values(1);

					if $value1 != 1 {
						error('value1 is not 1');
					}
					if $value2 != 2 {
						error('value2 is not 2');
					}
					if $value3 != 3 {
						error('value3 is not 3');
					}
					if $value2Again != 2 {
						error('value2Again is not 2');
					}
					if $value1Again != 1 {
						error('value1Again is not 1');
					}
				}`,
			},
			action: "call_get_several_values",
		},
		{
			// we test a single typed receiver because it calls a different interpreter function
			name: "calling an action that returns a table to values (single receiver)",
			stmt: []string{
				`CREATE ACTION get_table() public view returns table(value int) {
					RETURN NEXT 1;
					RETURN NEXT 2;
				}`,
				`CREATE ACTION call_get_table() public view {
					$value1 text := get_table();
				}`,
			},
			action: "call_get_table",
			err:    engine.ErrReturnShape,
		},
		{
			name: "calling an action that returns a table to values (multiple receivers)",
			stmt: []string{
				`CREATE ACTION get_table() public view returns table(value int) {
					RETURN NEXT 1, 2, 3;
					RETURN NEXT 4, 5, 6;
				};
				`,
				`CREATE ACTION call_get_table() public view {
					$value1, $value2, $value3 := get_table();
				}`,
			},
			action: "call_get_table",
			err:    engine.ErrReturnShape,
		},
		{
			name: "calling an action that returns not enough values (single receiver)",
			stmt: []string{
				`CREATE ACTION get_val() public view { /*returns nothing*/ }`,
				`CREATE ACTION call_get_val() public view {
					$value1 text := get_val();
				}`,
			},
			action: "call_get_val",
			err:    engine.ErrReturnShape,
		},
		{
			name: "calling an action that returns not enough values (multiple receivers)",
			stmt: []string{
				`CREATE ACTION get_val() public view returns (int) {
					RETURN 1;
				}`,
				`CREATE ACTION call_get_val() public view {
					$value1, $value2 := get_val();
				}`,
			},
			action: "call_get_val",
			err:    engine.ErrReturnShape,
		},
		{
			// we test a single typed receiver because it calls a different interpreter function
			name: "calling an action that returns wrong type (single receiver)",
			stmt: []string{
				`CREATE ACTION get_val() public view returns (int) {
					RETURN 1;
				}`,
				`CREATE ACTION call_get_val() public view {
					$value1 text := get_val();
				}`,
			},
			action: "call_get_val",
			err:    engine.ErrType,
		},
		{
			// we test multiple returns because it calls a different interpreter function
			// if we are returning more than 1 value
			name: "calling an action that returns wrong type (multiple receivers)",
			stmt: []string{
				`CREATE ACTION get_val() public view returns (int, int) {
					RETURN 1, 2;
				}`,
				`CREATE ACTION call_get_val() public view {
					$value1 text;
					$value1, $value2 := get_val();
				}`,
			},
			action: "call_get_val",
			err:    engine.ErrType,
		},
		rawTest("loop over array", `
		$arr := array[1,2,3];
		$sum := 0;
		for $i in array $arr {
			$sum := $sum + $i;
		};

		if $sum != 6{
			error('sum is not 6');
		};
		`),
		rawTest("loop over range", `
		$sum := 0;
		for $i in 1..4 {
			$sum := $sum + $i;
		}

		if $sum != 10 {
			error('sum is not 10');
		}
		`),
		rawTest("slice", `
		$arr := array[1,2,3,4,5];
		$slice := $arr[2:3];
		if $slice != array[2,3] {
			error('slice is not [2,3]');
		}
		`),
		rawTest("assign to array value", `
		$arr := array[1,2,3];
		$arr[2] := 5;
		if $arr != array[1,5,3] {
			error('array is not [1,5,3]');
		}
		if $arr[3] != 3 {
			error('array[3] is not 3');
		}
		`),
		{
			name: "call another action",
			stmt: []string{
				`CREATE NAMESPACE other;`,
				`{other}CREATE ACTION get_single_value() public view returns (value int) { return 1; }`,
				`{other}CREATE ACTION get_several_values() public view returns (value1 int, value2 int) { return 2, 3; }`,
				`{other}CREATE ACTION get_table($to int, $from int) public view returns table(value int) {
					for $i in $to..$from {
						RETURN NEXT $i;
					};
				}`,
				`CREATE ACTION call_other() public view {
					$value1 := other.get_single_value();
					if $value1 != 1 {
						error('value1 is not 1');
					}

					$value2, $value3 := other.get_several_values();
					if $value2 != 2 {
						error('value2 is not 2');
					}
					if $value3 != 3 {
						error('value3 is not 3');
					}

					_, $value3Again := other.get_several_values();
					if $value3Again != 3 {
						error('value3Again is not 3');
					}

					$iter := 0;
					for $row in other.get_table(1, 4) {
						$iter := $iter + 1;
						if $row.value != $iter {
							error('value is not equal to iter');
						}
					}
					if $iter != 4 {
						error('iter is not 4');
					}
				}`,
			},
			action: "call_other",
		},
		rawTest("assign notice to a var", `
		$a := notice('hello');
		`, engine.ErrReturnShape),
		rawTest("testing if, else if, else", `
		$a := 1;
		$b := 2;
		$total := 0;
		if $a < $b {
			$total := $total + 1;
		} else {
			error('a is not less than b');
		}

		if $a > $b {
			error('a is not greater than b');
		} else if $a == $b {
			error('a is not equal to b');
		} else {
			$total := $total + 1;
		}

		if $a + $b == 4 {
			error('a + b is not 4');
		} elseif $a + $b == 3 { -- supports else if and elseif
			$total := $total + 1;
		} else {
			error('a + b is not 3');
		}

		if $total != 3 {
			error('total is not 3');
		}
		`),
		rawTest("break", `
		$sum := 0;
		for $i in 1..10 {
			$sum := $sum + $i;
			if $i == 5 {
				break;
			}
		}

		if $sum != 15 {
			error('sum is not 15, but ' || $sum::text);
		}
		`),
		rawTest("continue", `
		$sum := 0;
		for $i in 1..10 {
			if $i == 5 {
				continue;
			}
			$sum := $sum + $i;
		}

		if $sum != 50 {
			error('sum is not 50, but ' || $sum::text);
		}
		`),
		rawTest("function call expression", `
		if abs(-1) != 1 {
			error('abs(-1) is not 1');
		}
		`),
		rawTest("logical expression", `
		if true and false {
			error('true and false is not false');
		}

		if true or false {
			-- pass
		} else {
			error('true or false is not true');
		}

		if (true or false) and true {
			-- pass
		} else {
			error('(true or false) and true is not true');
		}

		if true and null {
			error('true and null should be null');
		}
		if null and false {
			error('null and false should be null');
		}
		`),
		rawTest("arithmetic", `
		if 1 + 2 != 3 {
			error('1 + 2 is not 3');
		}
		if 1 - 2 != -1 {
			error('1 - 2 is not -1');
		}
		if 2 * 2 != 4 {
			error('2 * 2 is not 4');
		}
		if 4 / 2 != 2 {
			error('4 / 2 is not 2');
		}
		if 5 % 2 != 1 {
			error('5 % 2 is not 1');
		}
		if 5 + null is not null {
			error('5 + null is not null');
		}
		`),
		{
			name: "replace action",
			stmt: []string{
				"CREATE ACTION act() public { error('replace me'); };",
				"CREATE OR REPLACE ACTION act() public { /* no error */ };",
			},
			action: "act",
		},
		rawTest("adding a string to a number", `$a := 1 + 'a';`, engine.ErrType),
		rawTest("if on a number", `if 'a' { error('should not be true'); }`, engine.ErrType),
		rawTest("invalid function arg type", `abs('a');`, engine.ErrType),

		rawTest("for loop with invalid range", `for $i in 'a'..3 { error('should not be true'); }`, engine.ErrType),
		rawTest("for loop with invalid array", `for $i in array 'a' { error('should not be true'); }`, engine.ErrType),
		{
			name: "for loop over action that returns many records",
			stmt: []string{
				`CREATE ACTION get_users() public view returns table(name text, age int) {
					return next 'satoshi', 42;
					return next 'hal finney', 50;
				}`,
				`CREATE ACTION loop_over_users() public view {
					$i := 0;
					for $row in get_users() {
						if $i == 0 {
							if $row.name != 'satoshi' {
								error('name is not satoshi');
							};
						} else if $i == 1 {
							if $row.name != 'hal finney' {
								error('name is not hal finney');
							};
						} else {
							error('too many rows');
						}

						$i := $i + 1;
					};
				}`,
			},
			action: "loop_over_users",
		},
		{
			name: "for loop over action that returns an array",
			stmt: []string{
				`CREATE ACTION get_users($a int, $b int) public view returns (int[]) {
					return array[$a, $b];
				}`,
				`CREATE ACTION loop_over_users() public view {
					$i := 0;
					for $row in array get_users(1,2) {
						$i := $i + 1;
					}
					if $i != 2 {
						error('expected 2 rows');
					}

					$i := 0;
					-- without the array keyword, it should be treated as a single row
					for $row in get_users(3,4) {
						$i := $i + 1;
					}
					if $i != 1 {
						error('expected 1 row');
					}
				}`,
			},
			action: "loop_over_users",
		},
		rawTest("loop over array without ARRAY keyword", `
		$a := array[1,2,3];
		for $i in $a {
			error('should not be true');
		}
		`, engine.ErrLoop),
		{
			name: "nested query",
			stmt: []string{
				`CREATE ACTION create_users() public returns table(name text, age int) {
					for $row in SELECT 'satoshi' as name, 42 as age {
						INSERT INTO users (id, name, age) VALUES (1, $row.name, $row.age);
					}

					return SELECT name, age FROM users;
				}`,
			},
			action: "create_users",
			err:    engine.ErrQueryActive,
		},
		// case sensitivity
		{
			name: "case insensitivity",
			stmt: []string{
				"CREATE NAMESPACE cAsE_senSitivE;",
				"{cAsE_SenSitive}CReATE TaBLE tAbLee (cOl iNT PRImARY KEY);",
				"{CAsE_SenSitive}INSeRT InTO tAbLEe (cOL) VaLUES (1);",
				"{cASE_SENSITIVE}CREATE InDEX idX ON tAblee (Col);",
				"{cAsE_sEnSiTive}DROP INDEX iDx;",
				`{cAsE_sENSiTive}CREATE AcTiON aCt($aA inT) PuBLIC vIeW retUrns tabLe(vAl InT) {
							Return seleCt $Aa + 1;
						};`,
				`{cAsE_sEnSiTivE}CrEate AcTion acT2() pUbLic vIew ReTurns tAble(vAl Int) {
							for $rOw in Act(1) {
								rEturn NeXt $roW.VAL;
							}
						}`,
				// roles
				`CREATE ROLE teSt_rOle;`,
				`grant test_rolE to 'user';`,
				`revoke tesT_Role from 'user';`,
				`grant CaLL oN CASE_SEnsItive TO Test_rOle;`,
				`revoke cALl on case_SENsitive from test_ROLe;`,
				`dRop RoLe tEst_ROLE;`,
				// namespaces
				`CREATE NAMESPACE tEst_Namespace;`,
				`DROP NAMESPACE test_namespACe;`,
			},
			namespace: "case_sensITIVE",
			action:    "Act2",
			results:   [][]any{{int64(2)}},
		},
		rawTest("null array index", `
		$arr := array[1,2,3];
		$idx int;
		$a := $arr[$idx];
		if $a is not null {
			error('a is not null');
		}

		-- test null slices too
		$s1 := $arr[null:2];
		$s2 := $arr[1:null];
		$s3 := $arr[null:null];
		$s4 := $arr[:null];
		$s5 := $arr[null:];
		if $s1 is not null {
			error('s1 is not null');
		}
		if $s2 is not null {
			error('s2 is not null');
		}
		if $s3 is not null {
			error('s3 is not null');
		}
		if $s4 is not null {
			error('s4 is not null');
		}
		if $s5 is not null {
			error('s5 is not null');
		}
		`),
		rawTest("set null", `
			$a := 1;
			$a := null;
		`),
		rawTest("set null in array", `
		$arr := array[1,2,3];
		$arr[1] := null;
		`),
		rawTest("set null to untyped value", `
		 	$a := null;`),
		rawTest("allocate null to typed variable", `
			$a int := null;`),
		rawTest("set new type to variable", `
		$a int;
		$a text := 'hi';
		`, engine.ErrType),
		rawTest("set same type to variable", `
		$a := 1;
		$a int := 2;
		`),
		rawTest("assign int to @caller", `
			@caller int := 1;
		`, engine.ErrType),
		rawTest("assign text to @caller", `
			@caller text := 'hi';
		`, engine.ErrInvalidVariable),
		rawTest("assign to slice", `
		$arr := array[1,2,3];
		$arr[1:2] := array[4,5];
		if $arr != array[4,5,3] {
			error('arr is not [4,5,3]');
		}
		$arr[1:] := array[6,7,8];
		if $arr != array[6,7,8] {
			error('arr is not [6,7,8]');
		}
		$arr[:2] := array[9,10];
		if $arr != array[9,10,8] {
			error('arr is not [9,10,8]');
		}
		$arr[:] := array[11,12,13];
		if $arr != array[11,12,13] {
			error('arr is not [11,12,13]');
		}
		$arr[5] := 14;
		if $arr != array[11,12,13,null,14] {
			error('arr is not [11,12,13,null,14]');
		}

		-- test type casting is automatic
		$arr[1:2] := array['15','16'];
		if $arr != array[15,16,13,null,14] {
			error('arr is not [15,16,13,null,14]');
		}
		`),
		rawTest("assign to slice that is too short (will be truncated)", `
		$arr := array[1,2,3];
		$arr[1:2] := array[4,5,6];
		if $arr != array[4,5,3] {
			error('arr is not [4,5,3]');
		}
		`),
		rawTest("assign to slice that is too long (will err)", `
		$arr := array[1,2,3];
		$arr[1:2] := array[4];
		`, engine.ErrArrayTooSmall),
		rawTest("assign to null index", `
		$arr := array[1,2,3];
		$arr[null] := 4;
		`, engine.ErrInvalidNull),
		rawTest("assign to negative index", `
		$arr := array[1,2,3];
		$arr[-1] := 4;
		`, engine.ErrIndexOutOfBounds),
		rawTest("assign to slice with from > to", `
		$arr := array[1,2,3];
		$arr[2:1] := array[4,5];
		`, engine.ErrIndexOutOfBounds),
		rawTest("assign to slice with null from", `
		$arr := array[1,2,3];
		$arr[null:2] := array[4,5];
		`, engine.ErrInvalidNull),
		rawTest("assign to slice with null to", `
		$arr int[] := array[1,2,3];
		$arr[1:null] := array[4,5];
		`, engine.ErrInvalidNull),
		rawTest("loop over range with null", `
			for $i in null..3 {
				error('should not be true');
			}

			for $i in 1..null {
				error('should not be true');
			}

			$arr int[] := null;
			for $i in array $arr {
				error('should not be true');
			}
		`),
		rawTest("if null", `
		if null {
			error('should not be true');
		}
		`),
		rawTest(`access null array`, `
			$arr int[] := null;
			$a := $arr[1];
			$a := 1; -- should be an int, so this should be fine
		`),
		rawTest(`uuid kwil`, `
		$id := uuid_generate_kwil('a');
		if $id != '819ab751-e64c-5259-bbae-4d36f25bdd84'::uuid {
			error($id::TEXT);
		}
		`),
		{
			name: "action param changes do not reflect in the caller",
			stmt: []string{
				`CREATE ACTION change_param($a int) public view returns (b int) {
					$a := 2;
					RETURN $a;
				}`,
				`CREATE ACTION call_change_param() public view {
					$a := 1;
					$b := change_param($a);
					if $a != 1 {
						error('a is not 1');
					}
					if $b != 2 {
						error('b is not 2');
					}
				}`,
			},
			action: "call_change_param",
		},
		{
			name: "nested action returns null",
			stmt: []string{
				`CREATE ACTION get_null() public view returns (a int) { RETURN null; }`,
				`CREATE ACTION call_get_null() public view { $a := get_null(); if $a is not null { error('a is not null'); } }`,
			},
			action: "call_get_null",
		},
		{
			name: "action returns null to another action",
			stmt: []string{
				`CREATE ACTION get_null() public view returns (a int) { RETURN null; }`,
				`CREATE ACTION call_get_null() public view { $a := get_null()::TEXT; if $a is not null { error('a is not null'); } }`,
			},
			action: "call_get_null",
		},
		{
			name: "action returning nothing to another action",
			stmt: []string{
				`CREATE ACTION get_nothing() public view { /* returns nothing */ }`,
				`CREATE ACTION call_get_nothing() public view { $a := get_nothing(); }`,
			},
			action: "call_get_nothing",
			err:    engine.ErrReturnShape,
		},
		{
			// this is a regression test
			name: "special functions called in new namespaces works as expected",
			stmt: []string{
				`CREATE NAMESPACE test;`,
				`{test} create action get_uuid() public view returns (uuid) {return uuid_generate_kwil('a');}`,
			},
			namespace: "test",
			action:    "get_uuid",
			results:   [][]any{{mustUUID("819ab751-e64c-5259-bbae-4d36f25bdd84")}},
		},
		rawTest("loop over array with nulls", `
		$i := 1;
		for $name IN ARRAY ['Alice', null, 'Bob'] {
			if $i == 1 AND $name != 'Alice' {
				error('name is not Alice');
			}

			if $i == 2 AND $name is not null {
				error('name is not null');
			}

			if $i == 3 AND $name != 'Bob' {
				error('name is not Bob');
			}

			$i := $i + 1;
		}
		`),
		{
			name: "private actions can be called within the same namespace",
			stmt: []string{
				`CREATE ACTION private_action() private { }`,
				`CREATE ACTION call_private_action() public { private_action(); }`,
			},
			action: "call_private_action",
		},
		{
			name: "private actions cannot be called from another namespace",
			stmt: []string{
				`CREATE NAMESPACE test;`,
				`{test} CREATE ACTION private_action() private { }`,
				`CREATE ACTION call_private_action() public { test.private_action(); }`,
			},
			action: "call_private_action",
			err:    engine.ErrActionPrivate,
		},
		{
			name: "system actions can be called from any namespace",
			stmt: []string{
				`CREATE NAMESPACE test;`,
				`{test} CREATE ACTION call_system_action() system { }`,
				`{test} CREATE ACTION call_system_action2() system { test.call_system_action(); }`,
				`CREATE ACTION call_system_action3() public { test.call_system_action2(); }`,
			},
			action: "call_system_action3",
		},
		{
			name: "system actions cannot be called publicly",
			stmt: []string{
				`CREATE ACTION call_system_action() system { }`,
			},
			action: "call_system_action",
			err:    engine.ErrActionSystemOnly,
		},
		{
			// regression test
			name: "early return with no values",
			stmt: []string{
				`CREATE ACTION early_return() public view {
					if true {
						RETURN;
						error('should not get here');
					}
					error('should not get here');
				}`,
			},
			action: "early_return",
		},
		{
			name: "return early with sql",
			stmt: []string{
				`CREATE ACTION early_return() public view returns table(value int) {
					if true {
						RETURN SELECT 1;
						error('should not get here');
					}
					error('should not get here');
				}`,
			},
			action:  "early_return",
			results: [][]any{{int64(1)}},
		},
		{
			// this is a regression test
			name: "format inside error",
			stmt: []string{
				`CREATE ACTION format_error() public view {
					$a := 'SomeValue';
					error(format('this is an error with a format %s', $a));
				}`,
			},
			action:               "format_error",
			executionErrContains: "this is an error with a format SomeValue",
		},
		{
			name: "remove call from default role",
			stmt: []string{
				"CREATE ROLE some_role;",
				"CREATE NAMESPACE test;",
				"{test} CREATE ACTION act() public { }",
				"REVOKE CALL ON test FROM default;",
			},
			namespace: "test",
			action:    "act",
			caller:    "some_user",
			err:       engine.ErrDoesNotHavePrivilege,
		},
		{
			name: "empty array",
			stmt: []string{
				`CREATE ACTION empty_array() public view {
					$arr := array[];
				}`,
			},
			action: "empty_array",
			err:    engine.ErrArrayDimensionality,
		},
		{
			name: "empty array (typecasted)",
			stmt: []string{
				`CREATE ACTION empty_array() public view {
					$arr := array[]::text[];
				}`,
			},
			action: "empty_array",
		},
		{
			name: "0-length numeric array",
			stmt: []string{
				`CREATE ACTION smth($arr numeric(10,5)[]) public {
					$arr := array_append($arr, 1.0::numeric(10,5));
				}`,
			},
			action: "smth",
			values: []any{[]*types.Decimal{}},
		},
		{
			name: "select error",
			stmt: []string{
				`CREATE ACTION select_error() public view {
					SELECT error('abcdef_unique');
				}`,
			},
			action:               "select_error",
			executionErrContains: "abcdef_unique",
		},
		{
			name: "primary key conflict",
			stmt: []string{
				`CREATE TABLE t (a int PRIMARY KEY);`,
				`CREATE ACTION insert_conflict($a int) public {
					INSERT INTO t (a) VALUES ($a);
					INSERT INTO t (a) VALUES ($a);
				}`,
			},
			action:               "insert_conflict",
			values:               []any{1},
			executionErrContains: "duplicate key value violates unique constraint",
		},
		{
			name: "call function in loop",
			stmt: []string{
				`CREATE ACTION call_function_in_loop() public view {
					for $i in select 1 as a {
						$a := abs($i.a);
					}
				}`,
			},
			action: "call_function_in_loop",
			err:    engine.ErrQueryActive,
		},
		{
			// regression test from a bug hit by Usher Labs.
			// I'm not totally sure what caused this bug, but it was fixed by cloning
			// slices that were passed to resultFn.
			name: "returning a table of decimals",
			stmt: []string{
				`CREATE TABLE data (id int primary key, value numeric(10,5));`,
				`INSERT INTO data (id, value) VALUES (1, 1.0::numeric(10,5)), (2, 2.0::numeric(10,5));`,
				`CREATE ACTION test() public view returns table(id int, value numeric(10,5)) {
					return SELECT * FROM data ORDER BY id asc;
				}`,
			},
			action: "test",
			results: [][]any{
				{int64(1), mustExplicitDecimal("1.00000", 10, 5)},
				{int64(2), mustExplicitDecimal("2.00000", 10, 5)},
			},
		},
		rawTest("greatest, least, nullif", `
		if greatest(1,2,3) != 3 {
			error('greatest(1,2,3) is not 3');
		}
		if least(1,2,3) != 1 {
			error('least(1,2,3) is not 1');
		}

		if nullif(1,1) is not null {
			error('nullif(1,1) is not null');
		}

		if nullif(1,2) != 1 {
			error('nullif(1,2) is not 1');
		}

		if nullif(2,1) != 2 {
			error('nullif(2,1) is not 2');
		}

		if nullif(null,1) is not null {
			error('nullif(null,1) is not null');
		}

		if nullif(1,null) != 1 {
			error('nullif(1,null) is not 1');
		}
		`),
		rawTest("int cast", `
		$a := 1;
		$b := 2;
		$c := ($a + $b)::numeric(78,0);

		$d numeric(78,0) := 3::numeric(78,0);
		if $c != $d {
			error('c is not d');
		}
		`),
	}

	db := newTestDB(t, nil, nil)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx) // always rollback

			interp := newTestInterp(t, tx, test.stmt, true)

			var results [][]any
			res, err := interp.Call(newEngineCtx(test.caller), tx, test.namespace, test.action, test.values, func(v *common.Row) error {
				results = append(results, v.Values)
				return nil
			})
			if test.err != nil {
				if err == nil {
					require.Error(t, res.Error)
					require.ErrorIs(t, res.Error, test.err)
				} else {
					require.Error(t, err)
					require.ErrorIs(t, err, test.err)
				}
			} else if test.errContains != "" {
				if err == nil {
					require.Error(t, res.Error)
					require.Contains(t, res.Error.Error(), test.errContains)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), test.errContains)
				}
			} else {
				require.NoError(t, err)
				if test.executionErrContains != "" {
					require.NotNil(t, res.Error)
					require.Contains(t, res.Error.Error(), test.executionErrContains)
				}
			}

			require.Equal(t, len(test.results), len(results))
			for i, row := range results {
				require.Equal(t, len(test.results[i]), len(row))
				for j, val := range row {
					colEq(t, test.results[i][j], val)
				}
			}
		})
	}
}

type testPrecompile struct {
	alias  string
	i      int
	meta   map[string]any
	notify func(string)
}

func (t *testPrecompile) OnStart(ctx context.Context, app *common.App) error {
	t.notify("start")
	return nil
}

func (t *testPrecompile) OnUse(ctx *common.EngineContext, app *common.App) error {
	t.notify("use")
	return nil
}

func (t *testPrecompile) makeGetMethod(datatype *types.DataType) precompiles.Method {
	name := datatype.Name
	if datatype.IsArray {
		name += "_array"
	}
	return precompiles.Method{
		Name:       "get_" + name,
		Parameters: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("param", types.TextType, false)},
		Returns: &precompiles.MethodReturn{
			Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("value", datatype, false)},
		},
		Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
			v, ok := t.meta[inputs[0].(string)]
			if !ok {
				return errors.New("expected key in metadata")
			}

			return resultFn([]any{v})
		},
		AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
	}
}

func mustDecType(precision, scale uint16) *types.DataType {
	t, err := types.NewNumericType(precision, scale)
	if err != nil {
		panic(err)
	}
	return t
}

func mustDecArrType(precision, scale uint16) *types.DataType {
	t := mustDecType(precision, scale)
	t.IsArray = true
	return t
}

func (t *testPrecompile) OnUnuse(ctx *common.EngineContext, app *common.App) error {
	t.notify("unuse")
	return nil
}

// This function tests precompiles
func Test_Extensions(t *testing.T) {
	// notifications track in which order the extension is initialized, used, and unused
	var notifications []string

	// below we create a test precompile extension
	err := precompiles.RegisterInitializer("test", func(ctx context.Context, service *common.Service, db sql.DB, alias string, metadata map[string]any) (precompiles.Precompile, error) {
		tc := &testPrecompile{
			alias: alias,
			meta:  metadata,
			notify: func(s string) {
				notifications = append(notifications, s)
			},
		}
		tc.notify("initialize")
		return precompiles.Precompile{
			OnStart: tc.OnStart,
			OnUse:   tc.OnUse,
			OnUnuse: tc.OnUnuse,
			Methods: []precompiles.Method{
				{
					Name:            "concat",
					AccessModifiers: []precompiles.Modifier{precompiles.SYSTEM},
					Parameters: []precompiles.PrecompileValue{
						precompiles.NewPrecompileValue("a", types.TextType, false),
						precompiles.NewPrecompileValue("b", types.TextType, false),
					},
					Returns: &precompiles.MethodReturn{
						Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("val", types.TextType, false)},
					},
					Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
						tc.i++
						return resultFn([]any{inputs[0].(string) + inputs[1].(string)})
					},
				},
				{
					Name: "owner_only",
					Returns: &precompiles.MethodReturn{
						Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, false)},
					},
					Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
						count := 0
						ctx.OverrideAuthz = true
						_, err := app.Engine.Call(ctx, app.DB, tc.alias, "internal", nil, func(v *common.Row) error {
							count++
							if v.Values[0].(string) != "internal" {
								return errors.New("expected 'internal' message")
							}
							return nil
						})
						if err != nil {
							return err
						}
						if count != 1 {
							return errors.New("expected 1 internal call")
						}
						ctx.OverrideAuthz = false

						tc.i++
						return resultFn([]any{"owner_only"})
					},
					AccessModifiers: []precompiles.Modifier{precompiles.OWNER, precompiles.PUBLIC},
				},
				{
					Name: "internal",
					Returns: &precompiles.MethodReturn{
						Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, false)},
					},
					Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
						if len(inputs) != 0 {
							return errors.New("expected 0 inputs")
						}
						tc.i++

						return resultFn([]any{"internal"})
					},
					AccessModifiers: []precompiles.Modifier{precompiles.PRIVATE},
				},
				tc.makeGetMethod(types.TextType),
				tc.makeGetMethod(types.IntType),
				tc.makeGetMethod(types.BoolType),
				tc.makeGetMethod(mustDecType(10, 2)),
				tc.makeGetMethod(types.ByteaType),
				tc.makeGetMethod(types.UUIDType),
				tc.makeGetMethod(types.ArrayType(types.TextType)),
				tc.makeGetMethod(types.ArrayType(types.IntType)),
				tc.makeGetMethod(types.ArrayType(types.BoolType)),
				tc.makeGetMethod(types.ArrayType(types.ByteaType)),
				tc.makeGetMethod(types.ArrayType(types.UUIDType)),
				tc.makeGetMethod(mustDecArrType(10, 2)),
				{
					Name:       "get_param_1",
					Parameters: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, false)},
					Returns: &precompiles.MethodReturn{
						Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("val", types.IntType, false)},
					},
					Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
						tc.i++
						return resultFn([]any{tc.meta["param_1"]})
					},
					AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
				},
				{
					Name:       "get_param_2",
					Parameters: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, false)},
					Returns: &precompiles.MethodReturn{
						Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("val", types.ArrayType(types.ByteaType), false)},
					},
					Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
						tc.i++
						return resultFn([]any{tc.meta["param_2"]})
					},
					AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
				},
			},
		}, nil
	})
	require.NoError(t, err)

	// now we can test calling the precompile
	// There are a few things we should test. All of these tests should be performed twice:
	// once with the extension initialized and deployed at the same time, and once with an interpreter
	// restarted, which simulates a node restart.
	//
	// The following tests should be performed:
	// 1. concat can only be called by other actions
	// 2. get can be called publicly or by other actions, and can be called in a view action
	// 3. owner_only can only be called by the owner
	// 4. internal can only be called by other methods, and not externally
	// 5. metadata of every type is passed correctly (verify using get)
	// 6. importing the extension creates a namespace that can cannot dropped by the admin
	// 7. the extension namespace can have privileges granted to roles
	// 8. the owner cannot add tables, actions, etc. to the extension namespace. The admin can.

	// finally, the extension is initialized, used, and unused in the correct order (notifications)

	db := newTestDB(t, nil, nil)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	i := 0 // tracks iters, since some of these cannot be made idempotent (e.g. alter table)

	do := func(interp *interpreter.ThreadSafeInterpreter) {

		callFromUser := func(caller string, namespace, action string, values []any, fn func(*common.Row) error) error {
			_, err := interp.Call(newEngineCtx(caller), tx, namespace, action, values, fn)
			return err
		}
		adminCall := func(namespace, action string, values []any, fn func(*common.Row) error) error {
			_, err := interp.CallWithoutEngineCtx(ctx, tx, namespace, action, values, fn)
			return err
		}
		execFromUser := func(caller string, sql string, fn func(*common.Row) error) error {
			return interp.Execute(newEngineCtx(caller), tx, sql, nil, fn)
		}
		adminExec := func(sql string, fn func(*common.Row) error) error {
			return interp.Execute(adminCtx(), tx, sql, nil, fn)
		}

		// initialize the extension
		err = interp.Execute(newEngineCtx(defaultCaller), tx, `
		USE IF NOT EXISTS test {
			text: 'text',
			int8: 1+2,
			bool: true,
			bytea: 0x010203, -- hex encoded []byte{1,2,3}
			uuid: 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
			numeric: 1.23::numeric(10,2),
			text_array: array['text'],
			int8_array: array[1],
			bool_array: array[true],
			bytea_array: array[0x010203],
			uuid_array: array['f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid],
			numeric_array: array[1.23::numeric(10,2)],
			param_1: $a,
			param_2: $b
		} AS test_ext;
	`, map[string]any{
			"a": 1,
			"b": [][]byte{{1, 2}, {3, 4}},
		}, func(r *common.Row) error {
			return nil
		})
		require.NoError(t, err)

		// 1: concat can only be called by other actions
		err = callFromUser(defaultCaller, "test_ext", "concat", []any{"hello", "world"}, nil)
		assert.ErrorIs(t, err, engine.ErrActionSystemOnly)

		err = adminExec("CREATE ACTION IF NOT EXISTS call_concat() public view returns (text) { return test_ext.concat('hello', 'world'); }", nil)
		require.NoError(t, err)

		err = callFromUser(defaultCaller, "", "call_concat", nil, exact("helloworld"))
		require.NoError(t, err)

		// cannot be called in view action
		err = adminExec("CREATE ACTION IF NOT EXISTS call_concat_view() public view returns (text) { return test_ext.concat('hello', 'world'); }", nil)
		require.NoError(t, err)

		readTx, err := db.BeginReadTx(ctx)
		require.NoError(t, err)
		defer readTx.Rollback(ctx)

		_, err = interp.Call(newEngineCtx(defaultCaller), readTx, "", "call_concat_view", nil, exact("helloworld"))
		assert.ErrorIs(t, err, engine.ErrCannotMutateState)

		// 2: get can be called publicly or by other actions, and can be called in a view action
		err = callFromUser(defaultCaller, "test_ext", "get_text", []any{"text"}, exact("text"))
		require.NoError(t, err)

		err = adminExec("CREATE ACTION IF NOT EXISTS call_get() public view returns (text) { return test_ext.get_text('text'); }", nil)
		require.NoError(t, err)

		err = callFromUser(defaultCaller, "", "call_get", nil, exact("text"))
		require.NoError(t, err)

		// 3: owner_only can only be called by the owner
		err = adminCall("test_ext", "owner_only", nil, exact("owner_only"))
		require.NoError(t, err)

		err = callFromUser("user", "test_ext", "owner_only", nil, nil)
		assert.ErrorIs(t, err, engine.ErrActionOwnerOnly)

		// 4: internal can only be called by other methods, and not externally nor by
		// other actions in different namespaces

		// callable by other methods is tested implicitly with the get method
		err = callFromUser(defaultCaller, "test_ext", "internal", nil, exact("internal"))
		assert.ErrorIs(t, err, engine.ErrActionPrivate)

		// action in "main" namespace cannot call internal
		err = adminExec("CREATE ACTION IF NOT EXISTS call_internal() public view returns (text) { return test_ext.internal(); }", nil)
		require.NoError(t, err)

		err = callFromUser(defaultCaller, "", "call_internal", nil, exact("internal"))
		assert.ErrorIs(t, err, engine.ErrActionPrivate)

		// calling a private action with overrideAuthz should work
		err = adminCall("test_ext", "internal", nil, exact("internal"))
		require.NoError(t, err)

		// action in "test_ext" namespace can call internal
		err = adminExec("{test_ext}CREATE ACTION IF NOT EXISTS call_internal() public view returns (text) { return internal(); }", nil)
		require.NoError(t, err)

		err = callFromUser(defaultCaller, "test_ext", "call_internal", nil, exact("internal"))
		require.NoError(t, err)

		// 5. metadata of every type is passed correctly (verify using get)
		for _, get := range []struct {
			key   string
			value any
		}{
			{"text", "text"},
			{"int8", int64(3)},
			{"bool", true},
			{"bytea", []byte{1, 2, 3}},
			{"uuid", mustUUID("f47ac10b-58cc-4372-a567-0e02b2c3d479")},
			{"numeric", mustExplicitDecimal("1.23", 10, 2)},
			{"text_array", []string{"text"}},
			{"int8_array", []int64{1}},
			{"bool_array", []bool{true}},
			{"bytea_array", []*[]byte{{1, 2, 3}}},
			{"uuid_array", []*types.UUID{mustUUID("f47ac10b-58cc-4372-a567-0e02b2c3d479")}},
			{"numeric_array", []*types.Decimal{mustExplicitDecimal("1.23", 10, 2)}},
			{"param_1", int64(1)},
			{"param_2", []*[]byte{{1, 2}, {3, 4}}},
		} {
			err = adminCall("test_ext", "get_"+get.key, []any{get.key}, exact(get.value))
			require.NoErrorf(t, err, "key: %s", get.key)
		}

		// 6. The imported extension creates a namespace that cannot be dropped by the admin
		err = adminExec("DROP NAMESPACE IF EXISTS test_ext;", nil)
		require.ErrorIs(t, err, engine.ErrCannotMutateExtension)

		// 7. The extension namespace can have privileges granted to roles
		err = execFromUser(defaultCaller, "CREATE ROLE IF NOT EXISTS test_role;", nil)
		require.NoError(t, err)

		err = execFromUser(defaultCaller, "GRANT IF NOT GRANTED select ON test_ext TO test_role;", nil)
		require.NoError(t, err)

		// 8. The owner cannot create/alter/drop tables, actions, etc. to the extension namespace. The admin can.

		// tables
		err = execFromUser(defaultCaller, "{test_ext}CREATE TABLE IF NOT EXISTS test_table (id INT PRIMARY KEY);", nil)
		require.ErrorIs(t, err, engine.ErrCannotMutateExtension)

		err = adminExec("{test_ext}CREATE TABLE IF NOT EXISTS test_table (id INT PRIMARY KEY);", nil)
		require.NoError(t, err)

		err = execFromUser(defaultCaller, "{test_ext}ALTER TABLE test_table ADD COLUMN name TEXT;", nil)
		require.ErrorIs(t, err, engine.ErrCannotMutateExtension)

		if i == 0 {
			err = adminExec("{test_ext}ALTER TABLE test_table ADD COLUMN name TEXT;", nil)
			require.NoError(t, err)
		}

		// indexes
		err = execFromUser(defaultCaller, "{test_ext}CREATE INDEX IF NOT EXISTS test_index ON test_table (id);", nil)
		require.ErrorIs(t, err, engine.ErrCannotMutateExtension)

		err = adminExec("{test_ext}CREATE INDEX IF NOT EXISTS test_index ON test_table (id);", nil)
		require.NoError(t, err)

		err = execFromUser(defaultCaller, "{test_ext}DROP INDEX IF EXISTS test_index;", nil)
		require.ErrorIs(t, err, engine.ErrCannotMutateExtension)

		err = adminExec("{test_ext}DROP INDEX IF EXISTS test_index;", nil)
		require.NoError(t, err)

		// insert

		err = execFromUser(defaultCaller, "{test_ext}INSERT INTO test_table (id) VALUES (1);", nil)
		require.ErrorIs(t, err, engine.ErrCannotMutateExtension)

		err = adminExec("{test_ext}INSERT INTO test_table (id) VALUES (1);", nil)
		require.NoError(t, err)

		// drop table

		err = execFromUser(defaultCaller, "{test_ext}DROP TABLE IF EXISTS test_table;", nil)
		require.ErrorIs(t, err, engine.ErrCannotMutateExtension)

		err = adminExec("{test_ext}DROP TABLE IF EXISTS test_table;", nil)
		require.NoError(t, err)

		// actions

		err = execFromUser(defaultCaller, "{test_ext}CREATE ACTION IF NOT EXISTS test_action() public view returns (text) { return 'test'; }", nil)
		require.ErrorIs(t, err, engine.ErrCannotMutateExtension)

		err = adminExec("{test_ext}CREATE ACTION IF NOT EXISTS test_action() public view returns (text) { return 'test'; }", nil)
		require.NoError(t, err)

		err = execFromUser(defaultCaller, "{test_ext}DROP ACTION IF EXISTS test_action;", nil)
		require.ErrorIs(t, err, engine.ErrCannotMutateExtension)

		err = adminExec("{test_ext}DROP ACTION IF EXISTS test_action;", nil)
		require.NoError(t, err)

	}

	// first run: new interpreter
	interp := newTestInterp(t, tx, nil, true)
	do(interp)

	// check notifications
	require.Equal(t, []string{"initialize", "start", "use"}, notifications)

	// second run: restart interpreter
	// It will read in all previous data from the database.
	interp = newTestInterp(t, tx, nil, true)
	do(interp)

	// unuse
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `UNUSE test_ext;`, nil, nil)
	require.NoError(t, err)

	// check notifications
	require.Equal(t, []string{"initialize", "start", "use", "initialize", "start", "unuse"}, notifications)
}

// This test tests that functions can be overwritten by extension methods, and extension
// methods can be overwritten by actions. Dropping actions should restore the correct previous
// behavior.
func Test_NamingOverwrites(t *testing.T) {
	db := newTestDB(t, nil, nil)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	// we use an extension with one method "abs" to overwrite the built-in abs function
	absCalled := false
	err = precompiles.RegisterPrecompile("test2", precompiles.Precompile{
		Methods: []precompiles.Method{
			{
				Name: "abs",
				Parameters: []precompiles.PrecompileValue{
					precompiles.NewPrecompileValue("a", types.IntType, false),
				},
				Returns: &precompiles.MethodReturn{
					Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("val", types.IntType, false)},
				},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					absCalled = true
					raw, ok := inputs[0].(int64)
					if !ok {
						return errors.New("expected int64 input")
					}

					return resultFn([]any{int64(math.Abs(float64(raw)))})
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
			},
		},
	})
	require.NoError(t, err)

	interp := newTestInterp(t, tx, nil, true)

	err = interp.Execute(newEngineCtx(defaultCaller), tx, `USE IF NOT EXISTS test2 AS test_ext;`, nil, nil)
	require.NoError(t, err)

	// we will create an action in the extension schema and call abs
	err = interp.Execute(adminCtx(), tx, `{test_ext}CREATE OR REPLACE ACTION use_abs() public view returns (int) { return abs(-1); }`, nil, nil)
	require.NoError(t, err)

	// we will call it to ensure that it uses the extension method
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "test_ext", "use_abs", nil, exact(int64(1)))
	require.NoError(t, err)

	assert.True(t, absCalled)

	// now we will create an action that overwrites the abs function
	absCalled = false
	err = interp.Execute(adminCtx(), tx, `{test_ext}CREATE OR REPLACE ACTION abs($a int) system view returns (int) { return 2; }`, nil, nil)
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "test_ext", "use_abs", nil, exact(int64(2)))
	require.NoError(t, err)
	assert.False(t, absCalled)

	// we will make a new interpreter to ensure that they are loaded correctly
	interp = newTestInterp(t, tx, nil, true)

	// ensure that the action is still called
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "test_ext", "use_abs", nil, exact(int64(2)))
	require.NoError(t, err)

	// dropping the action should make it call the extension method again
	err = interp.Execute(adminCtx(), tx, `{test_ext}DROP ACTION abs;`, nil, nil)
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "test_ext", "use_abs", nil, exact(int64(1)))
	require.NoError(t, err)
	assert.True(t, absCalled)

	// will now try it to make sure we can go from action -> function
	err = interp.Execute(adminCtx(), tx, `create OR REPLACE action length($a text) public view returns (int) { return 1; }`, nil, nil)
	require.NoError(t, err)

	err = interp.Execute(adminCtx(), tx, `create OR REPLACE action use_length() public view returns (int) { return length('hello'); }`, nil, nil)
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "", "use_length", nil, exact(int64(1)))
	require.NoError(t, err)

	// dropping the action should restore the correct behavior
	err = interp.Execute(adminCtx(), tx, `DROP ACTION length;`, nil, nil)
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "", "use_length", nil, exact(int64(5)))
	require.NoError(t, err)
}

// This tests that db ownership functionality works as expected
func Test_Ownership(t *testing.T) {
	db := newTestDB(t, nil, nil)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	interp := newTestInterp(t, tx, nil, false)

	user2 := "user2"
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `TRANSFER OWNERSHIP TO '`+user2+`';`, nil, nil)
	require.NoError(t, err)

	// test that default user cannot create a table
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `CREATE TABLE test_table (id INT PRIMARY KEY);`, nil, nil)
	require.ErrorIs(t, err, engine.ErrDoesNotHavePrivilege)

	// test user2 can create a table
	err = interp.Execute(newEngineCtx(user2), tx, `CREATE TABLE test_table (id INT PRIMARY KEY);`, nil, nil)
	require.NoError(t, err)

	// user2 can transfer ownership back to default user
	err = interp.Execute(newEngineCtx(user2), tx, `TRANSFER OWNERSHIP TO '`+defaultCaller+`';`, nil, nil)
	require.NoError(t, err)

	// user2 cannot drop table
	err = interp.Execute(newEngineCtx(user2), tx, `DROP TABLE test_table;`, nil, nil)
	require.ErrorIs(t, err, engine.ErrDoesNotHavePrivilege)

	// default user can drop table
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `DROP TABLE test_table;`, nil, nil)
	require.NoError(t, err)

	// use WithoutCtx to force ownership transfer back to user 2
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `TRANSFER OWNERSHIP TO $user;`, map[string]any{
		"user": user2,
	}, nil)
	require.NoError(t, err)

	// user2 can create a table
	err = interp.Execute(newEngineCtx(user2), tx, `CREATE TABLE test_table (id INT PRIMARY KEY);`, nil, nil)
	require.NoError(t, err)

	// default user cannot drop table
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `DROP TABLE test_table;`, nil, nil)
	require.ErrorIs(t, err, engine.ErrDoesNotHavePrivilege)

	// default user cannot transfer ownership
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `TRANSFER OWNERSHIP TO 'user3';`, nil, nil)
	require.ErrorIs(t, err, engine.ErrDoesNotHavePrivilege)

	// it is impossible to revoke privileges from the owner, even if using WithoutCtx
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `REVOKE insert FROM owner;`, nil, nil)
	require.Contains(t, err.Error(), "owner role cannot have privileges revoked")
}

// This tests that the `notice` function works correctly, even when methods call an action that
// logs a notice, and that method is called from another action (which was a previous bug).
func Test_Notice(t *testing.T) {
	db := newTestDB(t, nil, nil)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	alias := "log_ext"
	err = precompiles.RegisterPrecompile("log", precompiles.Precompile{
		OnUse: func(ctx *common.EngineContext, app *common.App) error {
			// we create an action that logs a notice
			ctx.OverrideAuthz = true
			defer func() { ctx.OverrideAuthz = false }()
			return app.Engine.Execute(ctx, app.DB, "{"+alias+"}"+`CREATE ACTION log_notice() public view { notice('internal notice'); }`, nil, nil)
		},
		Methods: []precompiles.Method{
			{
				Name: "method_log_notice",
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					res, err := app.Engine.Call(ctx, app.DB, alias, "log_notice", nil, nil)
					if err != nil {
						return err
					}

					if len(res.Logs) != 1 {
						return errors.New("expected 1 log")
					}

					if res.Logs[0] != "internal notice" {
						return fmt.Errorf("expected 'internal notice', got %s", res.Logs[0])
					}

					return nil
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
			},
		},
	})
	require.NoError(t, err)

	interp := newTestInterp(t, tx, nil, true)

	err = interp.Execute(newEngineCtx(defaultCaller), tx, `USE log AS log_ext;`, nil, nil)
	require.NoError(t, err)

	err = interp.Execute(adminCtx(), tx, `{log_ext}CREATE OR REPLACE ACTION call_log_notice() public view { notice('external notice'); log_ext.method_log_notice(); }`, nil, nil)
	require.NoError(t, err)

	res, err := interp.Call(newEngineCtx(defaultCaller), tx, "log_ext", "call_log_notice", nil, nil)
	require.NoError(t, err)

	if len(res.Logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(res.Logs))
	}

	if res.Logs[0] != "external notice" {
		t.Fatalf("expected 'external notice', got %s", res.Logs[0])
	}

	if res.Logs[1] != "internal notice" {
		t.Fatalf("expected 'internal notice', got %s", res.Logs[1])
	}

	// we will also test that notice cannot be called within a sql statement
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `SELECT notice('hello');`, nil, nil)
	require.ErrorIs(t, err, engine.ErrIllegalFunctionUsage)
}

// this tests that extension type checks work properly
func Test_ExtensionTypeChecks(t *testing.T) {
	db := newTestDB(t, nil, nil)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	// we will add four methods:
	// 1. takes 1 param (cannot be null), returns nothing
	// 2. takes 1 param (can be null), returns nothing
	// 3. takes 1 param, returns the same type (return cannot be null)
	// 4. takes 1 param, returns the same type (return can be null)

	err = precompiles.RegisterPrecompile("types", precompiles.Precompile{
		Methods: []precompiles.Method{
			{
				Name:       "accept_null",
				Parameters: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, true)},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					return nil
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
			},
			{
				Name:       "accept_not_null",
				Parameters: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, false)},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					return nil
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
			},
			{
				Name:       "return_not_null",
				Parameters: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, true)},
				Returns: &precompiles.MethodReturn{
					Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("val", types.TextType, false)},
				},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					return resultFn(inputs)
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
			},
			{
				Name:       "return_null",
				Parameters: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, true)},
				Returns: &precompiles.MethodReturn{
					Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("val", types.TextType, true)},
				},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					return resultFn(inputs)
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
			},
			{
				Name: "returns_wrong_type",
				Returns: &precompiles.MethodReturn{
					Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, false)},
				},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					return resultFn([]any{1})
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
			},
			{
				Name: "returns_wrong_count",
				Returns: &precompiles.MethodReturn{
					Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", types.TextType, false), precompiles.NewPrecompileValue("b", types.TextType, false)},
				},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					return resultFn([]any{"hello"})
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
			},
			{
				Name: "returns empty decimal array",
				Returns: &precompiles.MethodReturn{
					Fields: []precompiles.PrecompileValue{precompiles.NewPrecompileValue("a", mustDecArrType(10, 2), false)},
				},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					return resultFn([]any{[]*types.Decimal{}})
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
			},
		},
	})
	require.NoError(t, err)

	interp := newTestInterp(t, tx, nil, true)

	err = interp.Execute(newEngineCtx(defaultCaller), tx, `USE types AS types_ext;`, nil, nil)
	require.NoError(t, err)

	// 1. takes 1 param (cannot be null), returns nothing
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "accept_not_null", []any{"hello"}, nil)
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "accept_not_null", []any{nil}, nil)
	require.ErrorIs(t, err, engine.ErrExtensionImplementation)

	// call with an int
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "accept_not_null", []any{1}, nil)
	require.ErrorIs(t, err, engine.ErrType)

	// 2. takes 1 param (can be null), returns nothing
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "accept_null", []any{"hello"}, nil)
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "accept_null", []any{nil}, nil)
	require.NoError(t, err)

	// 3. takes 1 param, returns the same type (return cannot be null)
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "return_not_null", []any{"hello"}, exact("hello"))
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "return_not_null", []any{nil}, nil)
	require.ErrorIs(t, err, engine.ErrExtensionImplementation)

	// 4. takes 1 param, returns the same type (return can be null)
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "return_null", []any{"hello"}, exact("hello"))
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "return_null", []any{nil}, exact(nil))
	require.NoError(t, err)

	// Other tests:
	// returns wrong type
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "returns_wrong_type", nil, nil)
	require.ErrorIs(t, err, engine.ErrExtensionImplementation)

	// returns wrong count
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "returns_wrong_count", nil, nil)
	require.ErrorIs(t, err, engine.ErrExtensionImplementation)

	// wrong count for parameters
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "accept_not_null", []any{"hello", "world"}, nil)
	require.ErrorIs(t, err, engine.ErrActionInvocation)

	// empty array works ok
	_, err = interp.Call(newEngineCtx(defaultCaller), tx, "types_ext", "returns empty decimal array", nil, exact([]*types.Decimal{}))
	require.NoError(t, err)
}

// This tests that SET CURRENT NAMESPACE works as expected
func Test_SetCurrentNamespace(t *testing.T) {
	db := newTestDB(t, nil, nil) // dropSchemas(t, append(mainSchemas, "test_ns")...)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	interp := newTestInterp(t, tx, nil, false)

	// setting current namespace to non-existent namespace should fail
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `SET CURRENT NAMESPACE TO non_existent;`, nil, nil)
	require.ErrorIs(t, err, engine.ErrNamespaceNotFound)

	err = interp.Execute(newEngineCtx(defaultCaller), tx, `CREATE NAMESPACE test_ns;`, nil, nil)
	require.NoError(t, err)

	// since SET CURRENT NAMESPACE only exists for the lifetime of a transaction, setting it and calling
	// a new function should not do anything
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `SET CURRENT NAMESPACE TO test_ns;`, nil, nil)
	require.NoError(t, err)

	// should be created in main since it is not the same call as SET CURRENT NAMESPACE
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `CREATE TABLE test_table (id INT PRIMARY KEY);`, nil, nil)
	require.NoError(t, err)

	hasTable(t, interp, tx, "main", "test_table")

	// should be created in test_ns since it is the same call as SET CURRENT NAMESPACE
	err = interp.Execute(newEngineCtx(defaultCaller), tx, `
	CREATE TABLE main_table (id INT PRIMARY KEY);
	SET CURRENT NAMESPACE TO test_ns;
	CREATE TABLE test_table (id INT PRIMARY KEY);
	CREATE NAMESPACE other_ns;
	{other_ns}CREATE TABLE other_table (id INT PRIMARY KEY);
	CREATE TABLE test_table2 (id INT PRIMARY KEY);
	`, nil, nil)
	require.NoError(t, err)
	hasTable(t, interp, tx, "test_ns", "test_table")
	hasTable(t, interp, tx, "test_ns", "test_table2")
	hasTable(t, interp, tx, "main", "main_table")
	hasTable(t, interp, tx, "other_ns", "other_table")
}

func hasTable(t *testing.T, i *interpreter.ThreadSafeInterpreter, tx sql.DB, namespace, table string) {
	count := 0
	err := i.ExecuteWithoutEngineCtx(context.Background(), tx, "SELECT * FROM info.tables WHERE name = $tbl AND namespace = $ns;", map[string]any{
		"tbl": table,
		"ns":  namespace,
	}, func(r *common.Row) error {
		count++
		return nil
	})
	require.NoError(t, err)

	switch count {
	case 0:
		assert.Fail(t, "table not found")
	case 1:
		return
	default:
		t.Fatalf("expected 0 or 1 rows, got %d", count)
	}
}

// exact is a helper function that verifies that a result is called exactly once, and that the result is equal to the expected value.
func exact(val any) func(*common.Row) error {
	called := false
	return func(row *common.Row) error {
		if called {
			return errors.New("result called multiple times")
		}
		called = true

		if len(row.Values) != 1 {
			return fmt.Errorf("expected 1 value, got %d", len(row.Values))
		}

		return eq(val, row.Values[0])
	}
}

// eq checks that two values are equal
func eq(a, b any) error {
	switch a.(type) {
	case []byte:
		if !bytes.Equal(a.([]byte), b.([]byte)) {
			return fmt.Errorf("expected %v, got %v", a, b)
		}
	case nil:
		if b != nil {
			return fmt.Errorf("expected %v, got %v", a, b)
		}
	default:
		// if it is a pointer, we need to dereference it
		if reflect.TypeOf(a).Kind() == reflect.Ptr {
			a = reflect.ValueOf(a).Elem().Interface()
		}

		// if b is a pointer, we need to dereference it
		if reflect.TypeOf(b).Kind() == reflect.Ptr {
			b = reflect.ValueOf(b).Elem().Interface()
		}

		// if b is an array or slice, we need to iterate through it
		if reflect.TypeOf(a).Kind() == reflect.Slice {
			// iterate using reflect in case it is not of []any
			for i := range reflect.ValueOf(a).Len() {
				// recursively call eq
				if err := eq(reflect.ValueOf(a).Index(i).Interface(), reflect.ValueOf(b).Index(i).Interface()); err != nil {
					return err
				}
			}

			return nil
		}

		if a != b {
			return fmt.Errorf("expected %v, got %v", a, b)
		}
	}

	return nil
}

func mustExplicitDecimal(s string, prec, scale uint16) *types.Decimal {
	d, err := types.ParseDecimalExplicit(s, prec, scale)
	if err != nil {
		panic(err)
	}
	return d
}

func mustUUID(s string) *types.UUID {
	u, err := types.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

func dropSchemas(t *testing.T, schemas ...string) func(db *pg.DB) {
	return func(db *pg.DB) {
		d := db.Pool()
		for _, schema := range schemas {
			_, err := d.Execute(context.Background(), fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE;`, schema))
			if err != nil {
				t.Logf("cleanup issue: %v", err)
			}
		}
	}
}

var mainSchemas = []string{"main", "info", "kwild_engine"}

func dropMainSchemas(t *testing.T) func(db *pg.DB) {
	return dropSchemas(t, mainSchemas...)
}

func newTestDB(t *testing.T, cleanUp func(d *pg.DB), schemaFilter func(string) bool) *pg.DB {
	cfg := &pg.DBConfig{
		PoolConfig: pg.PoolConfig{
			ConnConfig: pg.ConnConfig{
				Host:   "127.0.0.1",
				Port:   "5432",
				User:   "kwild",
				Pass:   "kwild", // would be ignored if pg_hba.conf set with trust
				DBName: "kwil_test_db",
			},
			MaxConns: 11,
		},
		SchemaFilter: schemaFilter,
	}

	if cleanUp == nil {
		cleanUp = dropMainSchemas(t)
	}

	return pgtest.NewTestDBWithCfg(t, cfg, cleanUp)
}

// newTestInterp creates a new interpreter for testing purposes.
// It is seeded with the default tables.

func newTestInterp(t *testing.T, tx sql.DB, seeds []string, includeTestTables bool) *interpreter.ThreadSafeInterpreter {
	interp, err := interpreter.NewInterpreter(context.Background(), tx, &common.Service{}, nil, nil, nil)
	require.NoError(t, err)

	engCtx := newEngineCtx(defaultCaller)
	engCtx.OverrideAuthz = true
	err = interp.ExecuteWithoutEngineCtx(context.Background(), tx, "TRANSFER OWNERSHIP TO $user", map[string]any{
		"user": defaultCaller,
	}, nil)
	require.NoError(t, err)

	seedStmts := []string{}
	if includeTestTables {
		seedStmts = append(seedStmts, createUsersTable, createPostsTable)
	}
	seedStmts = append(seedStmts, seeds...)

	for i, stmt := range seedStmts {
		err := interp.Execute(newEngineCtx(defaultCaller), tx, stmt, nil, nil)
		require.NoErrorf(t, err, "failed to execute seed statement %d: %s", i-1, stmt) // -1 to account for the two tables
	}

	return interp
}

// This tests that dropping a namespace invalidates the statement cache.
// If the cache is not invalidated, the test will fail because it will try to insert
// a string into an integer column.
func Test_NamespaceDropsCache(t *testing.T) {
	db := newTestDB(t, nil, nil)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	interp := newTestInterp(t, tx, nil, true)

	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `CREATE NAMESPACE test_ns;`, nil, nil)
	require.NoError(t, err)

	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `{test_ns}CREATE TABLE test_table (id INT PRIMARY KEY);`, nil, nil)
	require.NoError(t, err)

	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `{test_ns}CREATE ACTION smthn($a int) public { INSERT INTO test_table (id) VALUES ($a); }`, nil, nil)
	require.NoError(t, err)

	_, err = interp.CallWithoutEngineCtx(ctx, tx, "test_ns", "smthn", []any{1}, nil)
	require.NoError(t, err)

	// drop the namespace
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `DROP NAMESPACE test_ns;`, nil, nil)
	require.NoError(t, err)

	// create the namespace again
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `CREATE NAMESPACE test_ns;`, nil, nil)
	require.NoError(t, err)

	// create the table again
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `{test_ns}CREATE TABLE test_table (id TEXT PRIMARY KEY);`, nil, nil)
	require.NoError(t, err)

	// create the action again
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `{test_ns}CREATE ACTION smthn($a text) public { INSERT INTO test_table (id) VALUES ($a); }`, nil, nil)
	require.NoError(t, err)

	_, err = interp.CallWithoutEngineCtx(ctx, tx, "test_ns", "smthn", []any{"hello"}, nil)
	require.NoError(t, err)
}

// There is a bug where an in-line select (a select used within an action that is not a standalone statement,
// but rather part of a larger statement) does not work if the SELECT privileges are revoked. This is unexpected,
// since privileges should not apply within actions.
func Test_RevokedInlineSelectInAction(t *testing.T) {
	db := newTestDB(t, nil, nil)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	interp := newTestInterp(t, tx, nil, true)

	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `REVOKE SELECT FROM default`, nil, nil)
	require.NoError(t, err)

	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `CREATE ACTION m() public view returns table(id int) { return SELECT 1 AS id; }`, nil, nil)
	require.NoError(t, err)

	_, err = interp.Call(newEngineCtx("some_caller"), tx, "", "m", nil, func(r *common.Row) error { return nil })
	require.NoError(t, err)
}
