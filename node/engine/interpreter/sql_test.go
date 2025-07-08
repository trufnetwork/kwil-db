//go:build pglive

package interpreter

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

func Test_built_in_sql(t *testing.T) {
	type testcase struct {
		name string
		fn   func(ctx context.Context, db sql.DB)
	}
	tests := []testcase{
		{
			name: "test store and load actions",
			fn: func(ctx context.Context, db sql.DB) {
				for _, act := range all_test_actions {
					err := storeAction(ctx, db, "main", act, false)
					require.NoError(t, err)
				}

				actions, err := listActionsInBuiltInNamespace(ctx, db, "main")
				require.NoError(t, err)

				actMap := map[string]*action{}
				for _, act := range actions {
					actMap[act.Name] = act
				}

				require.Equal(t, len(all_test_actions), len(actMap))
				for _, act := range all_test_actions {
					stored, ok := actMap[act.Name]
					require.True(t, ok)
					require.Equal(t, act.Name, stored.Name)
					require.Equal(t, act.RawStatement, stored.RawStatement)
					require.Equal(t, act.Modifiers, stored.Modifiers)
					namedTypesEq(t, act.Parameters, stored.Parameters)

					if act.Returns != nil {
						require.NotNil(t, stored.Returns)
						require.Equal(t, act.Returns.IsTable, stored.Returns.IsTable)
						namedTypesEq(t, act.Returns.Fields, stored.Returns.Fields)
					} else {
						require.Nil(t, stored.Returns)
					}

					require.Equal(t, len(act.Body), len(stored.Body))
				}
			},
		},
		{
			name: "test store and load tables",
			fn: func(ctx context.Context, db sql.DB) {
				_, err := db.Execute(ctx, `
				CREATE TABLE main.users (
					id UUID PRIMARY KEY,
					name TEXT NOT NULL CHECK (name <> '' AND length(name) <= 100),
 					age INT CHECK (age >= 0),
					wallet_address TEXT UNIQUE NOT NULL
				);`)
				require.NoError(t, err)

				_, err = db.Execute(ctx, `
				CREATE TABLE main.posts (
					id UUID PRIMARY KEY,
					title TEXT NOT NULL,
					author_id UUID REFERENCES main.users (id) ON DELETE CASCADE
				);
				`)
				require.NoError(t, err)

				_, err = db.Execute(ctx, `CREATE UNIQUE INDEX ON main.users (name);`)
				require.NoError(t, err)

				_, err = db.Execute(ctx, `CREATE INDEX user_ages ON main.users (age);`)
				require.NoError(t, err)

				_, err = createNamespace(ctx, db, "other", namespaceTypeUser)
				require.NoError(t, err)

				_, err = db.Execute(ctx, `CREATE TABLE other.my_table (id UUID PRIMARY KEY);`)
				require.NoError(t, err)

				wantSchemas := map[string]map[string]*engine.Table{
					"main": {
						"users": {
							Name: "users",
							Columns: []*engine.Column{
								{
									Name:         "id",
									DataType:     types.UUIDType,
									IsPrimaryKey: true,
								},
								{
									Name:     "name",
									DataType: types.TextType,
								},
								{
									Name:     "age",
									DataType: types.IntType,
									Nullable: true,
								},
								{
									Name:     "wallet_address",
									DataType: types.TextType,
								},
							},
							Indexes: []*engine.Index{
								{
									Name:    "user_ages",
									Columns: []string{"age"},
									Type:    engine.BTREE,
								},
								{
									Name:    "users_name_idx",
									Columns: []string{"name"},
									Type:    engine.UNIQUE_BTREE,
								},
								{
									Name:    "users_pkey",
									Columns: []string{"id"},
									Type:    engine.PRIMARY,
								},
								{
									Name:    "users_wallet_address_key",
									Columns: []string{"wallet_address"},
									Type:    engine.UNIQUE_BTREE,
								},
							},
							Constraints: map[string]*engine.Constraint{
								"users_name_check": {
									Type:    engine.ConstraintCheck,
									Columns: []string{"name"},
								},
								"users_age_check": {
									Type:    engine.ConstraintCheck,
									Columns: []string{"age"},
								},
								"users_wallet_address_key": {
									Type:    engine.ConstraintUnique,
									Columns: []string{"wallet_address"},
								},
							},
						},
						"posts": {
							Name: "posts",
							Columns: []*engine.Column{
								{
									Name:         "id",
									DataType:     types.UUIDType,
									IsPrimaryKey: true,
								},
								{
									Name:     "title",
									DataType: types.TextType,
								},
								{
									Name:     "author_id",
									DataType: types.UUIDType,
									Nullable: true,
								},
							},
							Indexes: []*engine.Index{
								{
									Name:    "posts_pkey",
									Columns: []string{"id"},
									Type:    engine.PRIMARY,
								},
							},
							Constraints: map[string]*engine.Constraint{
								"posts_author_id_fkey": {
									Type:    engine.ConstraintFK,
									Columns: []string{"author_id"},
								},
							},
						},
					},
					"other": {
						"my_table": {
							Name: "my_table",
							Columns: []*engine.Column{
								{
									Name:         "id",
									DataType:     types.UUIDType,
									IsPrimaryKey: true,
								},
							},
							Indexes: []*engine.Index{
								{
									Name:    "my_table_pkey",
									Columns: []string{"id"},
									Type:    engine.PRIMARY,
								},
							},
						},
					},
				}

				tables := map[string]map[string]*engine.Table{}

				for schemaName := range wantSchemas {
					tbls, err := listTablesInNamespace(ctx, db, schemaName)
					require.NoError(t, err)
					tables[schemaName] = map[string]*engine.Table{}
					for _, tbl := range tbls {
						tables[schemaName][tbl.Name] = tbl
					}
				}

				require.Equal(t, len(wantSchemas), len(tables))
				for schemaName, wantSchema := range wantSchemas {
					storedTbls, ok := tables[schemaName]
					require.True(t, ok)
					for _, want := range wantSchema {
						stored, ok := storedTbls[want.Name]
						require.True(t, ok)
						require.Equal(t, want.Name, stored.Name)
						require.Equal(t, len(want.Columns), len(stored.Columns))
						for i, wc := range want.Columns {
							sc := stored.Columns[i]
							require.Equal(t, wc.Name, sc.Name)
							require.Equal(t, wc.DataType.String(), sc.DataType.String())
							require.Equal(t, wc.IsPrimaryKey, sc.IsPrimaryKey)
							require.Equal(t, wc.Nullable, sc.Nullable)
						}
						require.Equal(t, len(want.Indexes), len(stored.Indexes))
						for i, wi := range want.Indexes {
							si := stored.Indexes[i]
							require.Equal(t, wi.Columns, si.Columns)
							require.Equal(t, wi.Type, si.Type)
							require.Equal(t, wi.Name, si.Name)
						}
						require.Equal(t, len(stored.Constraints), len(want.Constraints))
						for i, wc := range want.Constraints {
							sc := stored.Constraints[i]
							require.Equal(t, wc.Type, sc.Type)
							require.Equal(t, wc.Columns, sc.Columns)
						}
					}
				}
			},
		},
		{
			name: "test store and load extensions",
			fn: func(ctx context.Context, db sql.DB) {
				vals := func() map[string]Value {
					return map[string]Value{
						"str":     mustNewVal("val1"),
						"int":     mustNewVal(123),
						"bool":    mustNewVal(true),
						"dec":     mustNewVal(mustDec("123.456")),
						"uuid":    mustNewVal(mustUUID("c7b6a54c-392c-48f9-803d-31cb97e76052")),
						"blob":    mustNewVal([]byte{1, 2, 3}),
						"strarr":  mustNewVal([]string{"a", "b", "c"}),
						"intarr":  mustNewVal([]int{1, 2, 3}),
						"boolarr": mustNewVal([]bool{true, false, true}),
						"decarr":  mustNewVal([]*types.Decimal{mustDec("1.23"), mustDec("4.56")}),
						"uuidarr": mustNewVal([]*types.UUID{mustUUID("c7b6a54c-392c-48f9-803d-31cb97e76052"), mustUUID("c7b6a54c-392c-48f9-803d-31cb97e76053")}),
						"blobarr": mustNewVal([][]byte{{1, 2, 3}, {4, 5, 6}}),
					}
				}

				err := RegisterExtensionInitialization(ctx, db, "ext1_init", "ext1", vals())
				require.NoError(t, err)

				err = RegisterExtensionInitialization(ctx, db, "ext2_init", "ext2", vals())
				require.NoError(t, err)

				exts, err := getExtensionInitializationMetadata(ctx, db)
				require.NoError(t, err)

				require.Equal(t, 2, len(exts))
				require.Equal(t, "ext1", exts[0].ExtName)
				require.Equal(t, "ext1_init", exts[0].Alias)
				vs := vals()
				require.EqualValues(t, vs, exts[0].Metadata)

				require.Equal(t, "ext2", exts[1].ExtName)
				require.Equal(t, "ext2_init", exts[1].Alias)
				require.EqualValues(t, vals(), exts[1].Metadata)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			}

			ctx := context.Background()

			db, err := pg.NewDB(ctx, cfg)
			require.NoError(t, err)
			defer db.Close()
			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx) // always rollback to avoid cleanup

			interp, err := NewInterpreter(ctx, tx, &common.Service{}, nil, nil, nil)
			require.NoError(t, err)
			_ = interp

			require.NoError(t, err)

			test.fn(ctx, tx)
		})
	}
}

func namedTypesEq(t *testing.T, a, b []*engine.NamedType) {
	require.Equal(t, len(a), len(b))
	for i, at := range a {
		require.Equal(t, at.Name, b[i].Name)
		require.Equal(t, at.Type.String(), b[i].Type.String())
	}
}

func mustNewVal(v any) Value {
	val, err := NewValue(v)
	if err != nil {
		panic(err)
	}
	return val
}

// This tests how the engine stores and queries all sorts of different DDL.
// It tests by:
// 1. Creating a bunch of different types of metadata
// 2. Querying the metadata from the info schema
// 3. Ensuring that the interpreter's in-memory metadata matches the database's metadata
func Test_Metadata(t *testing.T) {
	ctx := context.Background()

	db, err := pg.NewDB(ctx, &pg.DBConfig{
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
	})
	require.NoError(t, err)
	defer db.Close()
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback to avoid cleanup

	err = precompiles.RegisterPrecompile("store_test", testSchemaExt)
	require.NoError(t, err)

	interp, err := NewInterpreter(ctx, tx, &common.Service{}, nil, nil, nil)
	require.NoError(t, err)

	// set owner
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `TRANSFER OWNERSHIP TO '0xUser';`, nil, nil)
	require.NoError(t, err)

	// 1. Create a bunch of different types of metadata

	// 1.1 Tables: one with a composite foreign key, and one with a composite primary key. both have indexes
	createSchema := func(namespace string) {
		tmpl := `
		-- ========================
		-- Table: users
		-- - Single Primary Key (user_id)
		-- - CHECK constraint on balance >= 0
		-- - Single index on (email)
		-- - Demonstrates usage of: int8, text, bool, numeric, uuid, bytea
		-- ========================
		{%s}CREATE TABLE users (
		    user_id       UUID	PRIMARY KEY,
		    first_name    TEXT	NOT NULL,
		    last_name     TEXT	NOT NULL,
		    email         TEXT	NOT NULL,
		    is_active     BOOL	NOT NULL DEFAULT TRUE,
		    balance       NUMERIC(10,2) NOT NULL DEFAULT 0,
		    avatar        BYTEA,
		    CONSTRAINT check_balance CHECK (balance >= 0)
		);

		-- Single index on email
		{%s}CREATE INDEX idx_users_email
		    ON users (email);

		-- ========================
		-- Table: products
		-- - Single Primary Key (product_id)
		-- - Composite index on (name, price)
		-- - Demonstrates usage of: int8 (BIGINT), text, numeric, uuid, bytea
		-- ========================
		{%s}CREATE TABLE products (
		    product_id    UUID PRIMARY KEY,
		    name          TEXT UNIQUE NOT NULL,
		    description   TEXT,
		    price         NUMERIC(10,2) NOT NULL,
		    product_image BYTEA,
		    is_active     BOOLEAN NOT NULL DEFAULT TRUE
		);

		-- Composite index on (name, price)
		{%s}CREATE INDEX ON products (name, price);

		-- ========================
		-- Table: orders
		-- - Single Primary Key (order_id)
		-- - Single Foreign Key (user_id -> users.user_id)
		-- - Demonstrates usage of: int8 (BIGINT), numeric
		-- ========================
		{%s}CREATE TABLE orders (
		    order_id    UUID PRIMARY KEY,
		    user_id     UUID NOT NULL,
		    total_amt   NUMERIC(10,2) NOT NULL DEFAULT 0,
		    -- Single FK referencing users
		    CONSTRAINT fk_orders_users
		        FOREIGN KEY (user_id)
		        REFERENCES users(user_id)
		        ON DELETE CASCADE
		);

		-- ========================
		-- Table: order_details
		-- - Composite Primary Key (order_id, line_item)
		-- - Single Foreign Key on order_id -> orders(order_id)
		-- - Single Foreign Key on product_id -> products(product_id)
		-- - Demonstrates usage of: int8 (BIGINT), numeric
		-- ========================
		{%s}CREATE TABLE order_details (
		    order_id   UUID NOT NULL,
		    line_item  INT NOT NULL,
		    product_id UUID NOT NULL,

		    -- Composite PK
		    CONSTRAINT pk_order_details
		        PRIMARY KEY (order_id, line_item),

		    -- Single FKs
		    CONSTRAINT fk_order_details_orders
		        FOREIGN KEY (order_id)
		        REFERENCES orders(order_id)
		        ON DELETE CASCADE,
		    CONSTRAINT fk_order_details_products
		        FOREIGN KEY (product_id)
		        REFERENCES products(product_id)
		        ON DELETE RESTRICT,

			-- collide with constraint on users
			CONSTRAINT check_balance CHECK (line_item >= 0)
		);

		-- ========================
		-- Table: shipment
		-- - Single Primary Key (shipment_id)
		-- - Composite Foreign Key (order_id, line_item -> order_details)
		-- - Demonstrates usage of: int8 (BIGINT)
		-- ========================
		{%s}CREATE TABLE shipment (
		    shipment_id  UUID PRIMARY KEY,
		    order_id     UUID NOT NULL,
		    line_item    INT NOT NULL,

		    -- Composite FK referencing order_details
		    CONSTRAINT fk_shipment_order_details
		        FOREIGN KEY (order_id, line_item)
		        REFERENCES order_details(order_id, line_item)
		        ON DELETE CASCADE
		);
	`

		err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf(tmpl, namespace, namespace, namespace, namespace, namespace, namespace, namespace), nil, nil)
		require.NoError(t, err)

		// 1.2 Actions:
		// 	- one with no params and returns a single row
		//	- one with many params no returns
		//	- one that takes one params returns a table
		//	- one that has neither params nor returns
		err = interp.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf(`
	{%s}CREATE ACTION no_params_returns_single() public view returns (id int, name text) { return 1, 'hello'; };
	{%s}CREATE ACTION many_params_no_returns($a int, $b text, $c bool, $d numeric(10,5)) public view {};
	{%s}CREATE ACTION one_param_returns_table($a int) system view returns table (id int, name text) { return select 1 as id, 'hello' as name; };
	{%s}CREATE ACTION no_params_no_returns() private owner {};
	`, namespace, namespace, namespace, namespace), nil, nil)
		require.NoError(t, err)
	}

	createSchema("main")

	// we create another schema to test that our queries properly filter by namespace
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `CREATE namespace other;`, nil, nil)
	require.NoError(t, err)
	createSchema("other")

	// 1.3 Roles
	// 	- one with no permissions
	//	- one with some permissions
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `
	CREATE ROLE no_perms;
	CREATE ROLE some_perms;
	GRANT INSERT TO some_perms;
	GRANT SELECT ON info TO some_perms;
	GRANT some_perms TO '0xUser';
	GRANT no_perms TO '0xUser';
	`, nil, nil)
	require.NoError(t, err)

	// 1.4 Extensions
	// This extension will also create a namespace
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `
	USE store_test { init: 'init', init2: 2 } AS ext1;
	USE store_test { init: 'init2', init2: 3 } AS ext2;
	`, nil, nil)
	require.NoError(t, err)

	// infoQuery is a helper function that runs a query and asserts that the result matches the expected result.
	// It always queries the info namespace
	infoQuery := func(q string, fn func([]any) error) {
		err2 := interp.ExecuteWithoutEngineCtx(ctx, tx, "{info}"+q, nil, func(r *common.Row) error {
			return fn(r.Values)
		})
		require.NoError(t, err2)
	}

	// assertQuery is a helper function that runs a query and asserts that the result matches the expected result
	assertQuery := func(q string, want [][]any) {
		t.Logf("running query: %s", q)

		got := [][]any{}
		infoQuery(q, func(row []any) error {
			got = append(got, row)
			return nil
		})
		require.NoError(t, err)

		require.Equal(t, len(want), len(got))

		for i, w := range want {
			assert.Equal(t, len(w), len(got[i]))
			for j, v := range w {
				assert.EqualValuesf(t, v, got[i][j], "mismatch at row %d, col %d. want: %v, got: %v", i, j, v, got[i][j])
			}
		}
	}

	checkedNamespace := "main"

	// 2. Query the metadata from the info schema
	// 2.1 Tables
	// 2.1.1 "tables" table
	// We won't use the built-in function since they skip some columns, and their implementation's
	// might change since they are for internal use, rather than user-facing
	assertQuery(`SELECT * FROM tables WHERE namespace = 'main'`, [][]any{
		{"order_details", "main"},
		{"orders", "main"},
		{"products", "main"},
		{"shipment", "main"},
		{"users", "main"},
	})
	// 2.1.2 "columns" table
	// has columns namespace, table_name, name, data_type, is_nullable, default_value, is_primary_key, ordinal_position
	assertQuery(`SELECT * FROM columns WHERE namespace = 'main' order by table_name, ordinal_position`, [][]any{
		{"main", "order_details", "order_id", "uuid", false, nil, true, 1},
		{"main", "order_details", "line_item", "int8", false, nil, true, 2},
		{"main", "order_details", "product_id", "uuid", false, nil, false, 3},

		{"main", "orders", "order_id", "uuid", false, nil, true, 1},
		{"main", "orders", "user_id", "uuid", false, nil, false, 2},
		{"main", "orders", "total_amt", "numeric(10,2)", false, "0", false, 3},

		{"main", "products", "product_id", "uuid", false, nil, true, 1},
		{"main", "products", "name", "text", false, nil, false, 2},
		{"main", "products", "description", "text", true, nil, false, 3},
		{"main", "products", "price", "numeric(10,2)", false, nil, false, 4},
		{"main", "products", "product_image", "bytea", true, nil, false, 5},
		{"main", "products", "is_active", "boolean", false, "true", false, 6},

		{"main", "shipment", "shipment_id", "uuid", false, nil, true, 1},
		{"main", "shipment", "order_id", "uuid", false, nil, false, 2},
		{"main", "shipment", "line_item", "int8", false, nil, false, 3},

		{"main", "users", "user_id", "uuid", false, nil, true, 1},
		{"main", "users", "first_name", "text", false, nil, false, 2},
		{"main", "users", "last_name", "text", false, nil, false, 3},
		{"main", "users", "email", "text", false, nil, false, 4},
		{"main", "users", "is_active", "boolean", false, "true", false, 5},
		{"main", "users", "balance", "numeric(10,2)", false, "0", false, 6},
		{"main", "users", "avatar", "bytea", true, nil, false, 7},
	})
	// 2.1.3 "indexes" table
	// has columns namespace, table_name, name, is_pk, is_unique, columns
	assertQuery(`SELECT * FROM indexes WHERE namespace = 'main'`, [][]any{
		{"main", "order_details", "pk_order_details", true, true, stringArr("order_id", "line_item")},

		{"main", "orders", "orders_pkey", true, true, stringArr("order_id")},

		{"main", "products", "products_name_key", false, true, stringArr("name")},
		{"main", "products", "products_name_price_idx", false, false, stringArr("name", "price")},
		{"main", "products", "products_pkey", true, true, stringArr("product_id")},
		{"main", "shipment", "shipment_pkey", true, true, stringArr("shipment_id")},

		{"main", "users", "idx_users_email", false, false, stringArr("email")},
		{"main", "users", "users_pkey", true, true, stringArr("user_id")},
	})
	// 2.1.4 "constraints" table
	// has columns namespace, table_name, name, constraint_type, columns, expression
	assertQuery(`SELECT * FROM constraints WHERE namespace = 'main'`, [][]any{
		{"main", "order_details", "check_balance", "CHECK", stringArr("line_item"), "CHECK ((line_item >= 0))"},
		{"main", "products", "products_name_key", "UNIQUE", stringArr("name"), "UNIQUE (name)"},
		{"main", "users", "check_balance", "CHECK", stringArr("balance"), "CHECK ((balance >= (0)::numeric))"},
	})
	// 2.1.5 "foreign_keys" table
	// has columns namespace, table_name, name, columns, ref_table, ref_columns, on_update, on_delete
	assertQuery(`SELECT * FROM foreign_keys WHERE namespace = 'main'`, [][]any{
		{"main", "order_details", "fk_order_details_orders", stringArr("order_id"), "orders", stringArr("order_id"), "NO ACTION", "CASCADE"},
		{"main", "order_details", "fk_order_details_products", stringArr("product_id"), "products", stringArr("product_id"), "NO ACTION", "RESTRICT"},
		{"main", "orders", "fk_orders_users", stringArr("user_id"), "users", stringArr("user_id"), "NO ACTION", "CASCADE"},
		{"main", "shipment", "fk_shipment_order_details", stringArr("order_id", "line_item"), "order_details", stringArr("order_id", "line_item"), "NO ACTION", "CASCADE"},
	})

	// 2.2 Actions
	// the actions table has columns namespace, name, raw_statement, access_modifiers, parameter_names, parameter_types, return_names, return_types, returns_table, built_in
	assertQuery(`SELECT * FROM actions WHERE namespace = 'main'`, [][]any{
		{"main", "many_params_no_returns", "{main}CREATE ACTION many_params_no_returns($a int, $b text, $c bool, $d numeric(10,5)) public view {};", stringArr("PUBLIC", "VIEW"), stringArr("$a", "$b", "$c", "$d"), stringArr("int8", "text", "bool", "numeric(10,5)"), stringArr(), stringArr(), false, false},
		{"main", "no_params_no_returns", "{main}CREATE ACTION no_params_no_returns() private owner {};", stringArr("PRIVATE", "OWNER"), stringArr(), stringArr(), stringArr(), stringArr(), false, false},
		{"main", "no_params_returns_single", "{main}CREATE ACTION no_params_returns_single() public view returns (id int, name text) { return 1, 'hello'; };", stringArr("PUBLIC", "VIEW"), stringArr(), stringArr(), stringArr("id", "name"), stringArr("int8", "text"), false, false},
		{"main", "one_param_returns_table", "{main}CREATE ACTION one_param_returns_table($a int) system view returns table (id int, name text) { return select 1 as id, 'hello' as name; };", stringArr("SYSTEM", "VIEW"), stringArr("$a"), stringArr("int8"), stringArr("id", "name"), stringArr("int8", "text"), true, false},
	})

	// we also need to test the extension actions
	assertQuery(`SELECT * FROM actions WHERE namespace = 'ext1'`, [][]any{
		{"ext1", "no_params_no_returns", "", stringArr("PRIVATE", "OWNER"), stringArr(), stringArr(), stringArr(), stringArr(), false, true},
		{"ext1", "returns_one_named", "", stringArr("PUBLIC", "VIEW"), stringArr("$param_1"), stringArr("int8"), stringArr("id"), stringArr("int8"), false, true},
		{"ext1", "returns_one_no_param", "", stringArr("PUBLIC"), stringArr(), stringArr(), stringArr("id"), stringArr("int8"), false, true},
		{"ext1", "returns_table", "", stringArr("SYSTEM", "VIEW"), stringArr(), stringArr(), stringArr("id", "name"), stringArr("int8", "text"), true, true},
	})

	// 2.3 Roles
	// 2.3.1 "roles" table
	// the roles table has columns "name" and "built_in"
	assertQuery(`SELECT * FROM roles`, [][]any{
		{"default", true},
		{"no_perms", false},
		{"owner", true},
		{"some_perms", false},
	})
	// 2.3.2 "user_roles" table
	// the user_roles table has columns "role_name" and "user_identifier"
	assertQuery(`SELECT * FROM user_roles`, [][]any{
		{"no_perms", "0xUser"},
		{"owner", "0xUser"},
		{"some_perms", "0xUser"},
	})
	// 2.3.3 "role_privileges" table
	// the role_privileges table has columns "role_name", "privilege", "namespace"
	assertQuery(`SELECT * FROM role_privileges`, [][]any{
		// default has select and call
		{"default", "CALL", nil, true},
		{"default", "SELECT", nil, true},

		// owner has all privileges on all/nil namespaces
		{"owner", "ALTER", nil, true},
		{"owner", "CALL", nil, true},
		{"owner", "CREATE", nil, true},
		{"owner", "DELETE", nil, true},
		{"owner", "DROP", nil, true},
		{"owner", "INSERT", nil, true},
		{"owner", "ROLES", nil, true},
		{"owner", "SELECT", nil, true},
		{"owner", "UPDATE", nil, true},
		{"owner", "USE", nil, true},

		{"some_perms", "INSERT", nil, true},
		{"some_perms", "SELECT", "info", true},
	})

	// 2.4 Extensions
	// there is only one extensions table
	// it has columns namespace, extension, parameters, values
	assertQuery(`SELECT * FROM extensions`, [][]any{
		{"ext1", "store_test", stringArr("init", "init2"), stringArr("init", "2")},
		{"ext2", "store_test", stringArr("init", "init2"), stringArr("init2", "3")},
	})

	// 3. Ensure that the interpreter's in-memory metadata matches the database's metadata
	ns, ok := interp.i.namespaces[checkedNamespace]
	require.True(t, ok)

	// 3.1 Tables
	hasTable := func(ns *namespace, want *engine.Table) {
		tbl, ok := ns.tables[want.Name]
		require.True(t, ok)

		require.Equal(t, want.Name, tbl.Name)
		require.Equal(t, len(want.Columns), len(tbl.Columns))
		require.Equal(t, len(want.Indexes), len(tbl.Indexes))
		require.Equal(t, len(want.Constraints), len(tbl.Constraints))

		for i, wc := range want.Columns {
			sc := tbl.Columns[i]
			require.Equal(t, wc.Name, sc.Name)
			require.Equal(t, wc.DataType.String(), sc.DataType.String())
			require.Equal(t, wc.IsPrimaryKey, sc.IsPrimaryKey)
			require.Equal(t, wc.Nullable, sc.Nullable)
		}

		for i, wi := range want.Indexes {
			si := tbl.Indexes[i]
			require.Equal(t, wi.Columns, si.Columns)
			require.Equal(t, wi.Type, si.Type)
			require.Equal(t, wi.Name, si.Name)
		}

		for i, wc := range want.Constraints {
			sc := tbl.Constraints[i]
			require.Equal(t, wc.Type, sc.Type)
			require.Equal(t, wc.Columns, sc.Columns)
		}
	}

	hasTable(ns, &engine.Table{
		Name: "order_details",
		Columns: []*engine.Column{
			{
				Name:         "order_id",
				DataType:     types.UUIDType,
				IsPrimaryKey: true,
			},
			{
				Name:         "line_item",
				DataType:     types.IntType,
				IsPrimaryKey: true,
			},
			{
				Name:     "product_id",
				DataType: types.UUIDType,
			},
		},
		Indexes: []*engine.Index{
			{
				Name:    "pk_order_details",
				Type:    engine.PRIMARY,
				Columns: []string{"order_id", "line_item"},
			},
		},
		Constraints: map[string]*engine.Constraint{
			"check_balance": {
				Type:    engine.ConstraintCheck,
				Columns: []string{"line_item"},
			},
			"fk_order_details_orders": {
				Type:    engine.ConstraintFK,
				Columns: []string{"order_id"},
			},
			"fk_order_details_products": {
				Type:    engine.ConstraintFK,
				Columns: []string{"product_id"},
			},
		},
	})

	hasTable(ns, &engine.Table{
		Name: "orders",
		Columns: []*engine.Column{
			{
				Name:         "order_id",
				DataType:     types.UUIDType,
				IsPrimaryKey: true,
				Nullable:     false,
			},
			{
				Name:     "user_id",
				DataType: types.UUIDType,
				Nullable: false,
			},
			{
				Name:     "total_amt",
				DataType: mustDecType(10, 2),
				Nullable: false,
			},
		},
		Indexes: []*engine.Index{
			{
				Name:    "orders_pkey",
				Type:    engine.PRIMARY,
				Columns: []string{"order_id"},
			},
		},
		Constraints: map[string]*engine.Constraint{
			"fk_orders_users": {
				Type:    engine.ConstraintFK,
				Columns: []string{"user_id"},
			},
		},
	})

	hasTable(ns, &engine.Table{
		Name: "products",
		Columns: []*engine.Column{
			{
				Name:         "product_id",
				DataType:     types.UUIDType,
				IsPrimaryKey: true,
			},
			{
				Name:     "name",
				DataType: types.TextType,
				Nullable: false,
			},
			{
				Name:     "description",
				DataType: types.TextType,
				Nullable: true,
			},
			{
				Name:     "price",
				DataType: mustDecType(10, 2),
				Nullable: false,
			},
			{
				Name:     "product_image",
				DataType: types.ByteaType,
				Nullable: true,
			},
			{
				Name:     "is_active",
				DataType: types.BoolType,
				Nullable: false,
			},
		},
		Indexes: []*engine.Index{
			{
				Name:    "products_name_key",
				Type:    engine.UNIQUE_BTREE,
				Columns: []string{"name"},
			},
			{
				Name:    "products_name_price_idx",
				Type:    engine.BTREE,
				Columns: []string{"name", "price"},
			},
			{
				Name:    "products_pkey",
				Type:    engine.PRIMARY,
				Columns: []string{"product_id"},
			},
		},
		Constraints: map[string]*engine.Constraint{
			"products_name_key": {
				Type:    engine.ConstraintUnique,
				Columns: []string{"name"},
			},
		},
	})

	hasTable(ns, &engine.Table{
		Name: "shipment",
		Columns: []*engine.Column{
			{
				Name:         "shipment_id",
				DataType:     types.UUIDType,
				IsPrimaryKey: true,
			},
			{
				Name:     "order_id",
				DataType: types.UUIDType,
				Nullable: false,
			},
			{
				Name:     "line_item",
				DataType: types.IntType,
				Nullable: false,
			},
		},
		Indexes: []*engine.Index{
			{
				Name:    "shipment_pkey",
				Type:    engine.PRIMARY,
				Columns: []string{"shipment_id"},
			},
		},
		Constraints: map[string]*engine.Constraint{
			"fk_shipment_order_details": {
				Type:    engine.ConstraintFK,
				Columns: []string{"order_id", "line_item"},
			},
		},
	})

	hasTable(ns, &engine.Table{
		Name: "users",
		Columns: []*engine.Column{
			{
				Name:         "user_id",
				DataType:     types.UUIDType,
				IsPrimaryKey: true,
				Nullable:     false,
			},
			{
				Name:     "first_name",
				DataType: types.TextType,
				Nullable: false,
			},
			{
				Name:     "last_name",
				DataType: types.TextType,
				Nullable: false,
			},
			{
				Name:     "email",
				DataType: types.TextType,
				Nullable: false,
			},
			{
				Name:     "is_active",
				DataType: types.BoolType,
				Nullable: false,
			},
			{
				Name:     "balance",
				DataType: mustDecType(10, 2),
				Nullable: false,
			},
			{
				Name:     "avatar",
				DataType: types.ByteaType,
				Nullable: true,
			},
		},
		Indexes: []*engine.Index{
			{
				Name:    "idx_users_email",
				Type:    engine.BTREE,
				Columns: []string{"email"},
			},
			{
				Name:    "users_pkey",
				Type:    engine.PRIMARY,
				Columns: []string{"user_id"},
			},
		},
		Constraints: map[string]*engine.Constraint{
			"check_balance": {
				Type:    engine.ConstraintCheck,
				Columns: []string{"balance"},
			},
		},
	})

	// 3.2 Actions
	hasAction := func(ns *namespace, want string) {
		e, ok := ns.availableFunctions[want]
		require.True(t, ok)
		require.Equal(t, executableTypeAction, e.Type)
		// there are no further checks we can perform, since actions get
		// transformed into executable functions
	}

	hasAction(ns, "many_params_no_returns")
	hasAction(ns, "no_params_no_returns")
	hasAction(ns, "no_params_returns_single")
	hasAction(ns, "one_param_returns_table")

	// 3.3 Roles
	// hasRole func does not take the namespace because roles are global
	hasRole := func(want string, perms *perms) {
		t.Logf("checking role: %s", want)

		ps, ok := interp.i.accessController.roles[want]
		require.True(t, ok)

		assert.EqualValues(t, perms.globalPrivileges, ps.globalPrivileges)
		assert.EqualValues(t, perms.namespacePrivileges, ps.namespacePrivileges)
	}

	// all roles will have a namespacePrivileges map that has all the namespaces (but empty privileges)
	defaultNamespacePrivileges := map[string]map[privilege]struct{}{
		"info": {
			_SELECT_PRIVILEGE: {},
			_CALL_PRIVILEGE:   {},
		},
		"main": {
			_SELECT_PRIVILEGE: {},
			_CALL_PRIVILEGE:   {},
		},
		"other": {
			_SELECT_PRIVILEGE: {},
			_CALL_PRIVILEGE:   {},
		},
		"ext1": {
			_SELECT_PRIVILEGE: {},
			_CALL_PRIVILEGE:   {},
		},
		"ext2": {
			_SELECT_PRIVILEGE: {},
			_CALL_PRIVILEGE:   {},
		},
	}

	hasRole("default", &perms{
		namespacePrivileges: defaultNamespacePrivileges,
		globalPrivileges: map[privilege]struct{}{
			_CALL_PRIVILEGE:   {},
			_SELECT_PRIVILEGE: {},
		},
	})
	hasRole("no_perms", &perms{
		namespacePrivileges: map[string]map[privilege]struct{}{
			"info":  {},
			"main":  {},
			"other": {},
			"ext1":  {},
			"ext2":  {},
		},
		globalPrivileges: map[privilege]struct{}{},
	})

	allPrivs := map[privilege]struct{}{
		_ALTER_PRIVILEGE:  {},
		_CALL_PRIVILEGE:   {},
		_CREATE_PRIVILEGE: {},
		_DELETE_PRIVILEGE: {},
		_DROP_PRIVILEGE:   {},
		_INSERT_PRIVILEGE: {},
		_ROLES_PRIVILEGE:  {},
		_SELECT_PRIVILEGE: {},
		_UPDATE_PRIVILEGE: {},
		_USE_PRIVILEGE:    {},
	}

	hasRole("owner", &perms{
		namespacePrivileges: map[string]map[privilege]struct{}{
			"info":  allPrivs,
			"main":  allPrivs,
			"other": allPrivs,
			"ext1":  allPrivs,
			"ext2":  allPrivs,
		},
		globalPrivileges: allPrivs,
	})

	somePermsNamespacePrivileges := make(map[string]map[privilege]struct{})

	for ns := range defaultNamespacePrivileges {
		somePermsNamespacePrivileges[ns] = map[privilege]struct{}{}
	}

	somePermsNamespacePrivileges["info"] = map[privilege]struct{}{
		_SELECT_PRIVILEGE: {},
	}

	for _, privs := range somePermsNamespacePrivileges {
		privs[_INSERT_PRIVILEGE] = struct{}{}
	}

	hasRole("some_perms", &perms{
		namespacePrivileges: somePermsNamespacePrivileges,
		globalPrivileges: map[privilege]struct{}{
			_INSERT_PRIVILEGE: {},
		},
	})

	// 3.4 Extensions
	// hasExtension does not take the namespace because extensions are global.
	// params cannot be checked because they are only used at initialization time.
	// They are not stored in memory
	hasExtension := func(want string) {
		e, ok := interp.i.namespaces[want]
		require.True(t, ok)
		assert.Equal(t, e.namespaceType, namespaceTypeExtension)

		_, ok = e.availableFunctions["returns_one_no_param"]
		require.True(t, ok)
		_, ok = e.availableFunctions["returns_one_named"]
		require.True(t, ok)
		_, ok = e.availableFunctions["returns_table"]
		require.True(t, ok)
		_, ok = e.availableFunctions["no_params_no_returns"]
		require.True(t, ok)
	}

	hasExtension("ext1")
	hasExtension("ext2")
}

func mustDecType(prec, scale uint16) *types.DataType {
	dt, err := types.NewNumericType(prec, scale)
	if err != nil {
		panic(err)
	}
	return dt
}

// stringArr makes a string array that matches the engine's return format
func stringArr(vals ...string) []*string {
	if len(vals) == 0 {
		return make([]*string, 0)
	}
	arr := make([]*string, len(vals))
	for i, v := range vals {
		arr[i] = &v
	}
	return arr
}

var testSchemaExt = precompiles.Precompile{
	Methods: []precompiles.Method{
		{
			Name:            "returns_one_no_param",
			AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
			Returns: &precompiles.MethodReturn{
				Fields: []precompiles.PrecompileValue{
					{Name: "id", Type: types.IntType},
				},
			},
			Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
				return resultFn([]any{1})
			},
		},
		{
			Name:            "returns_one_named",
			AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
			Parameters: []precompiles.PrecompileValue{
				{Name: "id", Type: types.IntType},
			},
			Returns: &precompiles.MethodReturn{
				Fields: []precompiles.PrecompileValue{
					{Name: "id", Type: types.IntType},
				},
			},
			Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
				return resultFn([]any{2})
			},
		},
		{
			Name:            "returns_table",
			AccessModifiers: []precompiles.Modifier{precompiles.SYSTEM, precompiles.VIEW},
			Returns: &precompiles.MethodReturn{
				IsTable: true,
				Fields: []precompiles.PrecompileValue{
					{Name: "id", Type: types.IntType},
					{Name: "name", Type: types.TextType},
				},
			},
			Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
				return resultFn([]any{3, "three"})
			},
		},
		{
			Name:            "no_params_no_returns",
			AccessModifiers: []precompiles.Modifier{precompiles.PRIVATE, precompiles.OWNER},
			Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
				return nil
			},
		},
	},
}

// This test tests that batch statements executed against the interpreter are transactional
func Test_Transactionality(t *testing.T) {
	ctx := context.Background()

	db, err := pg.NewDB(ctx, &pg.DBConfig{
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
	})
	require.NoError(t, err)
	defer db.Close()

	cache := &transactionalCache{}
	err = precompiles.RegisterPrecompile("transactionality", precompiles.Precompile{
		Cache: cache,
		Methods: []precompiles.Method{
			{
				Name:            "increment",
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
				Parameters: []precompiles.PrecompileValue{
					{Name: "amount", Type: types.IntType},
				},
				Returns: &precompiles.MethodReturn{
					Fields: []precompiles.PrecompileValue{
						{Name: "counter", Type: types.IntType},
					},
				},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					amount := inputs[0].(int64)
					cache.counter += amount
					return resultFn([]any{cache.counter})
				},
			},
		},
	})
	require.NoError(t, err)

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback to avoid cleanup

	interp, err := NewInterpreter(ctx, tx, &common.Service{}, nil, nil, nil)
	require.NoError(t, err)
	_ = interp

	tx2, err := tx.BeginTx(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	// we will test that if I create two tables in the same statement and the second fails, that
	// the first table is not created.
	// The below tables are syntactically valid, but the second table has a foreign key constraint
	// that references a non-existent table.
	err = interp.ExecuteWithoutEngineCtx(ctx, tx2, `
		CREATE NAMESPACE not_exists;
		CREATE TABLE table1 (id INT PRIMARY KEY);
		CREATE TABLE table2 (id INT PRIMARY KEY, name TEXT REFERENCES not_exists(id));
		`, nil, nil)
	require.Error(t, err)

	err = tx2.Rollback(ctx)
	require.NoError(t, err)

	// we will check that the first table was not created
	_, ok := interp.i.namespaces[engine.DefaultNamespace].tables["table1"]
	require.False(t, ok)

	// fix the bug and continue
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `
	CREATE NAMESPACE not_exists;
	CREATE TABLE table1 (id INT PRIMARY KEY);
	CREATE TABLE table2 (id INT PRIMARY KEY, name TEXT);
	`, nil, nil)
	require.NoError(t, err)

	// test extension transactionality
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `
	USE transactionality AS trans;
	CREATE ACTION test_act() public {
		$j := 0;
		for $i in 1..10 {
			$j := trans.increment(1);
			if $j != $i {
				error('expected $i, got $j');
			}
		};

		error('rollback');
	};
	`, nil, nil)
	require.NoError(t, err)

	res, err := interp.Call(newInvalidEngineCtx(ctx), tx, "", "test_act", nil, nil)
	require.NoError(t, err)
	require.Error(t, res.Error)
	require.Contains(t, res.Error.Error(), "rollback")

	// check that the counter was not incremented
	if cache.counter != 0 {
		t.Fatalf("expected counter to be 0, got %d", cache.counter)
	}

	// we will also test a proper execution error, like a bad return type
	err = interp.ExecuteWithoutEngineCtx(ctx, tx, `
	CREATE ACTION bad_return() public returns (id int) {
		return 'hello';
	};`, nil, nil)
	require.NoError(t, err)

	_, err = interp.Call(newInvalidEngineCtx(ctx), tx, "", "bad_return", nil, nil)
	require.Error(t, err)

	// check that the counter was not incremented
	if cache.counter != 0 {
		t.Fatalf("expected counter to be 0, got %d", cache.counter)
	}
}

type transactionalCache struct {
	counter int64
}

func (t *transactionalCache) Copy() precompiles.Cache {
	return &transactionalCache{
		counter: t.counter,
	}
}

func (t *transactionalCache) Apply(cache precompiles.Cache) {
	t.counter = cache.(*transactionalCache).counter
}
