//go:build pglive

package pg

import (
	"cmp"
	"context"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

func TestMain(m *testing.M) {
	// UseLogger(log.NewStdOut(log.InfoLevel))
	m.Run()
}

const (
	pingStmt = `-- ping`
)

var (
	cfg = &DBConfig{
		PoolConfig: PoolConfig{
			ConnConfig: ConnConfig{
				Host:   "127.0.0.1",
				Port:   "5432",
				User:   "kwild",
				Pass:   "kwild", // would be ignored if pg_hba.conf set with trust
				DBName: "kwil_test_db",
			},
			MaxConns: 11,
		},
		SchemaFilter: func(s string) bool {
			return strings.Contains(s, DefaultSchemaFilterPrefix)
		},
	}
)

func TestColumnInfo(t *testing.T) {
	ctx := context.Background()

	db, err := NewPool(ctx, &cfg.PoolConfig)
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Make a temporary table to describe with ColumnInfo.

	tbl := "colcheck"
	_, err = tx.Execute(ctx, `drop table if exists `+tbl)
	require.NoError(t, err)
	_, err = tx.Execute(ctx, `create table if not exists `+tbl+
		` (a int8 not null, b int4 default 42, c text,
		   d bytea, e numeric(20,5), f int8[])`)
	require.NoError(t, err)

	cols, err := ColumnInfo(ctx, tx, "", tbl)
	if err != nil {
		t.Fatal(err)
	}

	wantCols := []ColInfo{
		{Pos: 1, Name: "a", DataType: "bigint", Nullable: false},
		{Pos: 2, Name: "b", DataType: "integer", Nullable: true, defaultVal: "42"},
		{Pos: 3, Name: "c", DataType: "text", Nullable: true},
		{Pos: 4, Name: "d", DataType: "bytea", Nullable: true},
		{Pos: 5, Name: "e", DataType: "numeric", Nullable: true},
		{Pos: 6, Name: "f", DataType: "bigint", Array: true, Nullable: true},
	}

	assert.Equal(t, wantCols, cols) // t.Logf("%#v", cols)
}

func TestQueryRowFunc(t *testing.T) {
	ctx := context.Background()

	db, err := NewPool(ctx, &cfg.PoolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	tbl := "colcheck"
	_, err = tx.Execute(ctx, `drop table if exists `+tbl)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Execute(ctx, `create table if not exists `+tbl+
		` (a int8 not null, b int4 default 42, c text,
		   d bytea, e numeric(20,3), f int8[])`)
	if err != nil {
		t.Fatal(err)
	}

	cols, err := ColumnInfo(ctx, tx, "", tbl)
	if err != nil {
		t.Fatal(err)
	}

	// First get the scan values with (*ColInfo).scanVal.

	wantRTs := []reflect.Type{
		reflect.TypeFor[*pgtype.Int8](),
		reflect.TypeFor[*pgtype.Int8](),
		reflect.TypeFor[*pgtype.Text](),
		reflect.TypeFor[*[]uint8](),
		reflect.TypeFor[*types.Decimal](),
		reflect.TypeFor[*pgtype.Array[pgtype.Int8]](),
	}

	var scans []any
	for i, col := range cols {
		sv := col.scanVal()
		// t.Logf("scanval: %v (%T)", sv, sv)
		scans = append(scans, sv)

		gotRT := reflect.TypeOf(sv)
		if wantRTs[i] != gotRT {
			t.Errorf("wrong type %v, wanted %v", gotRT, wantRTs[i])
		}
	}

	// Then use QueryRowFunc with the scan vals.

	wantDec, err := types.ParseDecimal("12.500") // numeric(x,3)!
	require.NoError(t, err)
	if wantDec.Scale() != 3 {
		t.Fatalf("scale of decimal does not match column def: %v", wantDec)
	}

	wantScans := []any{
		&pgtype.Int8{Int64: 5, Valid: true},
		&pgtype.Int8{Int64: 0, Valid: false},
		&pgtype.Text{String: "a", Valid: true},
		&[]uint8{0xab, 0xab},
		wantDec, // this seems way easier as long as we're internal: &pgtype.Numeric{Int: big.NewInt(1200000), Exp: -5, NaN: false, InfinityModifier: 0, Valid: true},
		&pgtype.Array[pgtype.Int8]{
			Elements: []pgtype.Int8{{Int64: 2, Valid: true}, {Int64: 3, Valid: true}, {Int64: 4, Valid: true}},
			Dims:     []pgtype.ArrayDimension{{Length: 3, LowerBound: 1}},
			Valid:    true,
		},
	}

	err = QueryRowFunc(ctx, tx, `SELECT * FROM `+tbl, scans,
		func() error {
			for i, val := range scans {
				// t.Logf("%#v (%T)", val, val)
				assert.Equal(t, wantScans[i], val)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNULL(t *testing.T) {
	ctx := context.Background()

	db, err := NewPool(ctx, &cfg.PoolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tx, err := db.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	tbl := "colcheck"
	_, err = tx.Execute(ctx, `drop table if exists `+tbl)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Execute(ctx, `create table if not exists `+tbl+` (a int8, b int4)`)
	if err != nil {
		t.Fatal(err)
	}

	insB := int64(6)
	_, err = tx.Execute(ctx, fmt.Sprintf(`insert into `+tbl+` values (null, %d)`, insB))
	if err != nil {
		t.Fatal(err)
	}

	sql := `select a, b from ` + tbl

	res, err := tx.Execute(ctx, sql)
	require.NoError(t, err)

	// no type for NULL values, just a nil interface{}
	a := res.Rows[0][0]
	// t.Logf("%v (%T)", a, a) // <nil> (<nil>)
	require.Equal(t, reflect.TypeOf(a), reflect.Type(nil))

	// only non-NULL values get a type
	b := res.Rows[0][1]
	// t.Logf("%v (%T)", b, b) // 6 (int64)
	require.Equal(t, reflect.TypeOf(b), reflect.TypeFor[int64]())

	// Now with scan vals

	// Cannot select a NULL value with pointers to vanilla types
	var av, bv int64
	scans := []any{&av, &bv}
	err = tx.QueryScanFn(ctx, sql, scans, func() error { return nil })
	// require.Error(t, err)
	require.ErrorContains(t, err, "cannot scan NULL into *int64")

	// Can Scan NULL values with pgtype.Int8 with a Valid bool field.
	var avn, bvn pgtype.Int8
	scans = []any{&avn, &bvn}
	err = tx.QueryScanFn(ctx, sql, scans, func() error { return nil })
	require.NoError(t, err)

	require.False(t, avn.Valid) // Valid=false for NULL
	require.True(t, bvn.Valid)

	require.Equal(t, avn.Int64, int64(0))
	require.Equal(t, bvn.Int64, insB)
}

func TestScanVal(t *testing.T) {
	cols := []ColInfo{
		{Pos: 1, Name: "a", DataType: "bigint", Nullable: false},
		{Pos: 2, Name: "b", DataType: "integer", Nullable: true, defaultVal: "42"},
		{Pos: 3, Name: "c", DataType: "text", Nullable: true},
		{Pos: 4, Name: "d", DataType: "bytea", Nullable: true},
		{Pos: 5, Name: "e", DataType: "numeric", Nullable: true},

		{Pos: 7, Name: "aa", DataType: "bigint", Array: true, Nullable: false},
		{Pos: 8, Name: "ba", DataType: "integer", Array: true, Nullable: true},
		{Pos: 9, Name: "ca", DataType: "text", Array: true, Nullable: true},
		{Pos: 10, Name: "da", DataType: "bytea", Array: true, Nullable: true},
		{Pos: 11, Name: "ea", DataType: "numeric", Array: true, Nullable: true},
	}
	var scans []any
	for _, col := range cols {
		scans = append(scans, col.scanVal())
	}
	// for _, val := range scans { t.Logf("%#v (%T)", val, val) }

	// want pointers to these base types
	var ba []byte
	var i8 pgtype.Int8
	var txt pgtype.Text
	var num types.Decimal // pgtype.Numeric

	// want pointers to these slices for array types
	// var ia []pgtype.Int8
	// var ta []pgtype.Text
	// var baa [][]byte
	// var na []pgtype.Numeric
	var ia pgtype.Array[pgtype.Int8]
	var ta pgtype.Array[pgtype.Text]
	var baa pgtype.Array[[]byte]
	var na types.DecimalArray // pgtype.Array[pgtype.Numeric]

	wantScans := []any{&i8, &i8, &txt, &ba, &num,
		&ia, &ia, &ta, &baa, &na}

	assert.Equal(t, wantScans, scans)
}

func TestQueryRowFuncAny(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	tbl := "colcheck"
	_, err = tx.Execute(ctx, `drop table if exists `+tbl)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tx.Execute(ctx, `create table if not exists `+tbl+
		` (a int8 not null, b int4, c text, d bytea, e numeric(20,5), f int8[])`)
	if err != nil {
		t.Fatal(err)
	}
	numCols := 6

	_, err = tx.Execute(ctx, `insert into `+tbl+
		` values (5, null, 'a', '\xabab', 12, '{2,NULL,4}'), `+
		`        (9, 2, 'b', '\xee', 0.9876, '{99}')`)
	if err != nil {
		t.Fatal(err)
	}

	wantTypes := []reflect.Type{ // same for each row scanned, when non-null
		reflect.TypeFor[int64](),
		reflect.TypeFor[int64](),
		reflect.TypeFor[string](),
		reflect.TypeFor[[]byte](),
		reflect.TypeFor[*types.Decimal](),
		reflect.TypeFor[[]*int64](),
	}
	mustDec := func(s string) *types.Decimal {
		d, err := types.ParseDecimal(s)
		require.NoError(t, err)
		return d
	}
	wantVals := [][]any{
		{int64(5), nil, "a", []byte{0xab, 0xab}, mustDec("12.00000"), []*int64{ptrFor(int64(2)), nil, ptrFor(int64(4))}},
		{int64(9), int64(2), "b", []byte{0xee}, mustDec("0.98760"), toPtrSlice([]int64{99})},
	}

	var rowNum int
	err = QueryRowFuncAny(ctx, tx, `SELECT * FROM `+tbl,
		func(vals []any) error {
			require.Len(t, vals, numCols)
			t.Logf("%#v", vals) // e.g. []interface {}{1, "a", "bigint", "YES", interface {}(nil)}
			for i, v := range vals {
				if v != nil {
					require.EqualValues(t, wantTypes[i], reflect.TypeOf(v),
						"it was %T not %v", v, wantTypes[i].String())
				}
				require.Equal(t, wantVals[rowNum][i], v)
				// t.Logf("%d: %v (%T)", i, v, v)
			}
			rowNum++
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var colInfo []ColInfo

	// To test QueryRowFuncAny, get some column info.
	stmt := `SELECT ordinal_position, column_name, is_nullable
        FROM information_schema.columns
        WHERE table_name = '` + tbl + `' ORDER BY ordinal_position ASC`
	numCols = 3 //based on stmt

	// NOTE:
	// - OID 19 pertains to information_schema.sql_identifier, which scans as text
	// - OID 1043 pertains to varchar, which can scan as text
	wantTypes = []reflect.Type{ // same for each row scanned
		reflect.TypeFor[int64](),  // ordinal_position
		reflect.TypeFor[string](), // column_name
		reflect.TypeFor[string](), // is_nullable has boolean semantics but values of "YES"/"NO"
	}
	wantVals = [][]any{
		{int64(1), "a", "NO"},
		{int64(2), "b", "YES"},
		{int64(3), "c", "YES"},
		{int64(4), "d", "YES"},
		{int64(5), "e", "YES"},
		{int64(6), "f", "YES"},
	}

	rowNum = 0
	err = QueryRowFuncAny(ctx, tx, stmt, func(vals []any) error {
		require.Len(t, vals, numCols)
		// t.Logf("%#v", vals) // e.g. []interface {}{1, "a", "bigint", "YES", interface {}(nil)}
		for i, v := range vals {
			require.Equal(t, reflect.TypeOf(v), wantTypes[i])
			require.Equal(t, v, wantVals[rowNum][i])
			// t.Logf("%d: %v (%T)", i, v, v)
		}
		rowNum++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Now the QueryScanFn method and QueryScanner interface with scan vars.
	scanner := tx.(sql.QueryScanner)
	var pos int
	var colName, isNullable string
	scans := []any{&pos, &colName, &isNullable}
	err = scanner.QueryScanFn(ctx, stmt, scans, func() error {
		colInfo = append(colInfo, ColInfo{
			Pos:      pos,
			Name:     colName,
			Nullable: strings.EqualFold(isNullable, "yes"),
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	slices.SortFunc(colInfo, func(a, b ColInfo) int {
		return cmp.Compare(a.Pos, b.Pos)
	})

	// now actually check the expected values!
}

// TestRollbackPreparedTxns tests the rollbackPreparedTxns in the following
// cases:
//
//  1. when there are no prepared transactions
//  2. when we create one and roll it back from the same connection
//  3. when we create one, disconnect, and make a fresh connection to rollback
//
// The final case is expected in crash recovery.
func TestRollbackPreparedTxns(t *testing.T) {
	ctx := context.Background()
	connStr := connString(cfg.Host, cfg.Port, cfg.User, cfg.Pass, cfg.DBName, false)
	cfg, _ := pgx.ParseConfig(connStr)
	warns := make(chan *pgconn.Notice, 1)
	var expectMessage string
	cfg.OnNotice = func(pc *pgconn.PgConn, n *pgconn.Notice) {
		if expectMessage != "" && strings.Contains(strings.ToLower(n.Message), expectMessage) {
			warns <- n
		}
	}
	cfg.OnPgError = func(_ *pgconn.PgConn, n *pgconn.PgError) bool { // for test debugging
		t.Logf("%v [%v]: %v / %v", n.Severity, n.Code, n.Message, n.Detail)
		return !strings.EqualFold(n.Severity, "FATAL")
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	// Run rollback with no prepared txns.
	_, err = rollbackPreparedTxns(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}

	_, err = conn.Exec(ctx, `create table if not exists prepared_test (x int8);`)
	if err != nil {
		t.Fatal(err)
	}

	// Make a prepared transaction
	var tx pgx.Tx

	readyPreparedTx := func() {
		tx, err = conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO prepared_test (x) VALUES (1);`); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `PREPARE TRANSACTION 'asdf1234';`)
		if err != nil {
			t.Fatal(err)
		}
	}

	readyPreparedTx()

	// test rollback from same connection.
	closed, err := rollbackPreparedTxns(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Errorf("rolled back %d, wanted %d", closed, 1)
	}

	// the transaction is now over, Commit emits a warn notice, but no error returns
	expectMessage = "there is no transaction in progress"
	err = tx.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-warns:
	case <-time.After(2 * time.Second):
		t.Error("no warning received")
	}

	// test rollback from new connection
	readyPreparedTx()

	err = conn.Close(ctx)
	if err != nil {
		t.Error(err) // but try to clean up the prepared txn
	}
	conn, err = pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	closed, err = rollbackPreparedTxns(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Errorf("rolled back %d, wanted %d", closed, 1)
	}
}

// TestSelectLiteralType ensures (and demonstrates) that simpler query execution
// modes can effectively handle inline queries like `SELECT $1;` when provided
// and argument that is not a string, which fails in the expanded execution
// modes that try to obtain argument OIDs (postgres data types) via a
// prepare/describe request to the postgres process. However, the to get the
// returned type correct and to deal with the invalidity of a statement like
// `SELECT $1 + $2` with text arguments, we provide a special
// QueryModeInferredArgTypes mode so such statements can succeed.
func TestSelectLiteralType(t *testing.T) {
	ctx := context.Background()
	connStr := connString(cfg.Host, cfg.Port, cfg.User, cfg.Pass, cfg.DBName, false)
	pgCfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		t.Fatal(err)
	}
	// pgCfg.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement // default
	// pgCfg.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	// pgCfg.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec
	// pgCfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	// pgCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(ctx, pgCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	// var arg any = int64(1)
	// args := []any{arg, arg}
	argMap := map[string]any{
		"a": int64(1),
		"b": int64(1),
	}
	var arg any = pgx.NamedArgs(argMap)
	args := []any{arg}
	stmt := `SELECT @a + @b;`

	// args := []any{arg}
	// stmt := `SELECT $1;`
	// TODO: make more thorough in-line expression test cases

	rows, err := queryImpliedArgTypes(ctx, conn, stmt, args...)
	if err != nil {
		t.Fatal(err)
	}

	// rows, err := conn.Query(ctx, stmt, arg, arg)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// Tip: try the named argument rewriter as such:
	// argMap := map[string]any{
	// 	"a": int64(1),
	// }
	// var arg any = pgx.NamedArgs(argMap)
	//  ^ with `SELECT @a;`
	// (with the same result)

	defer rows.Close()

	for rows.Next() {
		// rows.Values() // []any
		var val any
		err = rows.Scan(&val)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v (%T)", val, val)
		// valInt, err := conv.Int(val)
		// if err != nil {
		// 	t.Fatal(err)
		// }
		// t.Log(valInt, "(int64)")
	}

	err = rows.Err()
	if err != nil {
		t.Fatal(err)
	}

	// Now with our high level func and mode.
	args2 := append([]any{QueryModeInferredArgTypes}, args...)
	results, err := query(ctx, oidTypesMap(conn.TypeMap()), &cqWrapper{conn}, stmt, args2...)
	if err != nil {
		t.Fatal(err)
	}
	for _, val := range results.Rows[0] {
		t.Logf("%v (%T)", val, val)
	}
}

func TestNestedTx(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Query(ctx, pingStmt)
	if err != nil {
		t.Fatal(err)
	}

	// Start the outer transaction.
	tx, err := db.BeginPreparedTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Execute(ctx, pingStmt)
	if err != nil {
		t.Fatal(err)
	}

	// err = tx.Commit(ctx)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// tx.begintx below would then error with "tx is closed" (TODO: test that)

	// Start savepoint 0
	txNested, err := tx.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer txNested.Rollback(ctx)

	// OK query
	_, err = txNested.Execute(ctx, pingStmt)
	if err != nil {
		t.Fatal(err)
	}

	// release savepoint 0
	err = txNested.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Start savepoint 1
	txNested2, err := tx.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Query error
	_, err = txNested2.Execute(ctx, `SELECT notathing;`)
	if err == nil {
		t.Fatal("should have errored") // expect error
	}
	// if Commit now, should say: ERROR: current transaction is aborted, commands ignored until end of transaction block (SQLSTATE 25P02)

	// rollback savepoint 1 containing the error
	err = txNested2.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Now we should be able to keep going.  Make savepoint 3:
	txNested3, err := tx.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer txNested3.Rollback(ctx)

	_, err = txNested3.Execute(ctx, pingStmt)
	if err != nil {
		t.Fatal(err)
	}

	err = txNested3.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}

	id, err := tx.Precommit(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("commit id: %x", id)

	// success on outer tx even though failure in a savepoint
	err = tx.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// TODO: enure updates in other non-failed savepoints take
}

// func TestCommitWithoutPrecommit

// tests that a read tx can be created and used
// while another tx is in progress
func TestReadTxs(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Query(ctx, pingStmt)
	require.NoError(t, err)

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	tx2, err := db.BeginReadTx(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = tx.Rollback(ctx)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)
}

// TestTypeRoundtrip tests roundtripping different data types to and from Postgres.
func TestTypeRoundtrip(t *testing.T) {
	type testcase struct {
		// typ specifies the postgres type to use in the test.
		typ string
		// val is the value to pass to the query.
		val any
		// want is the expected value to be returned from the query.
		// if nil, val is expected to be returned
		want any
		// skipInferred skips the inferred arg types test.
		skipInferred bool
		// skipTbl skips the table test. This is used if we are testing
		// a value that isn't directly applicable to postgres.
		skipTbl bool
	}

	for _, v := range []testcase{
		/*{
			typ: "int8",
			val: int64(1),
		},
		{
			typ: "bool",
			val: true,
		},
		{
			typ: "text",
			val: "hello",
		},
		{
			typ: "bytea",
			val: []byte("world"),
		},
		{
			typ: "uuid",
			val: types.NewUUIDV5([]byte("1")),
		},
		{
			typ: "decimal(6,3)",
			val: mustDecimal("123.456"),
		},
		{
			typ: "decimal(5,0)",
			val: mustDecimal("12300"),
		},*/
		{
			typ:  "int8[]",
			val:  []int64{1, 2, 3},
			want: toPtrSlice([]int64{int64(1), int64(2), int64(3)}),
		},
		{
			typ:  "int8[]", // with nulls
			val:  []*int64{ptrFor(int64(1)), nil, ptrFor(int64(3))},
			want: []*int64{ptrFor(int64(1)), nil, ptrFor(int64(3))},
		},
		{
			typ:  "bool[]",
			val:  []bool{true, false, true},
			want: toPtrSlice([]bool{true, false, true}),
		},
		{
			typ:  "text[]",
			val:  []string{"a", "b", "c"},
			want: toPtrSlice([]string{"a", "b", "c"}),
		},
		{
			typ:  "bytea[]",
			val:  [][]byte{[]byte("a"), []byte("b"), []byte("c")},
			want: [][]byte{[]byte("a"), []byte("b"), []byte("c")},
		},
		{
			typ:  "uuid[]", // no real NULL with uuid-ossp
			val:  types.UUIDArray{types.NewUUIDV5([]byte("2")), types.NewUUIDV5([]byte("3"))},
			want: types.UUIDArray{types.NewUUIDV5([]byte("2")), types.NewUUIDV5([]byte("3"))},
		},
		{
			typ:  "decimal(6,4)[]",
			val:  types.DecimalArray{mustDecimal("12.4223"), mustDecimal("22.4425"), mustDecimal("23.7423")},
			want: types.DecimalArray{mustDecimal("12.4223"), mustDecimal("22.4425"), mustDecimal("23.7423")},
		},
		{
			typ:  "text[]",
			val:  []string{},
			want: []*string{},
		},
		{
			typ:  "int8[]",
			val:  []int64{},
			want: []*int64{},
		},
		{
			typ:     "nil",
			val:     nil,
			skipTbl: true,
		},
		{
			typ:     "[]uuid",
			val:     []any{"3146857c-8671-4f4e-99bd-fcc621f9d3d1", "3146857c-8671-4f4e-99bd-fcc621f9d3d1"},
			want:    toPtrSlice([]string{"3146857c-8671-4f4e-99bd-fcc621f9d3d1", "3146857c-8671-4f4e-99bd-fcc621f9d3d1"}),
			skipTbl: true,
		},
		{
			typ:          "int8[]",
			val:          []string{"1", "2"},
			want:         toPtrSlice([]int64{int64(1), int64(2)}),
			skipInferred: true,
		},
	} {
		t.Run(v.typ, func(t *testing.T) {
			ctx := context.Background()
			db, err := NewDB(ctx, cfg)
			require.NoError(t, err)
			defer db.Close()

			want := v.val
			if v.want != nil {
				want = v.want
			}

			if !v.skipInferred {
				res, err := db.Query(ctx, "SELECT $1", QueryModeInferredArgTypes, v.val)
				require.NoError(t, err)

				require.Len(t, res.Columns, 1)
				require.Len(t, res.Rows, 1)
				require.Len(t, res.Rows[0], 1)

				require.EqualValues(t, want, res.Rows[0][0])
			}

			if v.skipTbl {
				return
			}

			// here, we test without the QueryModeInferredArgTypes

			tx, err := db.BeginPreparedTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx) // always rollback

			_, err = tx.Execute(ctx, "CREATE TEMP TABLE test (val "+v.typ+")", QueryModeExec)
			require.NoError(t, err)

			_, err = tx.Execute(ctx, "INSERT INTO test (val) VALUES ($1)", QueryModeExec, v.val)
			require.NoError(t, err)

			res, err := tx.Execute(ctx, "SELECT val FROM test", QueryModeExec)
			require.NoError(t, err)

			require.Len(t, res.Columns, 1)
			require.Len(t, res.Rows, 1)
			require.Len(t, res.Rows[0], 1)

			require.EqualValues(t, want, res.Rows[0][0])

			// verify NULL value handling
			_, err = tx.Execute(ctx, "DELETE FROM test", QueryModeExec)
			require.NoError(t, err)

			_, err = tx.Execute(ctx, "INSERT INTO test (val) VALUES (NULL)")
			require.NoError(t, err)

			res, err = tx.Execute(ctx, "SELECT val FROM test", QueryModeExec)
			require.NoError(t, err)

			require.Len(t, res.Columns, 1)
			require.Len(t, res.Rows, 1)
			require.Len(t, res.Rows[0], 1)

			require.EqualValues(t, nil, res.Rows[0][0])
		})
	}
}

// mustDecimal panics if the string cannot be converted to a types.
func mustDecimal(s string) *types.Decimal {
	d, err := types.ParseDecimal(s)
	if err != nil {
		panic(err)
	}
	return d
}

func mustParseUUID(s string) *types.UUID {
	u, err := types.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

func Test_DelayedTx(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	tx := db.BeginDelayedReadTx()
	defer tx.Rollback(ctx)

	tx2, err := tx.BeginTx(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	_, err = tx2.Execute(ctx, pingStmt)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)
}

func ptrFor[T any](v T) *T {
	return &v
}

func toPtrSlice[T any](v []T) []*T {
	res := make([]*T, len(v))
	for i := range v {
		res[i] = &v[i]
	}
	return res
}

/*func fromPtrSlice[T any](v []*T) (res []T, nils []bool) {
	res = make([]T, len(v))
	nils = make([]bool, len(v))
	for i := range v {
		if v[i] == nil {
			nils[i] = true
			continue
		}
		res[i] = *v[i]
	}
	return
}*/

// This test tests changesets, and that they are properly encoded+decoded
func Test_Changesets(t *testing.T) {

	for i, tc := range []interface {
		run(t *testing.T)
	}{
		&changesetTestcase[string]{ // basic string test
			datatype:  "text",
			val:       "hello",
			arrayVal:  toPtrSlice([]string{"a", "b", "c"}),
			val2:      "world",
			arrayVal2: toPtrSlice([]string{"d", "e", "f"}),
		},
		&changesetTestcase[string]{ // null strings
			datatype:  "text",
			val:       "hello",
			arrayVal:  append(toPtrSlice([]string{"a", "b", "c"}), nil),
			val2:      "",
			nullval2:  true,
			arrayVal2: []*string{ptrFor("d"), nil, ptrFor("f")},
		},
		&changesetTestcase[string]{ // test with special characters and escaping
			datatype:  "text",
			val:       "heldcsklk;le''\"';",
			arrayVal:  toPtrSlice([]string{"hel,dcsklk;le','\",';", `";\\sdsw,"''"\',\""`}),
			val2:      "world",
			arrayVal2: toPtrSlice([]string{"'\"", "heldcsklk;le''\"';"}),
		},
		&changesetTestcase[int64]{
			datatype:  "int8",
			val:       1,
			arrayVal:  toPtrSlice([]int64{1, 2, 3987654}),
			val2:      2,
			arrayVal2: toPtrSlice([]int64{3, 4, 5}),
		},
		&changesetTestcase[bool]{
			datatype:  "bool",
			val:       true,
			arrayVal:  toPtrSlice([]bool{true, false, true}),
			val2:      false,
			arrayVal2: toPtrSlice([]bool{false, true, false}),
		},
		&changesetTestcase[[]byte]{
			datatype:  "bytea",
			val:       []byte("hello"),
			arrayVal:  toPtrSlice([][]byte{[]byte("a"), []byte("b"), []byte("c")}),
			val2:      []byte("world"),
			arrayVal2: toPtrSlice([][]byte{[]byte("d"), []byte("e"), []byte("f")}),
		},
		&changesetTestcase[types.Decimal]{
			datatype:  "decimal(6,3)",
			val:       *mustDecimal("123.456"),
			arrayVal:  types.DecimalArray{mustDecimal("123.456"), mustDecimal("123.456"), mustDecimal("123.456")},
			val2:      *mustDecimal("123.457"),
			arrayVal2: types.DecimalArray{mustDecimal("123.457"), mustDecimal("123.457"), mustDecimal("123.457")},
		},
		&changesetTestcase[types.UUID]{
			datatype:  "uuid",
			val:       *mustParseUUID("3146857c-8671-4f4e-99bd-fcc621f9d3d1"),
			arrayVal:  types.UUIDArray{mustParseUUID("3146857c-8671-4f4e-99bd-fcc621f9d3d1"), mustParseUUID("3146857c-8671-4f4e-99bd-fcc621f9d3d1")},
			val2:      *mustParseUUID("3146857c-8671-4f4e-99bd-fcc621f9d3d2"),
			arrayVal2: types.UUIDArray{mustParseUUID("3146857c-8671-4f4e-99bd-fcc621f9d3d2"), mustParseUUID("3146857c-8671-4f4e-99bd-fcc621f9d3d2")},
		},
	} {
		t.Run(fmt.Sprint(i), tc.run)
	}
}

// this is a hack to use generics in the test
type changesetTestcase[T any] struct {
	datatype string // the postgres datatype to test
	// the first vals will be inserted.
	// val will be the primary key
	val      T // the value to test
	nullval  bool
	arrayVal []*T // the array value to test
	// the second vals will update the first vals
	val2      T // the second value to test
	nullval2  bool
	arrayVal2 []*T // the second array value to test
}

func processChangesets(csChan chan any, changesetEntries *[]*ChangesetEntry, relations *[]*Relation, done chan struct{}) {
	defer close(done)

	for ch := range csChan {
		switch v := ch.(type) {
		case *ChangesetEntry:
			*changesetEntries = append(*changesetEntries, v)
		case *Relation:
			*relations = append(*relations, v)
		}
	}
}

func applyChangesets(ctx context.Context, tx sql.DB, csEntries []*ChangesetEntry, relations []*Relation) error {
	for _, entry := range csEntries {
		if int(entry.RelationIdx) >= len(relations) {
			return fmt.Errorf("relation not found")
		}

		if err := entry.ApplyChangesetEntry(ctx, tx, relations[entry.RelationIdx]); err != nil {
			return err
		}
	}
	return nil
}

// fromTestArrayType converts from some test array type to the Kwil PG array
// type with a Valuer for correctly inserting the array.
func fromTestArrayType(v any) any {
	switch vt := v.(type) {
	case []*types.Decimal:
		return types.DecimalArray(vt)
	case []*types.UUID:
		return types.UUIDArray(vt)
	case []*[]byte:
		var a [][]byte
		for _, v := range vt {
			if v == nil {
				a = append(a, nil)
				continue
			}
			a = append(a, *v)
		}
		return a
	}
	return v
}

func (c *changesetTestcase[T]) run(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	cleanup := func() {
		db.AutoCommit(true)
		_, err = db.Execute(ctx, "drop table if exists ds_test.test", QueryModeExec)
		require.NoError(t, err)
		_, err = db.Execute(ctx, "drop schema if exists ds_test", QueryModeExec)
		db.AutoCommit(false)
	}
	// attempt to clean up any old failed tests
	cleanup()
	defer cleanup()

	regularTx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer regularTx.Rollback(ctx)

	_, err = regularTx.Execute(ctx, "create schema ds_test", QueryModeExec)
	require.NoError(t, err)

	_, err = regularTx.Execute(ctx, "create table ds_test.test (val "+c.datatype+", name text,  array_val "+c.datatype+"[])", QueryModeExec)
	require.NoError(t, err)

	err = regularTx.Commit(ctx)
	require.NoError(t, err)

	/*
		Block 1: Insert
	*/

	tx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = tx.Execute(ctx, "insert into ds_test.test (val, array_val) values ($1, $2)", QueryModeExec, c.val, fromTestArrayType(c.arrayVal))
	require.NoError(t, err)

	// Receive each ChangesetEntry, which was captured in the logical
	// replication code and encoded to a ChangesetEntry using each type's
	// SerializeChangesetEntry function.
	changes := make(chan any, 1)
	var changesetEntries []*ChangesetEntry
	var relations []*Relation
	done := make(chan struct{})
	go processChangesets(changes, &changesetEntries, &relations, done)

	_, err = tx.Precommit(ctx, changes)
	require.NoError(t, err)

	// Get changeset entries
	<-done
	// fmt.Println(changesetEntries, relations)
	require.Len(t, relations, 1)
	require.Len(t, changesetEntries, 1)

	// Check the inserted values from the captured changeset match the values
	// from the testcase inputs that were the args to Execute.
	csEntry := changesetEntries[0]
	_, insertVals, err := csEntry.DecodeTuples(relations[0])
	require.NoError(t, err)

	// the third column is the array
	var insertedArray []*T
	switch vt := insertVals[2].(type) {
	case []T: // shouldn't be
		insertedArray = toPtrSlice(vt)
	case []*T:
		insertedArray = vt
	}
	require.EqualValues(t, c.arrayVal, insertedArray) // comparing slices of arrays, values of non-nil elements are compare, nils compared

	err = tx.Rollback(ctx)
	require.NoError(t, err)

	// ensure the rollback removed it
	res, err := tx.Execute(ctx, "select val, array_val from ds_test.test")
	require.NoError(t, err)
	require.Len(t, res.Rows, 0)

	// Apply the captured changesets. This tests DeserializeChangeset for each
	// data type to decode a ChangesetEntry into Go types used with Execute in
	// applyInsert, applyUpdate, and applyDelete.
	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	require.NoError(t, applyChangesets(ctx, tx, changesetEntries, relations))
	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	res, err = tx.Execute(ctx, "select val, array_val from ds_test.test")
	require.NoError(t, err)

	require.Len(t, res.Rows, 1)
	require.Len(t, res.Rows[0], 2)
	require.EqualValues(t, fromTestArrayType(c.arrayVal), res.Rows[0][1])

	/*
		Block 2: Update
	*/

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = tx.Execute(ctx, "update ds_test.test set val = $1, array_val = $2", QueryModeExec, c.val2, fromTestArrayType(c.arrayVal2))
	require.NoError(t, err)

	changes = make(chan any, 1)
	changesetEntries, relations = nil, nil
	done = make(chan struct{})

	go processChangesets(changes, &changesetEntries, &relations, done)
	_, err = tx.Precommit(ctx, changes)
	require.NoError(t, err)

	<-done
	require.Len(t, changesetEntries, 1)
	require.Len(t, relations, 1)

	oldVals, newVals, err := changesetEntries[0].DecodeTuples(relations[0])
	require.NoError(t, err)

	// OLD

	// the third column is the array
	var oldArray []*T
	switch vt := oldVals[2].(type) {
	case []T:
		oldArray = toPtrSlice(vt)
	case []*T:
		oldArray = vt
	}

	// verify the old vals are equal to the first vals
	if oldVals[0] == nil {
		require.True(t, c.nullval)
	} else {
		if vp, ok := oldVals[0].(*T); ok {
			require.EqualValues(t, &c.val, vp)
		} else {
			require.EqualValues(t, c.val, oldVals[0])
		}
	}
	// and the array
	require.EqualValues(t, c.arrayVal, oldArray)

	// NEW

	var newArray []*T
	switch vt := newVals[2].(type) {
	case []T:
		newArray = toPtrSlice(vt)
	case []*T:
		newArray = vt
	}

	// verify the new vals are equal to the second vals
	if newVals[0] == nil {
		require.True(t, c.nullval2)
	} else {
		if vp, ok := newVals[0].(*T); ok {
			require.EqualValues(t, &c.val2, vp)
		} else {
			require.EqualValues(t, c.val2, newVals[0])
		}
	}
	require.EqualValues(t, c.arrayVal2, newArray)

	err = tx.Rollback(ctx)
	require.NoError(t, err)

	res, err = tx.Execute(ctx, "select val, array_val, name from ds_test.test")
	require.NoError(t, err)

	require.Len(t, res.Rows, 1)
	require.Len(t, res.Rows[0], 3)
	require.EqualValues(t, res.Rows[0][1], fromTestArrayType(c.arrayVal))
	require.EqualValues(t, res.Rows[0][2], nil)

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	require.NoError(t, applyChangesets(ctx, tx, changesetEntries, relations))

	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	res, err = tx.Execute(ctx, "select val, array_val from ds_test.test")
	require.NoError(t, err)

	require.Len(t, res.Rows, 1)
	require.Len(t, res.Rows[0], 2)
	require.EqualValues(t, res.Rows[0][1], fromTestArrayType(c.arrayVal2))

	/*
		Block 3: Delete
	*/

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = tx.Execute(ctx, "delete from ds_test.test", QueryModeExec)
	require.NoError(t, err)

	changes = make(chan any, 1)
	changesetEntries, relations = nil, nil
	done = make(chan struct{})

	go processChangesets(changes, &changesetEntries, &relations, done)

	_, err = tx.Precommit(ctx, changes)
	require.NoError(t, err)

	<-done
	require.Len(t, changesetEntries, 1)
	require.Len(t, relations, 1)

	deleteVals, _, err := changesetEntries[0].DecodeTuples(relations[0])
	require.NoError(t, err)

	// the third column is the array
	var deletedArray []*T
	switch vt := deleteVals[2].(type) {
	case []T:
		deletedArray = toPtrSlice(vt)
	case []*T:
		deletedArray = vt
	}

	// verify the delete vals are equal to the second vals
	if deleteVals[0] == nil {
		require.True(t, c.nullval2)
	} else {
		if vp, ok := deleteVals[0].(*T); ok {
			require.EqualValues(t, &c.val2, vp)
		} else {
			require.EqualValues(t, c.val2, deleteVals[0])
		}
	}
	require.EqualValues(t, c.arrayVal2, deletedArray)

	err = tx.Rollback(ctx)
	require.NoError(t, err)

	res, err = tx.Execute(ctx, "select val, array_val from ds_test.test")
	require.NoError(t, err)

	require.Len(t, res.Rows, 1)

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	require.NoError(t, applyChangesets(ctx, tx, changesetEntries, relations))

	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	res, err = tx.Execute(ctx, "select val, array_val from ds_test.test")
	require.NoError(t, err)

	require.Len(t, res.Rows, 0)
}

func Test_ApplyChangesetsConflictResolution(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	cleanup := func() {
		db.AutoCommit(true)
		_, err = db.Execute(ctx, "drop table if exists ds_test.test", QueryModeExec)
		require.NoError(t, err)
		_, err = db.Execute(ctx, "drop schema if exists ds_test", QueryModeExec)
		db.AutoCommit(false)
	}
	// attempt to clean up any old failed tests
	cleanup()
	defer cleanup()

	regularTx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer regularTx.Rollback(ctx)

	_, err = regularTx.Execute(ctx, "create schema ds_test", QueryModeExec)
	require.NoError(t, err)

	_, err = regularTx.Execute(ctx, "create table ds_test.test (val int primary key, name text,  array_val int[])", QueryModeExec)
	require.NoError(t, err)

	err = regularTx.Commit(ctx)
	require.NoError(t, err)

	/*
		Insert
	*/

	tx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	insert0 := toPtrSlice([]int64{1, 2, 3})
	insert1 := []int64{11, 22, 33}

	_, err = tx.Execute(ctx, "insert into ds_test.test (val, name, array_val) values ($1, $2, $3)", QueryModeExec, 1, "hello", insert0)
	require.NoError(t, err)

	_, err = tx.Execute(ctx, "insert into ds_test.test (val, name, array_val) values ($1, $2, $3)", QueryModeExec, 2, "mellow", insert1)
	require.NoError(t, err)

	changes := make(chan any, 1)
	var changesetEntries []*ChangesetEntry
	var relations []*Relation
	done := make(chan struct{})
	go processChangesets(changes, &changesetEntries, &relations, done)

	_, err = tx.Precommit(ctx, changes)
	require.NoError(t, err)

	<-done
	require.Len(t, changesetEntries, 2)
	require.Len(t, relations, 1)

	_, insertVals, err := changesetEntries[0].DecodeTuples(relations[0])
	require.NoError(t, err)

	// verify the insert vals are equal to the first vals
	require.EqualValues(t, 1, insertVals[0])
	require.EqualValues(t, "hello", insertVals[1])
	require.EqualValues(t, insert0, insertVals[2])

	_, insertVals, err = changesetEntries[1].DecodeTuples(relations[0])
	require.NoError(t, err)

	// verify the insert vals are equal to the second vals
	require.EqualValues(t, 2, insertVals[0])
	require.EqualValues(t, "mellow", insertVals[1])
	require.EqualValues(t, toPtrSlice(insert1), insertVals[2])

	// Rollback the changes
	err = tx.Rollback(ctx)
	require.NoError(t, err)

	res, err := tx.Execute(ctx, "select val, array_val from ds_test.test")
	require.NoError(t, err)
	require.Len(t, res.Rows, 0)

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// insert a different value with same id and commit
	_, err = tx.Execute(ctx, "insert into ds_test.test (val, name, array_val) values ($1, $2, $3)", QueryModeExec, 1, "world", []int{4, 5, 6})
	require.NoError(t, err)

	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Ensure that the record is inserted
	res, err = tx.Execute(ctx, "select val, name from ds_test.test")
	require.NoError(t, err)

	require.Len(t, res.Rows, 1)
	require.Len(t, res.Rows[0], 2)
	require.EqualValues(t, 1, res.Rows[0][0])
	require.EqualValues(t, "world", res.Rows[0][1])

	// Try applying the changeset
	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	require.NoError(t, applyChangesets(ctx, tx, changesetEntries, relations))

	// Ensure that the record is not updated due to conflict resolution: Do Nothing for inserts
	res, err = tx.Execute(ctx, "select val, name from ds_test.test")
	require.NoError(t, err)

	require.Len(t, res.Rows, 2)
	require.Len(t, res.Rows[0], 2)
	require.EqualValues(t, 1, res.Rows[0][0])
	require.EqualValues(t, "world", res.Rows[0][1])
	require.EqualValues(t, 2, res.Rows[1][0])
	require.EqualValues(t, "mellow", res.Rows[1][1])

	// commit the changes
	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	/*
		Update:

		Current entries:
		1, world, {4, 5, 6}
		2, mellow, {11, 22, 33}
	*/

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Update: 1, world, {4, 5, 6} -> 1, hello, {1, 2, 3}
	_, err = tx.Execute(ctx, "update ds_test.test set name = $1, array_val = $2 where val = $3", QueryModeExec, "hello", []int64{1, 2, 3}, 1)
	require.NoError(t, err)

	// Update: 2, mellow, {11, 22, 33} -> 2, yellow, {11, 22, 33}
	_, err = tx.Execute(ctx, "update ds_test.test set name = $1 where val = $2", QueryModeExec, "yellow", 2)
	require.NoError(t, err)

	changes = make(chan any, 1)
	changesetEntries, relations = nil, nil
	done = make(chan struct{})

	go processChangesets(changes, &changesetEntries, &relations, done)
	_, err = tx.Precommit(ctx, changes)
	require.NoError(t, err)

	<-done
	require.Len(t, relations, 1)
	require.Len(t, changesetEntries, 2)

	// Rollback the changes
	err = tx.Rollback(ctx)
	require.NoError(t, err)

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Update: 1, world, {4, 5, 6} -> 1, helloworld, {111, 222, 333}
	update0 := []int64{111, 222, 333}
	_, err = tx.Execute(ctx, "update ds_test.test set name = $1, array_val = $2 where val = $3", QueryModeExec, "helloworld", update0, 1)
	require.NoError(t, err)

	// commit
	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Ensure that the record is updated
	res, err = tx.Execute(ctx, "select val, name, array_val from ds_test.test where val = $1", 1)
	require.NoError(t, err)

	require.Len(t, res.Rows, 1)
	require.Len(t, res.Rows[0], 3)
	require.EqualValues(t, 1, res.Rows[0][0])
	require.EqualValues(t, "helloworld", res.Rows[0][1])

	// Try applying the changeset
	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)

	require.NoError(t, applyChangesets(ctx, tx, changesetEntries, relations))

	// Ensure that the record with id 2 is updated and 1 is not updated due to conflict resolution
	// Expected entries:
	// 1, helloworld, {111, 222, 333}
	// 2, yellow, {11, 22, 33}
	res, err = tx.Execute(ctx, "select val, name, array_val from ds_test.test")
	require.NoError(t, err)

	require.Len(t, res.Rows, 2)
	require.Len(t, res.Rows[0], 3)
	require.EqualValues(t, 1, res.Rows[0][0])
	require.EqualValues(t, "helloworld", res.Rows[0][1])
	require.EqualValues(t, toPtrSlice(update0), res.Rows[0][2])
	require.EqualValues(t, 2, res.Rows[1][0])
	require.EqualValues(t, "yellow", res.Rows[1][1])
	require.EqualValues(t, toPtrSlice(insert1), res.Rows[1][2])

	// commit the changes
	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	/*
		Delete
	*/

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = tx.Execute(ctx, "delete from ds_test.test where val = $1", QueryModeExec, 1)
	require.NoError(t, err)

	_, err = tx.Execute(ctx, "delete from ds_test.test where val = $1", QueryModeExec, 2)
	require.NoError(t, err)

	changes = make(chan any, 1)
	changesetEntries, relations = nil, nil
	done = make(chan struct{})

	go processChangesets(changes, &changesetEntries, &relations, done)

	_, err = tx.Precommit(ctx, changes)
	require.NoError(t, err)

	<-done
	require.Len(t, changesetEntries, 2)
	require.Len(t, relations, 1)

	// Rollback the changes
	err = tx.Rollback(ctx)
	require.NoError(t, err)

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)

	// update the record with id 1
	_, err = tx.Execute(ctx, "update ds_test.test set name = $1, array_val = $2 where val = $3", QueryModeExec, "hello", insert0, 1)
	require.NoError(t, err)

	// commit
	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Apply the changeset and ensure that the delete is not applied for id 1 but is applied for id 2
	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)

	require.NoError(t, applyChangesets(ctx, tx, changesetEntries, relations))

	// Ensure that the record with id 1 is not deleted and id 2 is deleted
	res, err = tx.Execute(ctx, "select val, name, array_val from ds_test.test")
	require.NoError(t, err)

	require.Len(t, res.Rows, 1)
	require.Len(t, res.Rows[0], 3)
	require.EqualValues(t, 1, res.Rows[0][0])
	require.EqualValues(t, "hello", res.Rows[0][1])
	require.EqualValues(t, insert0, res.Rows[0][2])

	// commit the changes
	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)
}

// tests the custom parse_unix_timestamp function
func Test_ParseUnixTimestamp(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	res, err := tx.Execute(ctx, "select parse_unix_timestamp('2024-06-11 13:54:12.123456', 'YYYY-MM-DD HH24:MI:SS.US')", QueryModeExec)
	require.NoError(t, err)

	require.Len(t, res.Rows, 1)
	require.Len(t, res.Rows[0], 1)

	expected, err := types.ParseDecimal("1718114052.123456")
	require.NoError(t, err)

	require.EqualValues(t, expected, res.Rows[0][0])

	// reverse it
	res, err = tx.Execute(ctx, "select format_unix_timestamp(1718114052.123456::numeric(16,6), 'YYYY-MM-DD HH24:MI:SS.US')", QueryModeExec)
	require.NoError(t, err)

	require.Len(t, res.Rows, 1)
	require.Len(t, res.Rows[0], 1)

	require.EqualValues(t, "2024-06-11 13:54:12.123456", res.Rows[0][0])
}

func Test_Listen(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	/*
		we test writing to two different txs at the same time,
		ensuring that both listeners receive their respective
		notifications.
	*/

	tx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// allocating 20 to allow it to potentially receive
	// notifications from the other tx. We are testing
	// that this does not happen
	ch1, done, err := tx.Subscribe(ctx)
	require.NoError(t, err)
	defer done(ctx)

	// create a readTx that will also notify
	readTx, err := db.BeginReadTx(ctx)
	require.NoError(t, err)
	defer readTx.Rollback(ctx)

	ch2, done2, err := readTx.Subscribe(ctx)
	require.NoError(t, err)
	defer done2(ctx)

	var received []string
	var received2 []string

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		for s := range ch1 {
			received = append(received, s)
		}

		wg.Done()
	}()

	go func() {
		for s := range ch2 {
			received2 = append(received2, s)
		}

		wg.Done()
	}()

	// notify 10 times to each
	for i := range 10 {
		_, err = tx.Execute(ctx, "SELECT NOTICE($1);", fmt.Sprint(i))
		require.NoError(t, err)

		_, err = readTx.Execute(ctx, "SELECT NOTICE($1);", fmt.Sprint(-i))
		require.NoError(t, err)
	}

	err = done(ctx)
	require.NoError(t, err)
	err = done2(ctx)
	require.NoError(t, err)

	wg.Wait()

	require.Len(t, received, 10)
	require.Len(t, received2, 10)

	for i := range 10 {
		require.Equal(t, strconv.Itoa(i), received[i])
		require.Equal(t, strconv.Itoa(-i), received2[i])
	}
}

func Test_CancelListen(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	collected, done, err := tx.Subscribe(ctx)
	require.NoError(t, err)
	defer done(ctx)

	var received []string

	go func() {
		for s := range collected {
			received = append(received, s)
		}
	}()

	for i := range 10 {
		_, err = tx.Execute(ctx, "SELECT NOTICE($1);", fmt.Sprint(i))
		require.NoError(t, err)
	}

	// we stop mid way through, we should see no events since events
	// are sent on commit
	err = done(ctx)
	require.NoError(t, err)

	for i := range 10 {
		_, err = tx.Execute(ctx, "SELECT NOTICE($1);", fmt.Sprint(-(i + 1)))
		require.NoError(t, err)
	}

	require.Len(t, received, 10)
}

func Test_DeleteMe(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	_, err = tx.Execute(ctx, "CREATE TABLE users (id serial primary key, name text)", QueryModeExec)
	require.NoError(t, err)

	ids := []any{}
	res := []any{
		&ids,
	}
	err = QueryRowFunc(ctx, tx, "SELECT array_agg(id) from users", res, func() error {
		return nil
	})
	require.NoError(t, err)
}
