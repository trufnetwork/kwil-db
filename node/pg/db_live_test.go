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
	// t.Logf("%v (%T)", b, b) // 6 (int32) - int4 columns now correctly decode to int32
	require.Equal(t, reflect.TypeOf(b), reflect.TypeFor[int32]())

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
		reflect.TypeFor[int32](), // int4 columns now correctly decode to int32
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
		{int64(9), int32(2), "b", []byte{0xee}, mustDec("0.98760"), toPtrSlice([]int64{99})},
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
		reflect.TypeFor[int32](),  // ordinal_position - information_schema INT columns decode to int32
		reflect.TypeFor[string](), // column_name
		reflect.TypeFor[string](), // is_nullable has boolean semantics but values of "YES"/"NO"
	}
	wantVals = [][]any{
		{int32(1), "a", "NO"},
		{int32(2), "b", "YES"},
		{int32(3), "c", "YES"},
		{int32(4), "d", "YES"},
		{int32(5), "e", "YES"},
		{int32(6), "f", "YES"},
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
	results, err := query(ctx, OidTypesMap(conn.TypeMap()), &cqWrapper{conn}, stmt, args2...)
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
			typ:  "int4",
			val:  int32(123),
			want: int32(123),
		},
		{
			typ:          "int4[]",
			val:          []int32{1, 2, 3},
			want:         toPtrSlice([]int32{int32(1), int32(2), int32(3)}),
			skipInferred: true, // int32 types are inferred as INT8, not INT4
		},
		{
			typ:          "int4[]", // with nulls
			val:          []*int32{ptrFor(int32(1)), nil, ptrFor(int32(3))},
			want:         []*int32{ptrFor(int32(1)), nil, ptrFor(int32(3))},
			skipInferred: true, // int32 types are inferred as INT8, not INT4
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
	res, err := db.Query(ctx, "select val, array_val from ds_test.test")
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

	res, err = db.Query(ctx, "select val, array_val from ds_test.test")
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

	res, err = db.Query(ctx, "select val, array_val, name from ds_test.test")
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

	res, err = db.Query(ctx, "select val, array_val from ds_test.test")
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

	res, err = db.Query(ctx, "select val, array_val from ds_test.test")
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

	res, err = db.Query(ctx, "select val, array_val from ds_test.test")
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

	insert0Raw := []int32{1, 2, 3}
	insert0Vals := toPtrSlice(insert0Raw) // expected decoded shape: []*int32
	insert1Vals := []int32{11, 22, 33}    // int[] arrays now correctly decode to []*int32

	_, err = tx.Execute(ctx, "insert into ds_test.test (val, name, array_val) values ($1, $2, $3)", QueryModeExec, 1, "hello", insert0Raw)
	require.NoError(t, err)

	_, err = tx.Execute(ctx, "insert into ds_test.test (val, name, array_val) values ($1, $2, $3)", QueryModeExec, 2, "mellow", insert1Vals)
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
	require.EqualValues(t, insert0Vals, insertVals[2])

	_, insertVals, err = changesetEntries[1].DecodeTuples(relations[0])
	require.NoError(t, err)

	// verify the insert vals are equal to the second vals
	require.EqualValues(t, 2, insertVals[0])
	require.EqualValues(t, "mellow", insertVals[1])
	require.EqualValues(t, toPtrSlice(insert1Vals), insertVals[2])

	// Rollback the changes
	err = tx.Rollback(ctx)
	require.NoError(t, err)

	res, err := db.Query(ctx, "select val, array_val from ds_test.test")
	require.NoError(t, err)
	require.Len(t, res.Rows, 0)

	tx, err = db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// insert a different value with same id and commit
	_, err = tx.Execute(ctx, "insert into ds_test.test (val, name, array_val) values ($1, $2, $3)", QueryModeExec, 1, "world", []int32{4, 5, 6})
	require.NoError(t, err)

	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Ensure that the record is inserted
	res, err = db.Query(ctx, "select val, name from ds_test.test")
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
	_, err = tx.Execute(ctx, "update ds_test.test set name = $1, array_val = $2 where val = $3", QueryModeExec, "hello", []int32{1, 2, 3}, 1)
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
	updateVals := []int32{111, 222, 333} // int[] arrays now correctly decode to []*int32
	_, err = tx.Execute(ctx, "update ds_test.test set name = $1, array_val = $2 where val = $3", QueryModeExec, "helloworld", updateVals, 1)
	require.NoError(t, err)

	// commit
	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Ensure that the record is updated
	res, err = db.Query(ctx, "select val, name, array_val from ds_test.test where val = $1", 1)
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
	require.EqualValues(t, toPtrSlice(updateVals), res.Rows[0][2])
	require.EqualValues(t, 2, res.Rows[1][0])
	require.EqualValues(t, "yellow", res.Rows[1][1])
	require.EqualValues(t, toPtrSlice(insert1Vals), res.Rows[1][2])

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
	updateArray := toPtrSlice([]int32{1, 2, 3}) // int[] arrays now correctly decode to []*int32
	_, err = tx.Execute(ctx, "update ds_test.test set name = $1, array_val = $2 where val = $3", QueryModeExec, "hello", updateArray, 1)
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
	require.EqualValues(t, updateArray, res.Rows[0][2])

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

// TestMultiPreparedTxns tests the multi-transaction tracking introduced
// in Phase 1 of the 2PC refactor. It verifies:
//  1. Two transactions can be prepared sequentially and committed with CommitAll
//  2. Two transactions can be prepared and rolled back with RollbackAll
//  3. Prepare 1 tx, begin 2nd (unprepared), RollbackAll cleans up both
func TestMultiPreparedTxns(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	// Setup: use ds_ prefixed schema so inserts contribute to changeset hash.
	db.AutoCommit(true)
	_, err = db.Execute(ctx, `CREATE SCHEMA IF NOT EXISTS ds_multi_tx`, QueryModeExec)
	require.NoError(t, err)
	_, err = db.Execute(ctx, `CREATE TABLE IF NOT EXISTS ds_multi_tx.test (id INT8, val TEXT)`, QueryModeExec)
	require.NoError(t, err)
	_, err = db.Execute(ctx, `DELETE FROM ds_multi_tx.test`)
	require.NoError(t, err)
	db.AutoCommit(false)

	t.Run("CommitAll", func(t *testing.T) {
		// Tx 1: insert row.
		tx1, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx1.Execute(ctx, `INSERT INTO ds_multi_tx.test (id, val) VALUES (1, 'tx1')`)
		require.NoError(t, err)
		cid1, err := tx1.Precommit(ctx, nil)
		require.NoError(t, err)
		require.NotEmpty(t, cid1)

		// Tx 2: insert different row.
		tx2, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx2.Execute(ctx, `INSERT INTO ds_multi_tx.test (id, val) VALUES (2, 'tx2')`)
		require.NoError(t, err)
		cid2, err := tx2.Precommit(ctx, nil)
		require.NoError(t, err)
		require.NotEmpty(t, cid2)

		// Commit IDs should differ (different data).
		require.NotEqual(t, cid1, cid2)

		// CommitAll.
		err = db.CommitAll(ctx)
		require.NoError(t, err)

		// Verify both rows visible.
		res, err := db.Query(ctx, `SELECT id, val FROM ds_multi_tx.test ORDER BY id`)
		require.NoError(t, err)
		require.Len(t, res.Rows, 2)
		require.Equal(t, int64(1), res.Rows[0][0])
		require.Equal(t, "tx1", res.Rows[0][1])
		require.Equal(t, int64(2), res.Rows[1][0])
		require.Equal(t, "tx2", res.Rows[1][1])

		// Cleanup.
		db.AutoCommit(true)
		defer db.AutoCommit(false)
		_, err = db.Execute(ctx, `DELETE FROM ds_multi_tx.test`)
		require.NoError(t, err)
	})

	t.Run("RollbackAll_prepared", func(t *testing.T) {
		// Tx 1.
		tx1, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx1.Execute(ctx, `INSERT INTO ds_multi_tx.test (id, val) VALUES (3, 'tx3')`)
		require.NoError(t, err)
		_, err = tx1.Precommit(ctx, nil)
		require.NoError(t, err)

		// Tx 2.
		tx2, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx2.Execute(ctx, `INSERT INTO ds_multi_tx.test (id, val) VALUES (4, 'tx4')`)
		require.NoError(t, err)
		_, err = tx2.Precommit(ctx, nil)
		require.NoError(t, err)

		// RollbackAll.
		err = db.RollbackAll(ctx)
		require.NoError(t, err)

		// Verify no rows.
		res, err := db.Query(ctx, `SELECT id FROM ds_multi_tx.test`)
		require.NoError(t, err)
		require.Len(t, res.Rows, 0)
	})

	t.Run("RollbackAll_mixed", func(t *testing.T) {
		// Tx 1: prepared.
		tx1, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx1.Execute(ctx, `INSERT INTO ds_multi_tx.test (id, val) VALUES (5, 'tx5')`)
		require.NoError(t, err)
		_, err = tx1.Precommit(ctx, nil)
		require.NoError(t, err)

		// Tx 2: active (not prepared).
		tx2, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx2.Execute(ctx, `INSERT INTO ds_multi_tx.test (id, val) VALUES (6, 'tx6')`)
		require.NoError(t, err)
		// Don't precommit tx2 — it's still active.

		// RollbackAll should clean up both.
		err = db.RollbackAll(ctx)
		require.NoError(t, err)

		// Verify no rows.
		res, err := db.Query(ctx, `SELECT id FROM ds_multi_tx.test`)
		require.NoError(t, err)
		require.Len(t, res.Rows, 0)
	})

	// Cleanup: drop schema.
	db.AutoCommit(true)
	defer db.AutoCommit(false)
	_, err = db.Execute(ctx, `DROP SCHEMA IF EXISTS ds_multi_tx CASCADE`, QueryModeExec)
	require.NoError(t, err)
}

// TestSingleTxPathUnchanged verifies the original single-tx path
// (BeginPreparedTx → Precommit → Commit) still works after the refactor.
func TestSingleTxPathUnchanged(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	db.AutoCommit(true)
	_, err = db.Execute(ctx, `CREATE SCHEMA IF NOT EXISTS ds_single_tx`, QueryModeExec)
	require.NoError(t, err)
	_, err = db.Execute(ctx, `CREATE TABLE IF NOT EXISTS ds_single_tx.test (id INT8, val TEXT)`, QueryModeExec)
	require.NoError(t, err)
	_, err = db.Execute(ctx, `DELETE FROM ds_single_tx.test`)
	require.NoError(t, err)
	db.AutoCommit(false)

	// Classic single-tx path.
	tx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)

	_, err = tx.Execute(ctx, `INSERT INTO ds_single_tx.test (id, val) VALUES (1, 'hello')`)
	require.NoError(t, err)

	cid, err := tx.Precommit(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, cid)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify.
	res, err := db.Query(ctx, `SELECT id, val FROM ds_single_tx.test`)
	require.NoError(t, err)
	require.Len(t, res.Rows, 1)
	require.Equal(t, int64(1), res.Rows[0][0])

	// Cleanup.
	db.AutoCommit(true)
	defer db.AutoCommit(false)
	_, err = db.Execute(ctx, `DROP SCHEMA IF EXISTS ds_single_tx CASCADE`, QueryModeExec)
	require.NoError(t, err)
}

// TestMultiSequenceReplication verifies Phase 2: per-transaction sentry
// sequencing and replmon multi-sequence delivery. It tests:
//  1. Each prepared tx gets a unique sentry sequence and commitID
//  2. The muhash hasher resets between PREPAREs (per-tx hash isolation)
//  3. CommitIDs are deterministic (same data = same hash across runs)
func TestMultiSequenceReplication(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	// Setup: use ds_ prefixed schema so inserts contribute to changeset hash.
	db.AutoCommit(true)
	defer db.AutoCommit(false)
	_, err = db.Execute(ctx, `CREATE SCHEMA IF NOT EXISTS ds_multiseq`, QueryModeExec)
	require.NoError(t, err)
	_, err = db.Execute(ctx, `CREATE TABLE IF NOT EXISTS ds_multiseq.test (id INT8, val TEXT)`, QueryModeExec)
	require.NoError(t, err)
	_, err = db.Execute(ctx, `DELETE FROM ds_multiseq.test`)
	require.NoError(t, err)
	db.AutoCommit(false)

	t.Run("per_tx_hash_isolation", func(t *testing.T) {
		t.Cleanup(func() {
			require.NoError(t, db.RollbackAll(ctx))
		})

		// Tx 1: insert a specific row.
		tx1, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx1.Execute(ctx, `INSERT INTO ds_multiseq.test (id, val) VALUES (100, 'alpha')`)
		require.NoError(t, err)
		cid1, err := tx1.Precommit(ctx, nil)
		require.NoError(t, err)
		require.NotEmpty(t, cid1)

		// Tx 2: insert a different row.
		tx2, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx2.Execute(ctx, `INSERT INTO ds_multiseq.test (id, val) VALUES (200, 'beta')`)
		require.NoError(t, err)
		cid2, err := tx2.Precommit(ctx, nil)
		require.NoError(t, err)
		require.NotEmpty(t, cid2)

		// CommitIDs must differ — different data means different muhash.
		// This proves the hasher resets between PREPAREs.
		require.NotEqual(t, cid1, cid2, "commitIDs should differ for different data")

		err = db.CommitAll(ctx)
		require.NoError(t, err)

		// Cleanup.
		db.AutoCommit(true)
		defer db.AutoCommit(false)
		_, err = db.Execute(ctx, `DELETE FROM ds_multiseq.test`)
		require.NoError(t, err)
	})

	t.Run("deterministic_commitIDs", func(t *testing.T) {
		t.Cleanup(func() {
			require.NoError(t, db.RollbackAll(ctx))
		})

		// Run the same sequence twice and verify commitIDs match.
		// This proves that the WAL hash computation is deterministic
		// and that sentry sequence values don't leak into the hash.

		runSequence := func() ([]byte, []byte) {
			tx1, err := db.BeginPreparedTx(ctx)
			require.NoError(t, err)
			_, err = tx1.Execute(ctx, `INSERT INTO ds_multiseq.test (id, val) VALUES (1, 'deterministic')`)
			require.NoError(t, err)
			cid1, err := tx1.Precommit(ctx, nil)
			require.NoError(t, err)

			tx2, err := db.BeginPreparedTx(ctx)
			require.NoError(t, err)
			_, err = tx2.Execute(ctx, `INSERT INTO ds_multiseq.test (id, val) VALUES (2, 'test')`)
			require.NoError(t, err)
			cid2, err := tx2.Precommit(ctx, nil)
			require.NoError(t, err)

			err = db.CommitAll(ctx)
			require.NoError(t, err)

			// Cleanup for next run.
			db.AutoCommit(true)
			defer db.AutoCommit(false)
			_, err = db.Execute(ctx, `DELETE FROM ds_multiseq.test`)
			require.NoError(t, err)

			return cid1, cid2
		}

		// Run 1.
		cid1a, cid2a := runSequence()

		// Run 2.
		cid1b, cid2b := runSequence()

		// Same data → same hash (sentry seq differs but is NOT part of muhash).
		require.Equal(t, cid1a, cid1b, "commitID for tx1 should be deterministic across runs")
		require.Equal(t, cid2a, cid2b, "commitID for tx2 should be deterministic across runs")
	})

	t.Run("two_txns_sequential_unique_hashes", func(t *testing.T) {
		t.Cleanup(func() {
			require.NoError(t, db.RollbackAll(ctx))
		})

		// Verify 2 sequential prepare/precommit cycles produce
		// unique commitIDs and both commit successfully.
		// (Limited to 2 by default max_prepared_transactions=2.)
		tx1, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx1.Execute(ctx, `INSERT INTO ds_multiseq.test (id, val) VALUES (10, 'one')`)
		require.NoError(t, err)
		cid1, err := tx1.Precommit(ctx, nil)
		require.NoError(t, err)

		tx2, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx2.Execute(ctx, `INSERT INTO ds_multiseq.test (id, val) VALUES (20, 'two')`)
		require.NoError(t, err)
		cid2, err := tx2.Precommit(ctx, nil)
		require.NoError(t, err)

		// CommitIDs should be unique.
		require.NotEqual(t, cid1, cid2)

		err = db.CommitAll(ctx)
		require.NoError(t, err)

		// Verify both rows visible.
		res, err := db.Query(ctx, `SELECT id FROM ds_multiseq.test ORDER BY id`)
		require.NoError(t, err)
		require.Len(t, res.Rows, 2)
		require.Equal(t, int64(10), res.Rows[0][0])
		require.Equal(t, int64(20), res.Rows[1][0])

		// Cleanup.
		db.AutoCommit(true)
		defer db.AutoCommit(false)
		_, err = db.Execute(ctx, `DELETE FROM ds_multiseq.test`)
		require.NoError(t, err)
	})

	// Final cleanup.
	db.AutoCommit(true)
	defer db.AutoCommit(false)
	_, err = db.Execute(ctx, `DROP SCHEMA IF EXISTS ds_multiseq CASCADE`, QueryModeExec)
	require.NoError(t, err)
}

// TestAggregateChangesetHash verifies that AggregateChangesetHash produces
// a deterministic, non-zero hash from multiple prepared transactions, and
// that the result matches manually aggregating the individual commitIDs.
func TestAggregateChangesetHash(t *testing.T) {
	ctx := context.Background()

	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	// Setup: create test table in ds_ schema for changeset capture.
	db.AutoCommit(true)
	_, err = db.Execute(ctx, `CREATE SCHEMA IF NOT EXISTS ds_agghash`, QueryModeExec)
	require.NoError(t, err)
	_, err = db.Execute(ctx, `DROP TABLE IF EXISTS ds_agghash.test`, QueryModeExec)
	require.NoError(t, err)
	_, err = db.Execute(ctx, `CREATE TABLE ds_agghash.test (id INT PRIMARY KEY, val TEXT)`, QueryModeExec)
	require.NoError(t, err)
	db.AutoCommit(false)

	t.Run("matches_manual_aggregation", func(t *testing.T) {
		t.Cleanup(func() {
			require.NoError(t, db.RollbackAll(ctx))
		})

		// Prepare two transactions.
		tx1, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx1.Execute(ctx, `INSERT INTO ds_agghash.test (id, val) VALUES (1, 'first')`)
		require.NoError(t, err)
		cid1, err := tx1.Precommit(ctx, nil)
		require.NoError(t, err)

		tx2, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx2.Execute(ctx, `INSERT INTO ds_agghash.test (id, val) VALUES (2, 'second')`)
		require.NoError(t, err)
		cid2, err := tx2.Precommit(ctx, nil)
		require.NoError(t, err)

		// AggregateChangesetHash should return the same result as manual aggregation.
		aggHash, err := db.AggregateChangesetHash()
		require.NoError(t, err)
		require.Len(t, aggHash, 32)

		manualHash := aggregateCommitIDs([][]byte{cid1, cid2})
		require.Equal(t, manualHash, aggHash,
			"AggregateChangesetHash should match manual aggregation of [cid1, cid2]")

		// The aggregated hash should differ from either individual commitID.
		require.NotEqual(t, cid1, aggHash)
		require.NotEqual(t, cid2, aggHash)

		err = db.CommitAll(ctx)
		require.NoError(t, err)
	})

	t.Run("single_tx_aggregation", func(t *testing.T) {
		t.Cleanup(func() {
			require.NoError(t, db.RollbackAll(ctx))
		})

		tx1, err := db.BeginPreparedTx(ctx)
		require.NoError(t, err)
		_, err = tx1.Execute(ctx, `INSERT INTO ds_agghash.test (id, val) VALUES (10, 'solo')`)
		require.NoError(t, err)
		cid1, err := tx1.Precommit(ctx, nil)
		require.NoError(t, err)

		aggHash, err := db.AggregateChangesetHash()
		require.NoError(t, err)

		// Single ID: aggregate = SHA256(cid1), NOT cid1 itself.
		require.NotEqual(t, cid1, aggHash,
			"aggregated single commitID should differ from raw commitID")
		require.Equal(t, aggregateCommitIDs([][]byte{cid1}), aggHash)

		err = db.CommitAll(ctx)
		require.NoError(t, err)
	})

	t.Run("error_without_prepared_txns", func(t *testing.T) {
		_, err := db.AggregateChangesetHash()
		require.Error(t, err)
	})

	// Final cleanup.
	db.AutoCommit(true)
	_, err = db.Execute(ctx, `DROP SCHEMA IF EXISTS ds_agghash CASCADE`, QueryModeExec)
	require.NoError(t, err)
	db.AutoCommit(false)
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

// TestPrecommitWaitsForALargeTransaction checks that Precommit waits for a
// commit ID while the replication stream is still delivering the transaction.
// Postgres sends a prepared transaction only once it is prepared, and hashing
// 300,000 updated rows outlasts the stall set here, which a deadline counted
// from PREPARE would not allow.
func TestPrecommitWaitsForALargeTransaction(t *testing.T) {
	stall := commitIDStall
	defer func() { commitIDStall = stall }()
	commitIDStall = time.Second

	ctx := context.Background()
	db, err := NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	exec := func(stmt string) {
		t.Helper()
		db.AutoCommit(true)
		defer db.AutoCommit(false)
		_, err := db.Execute(ctx, stmt, QueryModeExec)
		require.NoError(t, err)
	}
	exec("drop schema if exists ds_large_txn cascade")
	defer exec("drop schema if exists ds_large_txn cascade")
	exec("create schema ds_large_txn")
	exec("create table ds_large_txn.rows (id int8 primary key, x int8)")
	exec("insert into ds_large_txn.rows select g, g from generate_series(1, 300000) g")

	tx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Execute(ctx, "update ds_large_txn.rows set x = x + 1", QueryModeExec)
	require.NoError(t, err)

	t0 := time.Now()
	_, err = tx.Precommit(ctx, nil)
	require.NoError(t, err)
	// Otherwise this machine hashed the transaction within the stall, and the
	// test shows nothing.
	require.Greater(t, time.Since(t0), commitIDStall)
}

// TestNewDBReplicationRole opens a DB as a role that has REPLICATION and is not
// a superuser. Such a role may not create the event trigger that gives new
// tables full replica identity, or the publication for all tables, so NewDB
// checks the ones a superuser set up, along with the role's grants and
// memberships.
func TestNewDBReplicationRole(t *testing.T) {
	ctx := context.Background()
	const role, dbName = "kwild_repl_role", "kwil_test_repl_role"

	admin, err := pgx.Connect(ctx, connString(cfg.Host, cfg.Port, cfg.User, cfg.Pass, cfg.DBName, false))
	require.NoError(t, err)
	t.Cleanup(func() { admin.Close(ctx) })

	drop := func() error {
		_, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+dbName+` WITH (FORCE)`)
		if err == nil {
			// A role that holds a privilege on a parameter cannot be dropped.
			_, err = admin.Exec(ctx, `DO $$ BEGIN
				IF EXISTS (SELECT FROM pg_roles WHERE rolname = '`+role+`') THEN
					REVOKE SET ON PARAMETER session_replication_role FROM `+role+`;
				END IF;
			END $$`)
		}
		if err == nil {
			_, err = admin.Exec(ctx, `DROP ROLE IF EXISTS `+role)
		}
		return err
	}
	require.NoError(t, drop()) // left by an interrupted run
	t.Cleanup(func() {
		// A closed DB's replication slot lasts until its walsender exits.
		assert.Eventually(t, func() bool { return drop() == nil }, 10*time.Second, 100*time.Millisecond)
	})

	_, err = admin.Exec(ctx, `CREATE ROLE `+role+` LOGIN REPLICATION NOSUPERUSER PASSWORD '`+cfg.Pass+`'`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `CREATE DATABASE `+dbName+` OWNER `+role)
	require.NoError(t, err)

	super, err := pgx.Connect(ctx, connString(cfg.Host, cfg.Port, cfg.User, cfg.Pass, dbName, false))
	require.NoError(t, err)
	defer super.Close(ctx)
	superExec := func(t *testing.T, stmt string) {
		t.Helper()
		_, err := super.Exec(ctx, stmt)
		require.NoError(t, err)
	}

	// A superuser sets up what the role may not, and keeps ownership of it:
	// the grant on session_replication_role, the publication, and the event
	// trigger with its function, which has a fixed search_path and lives in a
	// schema that the superuser owns and the role may not use. The role owns
	// the database, and so its public schema. The function's body is
	// sqlReplicaIdentityFuncBody, the body kwild expects, so the test checks
	// NewDB against kwild's own definition and not against any provisioning
	// script from another repository.
	// Running such a provisioning script through these checks is follow-up work.
	superExec(t, `CREATE SCHEMA replica_identity`)
	superExec(t, `REVOKE ALL ON SCHEMA replica_identity FROM PUBLIC`)
	prepared := func(t *testing.T) []string {
		t.Helper()
		rows, _ := super.Query(ctx, `SELECT gid FROM pg_prepared_xacts WHERE database = current_database() ORDER BY gid`)
		gids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		return gids
	}
	createFunc := func(schema string) string {
		return `CREATE FUNCTION ` + schema + `.set_replica_identity() RETURNS event_trigger
			LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$` + sqlReplicaIdentityFuncBody + `$$`
	}
	createTrigger := func(tags, schema string) string {
		return `CREATE EVENT TRIGGER set_replica_identity_on_create ON ddl_command_end
			WHEN TAG IN (` + tags + `) EXECUTE FUNCTION ` + schema + `.set_replica_identity()`
	}
	setUp := func(t *testing.T) {
		t.Helper()
		// A case may leave prepared transactions, which would also keep the
		// database from being dropped, and a NewDB that fails after it starts
		// logical replication leaves the walsender running.
		for _, gid := range prepared(t) {
			superExec(t, `ROLLBACK PREPARED '`+gid+`'`)
		}
		superExec(t, `SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots
			WHERE database = current_database() AND active_pid IS NOT NULL`)
		for _, stmt := range []string{
			`ALTER ROLE ` + role + ` NOSUPERUSER`,
			`REVOKE ` + cfg.User + `, pg_execute_server_program, pg_read_server_files, pg_write_server_files FROM ` + role,
			`GRANT SET ON PARAMETER session_replication_role TO ` + role,
			`DROP PUBLICATION IF EXISTS ` + publicationName,
			`CREATE PUBLICATION ` + publicationName + ` FOR ALL TABLES`,
			sqlDropEvtTriggerReplIdent,
			`DROP FUNCTION IF EXISTS replica_identity.set_replica_identity(), public.set_replica_identity()`,
			createFunc("replica_identity"),
			createTrigger(`'CREATE TABLE'`, "replica_identity"),
			`DROP FUNCTION IF EXISTS error(text), notice(text), end_notices(bigint),
				parse_unix_timestamp(text, text), format_unix_timestamp(numeric, text)`,
		} {
			superExec(t, stmt)
		}
	}

	roleCfg := *cfg
	roleCfg.User, roleCfg.DBName = role, dbName

	// NewDB fails while the role may act as a superuser or on the database
	// server, or while what a superuser sets up is missing, not as kwild
	// creates it, or in the role's reach. Each error says what to change.
	const (
		trigger     = "event trigger set_replica_identity_on_create in database " + dbName + " "
		publication = "publication " + publicationName + " in database " + dbName + " "
		reachable   = "can be dropped or changed by postgres role " + role
		notAsKwild  = "is not for all tables with every change published, as kwild creates it"
		memberOf    = "postgres role " + role + " is not a superuser but is a member of "
	)
	for _, tc := range []struct {
		name    string
		stmts   []string
		wantErr string
	}{
		{"trigger missing", []string{sqlDropEvtTriggerReplIdent}, trigger + "does not exist"},
		{"trigger disabled", []string{`ALTER EVENT TRIGGER set_replica_identity_on_create DISABLE`},
			trigger + "is not enabled"},
		{"trigger on more tags", []string{sqlDropEvtTriggerReplIdent,
			createTrigger(`'CREATE TABLE', 'CREATE TABLE AS'`, "replica_identity")},
			trigger + "does not fire on CREATE TABLE alone"},
		{"trigger on another tag", []string{sqlDropEvtTriggerReplIdent,
			createTrigger(`'CREATE SCHEMA'`, "replica_identity")}, trigger + "does not fire on CREATE TABLE alone"},
		{"trigger on another event", []string{sqlDropEvtTriggerReplIdent,
			`CREATE EVENT TRIGGER set_replica_identity_on_create ON ddl_command_start
			WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION replica_identity.set_replica_identity()`},
			trigger + "does not fire on CREATE TABLE alone"},
		{"other function body", []string{`CREATE OR REPLACE FUNCTION replica_identity.set_replica_identity()
			RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN END; $$`},
			trigger + "does not run set_replica_identity()"},
		{"function in public", []string{sqlDropEvtTriggerReplIdent, createFunc("public"),
			createTrigger(`'CREATE TABLE'`, "public")}, trigger + reachable},
		{"function owned by role", []string{`ALTER FUNCTION replica_identity.set_replica_identity() OWNER TO ` + role},
			trigger + reachable},
		{"trigger owned by role", []string{`ALTER ROLE ` + role + ` SUPERUSER`,
			`ALTER EVENT TRIGGER set_replica_identity_on_create OWNER TO ` + role, `ALTER ROLE ` + role + ` NOSUPERUSER`},
			trigger + reachable},
		{"publication missing", []string{`DROP PUBLICATION ` + publicationName}, publication + "does not exist"},
		{"publication for one schema", []string{`DROP PUBLICATION ` + publicationName,
			`CREATE PUBLICATION ` + publicationName + ` FOR TABLES IN SCHEMA public`}, publication + notAsKwild},
		{"publication of inserts", []string{`ALTER PUBLICATION ` + publicationName + ` SET (publish = 'insert')`},
			publication + notAsKwild},
		{"publication without truncate", []string{`ALTER PUBLICATION ` + publicationName +
			` SET (publish = 'insert, update, delete')`}, publication + notAsKwild},
		{"publication via partition root", []string{`ALTER PUBLICATION ` + publicationName +
			` SET (publish_via_partition_root = true)`}, publication + notAsKwild},
		{"publication owned by role", []string{`ALTER PUBLICATION ` + publicationName + ` OWNER TO ` + role},
			publication + reachable},
		{"no grant on session_replication_role", []string{`REVOKE SET ON PARAMETER session_replication_role FROM ` + role},
			"postgres role " + role + " may not set session_replication_role, which a snapshot restore sets"},
		{"member of a superuser", []string{`GRANT ` + cfg.User + ` TO ` + role}, memberOf + cfg.User + " (a superuser)"},
		{"member of pg_execute_server_program", []string{`GRANT pg_execute_server_program TO ` + role},
			memberOf + "pg_execute_server_program"},
		{"member of pg_read_server_files", []string{`GRANT pg_read_server_files TO ` + role},
			memberOf + "pg_read_server_files"},
		{"member of pg_write_server_files", []string{`GRANT pg_write_server_files TO ` + role},
			memberOf + "pg_write_server_files"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setUp(t)
			for _, stmt := range tc.stmts {
				superExec(t, stmt)
			}
			_, err := NewDB(ctx, &roleCfg)
			require.ErrorContains(t, err, tc.wantErr)
			if strings.HasPrefix(tc.wantErr, memberOf) {
				require.ErrorContains(t, err, "revoke that membership")
				return
			}
			// The error names everything a superuser must set up.
			for _, want := range []string{
				"GRANT SET ON PARAMETER session_replication_role TO " + role,
				"create in database " + dbName + ", owned by the superuser",
				"the publication " + publicationName + " FOR ALL TABLES",
				"the function set_replica_identity() as kwild defines it in a schema the superuser owns",
				"the event trigger set_replica_identity_on_create that runs it ON ddl_command_end WHEN TAG IN ('CREATE TABLE')",
			} {
				require.ErrorContains(t, err, want)
			}
		})
	}

	// A role that is not a superuser may roll back only the prepared
	// transactions it prepared, and may replace a function only with its
	// owner's privileges. NewDB rolls back the role's own prepared
	// transactions and creates or replaces the functions it may. It leaves a
	// function that another role owns as it is when it is as kwild creates it,
	// and otherwise stops, as it does on a prepared transaction that another
	// role prepared, with an error that says what a superuser must do.
	prepareAs := func(owner, gid string) []string {
		return []string{`SET ROLE ` + owner, `BEGIN`, `PREPARE TRANSACTION '` + gid + `'`, `RESET ROLE`}
	}
	const otherFunc = `CREATE FUNCTION error(msg text) RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql`
	notAsDefined := "function public.error(msg text) is not as kwild defines it, and postgres role " + role +
		" may not replace it, since only its owner, postgres role " + cfg.User + ", or a role with that role's " +
		"privileges may; a superuser must first run ALTER FUNCTION public.error(msg text) OWNER TO " + role
	for _, tc := range []struct {
		name    string
		stmts   []string
		wantErr string             // or NewDB opens the database
		after   func(t *testing.T) // checks what NewDB left
	}{
		{"transaction prepared by another role",
			slices.Concat(prepareAs(role, "kwil_test_own"), prepareAs(cfg.User, "kwil_test_other")),
			"postgres role " + role + " is not a superuser, so it may roll back only the prepared transactions " +
				"it prepared, but database " + dbName + " holds prepared transactions that other roles prepared: " +
				"'kwil_test_other' (prepared by " + cfg.User + "); a superuser must first run ROLLBACK PREPARED " +
				"for each in database " + dbName,
			func(t *testing.T) { // NewDB rolled back neither
				require.Equal(t, []string{"kwil_test_other", "kwil_test_own"}, prepared(t))
			}},
		{"transaction prepared by the role", prepareAs(role, "kwil_test_own"), "",
			func(t *testing.T) { require.Empty(t, prepared(t)) }},
		{"functions a superuser created as kwild does", []string{sqlCreateFuncError, sqlCreateFuncNotice,
			sqlCreateFuncEndNotices, sqlCreateParseUnixTimestampFunc, sqlCreateFormatUnixTimestampFunc}, "",
			func(t *testing.T) { // and still owns
				var owned int
				err := super.QueryRow(ctx, `SELECT count(*) FROM pg_proc
					WHERE pronamespace = 'public'::regnamespace AND proowner = $1::regrole AND
					proname IN ('error', 'notice', 'end_notices', 'parse_unix_timestamp', 'format_unix_timestamp')`,
					cfg.User).Scan(&owned)
				require.NoError(t, err)
				require.Equal(t, 5, owned)
			}},
		{"function a superuser created otherwise", []string{otherFunc}, notAsDefined, nil},
		{"function a superuser created as kwild does but strict", []string{sqlCreateFuncError,
			`ALTER FUNCTION error(text) STRICT`}, notAsDefined, nil},
		{"function the role owns, created otherwise", []string{otherFunc, `ALTER FUNCTION error(text) OWNER TO ` + role},
			"", func(t *testing.T) { // NewDB replaced it
				var body string
				err := super.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE oid = 'error(text)'::regprocedure`).
					Scan(&body)
				require.NoError(t, err)
				require.Equal(t, sqlFuncErrorBody, body)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setUp(t)
			for _, stmt := range tc.stmts {
				superExec(t, stmt)
			}
			db, err := NewDB(ctx, &roleCfg)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				require.NoError(t, db.Close())
			}
			if tc.after != nil {
				tc.after(t)
			}
		})
	}

	setUp(t)
	db, err := NewDB(ctx, &roleCfg)
	require.NoError(t, err)
	defer db.Close()

	// The role creates a table, and the trigger gives it full replica identity.
	db.AutoCommit(true)
	_, err = db.Execute(ctx, `CREATE SCHEMA ds_repl_role`, QueryModeExec)
	require.NoError(t, err)
	_, err = db.Execute(ctx, `CREATE TABLE ds_repl_role.test (id INT8 PRIMARY KEY, val TEXT)`, QueryModeExec)
	require.NoError(t, err)
	db.AutoCommit(false)

	var ident string
	err = super.QueryRow(ctx, `SELECT relreplident::text FROM pg_class WHERE oid = 'ds_repl_role.test'::regclass`).Scan(&ident)
	require.NoError(t, err)
	require.Equal(t, "f", ident)

	// The role reads the commit ID of a write over logical replication.
	tx, err := db.BeginPreparedTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Execute(ctx, `INSERT INTO ds_repl_role.test (id, val) VALUES (1, 'hello')`)
	require.NoError(t, err)
	cid, err := tx.Precommit(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, cid)
	require.NoError(t, tx.Commit(ctx))
}
