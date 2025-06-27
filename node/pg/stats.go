package pg

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// RowCount gets a precise row count for the named fully qualified table. If the
// Executor satisfies the RowCounter interface, that method will be used
// directly. Otherwise a simple select query is used.
func RowCount(ctx context.Context, qualifiedTable string, db sql.Executor) (int64, error) {
	stmt := `SELECT count(1) FROM ` + qualifiedTable
	res, err := db.Execute(ctx, stmt)
	if err != nil {
		return 0, fmt.Errorf("unable to count rows: %w", err)
	}
	if len(res.Rows) != 1 || len(res.Rows[0]) != 1 {
		return 0, errors.New("exactly one value not returned by row count query")
	}
	count, ok := sql.Int64(res.Rows[0][0])
	if !ok {
		return 0, fmt.Errorf("no row count for %s", qualifiedTable)
	}
	return count, nil
}

// TableStatser is an interface that the implementation of a sql.Executor may
// implement.
type TableStatser interface {
	TableStats(ctx context.Context, schema, table string) (*Statistics, error)
}

// TableStats collects deterministic statistics for a table. If schema is empty,
// the "public" schema is assumed. This method is used to obtain the ground
// truth statistics for a table; incremental statistics updates should be
// preferred when possible. If the sql.Executor implementation is a
// TableStatser, it's method is used directly. This is primarily to allow a stub
// DB for testing.
func TableStats(ctx context.Context, schema, table string, db sql.Executor) (*Statistics, error) {
	if ts, ok := db.(TableStatser); ok {
		return ts.TableStats(ctx, schema, table)
	}

	if schema == "" {
		schema = "public"
	}
	qualifiedTable := schema + "." + table

	count, err := RowCount(ctx, qualifiedTable, db)
	if err != nil {
		return nil, err
	}
	// TODO: We needs a schema-table stats database so we don't ever have to do
	// a full table scan for column stats.

	colInfo, err := ColumnInfo(ctx, db, schema, table)
	if err != nil {
		return nil, err
	}

	// Column statistics
	colStats, err := colStats(ctx, qualifiedTable, colInfo, db)
	if err != nil {
		return nil, err
	}

	return &Statistics{
		RowCount:         count,
		ColumnStatistics: colStats,
	}, nil
}

// rough outline for postgresql extension w/ a full stats function:
//
//  - function: collect_stats(tablename)
//  - iterate over each row, perform computations defined in the extension code
//  - SPI_connect() -> SPI_cursor_open(... query ...) -> SPI_cursor_fetch ->
//    SPI_processed -> SPI_tuptable -> SPI_getbinval

// colStats collects column-wise statistics for the specified table, using the
// provided column definitions to instantiate scan values used by the full scan
// that iterates over all rows of the table.
func colStats(ctx context.Context, qualifiedTable string, colInfo []ColInfo, db sql.Executor) ([]ColumnStatistics, error) {
	// rowCount is unused now, and can seemingly be computed via the scan
	// itself, but I intend to use it in for more complex statistics building algos.

	// https://wiki.postgresql.org/wiki/Retrieve_primary_key_columns
	getIndBase := `SELECT a.attname::text, i.indexrelid::int8
		FROM pg_index i
		JOIN pg_attribute a ON a.attnum = ANY(i.indkey) AND a.attrelid = i.indrelid
		WHERE i.indrelid = '` + qualifiedTable + `'::regclass`
	// use primary key columns first
	getPK := getIndBase + ` AND i.indisprimary;`
	// then unique+not-null index cols?
	// getUniqueInds := getIndBase + ` AND i.indisunique;`
	res, err := db.Execute(ctx, getPK)
	if err != nil {
		return nil, err
	}
	// IMPORTANT NOTE: if the iteration over all rows of the table involves *no*
	// ORDER BY clause, the scan order is not guaranteed. This should be an
	// error for tables where stats must be deterministic.
	//
	// if len(res.Rows) == 0 {
	// 	return nil, errors.New("no suitable orderby column")
	// }
	pkCols := make([]string, len(res.Rows))
	for i, row := range res.Rows {
		pkCols[i] = row[0].(string)
	}

	numCols := len(colInfo)
	colTypes := make([]ColType, numCols)
	for i := range colInfo {
		colTypes[i] = colInfo[i].Type()
	}

	colStats := make([]ColumnStatistics, numCols)

	// iterate over all rows (select *)
	var scans []any
	for _, col := range colInfo {
		scans = append(scans, col.scanVal())
	}
	stmt := `SELECT * FROM ` + qualifiedTable
	if len(pkCols) > 0 {
		stmt += ` ORDER BY ` + strings.Join(pkCols, ",")
	}
	err = QueryRowFunc(ctx, db, stmt, scans,
		func() error {
			var err error
			for i, val := range scans {
				stat := &colStats[i]
				if val == nil { // with QueryRowFuncAny and vals []any, or with QueryRowFunc where scans are native type pointers
					stat.NullCount++
					continue
				}

				// TODO: do something with array types (num elements stats????)

				switch colTypes[i] {
				case ColTypeInt: // use int64 in stats
					var valInt int64
					switch it := val.(type) {
					case interface{ Int64Value() (pgtype.Int8, error) }: // several of the pgtypes int types
						i8, err := it.Int64Value()
						if err != nil {
							return fmt.Errorf("bad int64: %T", val)
						}
						if !i8.Valid {
							stat.NullCount++
							continue
						}
						valInt = i8.Int64

					default:
						var ok bool
						valInt, ok = sql.Int64(val)
						if !ok {
							return fmt.Errorf("not int: %T", val)
						}
					}

					ins(stat, valInt, cmp.Compare[int64])

				case ColTypeText: // use string in stats
					valStr, null, ok := TextValue(val) // val.(string)
					if !ok {
						return fmt.Errorf("not string: %T", val)
					}
					if null {
						stat.NullCount++
						continue
					}

					ins(stat, valStr, strings.Compare)

				case ColTypeByteA: // use []byte in stats
					var valBytea []byte
					switch vt := val.(type) {
					// Presently we're just using []byte, not pgtype.Array, but
					// might need to for NULL...

					// case *pgtype.Array[byte]:
					// 	if !vt.Valid {
					// 		stat.NullCount++
					// 		continue
					// 	}
					// 	valBytea = vt.Elements
					// case pgtype.Array[byte]:
					// 	if !vt.Valid {
					// 		stat.NullCount++
					// 		continue
					// 	}
					// 	valBytea = vt.Elements
					case *[]byte:
						if vt == nil || *vt == nil {
							stat.NullCount++
							continue
						}
						valBytea = slices.Clone(*vt)
					case []byte:
						if vt == nil {
							stat.NullCount++
							continue
						}
						valBytea = slices.Clone(vt)
					default:
						return fmt.Errorf("not bytea: %T", val)
					}

					ins(stat, valBytea, bytes.Compare)

				case ColTypeBool: // use bool in stats
					var b bool
					switch v := val.(type) {
					case *pgtype.Bool:
						if !v.Valid {
							stat.NullCount++
							continue
						}
						b = v.Bool
					case pgtype.Bool:
						if !v.Valid {
							stat.NullCount++
							continue
						}
						b = v.Bool
					case *bool:
						b = *v
					case bool:
						b = v

					default:
						return fmt.Errorf("invalid bool (%T)", val)
					}

					ins(stat, b, cmpBool)

				case ColTypeNumeric: // use *decimal.Decimal in stats
					var dec *types.Decimal
					switch v := val.(type) {
					case *pgtype.Numeric:
						if !v.Valid {
							stat.NullCount++
							continue
						}
						if v.NaN {
							continue
						}

						dec, err = pgNumericToDecimal(*v)
						if err != nil {
							continue
						}

					case pgtype.Numeric:
						if !v.Valid {
							stat.NullCount++
							continue
						}
						if v.NaN {
							continue
						}

						dec, err = pgNumericToDecimal(v)
						if err != nil {
							continue
						}

					case *types.Decimal:
						if v.NaN() { // we're pretending this is NULL by our sql.Scanner's convetion
							stat.NullCount++
							continue
						}
						if v != nil {
							v2 := *v // clone!
							v = &v2
						}
						dec = v
					case types.Decimal:
						if v.NaN() { // we're pretending this is NULL by our sql.Scanner's convetion
							stat.NullCount++
							continue
						}
						v2 := v
						dec = &v2
					}

					ins(stat, dec, cmpDecimal)

				case ColTypeFloat: // we don't want, don't have
					var varFloat float64
					switch v := val.(type) {
					case *pgtype.Float8:
						if !v.Valid {
							stat.NullCount++
							continue
						}
						varFloat = v.Float64
					case *pgtype.Float4:
						if !v.Valid {
							stat.NullCount++
							continue
						}
						varFloat = float64(v.Float32)
					case pgtype.Float8:
						if !v.Valid {
							stat.NullCount++
							continue
						}
						varFloat = v.Float64
					case pgtype.Float4:
						if !v.Valid {
							stat.NullCount++
							continue
						}
						varFloat = float64(v.Float32)
					case float32:
						varFloat = float64(v)
					case float64:
						varFloat = v
					case *float32:
						varFloat = float64(*v)
					case *float64:
						varFloat = *v

					default:
						return fmt.Errorf("invalid float (%T)", val)
					}

					ins(stat, varFloat, cmp.Compare[float64])

				case ColTypeUUID:
					fallthrough // TODO
				default: // arrays and such
					// fmt.Println("unknown", colTypes[i])
				}
			}

			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	return colStats, nil
}

func cmpBool(a, b bool) int {
	if b {
		if a { // true == true
			return 0
		}
		return -1 // false < true
	}
	if a {
		return 1 // true > false
	}
	return 0 // false == false
}

func cmpDecimal(val, mm *types.Decimal) int {
	d, err := val.Cmp(mm)
	if err != nil {
		panic(fmt.Sprintf("%s: (nan decimal?) %v or %v", err, val, mm))
	}
	return d
}

func ins[T any](stats *ColumnStatistics, val T, comp func(v, m T) int) error {
	if stats.Min == nil {
		stats.Min = val
		stats.MinCount = 1
	} else if mn, ok := stats.Min.(T); ok {
		switch comp(val, mn) {
		case -1: // new MINimum
			stats.Min = val
			stats.MinCount = 1
		case 0: // another of the same
			stats.MinCount++
		}
	} else {
		return fmt.Errorf("invalid stats value type %T for tuple of type %T", val, stats.Min)
	}

	if stats.Max == nil {
		stats.Max = val
		stats.MaxCount = 1
	} else if mx, ok := stats.Max.(T); ok {
		switch comp(val, mx) {
		case 1: // new MAXimum
			stats.Max = val
			stats.MaxCount = 1
		case 0: // another of the same
			stats.MaxCount++
		}
	} else {
		return fmt.Errorf("invalid stats value type %T for tuple of type %T", val, stats.Max)
	}

	return nil
}
