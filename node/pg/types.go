package pg

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

func init() {
	registerDatatype(textType, textArrayType)
	registerDatatype(intType, intArrayType)
	registerDatatype(int4Type, int4ArrayType)
	registerDatatype(boolType, boolArrayType)
	registerDatatype(blobType, blobArrayType)
	registerDatatype(uuidType, uuidArrayType)
	registerDatatype(decimalType, decimalArrayType)
}

var (
	dataTypesByMatch   = map[reflect.Type]*datatype{}
	scalarToArray      = map[*datatype]*datatype{} // maps the scalar type to the array type
	datatypes          = map[*datatype]struct{}{}  // a set of all data types (used for iteration)
	kwilTypeToDataType = map[types.DataType]*datatype{}
)

var ErrUnsupportedOID = errors.New("unsupported OID")

const (
	// MinInt4 and MaxInt4 define the bounds of a signed 32-bit integer (PostgreSQL INT4).
	MinInt4 = -2147483648
	MaxInt4 = 2147483647
)

// registerOIDs registers all of the data types that we support in Postgres.
func registerDatatype(scalar *datatype, array *datatype) {
	for _, match := range scalar.Matches {
		_, ok := dataTypesByMatch[match]
		if ok {
			panic(fmt.Sprintf("data type %T already registered", match))
		}

		dataTypesByMatch[match] = scalar
	}

	// Always add scalar to datatypes set, regardless of whether it has Matches
	datatypes[scalar] = struct{}{}

	for _, match := range array.Matches {
		_, ok := dataTypesByMatch[match]
		if ok {
			panic(fmt.Sprintf("data type %T already registered", match))
		}

		dataTypesByMatch[match] = array
	}

	// Always add array to datatypes set, regardless of whether it has Matches
	datatypes[array] = struct{}{}

	_, ok := kwilTypeToDataType[*scalar.KwilType]
	if ok {
		k := kwilTypeToDataType
		_ = k
		panic(fmt.Sprintf("Kwil type %s already registered", scalar.KwilType.String()))
	}

	kwilTypeToDataType[*scalar.KwilType] = scalar

	_, ok = kwilTypeToDataType[*array.KwilType]
	if ok {
		panic(fmt.Sprintf("Kwil type %s already registered", array.KwilType.String()))
	}

	kwilTypeToDataType[*array.KwilType] = array

	scalarToArray[scalar] = array
}

// datatype allows us to easily register new data types.
// It is used to define how to encode and decode data types in Postgres.
// While all of the implementations for this are stored in the PG package,
// the primary reason for identifying this as an interface is to allow for
// easy addition of types in the future (knowing what needs to be implemented
// to support new data types).
type datatype struct {
	// KwilType is the Kwil-native data type that is tied to this data type.
	// There must be exactly one. It will ignore all metadata (e.g. for decimal, any
	// precision/scale is ignore).
	KwilType *types.DataType
	// Matches is the list of all data types that this type matches.
	// These will be stored in a map, and thus each match type can only be
	// used once across all data types.
	Matches []reflect.Type
	// OID returns the OID of the data type in Postgres.
	// It will be given to Postgres when encoding the data type
	// with QueryModeInferredArgTypes, and will also be used to identify
	// how values should be decoded.
	OID func(*pgtype.Map) uint32
	// ExtraOIDs returns any additional OIDs which the data type can be decoded from.
	// This is useful for int types, which can be decoded from int2, int4, and int8.
	// These will be used in addition to the OID returned by OID().
	// This can be nil if there are no additional OIDs.
	ExtraOIDs []uint32
	// EncodeInferred encodes a value into a byte slice, given the type of the value.
	// The passed value will always be of a type that matches one of the Matches types.
	// It must return the serialized data.
	// This is used when operating in QueryModeInferredArgTypes, to infer the postgres
	// data type from the native go type.
	// If not using QueryModeInferredArgTypes, it will be encoded using a driver.Valuer,
	// or as a native go type.
	EncodeInferred func(any) (any, error)
	// Decode decodes a data type received from Postgres. The input will either be a data type
	// native to Go, a type defined in pgx, or a type in a custom pgx Codec (which we currently
	// don't use). Decode should never be called with null values, but it may be called with
	// empty strings / 0 values.
	Decode func(any) (any, error)
	// SerializeChangeset decodes a data type received from Postgres as a string. PGX only returns
	// replication data as strings, so this is used to decode replication data.
	// https://github.com/jackc/pglogrepl/blob/828fbfe908e97cfeb409a17e4ec339dede1f1a17/message.go#L379
	// Every implementation must be able to handle a string "NULL".
	SerializeChangeset func(value string) ([]byte, error)
	// DeserializeChangeset encodes a data type from a changeset to its native
	// Go/Kwil type. This can then be used to execute an incoming changeset
	// against a database. This does NOT match SerializeChangeset, which starts
	// from a postgres string representation of a "tuple column", while this
	// returns a Go type that is provided as an argument to a SQL Execute() call.
	DeserializeChangeset func([]byte) (any, error)
}

var ErrNaN = errors.New("NaN")

func pgNumericToDecimal(num pgtype.Numeric) (*types.Decimal, error) {
	if num.NaN { // TODO: create a decimal.Decimal that supports NaN
		return nil, ErrNaN
	}
	if !num.Valid {
		return nil, errors.New("invalid or null") // TODO: create a decimal.Decimal that supports NULL
	}

	i, e := num.Int, num.Exp

	// Kwil's decimal semantics do not allow negative scale (only shift decimal
	// left), so if the exponent is positive we need to apply it to the integer.
	if e > 0 {
		// i * 10^e
		z := new(big.Int)
		z.Exp(big.NewInt(10), big.NewInt(int64(e)), nil)
		z.Mul(z, i)
		i, e = z, 0
	}

	// Really this could be uint256, which is same underlying type (a domain) as
	// Numeric. If the caller needs to know, that has to happen differently.
	return types.NewDecimalFromBigInt(i, e)
}

// pgStringArraySplit splits a pg array of strings that may have escape sequences.
// The curlys must already be removed.
func pgStringArraySplit(s string) []string {
	var tokens []string
	var token strings.Builder
	var inQuotes, escape bool

	for _, r := range s {
		switch {
		// If the previous character was a backslash, append the current rune.
		case escape:
			token.WriteRune(r)
			escape = false
		// Mark the next character as escaped.
		case r == '\\':
			escape = true
		// Toggle the inQuotes flag and do not add the quote itself.
		case r == '"':
			inQuotes = !inQuotes
		// If we hit a comma outside quotes, end the current token.
		case r == ',' && !inQuotes:
			tokens = append(tokens, token.String())
			token.Reset()
		// Otherwise, add the current rune to the token.
		default:
			token.WriteRune(r)
		}
	}

	// If the string ends with a trailing backslash, add it literally.
	if escape {
		token.WriteRune('\\')
	}

	// Append the final token.
	tokens = append(tokens, token.String())
	return tokens
}

var (
	textType = &datatype{
		KwilType:       types.TextType,
		Matches:        []reflect.Type{reflect.TypeFor[string]()},
		OID:            func(*pgtype.Map) uint32 { return pgtype.TextOID },
		ExtraOIDs:      []uint32{pgtype.VarcharOID},
		EncodeInferred: defaultEncodeDecode,
		Decode:         defaultEncodeDecode,
		SerializeChangeset: func(value string) ([]byte, error) {
			if value == `NULL` {
				return nil, nil
			}
			// DeserializeChangeset will pass through any non-nil []byte as a
			// string, the resulting variable going on to be inserted via an
			// Execute arg. In this flow, a nil any var is a NULL value, while
			// any other string is a non-NULL value. If we do not strip the
			// quotes from around a string containing "NULL", a non-NULL string
			// that is two bytes longer than the original will be inserted.
			if value == `"NULL"` {
				value = `NULL` // never change, postgres
			}
			return []byte(value), nil
		},
		DeserializeChangeset: func(b []byte) (any, error) {
			// Only nil represents a NULL value. An empty slice is an empty string.
			if b == nil {
				return nil, nil
			}
			return string(b), nil
		},
	}

	textArrayType = &datatype{
		KwilType:       types.TextArrayType,
		Matches:        []reflect.Type{reflect.TypeFor[[]string](), reflect.TypeFor[[]*string]()},
		OID:            func(*pgtype.Map) uint32 { return pgtype.TextArrayOID },
		EncodeInferred: defaultEncodeDecode,
		Decode:         decodePtrArray[string](textType.Decode),
		SerializeChangeset: func(value string) ([]byte, error) {
			// text arrays are delimited by commas, so we need to split on commas.
			// We also need to ensure that the commas
			var ok bool
			value, ok = trimCurlys(value)
			if !ok {
				return nil, fmt.Errorf("invalid text array: %s", value)
			}

			strs := pgStringArraySplit(value)

			return serializeArray(strs, 4, textType.SerializeChangeset)
		},
		DeserializeChangeset: deserializeArrayFn[string](4, textType.DeserializeChangeset),
	}

	// we intentionally ignore uint8, since we don't want to cause issues with []byte.
	// BACKWARD COMPATIBILITY: int32 and uint32 still handled by intType for now
	// TODO: Migrate to int4Type in a future version with proper migration strategy
	intType = &datatype{
		KwilType: types.IntType,
		Matches: []reflect.Type{reflect.TypeOf(int(0)), reflect.TypeOf(int8(0)), reflect.TypeOf(int16(0)),
			reflect.TypeOf(int32(0)), reflect.TypeOf(int64(0)), reflect.TypeOf(uint(0)), reflect.TypeOf(uint16(0)),
			reflect.TypeOf(uint32(0)), reflect.TypeOf(uint64(0))},
		OID:            func(*pgtype.Map) uint32 { return pgtype.Int8OID },
		ExtraOIDs:      []uint32{pgtype.Int2OID},
		EncodeInferred: defaultEncodeDecode,
		Decode: func(a any) (any, error) {
			v, ok := sql.Int64(a)
			if !ok {
				return nil, fmt.Errorf("unexpected type %T", a)
			}
			return v, nil
		},
		SerializeChangeset: func(value string) ([]byte, error) {
			if value == `NULL` {
				return nil, nil
			}
			intVal, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, err
			}

			buf := make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, uint64(intVal))
			return buf, nil
		},
		DeserializeChangeset: func(b []byte) (any, error) {
			if len(b) == 0 {
				return nil, nil
			}
			if len(b) != 8 {
				return nil, fmt.Errorf("invalid int64: %s", b)
			}
			return int64(binary.LittleEndian.Uint64(b)), nil
		},
	}

	intArrayType = &datatype{
		KwilType: types.IntArrayType,
		Matches: []reflect.Type{reflect.TypeOf([]int{}), reflect.TypeOf([]int8{}), reflect.TypeOf([]int16{}),
			reflect.TypeOf([]int32{}), reflect.TypeOf([]int64{}), reflect.TypeOf([]uint{}), reflect.TypeOf([]uint16{}),
			reflect.TypeOf([]uint32{}), reflect.TypeOf([]uint64{}), reflect.TypeOf([]*int{}), reflect.TypeOf([]*int8{}),
			reflect.TypeOf([]*int16{}), reflect.TypeOf([]*int32{}), reflect.TypeOf([]*int64{}), reflect.TypeOf([]*uint{}),
			reflect.TypeOf([]*uint16{}), reflect.TypeOf([]*uint32{}), reflect.TypeOf([]*uint64{})},
		OID:                  func(*pgtype.Map) uint32 { return pgtype.Int8ArrayOID },
		ExtraOIDs:            []uint32{pgtype.Int2ArrayOID},
		EncodeInferred:       defaultEncodeDecode,
		Decode:               decodePtrArray[int64](intType.Decode),
		SerializeChangeset:   arrayFromChildFunc(1, intType.SerializeChangeset),
		DeserializeChangeset: deserializeArrayFn[int64](1, intType.DeserializeChangeset),
	}

	// INT4 type - currently only for explicit int4 schema definitions
	// BACKWARD COMPATIBILITY: Does not handle int32/uint32 Go types yet
	// Those continue to be handled by intType for now
	int4Type = &datatype{
		KwilType:       types.Int4Type,
		Matches:        []reflect.Type{}, // No Go type matches for now - only for schema definitions
		OID:            func(*pgtype.Map) uint32 { return pgtype.Int4OID },
		EncodeInferred: defaultEncodeDecode,
		Decode: func(a any) (any, error) {
			v, ok := sql.Int64(a)
			if !ok {
				return nil, fmt.Errorf("unexpected type %T", a)
			}
			// Validate INT4 range
			if v < MinInt4 || v > MaxInt4 {
				return nil, fmt.Errorf("value %d out of range for INT4 (%d to %d)", v, MinInt4, MaxInt4)
			}
			return int32(v), nil
		},
		SerializeChangeset: func(value string) ([]byte, error) {
			if value == `NULL` {
				return nil, nil
			}
			intVal, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, err
			}
			// Validate INT4 range
			if intVal < MinInt4 || intVal > MaxInt4 {
				return nil, fmt.Errorf("value %d out of range for INT4 (%d to %d)", intVal, MinInt4, MaxInt4)
			}

			buf := make([]byte, 4)
			// Narrow to int32 explicitly before converting to uint32 for two's complement representation.
			binary.LittleEndian.PutUint32(buf, uint32(int32(intVal)))
			return buf, nil
		},
		DeserializeChangeset: func(b []byte) (any, error) {
			if len(b) == 0 {
				return nil, nil
			}
			if len(b) != 4 {
				return nil, fmt.Errorf("invalid int32 length: %d", len(b))
			}
			return int32(binary.LittleEndian.Uint32(b)), nil
		},
	}

	int4ArrayType = &datatype{
		KwilType:             types.Int4ArrayType,
		Matches:              []reflect.Type{}, // No Go type matches for now - only for schema definitions
		OID:                  func(*pgtype.Map) uint32 { return pgtype.Int4ArrayOID },
		EncodeInferred:       defaultEncodeDecode,
		Decode:               decodePtrArray[int32](int4Type.Decode),
		SerializeChangeset:   arrayFromChildFunc(1, int4Type.SerializeChangeset),
		DeserializeChangeset: deserializeArrayFn[int32](1, int4Type.DeserializeChangeset),
	}

	boolType = &datatype{
		KwilType:       types.BoolType,
		Matches:        []reflect.Type{reflect.TypeOf(true)},
		OID:            func(*pgtype.Map) uint32 { return pgtype.BoolOID },
		EncodeInferred: defaultEncodeDecode,
		Decode:         defaultEncodeDecode,
		SerializeChangeset: func(value string) ([]byte, error) {
			if value == `NULL` {
				return nil, nil
			}
			if strings.EqualFold(value, "true") || strings.EqualFold(value, "t") {
				return []byte{1}, nil
			}
			if strings.EqualFold(value, "false") || strings.EqualFold(value, "f") {
				return []byte{0}, nil
			}
			return nil, fmt.Errorf("invalid boolean value: %s", value)
		},
		DeserializeChangeset: func(b []byte) (any, error) {
			if len(b) == 0 {
				return nil, nil
			}
			return b[0] == 1, nil
		},
	}

	boolArrayType = &datatype{
		KwilType:             types.BoolArrayType,
		Matches:              []reflect.Type{reflect.TypeOf([]bool{}), reflect.TypeOf([]*bool{})},
		OID:                  func(*pgtype.Map) uint32 { return pgtype.BoolArrayOID },
		EncodeInferred:       defaultEncodeDecode,
		Decode:               decodePtrArray[bool](boolType.Decode),
		SerializeChangeset:   arrayFromChildFunc(1, boolType.SerializeChangeset),
		DeserializeChangeset: deserializeArrayFn[bool](1, boolType.DeserializeChangeset),
	}

	blobType = &datatype{
		KwilType:       types.ByteaType,
		Matches:        []reflect.Type{reflect.TypeOf([]byte{})},
		OID:            func(*pgtype.Map) uint32 { return pgtype.ByteaOID },
		EncodeInferred: defaultEncodeDecode,
		Decode:         defaultEncodeDecode,
		SerializeChangeset: func(value string) ([]byte, error) {
			if value == `NULL` {
				return nil, nil
			}
			// postgres returns all blobs as hex, prefixed with \x
			// we need to remove the \x and decode the hex
			if len(value) < 2 {
				return nil, fmt.Errorf("invalid blob value: %s", value)
			}

			if value[0] != '\\' || value[1] != 'x' {
				return nil, fmt.Errorf("invalid blob value: %s", value)
			}

			return hex.DecodeString(value[2:])
		},
		DeserializeChangeset: func(b []byte) (any, error) {
			if b == nil {
				return nil, nil
			}
			return b, nil
		},
	}

	blobArrayType = &datatype{
		KwilType:       types.ByteaArrayType,
		Matches:        []reflect.Type{reflect.TypeFor[[][]byte]()},
		OID:            func(*pgtype.Map) uint32 { return pgtype.ByteaArrayOID },
		EncodeInferred: defaultEncodeDecode,
		Decode:         decodeValueArray[[]byte](blobType.Decode),
		SerializeChangeset: func(value string) ([]byte, error) {
			// postgres wraps each hex encoded blob in double quotes, so we need to remove them
			var ok bool
			value, ok = trimCurlys(value)
			if !ok {
				return nil, fmt.Errorf("invalid blob array 1: %s", value)
			}

			// each blob is now wrapped in double quotes in the text literal, except for NULL
			vals := strings.Split(value, ",")

			bts := make([][]byte, len(vals))
			for i, v := range vals {
				// this has null handling up here instead of in the blobType.SerializeChangeset
				if v == `NULL` {
					continue
				}
				if !strings.HasPrefix(v, `"`) || !strings.HasSuffix(v, `"`) {
					return nil, fmt.Errorf("invalid blob array 2: %s => %v", value, v)
				}

				vals[i] = v[1 : len(v)-1]

				// for some reason, postgres adds an additional escape character to the hex in an array
				// that is not present in a single value. We need to remove it.
				// This irregularity is tested in db_live_test.go
				if len(vals[i]) == 0 {
					return nil, fmt.Errorf("invalid blob array, expected some value: %s", value)
				}

				if vals[i][0] != '\\' {
					return nil, fmt.Errorf("invalid blob array, expected \\: %s", value)
				}

				// decode the hex
				b, err := blobType.SerializeChangeset(vals[i][1:])
				if err != nil {
					return nil, err
				}

				bts[i] = b
			}

			return serializeArray(bts, 4, func(b []byte) ([]byte, error) {
				return b, nil
			})
		},
		DeserializeChangeset: deserializeArrayFn[[]byte](4, blobType.DeserializeChangeset),
	}

	uuidType = &datatype{
		KwilType: types.UUIDType,
		Matches:  []reflect.Type{reflect.TypeFor[types.UUID](), reflect.TypeFor[*types.UUID]()},
		OID:      func(*pgtype.Map) uint32 { return pgtype.UUIDOID },
		EncodeInferred: func(v any) (any, error) {
			var val *types.UUID
			switch v := v.(type) {
			case types.UUID:
				val = &v
			case *types.UUID:
				val = v
			case nil:
				return pgtype.UUID{
					Valid: false,
				}, nil
			default:
				return nil, fmt.Errorf("unexpected type encoding uuid %T", v)
			}
			if val == nil {
				return pgtype.UUID{
					Valid: false,
				}, nil
			}

			return pgtype.UUID{
				Bytes: [16]byte(val.Bytes()),
				Valid: true,
			}, nil
		},
		Decode: func(v any) (any, error) {
			var u types.UUID
			switch v := v.(type) {
			case pgtype.UUID:
				if !v.Valid { // also shouldn't ever happen with current uuid-ossp
					return nil, nil
				}
				u = types.UUID(v.Bytes)
			case [16]byte:
				u = types.UUID(v)
			case nil: // this won't happen unless uuid-ossp starts supporting NULL
				return nil, nil
			default:
				return nil, fmt.Errorf("unexpected type decoding uuid %T", v)
			}
			return &u, nil
		},
		SerializeChangeset: func(value string) ([]byte, error) {
			if value == `NULL` {
				return nil, nil
			}
			u, err := types.ParseUUID(value)
			if err != nil {
				return nil, err
			}
			return u.Bytes(), nil
		},
		DeserializeChangeset: func(b []byte) (any, error) {
			if len(b) == 0 {
				return nil, nil
			}
			if len(b) != len(types.UUID{}) {
				return nil, fmt.Errorf("invalid uuid length: %d", len(b))
			}
			u := types.UUID(b)
			return &u, nil
		},
	}

	uuidArrayType = &datatype{
		KwilType: types.UUIDArrayType,
		Matches:  []reflect.Type{reflect.TypeOf(types.UUIDArray{}), reflect.TypeOf([]*types.UUID{})},
		OID:      func(*pgtype.Map) uint32 { return pgtype.UUIDArrayOID },
		EncodeInferred: func(v any) (any, error) {
			var val types.UUIDArray
			switch v := v.(type) {
			case types.UUIDArray:
				val = v
			case []*types.UUID:
				val = types.UUIDArray(v)
			default:
				return nil, fmt.Errorf("expected UUIDArray, got %T", v)
			}

			var arr []any
			for _, u := range val {
				v2, err := uuidType.EncodeInferred(u)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v2)
			}

			return arr, nil
		},
		Decode: func(a any) (any, error) {
			arr, ok := a.([]any) // pgx always returns arrays as []any
			if !ok {
				return nil, fmt.Errorf("expected []any, got %T", a)
			}

			vals := make(types.UUIDArray, len(arr))
			for i, v := range arr {
				if v == nil {
					continue // leave nil, but uuid-ossp doesn't support NULL
				}
				val, err := uuidType.Decode(v)
				if err != nil {
					return nil, err
				}
				if val == nil {
					continue // leave nil
				}
				vals[i] = val.(*types.UUID)
			}

			return vals, nil
		},
		SerializeChangeset:   arrayFromChildFunc(1, uuidType.SerializeChangeset),
		DeserializeChangeset: deserializeArrayFn[types.UUID](1, uuidType.DeserializeChangeset),
	}

	decimalType = &datatype{
		KwilType: types.NumericType,
		Matches:  []reflect.Type{reflect.TypeFor[types.Decimal](), reflect.TypeFor[*types.Decimal]()},
		OID:      func(*pgtype.Map) uint32 { return pgtype.NumericOID },
		EncodeInferred: func(v any) (any, error) {
			var dec *types.Decimal
			switch v := v.(type) {
			case types.Decimal:
				dec = &v
			case *types.Decimal:
				dec = v
			case nil:
				return pgtype.Numeric{
					Valid: false,
				}, nil
			default:
				return nil, fmt.Errorf("unexpected type encoding decimal %T", v)
			}

			if dec == nil {
				return pgtype.Numeric{
					Valid: false,
				}, nil
			}

			return pgtype.Numeric{
				Int:   dec.BigInt(),
				Exp:   dec.Exp(),
				Valid: true,
			}, nil
		},
		Decode: func(a any) (any, error) {
			pgType, ok := a.(pgtype.Numeric)
			if !ok {
				return nil, fmt.Errorf("expected pgtype.Numeric, got %T", a)
			}

			return pgNumericToDecimal(pgType)
		},
		SerializeChangeset: func(value string) ([]byte, error) {
			if value == `NULL` {
				return nil, nil
			}
			// parse to ensure it is a valid decimal, then re-encode it to ensure it is in the correct format.
			dec, err := types.ParseDecimal(value)
			if err != nil {
				return nil, err
			}

			return []byte(dec.String()), nil
		},
		DeserializeChangeset: func(b []byte) (any, error) {
			if len(b) == 0 {
				return nil, nil
			}
			return types.ParseDecimal(string(b))
		},
	}

	decimalArrayType = &datatype{
		KwilType: types.NumericArrayType,
		Matches:  []reflect.Type{reflect.TypeOf(types.DecimalArray{}), reflect.TypeOf([]*types.Decimal{})},
		OID:      func(*pgtype.Map) uint32 { return pgtype.NumericArrayOID },
		EncodeInferred: func(v any) (any, error) {
			var val types.DecimalArray
			switch vt := v.(type) {
			case types.DecimalArray:
				val = vt
			case []*types.Decimal:
				val = vt
			default:
				return nil, fmt.Errorf("unexpected type encoding decimal array %T", v)
			}
			var arr []pgtype.Numeric
			for _, d := range val {
				v2, err := decimalType.EncodeInferred(d)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v2.(pgtype.Numeric))
			}

			return arr, nil
		},
		Decode: func(a any) (any, error) {
			arr, ok := a.([]any) // pgx always returns arrays as []any
			if !ok {
				return nil, fmt.Errorf("expected []any, got %T", a)
			}

			vals := make(types.DecimalArray, len(arr))
			for i, v := range arr {
				if v == nil {
					continue // leave nil
				}
				val, err := decimalType.Decode(v)
				if err != nil {
					return nil, err
				}
				vals[i] = val.(*types.Decimal)
			}

			return vals, nil
		},
		SerializeChangeset:   arrayFromChildFunc(2, decimalType.SerializeChangeset),
		DeserializeChangeset: deserializeArrayFn[types.Decimal](2, decimalType.DeserializeChangeset),
	}
)

// defaultEncodeDecode is the default Encode and Decode function for data types.
// It simply returns the value as is, without any modifications.
func defaultEncodeDecode(v any) (any, error) { return v, nil }

// decodePtrArray creates a function that decodes an array of a given type. it
// takes a generic for the target scalar type, as well as a decode function for
// the scalar type. The first return of the returned function is a []*T, which
// allows to represent NULL values.
func decodePtrArray[T any](decode func(any) (any, error)) func(any) (any, error) {
	return func(a any) (any, error) {
		arr, ok := a.([]any) // pgx always returns arrays as []any
		if !ok {
			return nil, fmt.Errorf("expected []any, got %T", a)
		}

		vals := make([]*T, len(arr))
		for i, v := range arr {
			if v == nil {
				continue // leaving it as nil
			}
			val, err := decode(v)
			if err != nil {
				return nil, err
			}

			if val == nil {
				continue // leaving it as nil
			}

			switch vt := val.(type) {
			case *T:
				vals[i] = vt
			case T:
				vals[i] = &vt
			}
		}

		return vals, nil
	}
}
func decodeValueArray[T any](decode func(any) (any, error)) func(any) (any, error) {
	return func(a any) (any, error) {
		arr, ok := a.([]any) // pgx always returns arrays as []any
		if !ok {
			return nil, fmt.Errorf("expected []any, got %T", a)
		}

		vals := make([]T, len(arr))
		for i, v := range arr {
			val, err := decode(v)
			if err != nil {
				return nil, err
			}

			if val == nil {
				continue // leaving it as the zero value
			}

			vals[i] = val.(T)
		}

		return vals, nil
	}
}

// encodeToPGType encodes several Go types to their corresponding pgx types.
// It is capable of detecting special Kwil types and encoding them to their
// corresponding pgx types. It is only used if using inferred argument types.
// If not using inferred argument types, pgx will rely on the Valuer interface
// to encode the Go types to their corresponding pgx types.
// It also returns the pgx type OIDs for each value.
func encodeToPGType(oids *pgtype.Map, values ...any) ([]any, []uint32, error) {
	if len(values) == 0 {
		return nil, nil, nil
	}

	encoded := make([]any, len(values))
	oidsArr := make([]uint32, len(values))
	for i, v := range values {
		if v == nil {
			encoded[i] = nil
			oidsArr[i] = pgtype.TextOID
			continue
		}

		// special case, if []any, we need to encode each element
		if arr, ok := v.([]any); ok {
			if len(arr) == 0 {
				encoded[i] = nil
				oidsArr[i] = pgtype.TextOID
				continue
			}

			encodedArr, oidsArrArr, err := encodeToPGType(oids, arr...)
			if err != nil {
				return nil, nil, err
			}

			encoded[i] = encodedArr

			// check that all OIDs are the same
			oid := oidsArrArr[0]
			for _, oid2 := range oidsArrArr {
				if oid != oid2 {
					return nil, nil, errors.New("all elements in an array must have the same data type")
				}
			}

			dt, ok := dataTypesByMatch[reflect.TypeOf(arr[0])]
			if !ok {
				return nil, nil, fmt.Errorf("unsupported type %T", arr[0])
			}

			arrDt, ok := scalarToArray[dt]
			if !ok {
				return nil, nil, fmt.Errorf("no array type for %T", arr[0])
			}

			oidsArr[i] = arrDt.OID(oids)

			continue
		}

		dt, ok := dataTypesByMatch[reflect.TypeOf(v)]
		if !ok {
			return nil, nil, fmt.Errorf("unsupported type %T", v)
		}

		encodedVal, err := dt.EncodeInferred(v)
		if err != nil {
			return nil, nil, err
		}

		encoded[i] = encodedVal
		oidsArr[i] = dt.OID(oids)
	}

	return encoded, oidsArr, nil
}

// for functions that return void, it will actually return
// a nil value with the void OID.
var voidOID = uint32(2278)

func decodeFromPGVal(val any, oid uint32, oidToDataType map[uint32]*datatype) (any, error) {
	if val == nil {
		return nil, nil
	}

	dt, ok := oidToDataType[oid]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedOID, oid)
	}

	return dt.Decode(val)
}

// DecodeFromPG decodes several pgx types to their corresponding Go types.
// It is capable of detecting special Kwil types and decoding them to their
// corresponding Go types. This is used when scanning blindly (into any or
// using row.Values()) when pgx uses whatever pgtype types it prefers.
func DecodeFromPG(vals []any, oids []uint32, oidToDataType map[uint32]*datatype) ([]any, error) {
	var results []any
	for i, oid := range oids {
		if oid == voidOID {
			continue
		}

		decoded, err := decodeFromPGVal(vals[i], oid, oidToDataType)
		if err != nil {
			return nil, err
		}

		results = append(results, decoded)
	}

	return results, nil
}

// OidTypesMap makes a map mapping oids to the Kwil type definition.
// It needs to be called after registerTypes.
func OidTypesMap(conn *pgtype.Map) map[uint32]*datatype {
	m := make(map[uint32]*datatype)
	for dt := range datatypes {
		oid := dt.OID(conn)
		_, ok := m[oid]
		if ok {
			panic("duplicate oid for type. OID:" + strconv.FormatUint(uint64(oid), 10))
		}
		m[oid] = dt

		for _, extraOID := range dt.ExtraOIDs {
			_, ok := m[extraOID]
			if ok {
				panic("duplicate oid for type. OID:" + strconv.FormatUint(uint64(extraOID), 10))
			}
			m[extraOID] = dt
		}
	}
	return m
}

// trimCurlys parses curly brackets on the outside of a string.
// It returns the string without the curly brackets, and a boolean
// indicating whether the string had curly brackets. It is useful
// for parsing stringified Postgres arrays.
func trimCurlys(s string) (string, bool) {
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		return s[1 : len(s)-1], true
	}

	return s, false
}

// serializeArray serializes an array of some type to []byte.
// It takes a function that serializes the scalar values to []byte.
// lengthSize is the byte size of the length of each element, which allows
// us to more efficiently serialize arrays of fixed-size elements (int, bool, etc).
// lengthSize must be 1, 2, or 4, corresponding to 8-bit, 16-bit, and 32-bit lengths.
func serializeArray[T any](arr []T, lengthSize uint8, serialize func(T) ([]byte, error)) ([]byte, error) {
	encodeLength := func(length int) []byte {
		switch lengthSize {
		case 1:
			return []byte{byte(length)}
		case 2:
			buf := make([]byte, 2)
			binary.BigEndian.PutUint16(buf, uint16(length))
			return buf
		case 4:
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, uint32(length))
			return buf
		default:
			panic("invalid length size")
		}
	}

	var buf []byte
	for _, v := range arr {
		encoded, err := serialize(v)
		if err != nil {
			return nil, err
		}
		if encoded == nil {
			buf = append(buf, 0x00) // signals NULL
			continue
		}

		// 1 byte for the NULL flag
		buf = append(buf, 0x01) // remember: deserialize funcs must match
		buf = append(buf, encodeLength(len(encoded))...)
		buf = append(buf, encoded...)
	}

	return buf, nil
}

// deserializeArray deserializes an array of some type from []byte.
// It takes a function that deserializes the scalar values from []byte.
// it is the inverse of serializeArray. lengthSize must be 1, 2, or 4,
// corresponding to 8-bit, 16-bit, and 32-bit lengths.
func deserializePtrArray[T any](buf []byte, lengthSize uint8, deserialize func([]byte) (any, error)) ([]*T, error) {
	// the lengthSize thing might be a bit overkill, but it is very encapsulated so
	// I'll keep it for now, since it can help decrease the size of the changeset that
	// a network has to process.
	determineLength := func(buf []byte) (int, []byte) {
		switch lengthSize {
		case 1:
			return int(buf[0]), buf[1:]
		case 2:
			return int(binary.BigEndian.Uint16(buf[:2])), buf[2:]
		case 4:
			return int(binary.BigEndian.Uint32(buf[:4])), buf[4:]
		default:
			panic("invalid length size")
		}
	}

	var arr []*T
	for len(buf) > 0 {
		// read the NULL flag
		var flag byte
		flag, buf = buf[0], buf[1:]
		if flag == 0 {
			arr = append(arr, nil)
			continue
		}

		if len(buf) < int(lengthSize) {
			return nil, errors.New("invalid array: not enough bytes for length")
		}

		length, rest := determineLength(buf)

		if len(rest) < length {
			return nil, errors.New("invalid array: element length exceeds buffer")
		}

		v, err := deserialize(rest[:length])
		if err != nil {
			return nil, err
		}

		// Support deserialize returning either value or pointer to T.
		switch vt := v.(type) {
		case T:
			arr = append(arr, &vt)
		case *T:
			arr = append(arr, vt)
		case nil: // untyped nil
			arr = append(arr, nil)
			// NOTE: if used with serializeArray and a well behaved serialize
			// function provided to it, which should return a nil interface{}
			// rather than a typed nil, we would have hit a null flag above.
		default:
			return nil, fmt.Errorf("invalid type %T", v)
		}

		buf = rest[length:]
	}

	return arr, nil
}

// arrayFromChildFunc splits a stringified array into its elements, and uses
// the callback function to serialize each element. It is meant to be used with
// array data types that do not have special parsing rules. It returns it as a function
// that can be used for decoding changesets
func arrayFromChildFunc(size uint8, serialize func(string) ([]byte, error)) func(string) ([]byte, error) {
	return func(s string) ([]byte, error) {
		s, ok := trimCurlys(s)
		if !ok {
			return nil, fmt.Errorf("invalid array: %s", s)
		}

		strs := strings.Split(s, ",")
		return serializeArray(strs, size, serialize)
	}
}

// deserializeArrayFn returns a function that deserializes an array of some type
// from a serialized array. It is the logical inverse of arrayFromChildFunc. The
// any return from the returned function will be a []*T (slice of pointers to T).
// See deserializePtrArray. This is required to support a NULL value within the array.
func deserializeArrayFn[T any](size uint8, deserialize func([]byte) (any, error)) func([]byte) (any, error) {
	return func(b []byte) (any, error) {
		return deserializePtrArray[T](b, size, deserialize)
	}
}
