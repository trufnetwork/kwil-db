package interpreter

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kwilteam/kwil-db/core/types"
	"github.com/kwilteam/kwil-db/node/engine"
)

// valueMapping maps Go types and Kwil native types.
type valueMapping struct {
	// KwilType is the Kwil type that the value maps to.
	// It will ignore the metadata of the type.
	KwilType *types.DataType
	// ZeroValue creates a zero-value of the type.
	ZeroValue func(t *types.DataType) (value, error)
	// NullValue creates a null-value of the type.
	NullValue func(t *types.DataType) (value, error)
}

var (
	kwilTypeToValue = map[struct {
		name    string
		isArray bool
	}]valueMapping{}
)

func registerValueMapping(ms ...valueMapping) {
	for _, m := range ms {
		k := struct {
			name    string
			isArray bool
		}{
			name:    m.KwilType.Name,
			isArray: m.KwilType.IsArray,
		}

		_, ok := kwilTypeToValue[k]
		if ok {
			panic(fmt.Sprintf("type %s already registered", m.KwilType.Name))
		}

		kwilTypeToValue[k] = m
	}
}

func init() {
	registerValueMapping(
		valueMapping{
			KwilType: types.IntType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return makeInt8(0), nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &int8Value{
					Int8: pgtype.Int8{
						Valid: false,
					},
				}, nil
			},
		},
		valueMapping{
			KwilType: types.TextType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return makeText(""), nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &textValue{
					Text: pgtype.Text{
						Valid: false,
					},
				}, nil
			},
		},
		valueMapping{
			KwilType: types.BoolType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return makeBool(false), nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &boolValue{
					Bool: pgtype.Bool{
						Valid: false,
					},
				}, nil
			},
		},
		valueMapping{
			KwilType: types.ByteaType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return makeBlob([]byte{}), nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &blobValue{}, nil
			},
		},
		valueMapping{
			KwilType: types.UUIDType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return makeUUID(&types.UUID{}), nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &uuidValue{
					UUID: pgtype.UUID{
						Valid: false,
					},
				}, nil
			},
		},
		valueMapping{
			KwilType: types.NumericType,
			ZeroValue: func(t *types.DataType) (value, error) {
				if !t.HasMetadata() {
					return nil, fmt.Errorf("cannot create zero value of decimal type with zero precision and scale")
				}

				dec, err := types.ParseDecimal("0")
				if err != nil {
					return nil, err
				}
				dec2 := makeDecimal(dec)

				prec := t.Metadata[0]
				scale := t.Metadata[1]
				dec2.metadata = &precAndScale{prec, scale}

				return dec2, nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				if !t.HasMetadata() {
					return nil, fmt.Errorf("cannot create null value of decimal type with zero precision and scale")
				}
				prec := t.Metadata[0]
				scale := t.Metadata[1]
				d := makeDecimal(nil)
				d.metadata = &precAndScale{prec, scale}
				return d, nil
			},
		},
		valueMapping{
			KwilType: types.IntArrayType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return &int8ArrayValue{
					singleDimArray: newValidArr([]pgtype.Int8{}),
				}, nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &int8ArrayValue{
					singleDimArray: newNullArray[pgtype.Int8](),
				}, nil
			},
		},
		valueMapping{
			KwilType: types.TextArrayType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return &textArrayValue{
					singleDimArray: newValidArr([]pgtype.Text{}),
				}, nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &textArrayValue{
					singleDimArray: newNullArray[pgtype.Text](),
				}, nil
			},
		},
		valueMapping{
			KwilType: types.BoolArrayType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return &boolArrayValue{
					singleDimArray: newValidArr([]pgtype.Bool{}),
				}, nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &boolArrayValue{
					singleDimArray: newNullArray[pgtype.Bool](),
				}, nil
			},
		},
		valueMapping{
			KwilType: types.ByteaArrayType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return &blobArrayValue{
					singleDimArray: newValidArr([]blobValue{}),
				}, nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &blobArrayValue{
					singleDimArray: newNullArray[blobValue](),
				}, nil
			},
		},
		valueMapping{
			KwilType: types.NumericArrayType,
			ZeroValue: func(t *types.DataType) (value, error) {
				prec := t.Metadata[0]
				scale := t.Metadata[1]

				arr := &decimalArrayValue{
					singleDimArray: newValidArr([]pgtype.Numeric{}),
					metadata:       &precAndScale{prec, scale},
				}
				return arr, nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				prec := t.Metadata[0]
				scale := t.Metadata[1]

				arr := newNullDecArr(types.NumericArrayType)
				arr.metadata = &precAndScale{prec, scale}
				return arr, nil
			},
		},
		valueMapping{
			KwilType: types.UUIDArrayType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return &uuidArrayValue{
					singleDimArray: newValidArr([]pgtype.UUID{}),
				}, nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &uuidArrayValue{
					singleDimArray: newNullArray[pgtype.UUID](),
				}, nil
			},
		},
		valueMapping{
			KwilType: types.NullType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return nil, fmt.Errorf("cannot create zero value of null type")
			},
			NullValue: func(t *types.DataType) (value, error) {
				return &nullValue{}, nil
			},
		},
		valueMapping{
			KwilType: types.NullArrayType,
			ZeroValue: func(t *types.DataType) (value, error) {
				return &arrayOfNulls{}, nil
			},
			NullValue: func(t *types.DataType) (value, error) {
				return nil, fmt.Errorf("cannot create null value of null array type")
			},
		},
	)
}

// newZeroValue creates a new zero value of the given type.
func newZeroValue(t *types.DataType) (value, error) {
	m, ok := kwilTypeToValue[struct {
		name    string
		isArray bool
	}{
		name:    t.Name,
		isArray: t.IsArray,
	}]
	if !ok {
		return nil, fmt.Errorf("type %s not found", t.String())
	}

	return m.ZeroValue(t)
}

// value is a value that can be compared, used in arithmetic operations,
// and have unary operations applied to it.
type value interface {
	// Type returns the type of the variable.
	Type() *types.DataType
	// RawValue returns the value of the variable.
	// This is one of: nil, int64, string, bool, []byte, *types.UUID, *decimal.Decimal,
	// []*int64, []*string, []*bool, [][]byte, []*decimal.Decimal, []*types.UUID
	RawValue() any
	// Null returns true if the variable is null.
	Null() bool
	// Compare compares the variable with another variable using the given comparison operator.
	// It will return a boolean value or null, depending on the comparison and the values.
	Compare(v value, op comparisonOp) (*boolValue, error)
	// Cast casts the variable to the given type.
	// It is meant to mirror Postgres's type casting behavior.
	Cast(t *types.DataType) (value, error)
}

// scalarValue is a scalar value that can be computed on and have unary operations applied to it.
type scalarValue interface {
	value
	// Arithmetic performs an arithmetic operation on the variable with another variable.
	Arithmetic(v scalarValue, op arithmeticOp) (scalarValue, error)
	// Unary applies a unary operation to the variable.
	Unary(op unaryOp) (scalarValue, error)
}

// arrayValue is an array value that can be compared and have unary operations applied to it.
type arrayValue interface {
	value
	// Len returns the length of the array.
	Len() int32
	// Get returns the value at the given index.
	// If the index is out of bounds, an error is returned.
	// All indexing is 1-based.
	Get(i int32) (scalarValue, error)
	// Set sets the value at the given index.
	// If the index is out of bounds, enough space is allocated to set the value.
	// This matches the behavior of Postgres.
	// All indexing is 1-based.
	Set(i int32, v scalarValue) error
}

func newValidArr[T any](a []T) singleDimArray[T] {
	return singleDimArray[T]{
		Array: pgtype.Array[T]{
			Elements: a,
			Dims:     []pgtype.ArrayDimension{{Length: int32(len(a)), LowerBound: 1}},
			Valid:    true,
		},
	}
}

func newNullArray[T any]() singleDimArray[T] {
	return singleDimArray[T]{
		Array: pgtype.Array[T]{
			Valid: false,
			Dims: []pgtype.ArrayDimension{
				{
					Length:     0,
					LowerBound: 1,
				},
			},
		},
	}
}

// newValue creates a new Value from the given any val.
func newValue(v any) (value, error) {
	switch v := v.(type) {
	case value:
		return v, nil
	case int64:
		return makeInt8(v), nil
	case *int64:
		if v == nil {
			return makeNull(types.IntType)
		}
		return makeInt8(*v), nil
	case int:
		return makeInt8(int64(v)), nil
	case *int:
		if v == nil {
			return makeNull(types.IntType)
		}
		return makeInt8(int64(*v)), nil
	case string:
		return makeText(v), nil
	case *string:
		if v == nil {
			return makeNull(types.TextType)
		}
		return makeText(*v), nil
	case bool:
		return makeBool(v), nil
	case *bool:
		if v == nil {
			return makeNull(types.BoolType)
		}
		return makeBool(*v), nil
	case []byte:
		return makeBlob(v), nil
	case *[]byte:
		if v == nil {
			return makeNull(types.ByteaType)
		}
		return makeBlob(*v), nil
	case *types.UUID:
		if v == nil {
			return makeNull(types.UUIDType)
		}
		return makeUUID(v), nil
	case types.UUID:
		return makeUUID(&v), nil
	case *types.Decimal:
		// makeDecimal accounts for nil, so we can pass it directly
		return makeDecimal(v), nil
	case types.Decimal:
		return makeDecimal(&v), nil
	case []int64:
		if v == nil {
			return makeNull(types.IntArrayType)
		}

		pgInts := make([]pgtype.Int8, len(v))
		for i, val := range v {
			pgInts[i].Int64 = val
			pgInts[i].Valid = true
		}

		return &int8ArrayValue{
			singleDimArray: newValidArr(pgInts),
		}, nil
	case []*int64:
		if v == nil {
			return makeNull(types.IntArrayType)
		}

		pgInts := make([]pgtype.Int8, len(v))
		for i, val := range v {
			if val == nil {
				pgInts[i].Valid = false
			} else {
				pgInts[i].Int64 = *val
				pgInts[i].Valid = true
			}
		}
		return &int8ArrayValue{
			singleDimArray: newValidArr(pgInts),
		}, nil
	case []int:
		if v == nil {
			return makeNull(types.IntArrayType)
		}

		pgInts := make([]pgtype.Int8, len(v))
		for i, val := range v {
			pgInts[i].Int64 = int64(val)
			pgInts[i].Valid = true
		}

		return &int8ArrayValue{
			singleDimArray: newValidArr(pgInts),
		}, nil
	case []*int:
		if v == nil {
			return makeNull(types.IntArrayType)
		}

		pgInts := make([]pgtype.Int8, len(v))
		for i, val := range v {
			if val == nil {
				pgInts[i].Valid = false
			} else {
				pgInts[i].Int64 = int64(*val)
				pgInts[i].Valid = true
			}
		}
		return &int8ArrayValue{
			singleDimArray: newValidArr(pgInts),
		}, nil
	case []string:
		if v == nil {
			return makeNull(types.TextArrayType)
		}

		pgTexts := make([]pgtype.Text, len(v))
		for i, val := range v {
			pgTexts[i].String = val
			pgTexts[i].Valid = true
		}

		return &textArrayValue{
			singleDimArray: newValidArr(pgTexts),
		}, nil
	case []*string:
		if v == nil {
			return makeNull(types.TextArrayType)
		}

		pgTexts := make([]pgtype.Text, len(v))
		for i, val := range v {
			if val == nil {
				pgTexts[i].Valid = false
			} else {
				pgTexts[i].String = *val
				pgTexts[i].Valid = true
			}
		}

		return &textArrayValue{
			singleDimArray: newValidArr(pgTexts),
		}, nil
	case []bool:
		if v == nil {
			return makeNull(types.BoolArrayType)
		}

		pgBools := make([]pgtype.Bool, len(v))
		for i, val := range v {
			pgBools[i].Bool = val
			pgBools[i].Valid = true
		}

		return &boolArrayValue{
			singleDimArray: newValidArr(pgBools),
		}, nil
	case []*bool:
		if v == nil {
			return makeNull(types.BoolArrayType)
		}

		pgBools := make([]pgtype.Bool, len(v))
		for i, val := range v {
			if val == nil {
				pgBools[i].Valid = false
			} else {
				pgBools[i].Bool = *val
				pgBools[i].Valid = true
			}
		}

		return &boolArrayValue{
			singleDimArray: newValidArr(pgBools),
		}, nil
	case [][]byte:
		if v == nil {
			return makeNull(types.ByteaArrayType)
		}

		pgBlobs := make([]blobValue, len(v))
		for i, val := range v {
			if val == nil {
				pgBlobs[i] = blobValue{}
			} else {
				pgBlobs[i] = *makeBlob(val)
			}
		}

		return &blobArrayValue{
			singleDimArray: newValidArr(pgBlobs),
		}, nil
	case []*[]byte:
		if v == nil {
			return makeNull(types.ByteaArrayType)
		}

		pgBlobs := make([]blobValue, len(v))
		for i, val := range v {
			if val == nil {
				pgBlobs[i] = blobValue{}
			} else {
				pgBlobs[i] = *makeBlob(*val)
			}
		}

		return &blobArrayValue{
			singleDimArray: newValidArr(pgBlobs),
		}, nil
	case []*types.Decimal:
		if v == nil {
			return makeNull(types.NumericArrayType)
		}

		pgDecs := make([]pgtype.Numeric, len(v))
		var firstNonNilDecimal *types.Decimal
		for i, val := range v {
			pgDecs[i] = pgTypeFromDec(val)
			if val != nil && firstNonNilDecimal == nil {
				firstNonNilDecimal = val
			}
		}

		var metadata *precAndScale
		if firstNonNilDecimal != nil {
			precCopy := firstNonNilDecimal.Precision()
			scaleCopy := firstNonNilDecimal.Scale()
			metadata = &precAndScale{precCopy, scaleCopy}
		}

		return &decimalArrayValue{
			singleDimArray: newValidArr(pgDecs),
			metadata:       metadata,
		}, nil
	case []*types.UUID:
		if v == nil {
			return makeNull(types.UUIDArrayType)
		}

		pgUUIDs := make([]pgtype.UUID, len(v))
		for i, val := range v {
			if val == nil {
				pgUUIDs[i].Valid = false
			} else {
				pgUUIDs[i].Bytes = *val
				pgUUIDs[i].Valid = true
			}
		}

		return &uuidArrayValue{
			singleDimArray: newValidArr(pgUUIDs),
		}, nil
	case nil:
		return &nullValue{}, nil
	case []any:
		// if type []any, they all must be nil
		for _, val := range v {
			if val != nil {
				return nil, fmt.Errorf("values passed as []any must all be nil. Got: %v", v)
			}
		}

		return &arrayOfNulls{
			length: int32(len(v)),
		}, nil
	default:
		// if they are pointers, dereference them
		// TODO: handle this with a type switch
		ref := reflect.ValueOf(v)
		if ref.Kind() == reflect.Ptr {
			return newValue(ref.Elem().Interface())
		}
		return nil, fmt.Errorf("unexpected type %T", v)
	}
}

func makeTypeErr(left, right value) error {
	return fmt.Errorf("%w: left: %s right: %s", engine.ErrType, left.Type(), right.Type())
}

func makeInt8(i int64) *int8Value {
	return &int8Value{
		Int8: pgtype.Int8{
			Int64: i,
			Valid: true,
		},
	}
}

type int8Value struct {
	pgtype.Int8
}

func (i *int8Value) Null() bool {
	return !i.Valid
}

func (v *int8Value) Compare(v2 value, op comparisonOp) (*boolValue, error) {
	if res, early := nullCmp(v, v2, op); early {
		return res, nil
	}

	val2, ok := v2.(*int8Value)
	if !ok {
		return nil, makeTypeErr(v, v2)
	}

	var b bool
	switch op {
	case _EQUAL:
		b = v.Int64 == val2.Int64
	case _LESS_THAN:
		b = v.Int64 < val2.Int64
	case _GREATER_THAN:
		b = v.Int64 > val2.Int64
	case _IS_DISTINCT_FROM:
		b = v.Int64 != val2.Int64
	default:
		return nil, fmt.Errorf("%w: cannot compare int with operator %s", engine.ErrComparison, op)
	}

	return makeBool(b), nil
}

// nullCmp is a helper function for comparing null values.
// It takes two values and a comparison operator.
// If the operator is IS or IS DISTINCT FROM, it will return a boolean value
// based on the comparison of the two values.
// If the operator is any other operator and either of the values is null,
// it will return a null value.
func nullCmp(a, b value, op comparisonOp) (*boolValue, bool) {
	// if it is is_DISTINCT_FROM or is, we should handle nulls
	// Otherwise, if either is a null, we return early because we cannot compare
	// a null value with a non-null value.
	if op == _IS_DISTINCT_FROM {
		if a.Null() && b.Null() {
			return makeBool(false), true
		}
		if a.Null() || b.Null() {
			return makeBool(true), true
		}

		// otherwise, we let equality handle it
	}

	if op == _IS {
		if a.Null() && b.Null() {
			return makeBool(true), true
		}
		if a.Null() || b.Null() {
			return makeBool(false), true
		}
	}

	if a.Null() || b.Null() {
		nv, err := makeNull(types.BoolType)
		if err != nil {
			panic(err) // should never happen, MakeNull(types.BoolType) should never return an error
		}
		boolType, ok := nv.(*boolValue)
		if !ok {
			panic("MakeNull(types.BoolType) did not return a *BoolValue") // should never happen
		}

		return boolType, true
	}

	return nil, false
}

// checks if any value is null. If so, it will return the null value.
func checkScalarNulls(v ...scalarValue) (scalarValue, bool) {
	for _, val := range v {
		if val.Null() {
			return val, true
		}
	}

	return nil, false
}

func (i *int8Value) Arithmetic(v scalarValue, op arithmeticOp) (scalarValue, error) {
	if res, early := checkScalarNulls(i, v); early {
		return res, nil
	}

	val2, ok := v.(*int8Value)
	if !ok {
		return nil, makeTypeErr(i, v)
	}

	var r int64

	switch op {
	case _ADD:
		r = i.Int64 + val2.Int64
	case _SUB:
		r = i.Int64 - val2.Int64
	case _MUL:
		r = i.Int64 * val2.Int64
	case _DIV:
		if val2.Int64 == 0 {
			return nil, fmt.Errorf("%w: cannot divide by zero", engine.ErrArithmetic)
		}
		r = i.Int64 / val2.Int64
	case _MOD:
		if val2.Int64 == 0 {
			return nil, fmt.Errorf("%w: cannot modulo by zero", engine.ErrArithmetic)
		}
		r = i.Int64 % val2.Int64
	case _EXP:
		p := math.Pow(float64(i.Int64), float64(val2.Int64))
		if p > math.MaxInt64 {
			return nil, fmt.Errorf("%w: result of exponentiation is too large", engine.ErrArithmetic)
		}
		r = int64(p)
	default:
		return nil, fmt.Errorf("%w: cannot perform arithmetic operation %s on type int", engine.ErrArithmetic, op)
	}

	return &int8Value{
		Int8: pgtype.Int8{
			Int64: r,
			Valid: true,
		},
	}, nil
}

func (i *int8Value) Unary(op unaryOp) (scalarValue, error) {
	if i.Null() {
		return i, nil
	}

	switch op {
	case _NEG:
		return &int8Value{Int8: pgtype.Int8{Int64: -i.Int64, Valid: true}}, nil
	case _NOT:
		return nil, fmt.Errorf("%w: cannot apply logical NOT to an integer", engine.ErrUnary)
	case _POS:
		return i, nil
	default:
		return nil, fmt.Errorf("%w: unknown unary operator: %s", engine.ErrUnary, op)
	}
}

func (i *int8Value) Type() *types.DataType {
	return types.IntType
}

func (i *int8Value) RawValue() any {
	if !i.Valid {
		return nil
	}

	return i.Int64
}

func (i *int8Value) Cast(t *types.DataType) (value, error) {
	if i.Null() {
		return makeNull(t)
	}

	// we check for decimal first since type switching on it
	// doesn't work, since it has precision and scale
	if t.Name == types.NumericStr {
		if t.IsArray {
			return nil, castErr(errors.New("cannot cast int to decimal array"))
		}

		dec, err := types.ParseDecimalExplicit(fmt.Sprint(i.Int64), t.Metadata[0], t.Metadata[1])
		if err != nil {
			return nil, castErr(err)
		}

		return makeDecimal(dec), nil
	}

	switch *t {
	case *types.IntType:
		return i, nil
	case *types.TextType:
		return makeText(fmt.Sprint(i.Int64)), nil
	case *types.BoolType:
		return makeBool(i.Int64 != 0), nil
	default:
		return nil, castErr(fmt.Errorf("cannot cast int to %s", t))
	}
}

// makeNull creates a new null value of the given type.
func makeNull(t *types.DataType) (value, error) {
	m, ok := kwilTypeToValue[struct {
		name    string
		isArray bool
	}{
		name:    t.Name,
		isArray: t.IsArray,
	}]
	if !ok {
		return nil, fmt.Errorf("type %s not found", t.String())
	}

	return m.NullValue(t)
}

func makeText(s string) *textValue {
	return &textValue{
		Text: pgtype.Text{
			String: s,
			Valid:  true,
		},
	}
}

type textValue struct {
	pgtype.Text
}

func (t *textValue) Null() bool {
	return !t.Valid
}

func (s *textValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	if res, early := nullCmp(s, v, op); early {
		return res, nil
	}

	val2, ok := v.(*textValue)
	if !ok {
		return nil, makeTypeErr(s, v)
	}

	var b bool
	switch op {
	case _EQUAL:
		b = s.String == val2.String
	case _LESS_THAN:
		b = s.String < val2.String
	case _GREATER_THAN:
		b = s.String > val2.String
	case _IS_DISTINCT_FROM:
		b = s.String != val2.String
	default:
		return nil, fmt.Errorf("%w: cannot use comparison operator %s with type %s", engine.ErrComparison, s.Type(), op)
	}

	return makeBool(b), nil
}

func (s *textValue) Arithmetic(v scalarValue, op arithmeticOp) (scalarValue, error) {
	if res, early := checkScalarNulls(s, v); early {
		return res, nil
	}

	val2, ok := v.(*textValue)
	if !ok {
		return nil, makeTypeErr(s, v)
	}

	if op == _CONCAT {
		return makeText(s.String + val2.String), nil
	}

	return nil, fmt.Errorf("%w: cannot perform arithmetic operation %s on type string", engine.ErrArithmetic, op)
}

func (s *textValue) Unary(op unaryOp) (scalarValue, error) {
	return nil, fmt.Errorf("%w: cannot perform unary operation on string", engine.ErrUnary)
}

func (s *textValue) Type() *types.DataType {
	return types.TextType
}

func (s *textValue) RawValue() any {
	if !s.Valid {
		return nil
	}

	return s.String
}

func (s *textValue) Cast(t *types.DataType) (value, error) {
	if s.Null() {
		return makeNull(t)
	}

	if t.Name == types.NumericStr {
		if t.IsArray {
			return nil, castErr(errors.New("cannot cast text to decimal array"))
		}

		dec, err := types.ParseDecimalExplicit(s.String, t.Metadata[0], t.Metadata[1])
		if err != nil {
			return nil, castErr(err)
		}

		return makeDecimal(dec), nil
	}

	switch *t {
	case *types.IntType:
		i, err := strconv.ParseInt(s.String, 10, 64)
		if err != nil {
			return nil, castErr(err)
		}

		return makeInt8(i), nil
	case *types.TextType:
		return s, nil
	case *types.BoolType:
		b, err := strconv.ParseBool(s.String)
		if err != nil {
			return nil, castErr(err)
		}

		return makeBool(b), nil
	case *types.UUIDType:
		u, err := types.ParseUUID(s.String)
		if err != nil {
			return nil, castErr(err)
		}

		return makeUUID(u), nil
	case *types.ByteaType:
		return makeBlob([]byte(s.String)), nil
	default:
		return nil, castErr(fmt.Errorf("cannot cast text to %s", t))
	}
}

func makeBool(b bool) *boolValue {
	return &boolValue{
		Bool: pgtype.Bool{
			Bool:  b,
			Valid: true,
		},
	}
}

type boolValue struct {
	pgtype.Bool
}

func (b *boolValue) Null() bool {
	return !b.Valid
}

func (b *boolValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	if res, early := nullCmp(b, v, op); early {
		return res, nil
	}

	val2, ok := v.(*boolValue)
	if !ok {
		return nil, makeTypeErr(b, v)
	}

	var b2 bool
	switch op {
	case _EQUAL:
		b2 = b.Bool.Bool == val2.Bool.Bool
	case _IS_DISTINCT_FROM:
		b2 = b.Bool.Bool != val2.Bool.Bool
	case _LESS_THAN:
		b2 = !b.Bool.Bool && val2.Bool.Bool
	case _GREATER_THAN:
		b2 = b.Bool.Bool && !val2.Bool.Bool
	case _IS:
		b2 = b.Bool.Bool == val2.Bool.Bool
	default:
		return nil, fmt.Errorf("%w: cannot use comparison operator %s with type %s", engine.ErrComparison, b.Type(), op)
	}

	return makeBool(b2), nil
}

func (b *boolValue) Arithmetic(v scalarValue, op arithmeticOp) (scalarValue, error) {
	return nil, fmt.Errorf("%w: cannot perform arithmetic operation on bool", engine.ErrArithmetic)
}

func (b *boolValue) Unary(op unaryOp) (scalarValue, error) {
	if b.Null() {
		return b, nil
	}

	switch op {
	case _NOT:
		return makeBool(!b.Bool.Bool), nil
	case _NEG, _POS:
		return nil, fmt.Errorf("%w: cannot perform unary operation %s on bool", engine.ErrUnary, op)
	default:
		return nil, fmt.Errorf("%w: unexpected operator id %s for bool", engine.ErrUnary, op)
	}
}

func (b *boolValue) Type() *types.DataType {
	return types.BoolType
}

func (b *boolValue) RawValue() any {
	if !b.Valid {
		return nil
	}

	return b.Bool.Bool
}

func (b *boolValue) Cast(t *types.DataType) (value, error) {
	if b.Null() {
		return makeNull(t)
	}

	switch *t {
	case *types.IntType:
		if b.Bool.Bool {
			return makeInt8(1), nil
		}

		return makeInt8(0), nil
	case *types.TextType:
		return makeText(strconv.FormatBool(b.Bool.Bool)), nil
	case *types.BoolType:
		return b, nil
	default:
		return nil, castErr(fmt.Errorf("cannot cast bool to %s", t))
	}
}

func makeBlob(b []byte) *blobValue {
	return &blobValue{
		bts: b,
	}
}

type blobValue struct {
	bts []byte
}

func (b *blobValue) Null() bool {
	return b.bts == nil
}

func (b *blobValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	if res, early := nullCmp(b, v, op); early {
		return res, nil
	}

	val2, ok := v.(*blobValue)
	if !ok {
		return nil, makeTypeErr(b, v)
	}

	var b2 bool
	switch op {
	case _EQUAL:
		b2 = string(b.bts) == string(val2.bts)
	case _IS_DISTINCT_FROM:
		b2 = string(b.bts) != string(val2.bts)
	default:
		return nil, fmt.Errorf("%w: cannot use comparison operator %s with type %s", engine.ErrComparison, b.Type(), op)
	}

	return makeBool(b2), nil
}

func (b *blobValue) Arithmetic(v scalarValue, op arithmeticOp) (scalarValue, error) {
	if res, early := checkScalarNulls(b, v); early {
		return res, nil
	}

	val2, ok := v.(*blobValue)
	if !ok {
		return nil, makeTypeErr(b, v)
	}

	if op == _CONCAT {
		return makeBlob(append(b.bts, val2.bts...)), nil
	}

	return nil, fmt.Errorf("%w: cannot perform arithmetic operation %s on blob", engine.ErrArithmetic, op)
}

func (b *blobValue) Unary(op unaryOp) (scalarValue, error) {
	return nil, fmt.Errorf("%w: cannot perform unary operation on blob", engine.ErrUnary)
}

func (b *blobValue) Type() *types.DataType {
	return types.ByteaType
}

func (b *blobValue) RawValue() any {
	// RawValue returns an any, so if we `return nil`, it return a nil
	// interface{}. However, if we `return []byte(nil)`, the returned
	// interface{} is NOT nil.
	if b.bts == nil {
		return nil
	}
	return b.bts
}

func (b *blobValue) Cast(t *types.DataType) (value, error) {
	if b.Null() {
		return makeNull(t)
	}

	switch *t {
	case *types.IntType:
		i, err := strconv.ParseInt(string(b.bts), 10, 64)
		if err != nil {
			return nil, castErr(err)
		}

		return makeInt8(i), nil
	case *types.TextType:
		return makeText(string(b.bts)), nil
	case *types.ByteaType:
		return b, nil
	default:
		return nil, castErr(fmt.Errorf("cannot cast blob to %s", t))
	}
}

var _ pgtype.BytesScanner = (*blobValue)(nil)
var _ pgtype.BytesValuer = (*blobValue)(nil)

// ScanBytes implements the pgtype.BytesScanner interface.
func (b *blobValue) ScanBytes(src []byte) error {
	if src == nil {
		b.bts = nil
		return nil
	}

	// copy the src bytes into the prealloc bytes
	b.bts = make([]byte, len(src))
	copy(b.bts, src)
	return nil
}

// BytesValue implements the pgtype.BytesValuer interface.
func (b *blobValue) BytesValue() ([]byte, error) {
	if b.Null() {
		return nil, nil
	}

	return b.bts, nil
}

// Value implements the driver.Valuer interface.
func (b *blobValue) Value() (driver.Value, error) {
	if b.Null() {
		return nil, nil
	}

	return b.bts, nil
}

func makeUUID(u *types.UUID) *uuidValue {
	if u == nil {
		return &uuidValue{
			UUID: pgtype.UUID{
				Valid: false,
			},
		}
	}
	return &uuidValue{
		UUID: pgtype.UUID{
			Bytes: *u,
			Valid: true,
		},
	}
}

type uuidValue struct {
	pgtype.UUID
}

func (u *uuidValue) Null() bool {
	return !u.Valid
}

func (u *uuidValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	if res, early := nullCmp(u, v, op); early {
		return res, nil
	}

	val2, ok := v.(*uuidValue)
	if !ok {
		return nil, makeTypeErr(u, v)
	}

	var b bool
	switch op {
	case _EQUAL:
		b = u.Bytes == val2.Bytes
	case _IS_DISTINCT_FROM:
		b = u.Bytes != val2.Bytes
	default:
		return nil, fmt.Errorf("%w: cannot use comparison operator %s with type %s", engine.ErrComparison, u.Type(), op)
	}

	return makeBool(b), nil
}

func (u *uuidValue) Arithmetic(v scalarValue, op arithmeticOp) (scalarValue, error) {
	return nil, fmt.Errorf("%w: cannot perform arithmetic operation on uuid", engine.ErrArithmetic)
}

func (u *uuidValue) Unary(op unaryOp) (scalarValue, error) {
	return nil, fmt.Errorf("%w: cannot perform unary operation on uuid", engine.ErrUnary)
}

func (u *uuidValue) Type() *types.DataType {
	return types.UUIDType
}

func (u *uuidValue) RawValue() any {
	if !u.Valid {
		return nil
	}

	// kwil always handled uuids as pointers
	u2 := types.UUID(u.Bytes)
	return &u2
}

func (u *uuidValue) Cast(t *types.DataType) (value, error) {
	if u.Null() {
		return makeNull(t)
	}

	switch *t {
	case *types.TextType:
		return makeText(types.UUID(u.Bytes).String()), nil
	case *types.ByteaType:
		return makeBlob(u.Bytes[:]), nil
	case *types.UUIDType:
		return u, nil
	default:
		return nil, castErr(fmt.Errorf("cannot cast uuid to %s", t))
	}
}

func pgTypeFromDec(d *types.Decimal) pgtype.Numeric {
	if d == nil {
		return pgtype.Numeric{
			Valid: false,
		}
	}
	if d.NaN() {
		return pgtype.Numeric{
			NaN:   true,
			Valid: true,
		}
	}

	bigint := d.BigInt()
	// cockroach's APD library tracks negativity outside of the BigInt,
	// so here we need to check if the decimal is negative, and if so,
	// apply it to the big int we are putting into the pgtype.
	if d.IsNegative() {
		bigint = bigint.Neg(bigint)
	}

	return pgtype.Numeric{
		Int:   bigint,
		Exp:   d.Exp(),
		Valid: true,
	}
}

func decFromPgType(n pgtype.Numeric, meta *precAndScale) (*types.Decimal, error) {
	if n.NaN {
		return types.NewNaNDecimal(), nil
	}
	if !n.Valid {
		// we should never get here, but just in case
		return nil, fmt.Errorf("internal bug: null decimal")
	}

	dec, err := types.NewDecimalFromBigInt(n.Int, n.Exp)
	if err != nil {
		return nil, err
	}

	if meta != nil {
		err = dec.SetPrecisionAndScale(meta[0], meta[1])
		if err != nil {
			return nil, err
		}
	}

	return dec, nil
}

func makeDecimal(d *types.Decimal) *decimalValue {
	if d == nil {
		return &decimalValue{
			Numeric: pgtype.Numeric{
				Valid: false,
			},
		}
	}

	prec := d.Precision()
	scale := d.Scale()
	return &decimalValue{
		Numeric:  pgTypeFromDec(d),
		metadata: &precAndScale{prec, scale},
	}
}

type decimalValue struct {
	pgtype.Numeric
	metadata *precAndScale // can be nil
}

type precAndScale [2]uint16

func (d *decimalValue) Null() bool {
	return !d.Valid
}

func (d *decimalValue) dec() (*types.Decimal, error) {
	if d.NaN {
		return nil, fmt.Errorf("NaN")
	}
	if !d.Valid {
		// we should never get here, but just in case
		return nil, fmt.Errorf("internal bug: null decimal")
	}

	d2, err := types.NewDecimalFromBigInt(d.Int, d.Exp)
	if err != nil {
		return nil, err
	}

	if d.metadata != nil {
		meta := *d.metadata
		err = d2.SetPrecisionAndScale(meta[0], meta[1])
		if err != nil {
			return nil, err
		}
	}

	return d2, nil
}

func (d *decimalValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	if res, early := nullCmp(d, v, op); early {
		return res, nil
	}

	val2, ok := v.(*decimalValue)
	if !ok {
		return nil, makeTypeErr(d, v)
	}

	dec1, err := d.dec()
	if err != nil {
		return nil, err
	}

	dec2, err := val2.dec()
	if err != nil {
		return nil, err
	}

	res, err := dec1.Cmp(dec2)
	if err != nil {
		return nil, err
	}

	return cmpIntegers(res, 0, op)
}

func (d *decimalValue) Arithmetic(v scalarValue, op arithmeticOp) (scalarValue, error) {
	if res, early := checkScalarNulls(d, v); early {
		return res, nil
	}

	// we check they are both decimal, but we don't check the precision and scale
	// because our decimal library will calculate with higher precision and scale anyways.
	if v.Type().Name != d.Type().Name {
		return nil, makeTypeErr(d, v)
	}

	val2, ok := v.(*decimalValue)
	if !ok {
		return nil, makeTypeErr(d, v)
	}

	dec1, err := d.dec()
	if err != nil {
		return nil, err
	}

	dec2, err := val2.dec()
	if err != nil {
		return nil, err
	}

	var d2 *types.Decimal
	switch op {
	case _ADD:
		d2, err = types.DecimalAdd(dec1, dec2)
	case _SUB:
		d2, err = types.DecimalSub(dec1, dec2)
	case _MUL:
		d2, err = types.DecimalMul(dec1, dec2)
	case _DIV:
		d2, err = types.DecimalDiv(dec1, dec2)
	case _EXP:
		d2, err = types.DecimalPow(dec1, dec2)
	case _MOD:
		d2, err = types.DecimalMod(dec1, dec2)
	default:
		return nil, fmt.Errorf("%w: unexpected operator id %d for decimal", engine.ErrArithmetic, op)
	}
	if err != nil {
		return nil, err
	}

	err = d2.SetPrecisionAndScale(dec1.Precision(), dec1.Scale())
	if err != nil {
		return nil, err
	}

	return makeDecimal(d2), nil
}

func (d *decimalValue) Unary(op unaryOp) (scalarValue, error) {
	if d.Null() {
		return d, nil
	}

	switch op {
	case _NEG:
		dec, err := d.dec()
		if err != nil {
			return nil, err
		}

		err = dec.Neg()
		if err != nil {
			return nil, err
		}

		return makeDecimal(dec), nil
	case _POS:
		return d, nil
	default:
		return nil, fmt.Errorf("%w: unexpected operator id %s for decimal", engine.ErrUnary, op)
	}
}

func (d *decimalValue) Type() *types.DataType {
	if d.metadata == nil {
		return types.NumericType
	}

	t := types.NumericType.Copy()
	t.Metadata = *d.metadata
	return t
}

func (d *decimalValue) RawValue() any {
	if !d.Valid {
		return nil
	}
	dec, err := d.dec()
	if err != nil {
		panic(err)
	}

	return dec
}

func (d *decimalValue) Cast(t *types.DataType) (value, error) {
	if d.Null() {
		return makeNull(t)
	}
	if t.Name == types.NumericStr {
		if t.IsArray {
			return nil, castErr(errors.New("cannot cast decimal to decimal array"))
		}

		// otherwise, we need to alter the precision and scale

		dec, err := d.dec()
		if err != nil {
			return nil, castErr(err)
		}

		err = dec.SetPrecisionAndScale(t.Metadata[0], t.Metadata[1])
		if err != nil {
			return nil, castErr(err)
		}

		return makeDecimal(dec), nil
	}

	switch *t {
	case *types.IntType:
		dec, err := d.dec()
		if err != nil {
			return nil, castErr(err)
		}

		i, err := dec.Int64()
		if err != nil {
			return nil, castErr(err)
		}

		return makeInt8(i), nil
	case *types.TextType:
		dec, err := d.dec()
		if err != nil {
			return nil, castErr(err)
		}

		return makeText(dec.String()), nil
	default:
		return nil, castErr(fmt.Errorf("cannot cast decimal to %s", t))
	}
}

func newIntArr(v []*int64) *int8ArrayValue {
	pgInts := make([]pgtype.Int8, len(v))
	for i, val := range v {
		if val == nil {
			pgInts[i].Valid = false
		} else {
			pgInts[i].Int64 = *val
			pgInts[i].Valid = true
		}
	}

	return &int8ArrayValue{
		singleDimArray: newValidArr(pgInts),
	}
}

// singleDimArray array intercepts the pgtype SetDimensions method to ensure that all arrays we scan are
// 1D arrays. This is because we do not support multi-dimensional arrays.
type singleDimArray[T any] struct {
	pgtype.Array[T]
}

//lint:ignore U1000 This is an internal helper function satisfying the internalArray interface
func (o *singleDimArray[T]) pgtypeArr() *pgtype.Array[T] {
	return &o.Array
}

// internalArray is an internal helper interface to allow us to access the underlying pgtype.Array
// when using an array type
type internalArray[T any] interface {
	pgtypeArr() *pgtype.Array[T]
	Type() *types.DataType
	Len() int32
}

var _ pgtype.ArraySetter = (*singleDimArray[any])(nil)
var _ pgtype.ArrayGetter = (*singleDimArray[any])(nil)

func (a *singleDimArray[T]) SetDimensions(dims []pgtype.ArrayDimension) error {
	// if len(dims) is 0, it is null.
	// if len(dims) is 1, it is a 1D array.
	// Kwil does not support multi-dimensional arrays.
	switch len(dims) {
	case 0, 1:
		return a.Array.SetDimensions(dims)
	default:
		return fmt.Errorf("%w: expected 1 dimension, got %d", engine.ErrArrayDimensionality, len(dims))
	}
}

func (a *singleDimArray[T]) Value() (driver.Value, error) {
	if !a.Valid {
		return nil, nil
	}
	// for some reason, not having this Value method causes the OneDArray type
	// to not function despite implementing the pgtype.ArrayGetter interface.
	return a.Array, nil
}

// getArr gets the value at index i in the array.
// It treats the array as 1-based.
func getArr[T any](arr internalArray[T], i int32, fn func(T) scalarValue) (scalarValue, error) {
	// to match postgres, accessing a non-existent index should return null
	if i < 1 || i > arr.Len() {
		v, err := makeNull(arr.Type())
		if err != nil {
			return nil, err
		}

		s, ok := v.(scalarValue)
		if !ok {
			return nil, fmt.Errorf("expected to create a null scalar value, got %T", v)
		}

		return s, nil
	}

	pgArr := arr.pgtypeArr()

	return fn(pgArr.Elements[i-1]), nil
}

// setArr sets the value at index i in the array.
// It treats the array as 1-based.
func setArr[T, B any](arr internalArray[T], i int32, v scalarValue, fn func(B) T) error {
	if i < 1 { // 1-based indexing
		return engine.ErrIndexOutOfBounds
	}

	dtScalar := arr.Type().Copy()
	dtScalar.IsArray = false

	// makeNull creates a new null value that can be set in the array.
	makeNull := func() (T, error) {
		nullVal, err := makeNull(dtScalar)
		if err != nil {
			return *new(T), err
		}

		nvt, ok := nullVal.(B)
		if !ok {
			return *new(T), fmt.Errorf("cannot set null value in array: internal type bug")
		}

		return fn(nvt), nil
	}

	pgArr := arr.pgtypeArr()

	currentLen := int32(len(pgArr.Elements))

	// Postgres semantics: if the index is beyond the current length we must
	// extend the array.  Optimise for the very common append-by-one case where
	// copySingleDimArray has already reserved capacity.

	if i > currentLen {
		// Fast-path: appending exactly one element and capacity already exists.
		if i == currentLen+1 && cap(pgArr.Elements) >= int(i) {
			// Simply grow slice length within existing capacity.
			pgArr.Elements = pgArr.Elements[:i]
			pgArr.Dims[0] = pgtype.ArrayDimension{Length: i, LowerBound: 1}
			pgArr.Valid = true
		} else {
			// General path: allocate a new slice large enough, copy, null-fill.
			// Exponential-growth strategy: double capacity until it fits i.
			newCap := cap(pgArr.Elements)
			if newCap == 0 {
				newCap = 1
			}
			for newCap < int(i) {
				newCap *= 2
			}

			// Allocate slice with len=i and the computed capacity.
			newVal := make([]T, i, newCap)
			copy(newVal, pgArr.Elements)

			// Fill any new positions (including the slot at i-1) with typed NULLs.
			for j := int(currentLen); j < int(i); j++ {
				nn, err := makeNull()
				if err != nil {
					return err
				}
				newVal[j] = nn
			}

			pgArr.Elements = newVal
			pgArr.Dims[0] = pgtype.ArrayDimension{Length: i, LowerBound: 1}
			pgArr.Valid = true
		}
	}

	// if the new value is null, we will create a new null of this type and
	// set it in the array.
	if v.Null() {
		nn, err := makeNull()
		if err != nil {
			return err
		}

		pgArr.Elements[i-1] = nn
		return nil
	}

	// if the value is not null, we will cast it to the scalar type of the array.
	// This matches Postgres:
	// postgres=# select array[1, '2'];
	//  array
	//  -------
	//   {1,2}
	scalar, err := v.Cast(dtScalar)
	if err != nil {
		return err
	}

	val, ok := scalar.(B)
	if !ok {
		return fmt.Errorf(`cannot set value of type "%s" in array of type "%s"`, v.Type(), arr.Type())
	}

	pgArr.Elements[i-1] = fn(val)
	return nil
}

type int8ArrayValue struct {
	singleDimArray[pgtype.Int8]
}

func (a *int8ArrayValue) Null() bool {
	return !a.Valid
}

func (a *int8ArrayValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	return cmpArrs(a, v, op)
}

func (a *int8ArrayValue) Len() int32 {
	return int32(len(a.Elements))
}

func (a *int8ArrayValue) Get(i int32) (scalarValue, error) {
	return getArr(a, i, func(i pgtype.Int8) scalarValue {
		return &int8Value{i}
	})
}

func (a *int8ArrayValue) Set(i int32, v scalarValue) error {
	return setArr(a, i, v, func(v2 *int8Value) pgtype.Int8 {
		return v2.Int8
	})
}

func (a *int8ArrayValue) Type() *types.DataType {
	return types.IntArrayType
}

func (a *int8ArrayValue) RawValue() any {
	if !a.Valid {
		return nil
	}

	res := make([]*int64, len(a.Elements))
	for i, v := range a.Elements {
		if v.Valid {
			res[i] = &v.Int64
		} else {
			res[i] = nil
		}
	}

	return res
}

func (a *int8ArrayValue) Cast(t *types.DataType) (value, error) {
	if a.Null() {
		return makeNull(t)
	}

	if t.Name == types.NumericStr {
		if !t.IsArray {
			return nil, castErr(errors.New("cannot cast int array to decimal"))
		}

		return castArrWithPtr(a, func(i int64) (*types.Decimal, error) {
			return types.ParseDecimalExplicit(strconv.FormatInt(i, 10), t.Metadata[0], t.Metadata[1])
		}, newDecArrFn(t))
	}

	switch *t {
	case *types.IntArrayType:
		return a, nil
	case *types.TextArrayType:
		return castArr(a, func(i int64) (string, error) { return strconv.FormatInt(i, 10), nil }, newTextArrayValue)
	case *types.BoolArrayType:
		return castArr(a, func(i int64) (bool, error) { return i != 0, nil }, newBoolArrayValue)
	default:
		return nil, castErr(fmt.Errorf("cannot cast int array to %s", t))
	}
}

func newTextArrayValue(s []*string) *textArrayValue {
	vals := make([]pgtype.Text, len(s))
	for i, v := range s {
		if v == nil {
			vals[i] = pgtype.Text{Valid: false}
		} else {
			vals[i] = pgtype.Text{String: *v, Valid: true}
		}
	}

	return &textArrayValue{
		singleDimArray: newValidArr(vals),
	}
}

type textArrayValue struct {
	singleDimArray[pgtype.Text]
}

func (a *textArrayValue) Null() bool {
	return !a.Valid
}

func (a *textArrayValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	return cmpArrs(a, v, op)
}

func (a *textArrayValue) Len() int32 {
	return int32(len(a.Elements))
}

func (a *textArrayValue) Get(i int32) (scalarValue, error) {
	return getArr(a, i, func(i pgtype.Text) scalarValue {
		return &textValue{i}
	})
}

func (a *textArrayValue) Set(i int32, v scalarValue) error {
	return setArr(a, i, v, func(v2 *textValue) pgtype.Text {
		return v2.Text
	})
}

func (a *textArrayValue) Type() *types.DataType {
	return types.TextArrayType
}

func (a *textArrayValue) RawValue() any {
	if !a.Valid {
		return nil
	}

	res := make([]*string, len(a.Elements))
	for i, v := range a.Elements {
		if v.Valid {
			res[i] = &v.String
		}
	}

	return res
}

func (a *textArrayValue) Cast(t *types.DataType) (value, error) {
	if a.Null() {
		return makeNull(t)
	}
	if t.Name == types.NumericStr {
		if !t.IsArray {
			return nil, castErr(errors.New("cannot cast text array to decimal"))
		}

		return castArrWithPtr(a, func(s string) (*types.Decimal, error) {
			return types.ParseDecimalExplicit(s, t.Metadata[0], t.Metadata[1])
		}, newDecArrFn(t))
	}

	switch *t {
	case *types.IntArrayType:
		return castArr(a, func(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }, newIntArr)
	case *types.BoolArrayType:
		return castArr(a, strconv.ParseBool, newBoolArrayValue)
	case *types.UUIDArrayType:
		return castArrWithPtr(a, types.ParseUUID, newUUIDArrayValue)
	case *types.TextArrayType:
		return a, nil
	case *types.ByteaArrayType:
		return castValArr(a, func(s string) ([]byte, error) { return []byte(s), nil }, newBlobArrayValue)
	default:
		return nil, castErr(fmt.Errorf("cannot cast text array to %s", t))
	}
}

// castArr casts an array of one type to an array of another type.
// Generics:
// A is the current scalar Kwil type
// B is the desired scalar Kwil type
// C is the current array Kwil type
// D is the desired array Kwil type
// Params:
// c: the current array
// get: a function that converts the current array's scalar type to the desired scalar type
// newArr: a function that creates a new array of the desired type
func castArr[A any, B any, C arrayValue, D arrayValue](c C, get func(a A) (B, error), newArr func([]*B) D) (D, error) {
	return castArrWithPtr(c, func(b A) (*B, error) {
		res, err := get(b)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}, newArr)
}

// castArrWithPtr casts an array of one type to an array of another type.
// It expects that the get function will return a pointer to the desired type.
func castArrWithPtr[A any, B any, C arrayValue, D arrayValue](c C, get func(a A) (*B, error), newArr func([]*B) D) (D, error) {
	res := make([]*B, c.Len())
	for i := range c.Len() {
		v, err := c.Get(i + 1) // SQL Indexes are 1-based
		if err != nil {
			return *new(D), castErr(err)
		}

		// if the value is nil, we dont need to do anything; a nil value is already
		// in the array
		if !v.Null() {
			raw, ok := v.RawValue().(A)
			if !ok {
				// should never happen unless I messed up the usage of generics or implementation
				// of RawValue
				return *new(D), castErr(fmt.Errorf("internal bug: unexpected type %T", v.RawValue()))
			}

			res[i], err = get(raw)
			if err != nil {
				return *new(D), castErr(err)
			}
		}
	}

	return newArr(res), nil
}

// castValArr is for when B is itself nilable, like a slice or map, and the
// slice passed to newArray should be a []B.
func castValArr[A any, B any, C arrayValue, D arrayValue](c C, get func(a A) (B, error), newArr func([]B) D) (D, error) {
	var d D
	res := make([]B, c.Len())
	for i := range c.Len() {
		v, err := c.Get(i + 1) // SQL Indexes are 1-based
		if err != nil {
			return d, castErr(err)
		}
		if v.Null() {
			continue
		}

		va, ok := v.RawValue().(A)
		if !ok {
			return d, castErr(fmt.Errorf("internal bug: unexpected type %T", v.RawValue()))
		}

		res[i], err = get(va) // B <= A
		if err != nil {
			return d, castErr(err)
		}
	}

	return newArr(res), nil
}

func newBoolArrayValue(b []*bool) *boolArrayValue {
	vals := make([]pgtype.Bool, len(b))
	for i, v := range b {
		if v == nil {
			vals[i] = pgtype.Bool{Valid: false}
		} else {
			vals[i] = pgtype.Bool{Bool: *v, Valid: true}
		}
	}

	return &boolArrayValue{
		singleDimArray: newValidArr(vals),
	}
}

type boolArrayValue struct {
	singleDimArray[pgtype.Bool]
}

func (a *boolArrayValue) Null() bool {
	return !a.Valid
}

func (a *boolArrayValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	return cmpArrs(a, v, op)
}

func (a *boolArrayValue) Len() int32 {
	return int32(len(a.Elements))
}

func (a *boolArrayValue) Get(i int32) (scalarValue, error) {
	return getArr(a, i, func(i pgtype.Bool) scalarValue {
		return &boolValue{i}
	})
}

func (a *boolArrayValue) Set(i int32, v scalarValue) error {
	return setArr(a, i, v, func(v2 *boolValue) pgtype.Bool {
		return v2.Bool
	})
}

func (a *boolArrayValue) Type() *types.DataType {
	return types.BoolArrayType
}

func (a *boolArrayValue) RawValue() any {
	if !a.Valid {
		return nil
	}

	barr := make([]*bool, len(a.Elements))
	for i, v := range a.Elements {
		if v.Valid {
			barr[i] = &v.Bool
		}
	}

	return barr
}

func (a *boolArrayValue) Cast(t *types.DataType) (value, error) {
	if a.Null() {
		return makeNull(t)
	}

	switch *t {
	case *types.TextArrayType:
		return castArr(a, func(b bool) (string, error) { return strconv.FormatBool(b), nil }, newTextArrayValue)
	case *types.IntArrayType:
		return castArr(a, func(b bool) (int64, error) {
			if b {
				return 1, nil
			} else {
				return 0, nil
			}
		}, newIntArr)
	case *types.BoolArrayType:
		return a, nil
	default:
		return nil, castErr(fmt.Errorf("cannot cast bool array to %s", t))
	}
}

func newNullDecArr(t *types.DataType) *decimalArrayValue {
	if t.Name != types.NumericStr {
		panic("internal bug: expected decimal type")
	}
	if !t.IsArray {
		panic("internal bug: expected array type")
	}
	precCopy := t.Metadata[0]
	scaleCopy := t.Metadata[1]

	return &decimalArrayValue{
		singleDimArray: singleDimArray[pgtype.Numeric]{
			Array: newNullArray[pgtype.Numeric]().Array,
		},
		metadata: &precAndScale{precCopy, scaleCopy},
	}
}

// newDecArrFn returns a function that creates a new DecimalArrayValue.
// It is used for type casting.
func newDecArrFn(t *types.DataType) func(d []*types.Decimal) *decimalArrayValue {
	return func(d []*types.Decimal) *decimalArrayValue {
		return newDecimalArrayValue(d, t)
	}
}

func newDecimalArrayValue(d []*types.Decimal, t *types.DataType) *decimalArrayValue {
	vals := make([]pgtype.Numeric, len(d))
	for i, v := range d {
		var newDec pgtype.Numeric
		if v == nil {
			newDec = pgtype.Numeric{Valid: false}
		} else {
			newDec = pgTypeFromDec(v)
		}

		vals[i] = newDec
	}

	precCopy := t.Metadata[0]
	scaleCopy := t.Metadata[1]

	return &decimalArrayValue{
		singleDimArray: newValidArr(vals),
		metadata:       &precAndScale{precCopy, scaleCopy},
	}
}

type decimalArrayValue struct {
	singleDimArray[pgtype.Numeric]               // we embed decimal value here because we need to track the precision and scale
	metadata                       *precAndScale // can be nil
}

func (a *decimalArrayValue) Null() bool {
	return !a.Valid
}

func (a *decimalArrayValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	return cmpArrs(a, v, op)
}

// cmpArrs compares two Kwil array types.
func cmpArrs[M arrayValue](a M, b value, op comparisonOp) (*boolValue, error) {
	if res, early := nullCmp(a, b, op); early {
		return res, nil
	}

	val2, ok := b.(M)
	if !ok {
		return nil, makeTypeErr(a, b)
	}

	isEqual := func(a, b arrayValue) (isEq bool, err error) {
		if a.Len() != b.Len() {
			return false, nil
		}

		for i := int32(1); i <= a.Len(); i++ {
			v1, err := a.Get(i)
			if err != nil {
				return false, err
			}

			v2, err := b.Get(i)
			if err != nil {
				return false, err
			}

			if v1.Null() && v2.Null() {
				continue
			}

			if v1.Null() || v2.Null() {
				return false, nil
			}

			res, err := v1.Compare(v2, _EQUAL)
			if err != nil {
				return false, err
			}

			if !res.Bool.Bool {
				return false, nil
			}
		}

		return true, nil
	}

	eq, err := isEqual(a, val2)
	if err != nil {
		return nil, err
	}

	switch op {
	case _EQUAL:
		return makeBool(eq), nil
	case _IS_DISTINCT_FROM:
		return makeBool(!eq), nil
	default:
		return nil, fmt.Errorf("%w: only =, IS DISTINCT FROM are supported for array comparison", engine.ErrComparison)
	}
}

func (a *decimalArrayValue) Len() int32 {
	return int32(len(a.Elements))
}

func (a *decimalArrayValue) Get(i int32) (scalarValue, error) {
	return getArr(a, i, func(i pgtype.Numeric) scalarValue {
		return &decimalValue{
			Numeric:  i,
			metadata: a.metadata,
		}
	})
}

func (a *decimalArrayValue) Set(i int32, v scalarValue) error {
	// if incoming value is of type decimal, it must have the same precision and scale as the array
	if v.Type().Name == types.NumericStr {
		val, ok := v.(*decimalValue)
		if !ok {
			return fmt.Errorf("internal bug: variable of declared type decimal was not a decimal")
		}

		if val.metadata != nil && a.metadata != nil && *val.metadata != *a.metadata {
			valMeta := *val.metadata
			aMeta := *a.metadata
			return fmt.Errorf("cannot set decimal with precision %d and scale %d in array with precision %d and scale %d", valMeta[0], valMeta[1], aMeta[0], aMeta[1])
		}
	}

	return setArr(a, i, v, func(v2 *decimalValue) pgtype.Numeric {
		return v2.Numeric
	})
}

func (a *decimalArrayValue) Type() *types.DataType {
	if a.metadata == nil {
		return types.NumericArrayType
	}

	t := types.NumericArrayType.Copy()
	t.Metadata = *a.metadata
	return t
}

func (a *decimalArrayValue) RawValue() any {
	if !a.Valid {
		return nil
	}

	res := make([]*types.Decimal, len(a.Elements))
	for i, v := range a.Elements {
		if v.Valid {
			dec, err := decFromPgType(v, a.metadata)
			if err != nil {
				panic(err)
			}

			res[i] = dec
		}
	}

	return res
}

func (a *decimalArrayValue) Cast(t *types.DataType) (value, error) {
	if a.Null() {
		return makeNull(t)
	}

	if t.Name == types.NumericStr {
		if !t.IsArray {
			return nil, castErr(errors.New("cannot cast decimal array to decimal"))
		}

		// otherwise, we need to alter the precision and scale
		res := make([]*types.Decimal, a.Len())
		for i := int32(1); i <= a.Len(); i++ {
			v, err := a.Get(i)
			if err != nil {
				return nil, err
			}

			if v.Null() {
				res[i-1] = nil
				continue
			}

			dec, err := v.(*decimalValue).dec()
			if err != nil {
				return nil, err
			}

			err = dec.SetPrecisionAndScale(t.Metadata[0], t.Metadata[1])
			if err != nil {
				return nil, err
			}

			res[i-1] = dec
		}

		return newDecimalArrayValue(res, t), nil
	}

	switch *t {
	case *types.TextArrayType:
		return castArr(a, func(d *types.Decimal) (string, error) { return d.String(), nil }, newTextArrayValue)
	case *types.IntArrayType:
		return castArr(a, func(d *types.Decimal) (int64, error) { return d.Int64() }, newIntArr)
	case *types.NumericArrayType:
		return a, nil
	default:
		return nil, castErr(fmt.Errorf("cannot cast decimal array to %s", t))
	}
}

func newBlobArrayValue(b [][]byte) *blobArrayValue {
	vals := make([]blobValue, len(b))
	for i, v := range b {
		if v == nil {
			vals[i] = blobValue{bts: nil}
		} else {
			vals[i] = blobValue{bts: v}
		}
	}

	return &blobArrayValue{
		singleDimArray: newValidArr(vals),
	}
}

type blobArrayValue struct {
	// we embed BlobValue because unlike other types, there is no native pgtype embedded within
	// blob value that allows pgx to scan the value into the struct.
	singleDimArray[blobValue]
}

func (a *blobArrayValue) Null() bool {
	return !a.Valid
}

// A special Value method is needed since pgx handles byte slices differently than other types.
func (a *blobArrayValue) Value() (driver.Value, error) {
	var btss [][]byte
	for _, v := range a.Elements {
		btss = append(btss, v.bts)
	}

	return btss, nil
}

func (a *blobArrayValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	return cmpArrs(a, v, op)
}

func (a *blobArrayValue) Len() int32 {
	return int32(len(a.Elements))
}

func (a *blobArrayValue) Get(i int32) (scalarValue, error) {
	return getArr(a, i, func(bv blobValue) scalarValue {
		return &bv
	})
}

func (a *blobArrayValue) Set(i int32, v scalarValue) error {
	return setArr(a, i, v, func(v2 *blobValue) blobValue {
		return *v2
	})
}

func (a *blobArrayValue) Type() *types.DataType {
	return types.ByteaArrayType
}

func (a *blobArrayValue) RawValue() (v any) {
	if !a.Valid {
		return nil
	}

	res := make([][]byte, len(a.Elements))
	for i, v := range a.Elements {
		if v.bts != nil {
			res[i] = make([]byte, len(v.bts))
			copy(res[i], v.bts)
		}
	}

	return res
}

func (a *blobArrayValue) Cast(t *types.DataType) (value, error) {
	if a.Null() {
		return makeNull(t)
	}

	switch *t {
	case *types.TextArrayType:
		return castArr(a, func(b []byte) (string, error) { return string(b), nil }, newTextArrayValue)
	case *types.ByteaArrayType:
		return a, nil
	default:
		return nil, castErr(fmt.Errorf("cannot cast blob array to %s", t))
	}
}

func newUUIDArrayValue(u []*types.UUID) *uuidArrayValue {
	vals := make([]pgtype.UUID, len(u))
	for i, v := range u {
		if v == nil {
			vals[i] = pgtype.UUID{Valid: false}
		} else {
			vals[i] = pgtype.UUID{Bytes: *v, Valid: true}
		}
	}

	return &uuidArrayValue{
		singleDimArray: newValidArr(vals),
	}
}

type uuidArrayValue struct {
	singleDimArray[pgtype.UUID]
}

func (a *uuidArrayValue) Null() bool {
	return !a.Valid
}

func (a *uuidArrayValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	return cmpArrs(a, v, op)
}

func (a *uuidArrayValue) Len() int32 {
	return int32(len(a.Elements))
}

func (a *uuidArrayValue) Get(i int32) (scalarValue, error) {
	return getArr(a, i, func(i pgtype.UUID) scalarValue {
		return &uuidValue{i}
	})
}

func (a *uuidArrayValue) Set(i int32, v scalarValue) error {
	return setArr(a, i, v, func(v2 *uuidValue) pgtype.UUID {
		return v2.UUID
	})
}

func (a *uuidArrayValue) Type() *types.DataType {
	return types.UUIDArrayType
}

func (a *uuidArrayValue) RawValue() any {
	if !a.Valid {
		return nil
	}

	res := make([]*types.UUID, len(a.Elements))
	for i, v := range a.Elements {
		if v.Valid {
			u := types.UUID(v.Bytes)
			res[i] = &u
		}
	}

	return res
}

func (a *uuidArrayValue) Cast(t *types.DataType) (value, error) {
	if a.Null() {
		return makeNull(t)
	}

	switch *t {
	case *types.TextArrayType:
		return castArr(a, func(u *types.UUID) (string, error) { return u.String(), nil }, newTextArrayValue)
	case *types.UUIDArrayType:
		return a, nil
	case *types.ByteaArrayType:
		return castValArr(a, func(u *types.UUID) ([]byte, error) { return u.Bytes(), nil }, newBlobArrayValue)
	default:
		return nil, castErr(fmt.Errorf("cannot cast uuid array to %s", t))
	}
}

// emptyRecordValue creates a new empty record value.
func emptyRecordValue() *recordValue {
	return &recordValue{
		Fields: make(map[string]value),
	}
}

// recordValue is a special type that represents a row in a table.
type recordValue struct {
	Fields map[string]value
	Order  []string
}

func (r *recordValue) Null() bool {
	return len(r.Fields) == 0
}

func (r *recordValue) AddValue(k string, v value) error {
	_, ok := r.Fields[k]
	if ok {
		// protecting against this since it would detect non-determinism,
		// but our query planner should already protect against this
		return fmt.Errorf("record already has field %s", k)
	}

	r.Fields[k] = v
	r.Order = append(r.Order, k)
	return nil
}

func (o *recordValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	if res, early := nullCmp(o, v, op); early {
		return res, nil
	}

	val2, ok := v.(*recordValue)
	if !ok {
		return nil, makeTypeErr(o, v)
	}

	isSame := true
	if len(o.Fields) != len(val2.Fields) {
		isSame = false
	}

	if isSame {
		for i, field := range o.Order {
			v2, ok := val2.Fields[field]
			if !ok {
				isSame = false
				break
			}

			eq, err := o.Fields[field].Compare(v2, _EQUAL)
			if err != nil {
				return nil, err
			}

			if !eq.RawValue().(bool) {
				isSame = false
				break
			}

			// check the order
			if field != val2.Order[i] {
				isSame = false
				break
			}
		}
	}

	switch op {
	case _EQUAL:
		return makeBool(isSame), nil
	default:
		return nil, fmt.Errorf("%w: cannot use comparison operator %s with record type", engine.ErrComparison, op)
	}
}

func (o *recordValue) Type() *types.DataType {
	return &types.DataType{
		Name: "record", // special type that is NOT in the types package
	}
}

func (o *recordValue) RawValue() any {
	return o.Fields
}

func (o *recordValue) Cast(t *types.DataType) (value, error) {
	if o.Null() {
		return makeNull(t)
	}

	return nil, castErr(fmt.Errorf("cannot cast record to %s", t))
}

// nullValue is a special type that represents a NULL value.
// It is both a scalar and an array type.
type nullValue struct{}

var _ value = (*nullValue)(nil)

var _ arrayValue = (*nullValue)(nil)
var _ scalarValue = (*nullValue)(nil)

func (n *nullValue) Null() bool {
	return true
}

// since NullValue is a special value that can be used anywhere, it will always return null
// unless the comparison operator is IS or IS DISTINCT FROM
func (n *nullValue) Compare(v value, op comparisonOp) (*boolValue, error) {
	switch op {
	case _IS:
		if v.Null() {
			return makeBool(true), nil
		}
		return makeBool(false), nil
	case _IS_DISTINCT_FROM:
		if v.Null() {
			return makeBool(false), nil
		}
		return makeBool(true), nil
	default:
		/// otherwise, it is just null
		nv, err := makeNull(types.BoolType)
		if err != nil {
			return nil, err
		}

		bv, ok := nv.(*boolValue)
		if !ok {
			return nil, fmt.Errorf("unexpected type %T", nv)
		}

		return bv, nil
	}
}

func (n *nullValue) Type() *types.DataType {
	return types.NullType.Copy()
}

func (n *nullValue) RawValue() any {
	return nil
}

func (n *nullValue) Value() (driver.Value, error) {
	return nil, nil
}

func (n *nullValue) Cast(t *types.DataType) (value, error) {
	return makeNull(t)
}

func (n *nullValue) Arithmetic(v scalarValue, op arithmeticOp) (scalarValue, error) {
	return n, nil
}

func (n *nullValue) Unary(op unaryOp) (scalarValue, error) {
	return n, nil
}

func (n *nullValue) Len() int32 {
	return 0
}

func (n *nullValue) Get(i int32) (scalarValue, error) {
	return n, nil
}

func (n *nullValue) Set(i int32, v scalarValue) error {
	return fmt.Errorf("%w: cannot set element in null", engine.ErrArrayDimensionality)
}

// arrayOfNulls represents an array of nulls that does not (yet) have a type.
// It itself is NOT a null value; simply all of its values were sent by the client
// as null, so we do not know the type. It itself can never be null, and can be casted
// to any array type. If one of its fields is set to a non-null value, then the array
// will be converted to that type.
type arrayOfNulls struct {
	length int32 // 0-based
}

var _ driver.Valuer = (*arrayOfNulls)(nil)

var _ arrayValue = (*arrayOfNulls)(nil)

func (n *arrayOfNulls) Len() int32 {
	return n.length
}

func (n *arrayOfNulls) Get(i int32) (scalarValue, error) {
	return &nullValue{}, nil
}

func (n *arrayOfNulls) Value() (driver.Value, error) {
	// We encode as TEXT[] full of NULLs, mirroring Postgres.
	sd := newValidArr(make([]pgtype.Text, n.length))
	for i := int32(0); i < n.length; i++ {
		sd.Elements[i] = pgtype.Text{Valid: false}
	}
	return sd.Value()
}

func (n *arrayOfNulls) Set(i int32, v scalarValue) error {
	if i < 1 {
		return engine.ErrIndexOutOfBounds
	}

	// If the incoming value is NULL we simply expand the length and keep the
	// current array-of-nulls representation.
	if v.Null() {
		if i > n.length {
			n.length = i
		}
		return nil
	}

	// Non-null value: convert to the appropriate concrete array type and then
	// delegate the Set.  We mimic the previous behaviour by creating the array
	// on the fly and setting the element, but because callers ignore the
	// returned array we just perform the operation and return.
	vt := v.Type().Copy()
	vt.IsArray = true

	newVal, err := newZeroValue(vt)
	if err != nil {
		return err
	}

	concreteArr := newVal.(arrayValue)

	// Copy existing NULLs
	for idx := int32(1); idx <= n.length; idx++ {
		if err := concreteArr.Set(idx, &nullValue{}); err != nil {
			return err
		}
	}

	return concreteArr.Set(i, v)
}

func (n *arrayOfNulls) Type() *types.DataType {
	return types.NullArrayType.Copy()
}

func (n *arrayOfNulls) RawValue() any {
	return make([]any, n.length)
}

func (n *arrayOfNulls) Null() bool {
	return false
}

func (n *arrayOfNulls) Compare(v value, op comparisonOp) (*boolValue, error) {
	return cmpArrs(n, v, op)
}

func (n *arrayOfNulls) Cast(t *types.DataType) (value, error) {
	if !t.IsArray {
		return nil, fmt.Errorf("%w: cannot cast null array to non-array type", engine.ErrCast)
	}

	switch *t {
	case *types.IntArrayType:
		return newIntArr(make([]*int64, n.length)), nil
	case *types.TextArrayType:
		return newTextArrayValue(make([]*string, n.length)), nil
	case *types.BoolArrayType:
		return newBoolArrayValue(make([]*bool, n.length)), nil
	case *types.UUIDArrayType:
		return newUUIDArrayValue(make([]*types.UUID, n.length)), nil
	case *types.ByteaArrayType:
		return newBlobArrayValue(make([][]byte, n.length)), nil
	default:
		if t.Name == types.NumericStr {
			return newDecimalArrayValue(make([]*types.Decimal, n.length), t), nil
		}
		return nil, fmt.Errorf("%w: cannot cast null array to %s", engine.ErrCast, t)
	}
}

func cmpIntegers(a, b int, op comparisonOp) (*boolValue, error) {
	switch op {
	case _EQUAL:
		return makeBool(a == b), nil
	case _LESS_THAN:
		return makeBool(a < b), nil
	case _GREATER_THAN:
		return makeBool(a > b), nil
	case _IS_DISTINCT_FROM:
		return makeBool(a != b), nil
	default:
		return nil, fmt.Errorf("%w: cannot use comparison operator %s with numeric types", engine.ErrComparison, op)
	}
}

// stringifyValue converts a value to a string.
// It can be reversed using ParseValue.
func stringifyValue(v value) (string, error) {
	if v.Null() {
		return "NULL", nil
	}

	array, ok := v.(arrayValue)
	if ok {
		// we will convert each element to a string and join them with a comma
		strs := make([]string, array.Len())
		for i := int32(1); i <= array.Len(); i++ {
			val, err := array.Get(i)
			if err != nil {
				return "", err
			}

			str, err := stringifyValue(val)
			if err != nil {
				return "", err
			}

			strs[i-1] = str
		}

		return strings.Join(strs, ","), nil
	}

	switch val := v.(type) {
	case *textValue:
		return val.Text.String, nil
	case *int8Value:
		return strconv.FormatInt(val.Int64, 10), nil
	case *boolValue:
		return strconv.FormatBool(val.Bool.Bool), nil
	case *uuidValue:
		return types.UUID(val.UUID.Bytes).String(), nil
	case *decimalValue:
		dec, err := val.dec()
		if err != nil {
			return "", err
		}

		return dec.String(), nil
	case *blobValue:
		return string(val.bts), nil
	case *recordValue:
		return "", fmt.Errorf("cannot convert record to string")
	default:
		return "", fmt.Errorf("unexpected type %T", v)
	}
}

// parseValue parses a string into a value.
// It is the reverse of StringifyValue.
func parseValue(s string, t *types.DataType) (value, error) {
	if s == "NULL" {
		return makeNull(t)
	}

	if s == "" {
		return newZeroValue(t)
	}

	if t.IsArray {
		return parseArray(s, t)
	}

	if t.Name == types.NumericStr {
		dec, err := types.ParseDecimalExplicit(s, t.Metadata[0], t.Metadata[1])
		if err != nil {
			return nil, err
		}

		return makeDecimal(dec), nil
	}

	switch *t {
	case *types.TextType:
		return makeText(s), nil
	case *types.IntType:
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, err
		}

		return makeInt8(i), nil
	case *types.BoolType:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, err
		}

		return makeBool(b), nil
	case *types.UUIDType:
		u, err := types.ParseUUID(s)
		if err != nil {
			return nil, err
		}

		return makeUUID(u), nil
	case *types.ByteaType:
		return makeBlob([]byte(s)), nil
	default:
		return nil, fmt.Errorf("unexpected type %s", t)
	}
}

// parseArray parses a string into an array value.
func parseArray(s string, t *types.DataType) (arrayValue, error) {
	if s == "NULL" {
		nv, err := makeNull(t)
		if err != nil {
			return nil, err
		}

		nva, ok := nv.(arrayValue)
		if !ok {
			return nil, fmt.Errorf("unexpected type for null array %T", nv)
		}

		return nva, nil
	}

	// we will parse the string into individual values and then cast them to the
	// correct type
	strs := strings.Split(s, ",")
	fields := make([]scalarValue, len(strs))
	scalarType := t.Copy()
	scalarType.IsArray = false
	for i, str := range strs {
		val, err := parseValue(str, scalarType)
		if err != nil {
			return nil, err
		}

		scalar, ok := val.(scalarValue)
		if !ok {
			return nil, fmt.Errorf("unexpected type %T", val)
		}

		fields[i] = scalar
	}

	return makeArray(fields, t)
}

func castErr(e error) error {
	return fmt.Errorf("%w: %w", engine.ErrCast, e)
}

// makeArray creates an array value from a list of scalar values.
// All of the scalar values must be of the same type.
// If t is nil, it will infer the type from the first element.

func makeArray(vals []scalarValue, t *types.DataType) (arrayValue, error) {
	expectedType := t
	if len(vals) == 0 && expectedType == nil {
		return nil, fmt.Errorf("%w: cannot create an empty array of unknown type. Try typecasting it", engine.ErrArrayDimensionality)
	}

	// if no type has been provided, we should search for the first non-null value
	for _, v := range vals {
		if !v.Type().EqualsStrict(types.NullType) {
			if expectedType == nil {
				expectedType = v.Type().Copy()
				expectedType.IsArray = true
			}
		}
	}

	// if it is still null, it is a text array. This seems somewhat arbitrary,
	// but it is consistent with Postgres.
	if expectedType == nil {
		expectedType = types.TextType.Copy()
	}

	if !expectedType.IsArray {
		return nil, fmt.Errorf("%w: cannot cast array to a scalar type", engine.ErrCast)
	}

	// we now need to make a zero value of the new array type
	zeroVal, err := newZeroValue(expectedType)
	if err != nil {
		return nil, err
	}
	zeroArr, ok := zeroVal.(arrayValue)
	if !ok {
		return nil, fmt.Errorf("unexpected zero array value of type %T", zeroVal)
	}

	// we need the expected scalar type
	expectScalar := expectedType.Copy()
	expectScalar.IsArray = false

	// now, we must cast all of the values to the expected type
	for i, v := range vals {
		casted, err := v.Cast(expectScalar)
		if err != nil {
			return nil, err
		}
		castedScalar, ok := casted.(scalarValue)
		if !ok {
			return nil, fmt.Errorf("unexpected casted value of type %T", casted)
		}

		err = zeroArr.Set(int32(i+1), castedScalar) // 1-based index
		if err != nil {
			return nil, err
		}
	}

	return zeroArr, nil
}

// newValueWithSoftCast is a helper function that makes a new value.
// It is meant to handle user-provided values by handling edge cases where
// go's typing does not exactly match the engines. For example, if a 0-length
// decimal array is passed, there is no way for Go to know the precision and
// scale of the array. But in our interpreter, we do know this information.
// If it cannot be soft casted to the correct type, it will return a false.
// It will only return an error if there is an unexpected error.
// A value will always be returned if err is nil, even if ok is false.
func newValueWithSoftCast(v any, dt *types.DataType) (val value, ok bool, err error) {
	val, err = newValue(v)
	if err != nil {
		return nil, false, err
	}

	// if v is null or if it is a 0-length array, we need to cast it to the correct type
	if val.Null() {
		val, err = val.Cast(dt)
		if err != nil {
			return nil, false, err
		}
	}
	if arr, ok := val.(arrayValue); ok && arr.Len() == 0 {
		// if it is an array value, then the scalar type and IsArray values must match.
		if arr.Type().IsArray != dt.IsArray {
			return val, false, nil
		}
		if arr.Type().Name != dt.Name {
			return val, false, nil
		}

		val, err = val.Cast(dt)
		if err != nil {
			return nil, false, err
		}
	}

	if !val.Type().Equals(dt) {
		return val, false, nil
	}

	return val, true, nil
}

// copySingleDimArray performs a deep copy of the slice data for singleDimArray
func copySingleDimArray[T any](original *singleDimArray[T]) singleDimArray[T] {
	if original == nil {
		return newNullArray[T]()
	}
	// Shallow copy struct fields first (Valid, Dims header, Elements header)
	newArr := *original

	// Deep copy Dims slice
	if len(original.Dims) > 0 {
		newArr.Dims = make([]pgtype.ArrayDimension, len(original.Dims))
		copy(newArr.Dims, original.Dims)
	}

	// Deep copy Elements slice
	if original.Valid {
		// make a slice with capacity to allow for efficient append later via Set()
		newArr.Elements = make([]T, len(original.Elements), len(original.Elements)+1)
		copy(newArr.Elements, original.Elements)
	}
	// if !original.Valid, Elements will be nil, which is correct
	return newArr
}

// copyArray efficiently deep copies an arrayValue by copying the underlying slice,
// avoiding the slow stringify/parse cycle of copyVal.
func copyArray(v arrayValue) (arrayValue, error) {
	if v == nil {
		return nil, fmt.Errorf("copyArray: nil input")
	}
	if v.Null() {
		nullVal, err := makeNull(v.Type())
		if err != nil {
			return nil, err
		}
		return nullVal.(arrayValue), nil
	}

	switch original := v.(type) {
	case *int8ArrayValue:
		newArr := &int8ArrayValue{}
		newArr.singleDimArray = copySingleDimArray(&original.singleDimArray)
		return newArr, nil
	case *textArrayValue:
		newArr := &textArrayValue{}
		newArr.singleDimArray = copySingleDimArray(&original.singleDimArray)
		return newArr, nil
	case *boolArrayValue:
		newArr := &boolArrayValue{}
		newArr.singleDimArray = copySingleDimArray(&original.singleDimArray)
		return newArr, nil
	case *blobArrayValue:
		newArr := &blobArrayValue{}
		newArr.singleDimArray = copySingleDimArray(&original.singleDimArray)
		// The copy is shallow for blob values, so we must manually deep copy the bytes.
		if newArr.Valid {
			for i := range newArr.Elements {
				if newArr.Elements[i].bts != nil {
					newBts := make([]byte, len(newArr.Elements[i].bts))
					copy(newBts, newArr.Elements[i].bts)
					newArr.Elements[i].bts = newBts
				}
			}
		}
		return newArr, nil
	case *uuidArrayValue:
		newArr := &uuidArrayValue{}
		newArr.singleDimArray = copySingleDimArray(&original.singleDimArray)
		return newArr, nil
	case *decimalArrayValue:
		newArr := &decimalArrayValue{}
		newArr.singleDimArray = copySingleDimArray(&original.singleDimArray)
		// Copy metadata pointer if it exists
		if original.metadata != nil {
			metaCopy := *original.metadata
			newArr.metadata = &metaCopy
		}
		// The copy is shallow for decimal/numeric values, so we must manually deep copy the big.Int.
		if newArr.Valid {
			for i := range newArr.Elements {
				if newArr.Elements[i].Int != nil {
					newInt := new(big.Int)
					newInt.Set(newArr.Elements[i].Int)
					newArr.Elements[i].Int = newInt
				}
			}
		}
		return newArr, nil
	case *nullValue:
		// Handles the case where the array itself is the generic NULL type
		return &nullValue{}, nil
	case *arrayOfNulls:
		// Just copy the struct for arrayOfNulls
		newArr := *original
		return &newArr, nil
	default:
		// Fallback or error. For safety, we error.
		// We could optionally fallback: return copyVal(v)
		return nil, fmt.Errorf("unsupported array type for efficient copyArray: %T", v)
	}
}

// copyVal deep copies a value.
// There are certainly more efficient ways to do this, but I am doing this
// under a time constraint.
// NOTE: This is slow, use copyArray for array types where possible.
func copyVal[V value](v V) (V, error) {
	// all errors returned in this function signal some sort of
	// internal bug, and not a user error.
	v2 := *new(V)
	str, err := stringifyValue(v)
	if err != nil {
		return v2, fmt.Errorf("could not copy val: %w", err)
	}

	parsed, err := parseValue(str, v.Type())
	if err != nil {
		return v2, fmt.Errorf("could not copy val: %w", err)
	}

	v3, ok := parsed.(V)
	if !ok {
		return v2, fmt.Errorf("could not copy val: unexpected type %T", parsed)
	}

	return v3, nil
}
