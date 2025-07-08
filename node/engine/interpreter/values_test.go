package interpreter

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
)

func Test_Arithmetic(t *testing.T) {
	type testcase struct {
		name   string
		a      any
		b      any
		add    any
		sub    any
		mul    any
		div    any
		mod    any
		concat any
		exp    any
	}

	tests := []testcase{
		{
			name:   "int",
			a:      int64(10),
			b:      int64(5),
			add:    int64(15),
			sub:    int64(5),
			mul:    int64(50),
			div:    int64(2),
			mod:    int64(0),
			concat: engine.ErrArithmetic,
			exp:    int64(100000),
		},
		{
			name:   "decimal",
			a:      mustExplicitDecimal("10.00", 100, 50),
			b:      mustExplicitDecimal("5.00", 100, 50),
			add:    mustDec("15.00"),
			sub:    mustDec("5.00"),
			mul:    mustDec("50.00"),
			div:    mustDec("2.00"),
			mod:    mustDec("0.00"),
			concat: engine.ErrArithmetic,
			exp:    mustExplicitDecimal("100000.00", 100, 50),
		},
		{
			name:   "text",
			a:      "hello",
			b:      "world",
			add:    engine.ErrArithmetic,
			sub:    engine.ErrArithmetic,
			mul:    engine.ErrArithmetic,
			div:    engine.ErrArithmetic,
			mod:    engine.ErrArithmetic,
			concat: "helloworld",
			exp:    engine.ErrArithmetic,
		},
		{
			name:   "uuid",
			a:      mustUUID("550e8400-e29b-41d4-a716-446655440000"),
			b:      mustUUID("550e8400-e29b-41d4-a716-446655440000"),
			add:    engine.ErrArithmetic,
			sub:    engine.ErrArithmetic,
			mul:    engine.ErrArithmetic,
			div:    engine.ErrArithmetic,
			mod:    engine.ErrArithmetic,
			concat: engine.ErrArithmetic,
			exp:    engine.ErrArithmetic,
		},
		{
			name:   "blob",
			a:      []byte("hello"),
			b:      []byte("world"),
			add:    engine.ErrArithmetic,
			sub:    engine.ErrArithmetic,
			mul:    engine.ErrArithmetic,
			div:    engine.ErrArithmetic,
			mod:    engine.ErrArithmetic,
			concat: []byte("helloworld"),
			exp:    engine.ErrArithmetic,
		},
		{
			name:   "bool",
			a:      true,
			b:      false,
			add:    engine.ErrArithmetic,
			sub:    engine.ErrArithmetic,
			mul:    engine.ErrArithmetic,
			div:    engine.ErrArithmetic,
			mod:    engine.ErrArithmetic,
			concat: engine.ErrArithmetic,
			exp:    engine.ErrArithmetic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			makeVal := func(v any) scalarValue {
				val, err := NewValue(v)
				require.NoError(t, err)
				return val.(scalarValue)
			}

			a := makeVal(tt.a)
			b := makeVal(tt.b)

			isErrOrResult := func(a, b scalarValue, op arithmeticOp, want any) {
				res, err := a.Arithmetic(b, op)
				if wantErr, ok := want.(error); ok {
					require.Error(t, err)
					require.ErrorIs(t, err, wantErr)
					return
				}
				require.NoError(t, err)

				raw := res.RawValue()

				eq(t, want, raw)

				// operations on null values should always return null
				null, err := makeNull(a.Type())
				require.NoError(t, err)

				res, err = a.Arithmetic(null.(scalarValue), op)
				require.NoError(t, err)

				require.True(t, res.Null())
				require.Nil(t, res.RawValue())
			}

			isErrOrResult(a, b, _ADD, tt.add)
			isErrOrResult(a, b, _SUB, tt.sub)
			isErrOrResult(a, b, _MUL, tt.mul)
			isErrOrResult(a, b, _DIV, tt.div)
			isErrOrResult(a, b, _MOD, tt.mod)
			isErrOrResult(a, b, _EXP, tt.exp)
			isErrOrResult(a, b, _CONCAT, tt.concat)

			// test rountripping strings
			testRoundTripParse(t, a)
			testRoundTripParse(t, b)
		})
	}
}

// eq is a helper function that checks if two values are equal.
// It handles the semantics of comparing decimal values.
func eq(t *testing.T, a, b any) {
	// if the values are decimals, we need to compare them manually
	if aDec, ok := a.(*types.Decimal); ok {
		bDec, ok := b.(*types.Decimal)
		require.True(t, ok)

		rec, err := aDec.Cmp(bDec)
		require.NoError(t, err)
		assert.Zero(t, rec)
		return
	}

	if aDec, ok := a.([]*types.Decimal); ok {
		bDec, ok := b.([]*types.Decimal)
		require.True(t, ok)

		require.Len(t, aDec, len(bDec))
		for i := range aDec {
			if aDec[i] == nil {
				assert.Nil(t, bDec[i])
				continue
			}
			eq(t, aDec[i], bDec[i])
		}
		return
	}

	assert.EqualValues(t, a, b)
}

func Test_Comparison(t *testing.T) {
	type testcase struct {
		name         string
		a            any
		b            any
		gt           any
		lt           any
		eq           any
		is           any
		distinctFrom any
	}

	// there are 6 types: int, text, bool, blob, uuid, decimal
	// Each type can also have a one dimensional array of that type
	// We need tests for each type and each array type, testing comparison against each other
	// as well as against null values.
	tests := []testcase{
		{
			name:         "int",
			a:            int64(10),
			b:            int64(5),
			eq:           false,
			gt:           true,
			lt:           false,
			is:           engine.ErrComparison,
			distinctFrom: true,
		},
		{
			name:         "decimal",
			a:            mustDec("10.00"),
			b:            mustDec("5.00"),
			eq:           false,
			gt:           true,
			lt:           false,
			is:           engine.ErrComparison,
			distinctFrom: true,
		},
		{
			name:         "text",
			a:            "hello",
			b:            "world",
			eq:           false,
			gt:           false,
			lt:           true,
			is:           engine.ErrComparison,
			distinctFrom: true,
		},
		{
			name:         "uuid",
			a:            mustUUID("550e8400-e29b-41d4-a716-446655440000"),
			b:            mustUUID("550e8400-e29b-41d4-a716-446655440000"),
			eq:           true,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: false,
		},
		{
			name:         "blob",
			a:            []byte("hello"),
			b:            []byte("world"),
			eq:           false,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: true,
		},
		{
			name:         "bool",
			a:            true,
			b:            false,
			eq:           false,
			gt:           true,
			lt:           false,
			is:           false,
			distinctFrom: true,
		},
		{
			name:         "int-null",
			a:            int64(10),
			b:            nil,
			eq:           nil,
			gt:           nil,
			lt:           nil,
			is:           false,
			distinctFrom: true,
		},
		{
			name:         "null-null",
			a:            nil,
			b:            nil,
			eq:           nil,
			gt:           nil,
			lt:           nil,
			is:           true,
			distinctFrom: false,
		},
		// array tests
		{
			name:         "int-array",
			a:            []int64{1, 2, 3},
			b:            []int64{1, 2, 3},
			eq:           true,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: false,
		},
		{
			name:         "text-array",
			a:            []string{"hello", "world"},
			b:            []string{"hello", "world"},
			eq:           true,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: false,
		},
		{
			name:         "decimal-array",
			a:            []*types.Decimal{mustDec("1.00"), mustDec("2.00"), mustDec("3.00")},
			b:            []*types.Decimal{mustDec("1.00"), mustDec("2.00"), mustDec("3.00")},
			eq:           true,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: false,
		},
		{
			name:         "text array not equal",
			a:            []string{"hello", "world"},
			b:            []string{"world", "hello"},
			eq:           false,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: true,
		},
		{
			name:         "uuid-array",
			a:            []*types.UUID{mustUUID("550e8400-e29b-41d4-a716-446655440000")},
			b:            []*types.UUID{mustUUID("550e8400-e29b-41d4-a716-446655440000")},
			eq:           true,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: false,
		},
		{
			name:         "blob-array",
			a:            [][]byte{[]byte("hello"), []byte("world")},
			b:            [][]byte{[]byte("hello"), []byte("world")},
			eq:           true,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: false,
		},
		{
			name:         "bool-array",
			a:            []bool{true, false},
			b:            []bool{true, false},
			eq:           true,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: false,
		},
		{
			name:         "int-array-null",
			a:            []int64{1, 2, 3},
			b:            nil,
			eq:           nil,
			gt:           nil,
			lt:           nil,
			is:           false,
			distinctFrom: true,
		},
		{
			name:         "nullarray-nullarray",
			a:            []any{nil, nil, nil},
			b:            []any{nil, nil, nil},
			eq:           true,
			gt:           engine.ErrComparison,
			lt:           engine.ErrComparison,
			is:           engine.ErrComparison,
			distinctFrom: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			makeVal := func(v any) Value {
				val, err := NewValue(v)
				require.NoError(t, err)
				return val
			}

			a := makeVal(tt.a)
			b := makeVal(tt.b)

			isErrOrResult := func(a, b Value, op comparisonOp, want any) {
				t.Log(op.String())
				res, err := a.Compare(b, op)
				if wantErr, ok := want.(error); ok {
					require.Error(t, err)
					require.ErrorIs(t, err, wantErr)
					return
				}
				require.NoError(t, err)

				switch wantVal := want.(type) {
				default:
					require.EqualValues(t, wantVal, res.RawValue())
				case nil:
					require.True(t, res.Null())
					require.Nil(t, res.RawValue())
				case bool:
					require.Equal(t, wantVal, res.RawValue())
				case *bool:
					require.Equal(t, *wantVal, res.RawValue())
				}
			}

			isErrOrResult(a, b, _LESS_THAN, tt.lt)
			isErrOrResult(a, b, _GREATER_THAN, tt.gt)
			isErrOrResult(a, b, _EQUAL, tt.eq)
			isErrOrResult(a, b, _IS, tt.is)
			isErrOrResult(a, b, _IS_DISTINCT_FROM, tt.distinctFrom)

			// test rountripping strings
			testRoundTripParse(t, a)
			testRoundTripParse(t, b)
		})
	}
}

func Test_Cast(t *testing.T) {
	// for this test, we want to test each type and array type,
	// and ensure it can be casted to each other type and array type
	// all numerics will be precision 10, scale 5.
	// If a Value is left as nil, it will expect an error when casted to that type.
	type testcase struct {
		name       string
		val        any
		intVal     any
		text       any
		boolVal    any
		decimalVal any
		uuidVal    any
		blobVal    any
		intArr     any
		textArr    any
		boolArr    any
		decimalArr any
		uuidArr    any
		blobArr    any
	}

	mDec := func(dec string) *types.Decimal {
		// all decimals will be precision 10, scale 5
		d, err := types.ParseDecimal(dec)
		require.NoError(t, err)

		err = d.SetPrecisionAndScale(10, 5)
		require.NoError(t, err)
		return d
	}

	mDecArr := func(decimals ...string) []*types.Decimal {
		var res []*types.Decimal
		for _, dec := range decimals {
			res = append(res, mDec(dec))
		}
		return res
	}
	_ = mDecArr

	tests := []testcase{
		{
			name:       "int",
			val:        int64(10),
			intVal:     int64(10),
			text:       "10",
			boolVal:    true,
			decimalVal: mDec("10.00000"),
		},
		{
			name:    "text",
			val:     "hello",
			text:    "hello",
			blobVal: []byte("hello"),
		},
		{
			name:       "text (number)",
			val:        "10",
			intVal:     10,
			text:       "10",
			decimalVal: mDec("10.00000"),
			blobVal:    []byte("10"),
		},
		{
			name:    "text (bool)",
			val:     "true",
			boolVal: true,
			text:    "true",
			blobVal: []byte("true"),
		},
		{
			name:       "text (decimal)",
			val:        "10.5",
			decimalVal: mDec("10.50000"),
			text:       "10.5",
			blobVal:    []byte("10.5"),
		},
		{
			name:    "text (uuid)",
			val:     "550e8400-e29b-41d4-a716-446655440000",
			uuidVal: mustUUID("550e8400-e29b-41d4-a716-446655440000"),
			text:    "550e8400-e29b-41d4-a716-446655440000",
			blobVal: []byte("550e8400-e29b-41d4-a716-446655440000"),
		},
		{
			name:    "bool",
			val:     true,
			boolVal: true,
			text:    "true",
			intVal:  int64(1),
		},
		{
			name:       "decimal",
			val:        mDec("10.00000"),
			decimalVal: mDec("10.00000"),
			text:       "10.00000",
			intVal:     int64(10),
		},
		{
			name:    "uuid",
			val:     mustUUID("550e8400-e29b-41d4-a716-446655440000"),
			uuidVal: mustUUID("550e8400-e29b-41d4-a716-446655440000"),
			text:    "550e8400-e29b-41d4-a716-446655440000",
			blobVal: mustUUID("550e8400-e29b-41d4-a716-446655440000").Bytes(),
		},
		{
			name:    "blob",
			val:     []byte("hello"),
			blobVal: []byte("hello"),
			text:    "hello",
		},
		{
			name:       "int-array",
			val:        []int64{1, 2, 3},
			intArr:     []int64{1, 2, 3},
			textArr:    []string{"1", "2", "3"},
			boolArr:    []bool{true, true, true},
			decimalArr: mDecArr("1", "2", "3"),
		},
		{
			name:    "text-array",
			val:     []string{"hello", "world"},
			textArr: []string{"hello", "world"},
			blobArr: [][]byte{[]byte("hello"), []byte("world")},
		},
		{
			name:    "text-array (uuid)",
			val:     []string{"550e8400-e29b-41d4-a716-446655440000"},
			uuidArr: []*types.UUID{mustUUID("550e8400-e29b-41d4-a716-446655440000")},
			textArr: []string{"550e8400-e29b-41d4-a716-446655440000"},
			blobArr: [][]byte{[]byte("550e8400-e29b-41d4-a716-446655440000")},
		},
		{
			name:    "bool-array",
			val:     []bool{true, false},
			boolArr: []bool{true, false},
			textArr: []string{"true", "false"},
			intArr:  []int64{1, 0},
		},
		{
			name:       "decimal-array",
			val:        mDecArr("1", "2", "3"),
			decimalArr: mDecArr("1", "2", "3"),
			textArr:    []string{"1.00000", "2.00000", "3.00000"},
			intArr:     []int64{1, 2, 3},
		},
		{
			name:    "uuid-array",
			val:     []*types.UUID{mustUUID("550e8400-e29b-41d4-a716-446655440000")},
			uuidArr: []*types.UUID{mustUUID("550e8400-e29b-41d4-a716-446655440000")},
			textArr: []string{"550e8400-e29b-41d4-a716-446655440000"},
			blobArr: [][]byte{mustUUID("550e8400-e29b-41d4-a716-446655440000").Bytes()},
		},
		{
			name:    "blob-array",
			val:     [][]byte{[]byte("hello"), []byte("world"), nil},
			blobArr: [][]byte{[]byte("hello"), []byte("world"), nil},
			textArr: []*string{ptr("hello"), ptr("world"), nil},
		},
		{
			name:       "null array",
			val:        []any{nil, nil},
			intArr:     make([]*int64, 2),
			textArr:    make([]*string, 2),
			boolArr:    make([]*bool, 2),
			decimalArr: make([]*types.Decimal, 2),
			uuidArr:    make([]*types.UUID, 2),
			blobArr:    [][]byte{nil, nil},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := NewValue(tt.val)
			require.NoError(t, err)

			check := func(dataType *types.DataType, want any) {
				t.Log(dataType.String())
				if want == nil {
					want = engine.ErrCast
				}

				res, err := val.Cast(dataType)
				if wantErr, ok := want.(error); ok {
					assert.Error(t, err)
					assert.ErrorIs(t, err, wantErr)
					return
				}
				require.NoError(t, err)

				eq(t, want, res.RawValue())
			}

			decimalType, err := types.NewNumericType(10, 5)
			require.NoError(t, err)

			decArrType := decimalType.Copy()
			decArrType.IsArray = true

			check(types.IntType, tt.intVal)
			check(types.TextType, tt.text)
			check(types.BoolType, tt.boolVal)
			check(decimalType, tt.decimalVal)
			check(types.UUIDType, tt.uuidVal)
			check(types.ByteaType, tt.blobVal)

			if intArr, ok := tt.intArr.([]int64); ok {
				tt.intArr = ptrArr(intArr)
			}
			if textArr, ok := tt.textArr.([]string); ok {
				tt.textArr = ptrArr(textArr)
			}
			if boolArr, ok := tt.boolArr.([]bool); ok {
				tt.boolArr = ptrArr(boolArr)
			}

			check(types.IntArrayType, tt.intArr)
			check(types.TextArrayType, tt.textArr)
			check(types.BoolArrayType, tt.boolArr)
			check(decArrType, tt.decimalArr)
			check(types.UUIDArrayType, tt.uuidArr)
			check(types.ByteaArrayType, tt.blobArr)

			// test rountripping strings
			testRoundTripParse(t, val)
		})
	}
}

func Test_CastNumerics(t *testing.T) {
	intVal, err := NewValue(int64(10))
	require.NoError(t, err)

	textVal, err := NewValue("10")
	require.NoError(t, err)

	nt, err := types.NewNumericType(10, 5)
	require.NoError(t, err)

	dec1, err := intVal.Cast(nt)
	require.NoError(t, err)

	dec2, err := textVal.Cast(nt)
	require.NoError(t, err)

	eq(t, dec1.RawValue(), dec2.RawValue())
	eq(t, dec1.Type(), dec2.Type())
}

func Test_Unary(t *testing.T) {
	type testcase struct {
		name string
		val  any
		pos  any
		neg  any
		not  any
	}

	// any values left nil will expect an error when the unary operator is applied
	tests := []testcase{
		{
			name: "int",
			val:  int64(10),
			pos:  int64(10),
			neg:  int64(-10),
		},
		{
			name: "decimal",
			val:  mustDec("10.00"),
			pos:  mustDec("10.00"),
			neg:  mustDec("-10.00"),
		},
		{
			name: "text",
			val:  "hello",
			// text values should not be able to be used with unary operators
		},
		{
			name: "uuid",
			val:  mustUUID("550e8400-e29b-41d4-a716-446655440000"),
			// uuid values should not be able to be used with unary operators
		},
		{
			name: "blob",
			// blob values should not be able to be used with unary operators
			val: []byte("hello"),
		},
		{
			name: "bool",
			val:  true,
			not:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := NewValue(tt.val)
			require.NoError(t, err)
			scal, ok := val.(scalarValue)
			require.True(t, ok)

			check := func(op unaryOp, want any) {
				if want == nil {
					want = engine.ErrUnary
				}

				t.Log(op.String())
				res, err := scal.Unary(op)
				if wantErr, ok := want.(error); ok {
					require.Error(t, err)
					require.ErrorIs(t, err, wantErr)
					return
				}

				require.NoError(t, err)
				eq(t, want, res.RawValue())
			}

			check(_POS, tt.pos)
			check(_NEG, tt.neg)
			check(_NOT, tt.not)

			// test rountripping strings
			testRoundTripParse(t, val)
		})
	}
}

func Test_MakeArray(t *testing.T) {
	type testcase struct {
		name    string
		vals    []any
		wantErr error
	}

	// all values will be put into an array.
	// unless the wantErr is specified, it will expect the array to be created successfully

	tests := []testcase{
		{
			name: "int",
			vals: []any{int64(1), int64(2), int64(3)},
		},
		{
			name: "decimal",
			vals: []any{mustDec("1.00"), mustDec("2.00"), mustDec("3.00")},
		},
		{
			name: "text",
			vals: []any{"hello", "world"},
		},
		{
			name: "uuid",
			vals: []any{mustUUID("550e8400-e29b-41d4-a716-446655440000"), mustUUID("550e8400-e29b-41d4-a716-446655440001")},
		},
		{
			name: "blob",
			vals: []any{[]byte("hello"), []byte("world")},
		},
		{
			name: "bool",
			vals: []any{true, false},
		},
		{
			name:    "mixed",
			vals:    []any{int64(1), "hello"},
			wantErr: engine.ErrCast,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.vals) == 0 {
				t.Fatal("no values provided")
			}

			var vals []scalarValue
			for _, v := range tt.vals {
				val, err := NewValue(v)
				require.NoError(t, err)
				vals = append(vals, val.(scalarValue))
			}

			res, err := makeArray(vals, nil)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			for i := range res.Len() {
				s, err := res.Get(i + 1) // 1-indexed
				require.NoError(t, err)

				eq(t, tt.vals[i], s.RawValue())
			}

			// we will now set them all to nulls and test that the array is created successfully
			dt := vals[0].Type()
			for i := range vals {
				nullVal, err := makeNull(dt)
				require.NoError(t, err)

				err = res.Set(int32(i+1), nullVal.(scalarValue))
				require.NoError(t, err)
			}

			for i := range res.Len() {
				s, err := res.Get(i + 1) // 1-indexed
				require.NoError(t, err)

				isNull := s.Null()
				_ = isNull
				require.True(t, s.Null())
				require.Nil(t, s.RawValue())
			}

			// test rountripping strings
			testRoundTripParse(t, res)
		})
	}
}

// this test tests setting null values to an array of different types
func Test_SetArrayNull(t *testing.T) {
	decType, err := types.NewNumericType(10, 5)
	require.NoError(t, err)
	decType.IsArray = true
	for _, dt := range []*types.DataType{
		types.IntArrayType,
		types.TextArrayType,
		types.BoolArrayType,
		decType,
		types.UUIDArrayType,
		types.ByteaArrayType,
	} {
		n, err := makeNull(dt)
		require.NoError(t, err)

		err = n.(arrayValue).Set(1, &nullValue{})
		require.NoError(t, err)
	}
}

// ptrArr is a helper function that converts a slice of values to a slice of pointers to those values.
// Since Kwil returns pointers to account for nulls, we need to convert the slice of values to pointers
func ptrArr[T any](arr []T) []*T {
	var res []*T
	for i := range arr {
		res = append(res, &arr[i])
	}
	return res
}

func ptr[T any](v T) *T {
	return &v
}

func mustDec(dec string) *types.Decimal {
	d, err := types.ParseDecimal(dec)
	if err != nil {
		panic(err)
	}
	return d
}

func mustExplicitDecimal(dec string, precision, scale uint16) *types.Decimal {
	d, err := types.ParseDecimalExplicit(dec, precision, scale)
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

// testRoundTripParse is a helper function that formats a Value to a string, then parses it back to a Value.
// It is meant to be used within these other tests.
func testRoundTripParse(t *testing.T, v Value) {
	if _, ok := v.(*nullValue); ok {
		return
	}
	if _, ok := v.(*arrayOfNulls); ok {
		return
	}
	str, err := stringifyValue(v)
	require.NoError(t, err)

	val2, err := parseValue(str, v.Type())
	require.NoError(t, err)

	equal, err := v.Compare(val2, _EQUAL)
	require.NoError(t, err)

	if !equal.RawValue().(bool) {
		t.Fatalf("values not equal: %v != %v", v.RawValue(), val2.RawValue())
	}
}

func Test_blobValue_Cast(t *testing.T) {
	type fields struct {
		bts []byte
	}
	type args struct {
		t *types.DataType
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    Value
		wantErr bool
	}{
		{
			name: "cast to int - valid",
			fields: fields{
				bts: []byte("123"),
			},
			args: args{
				t: types.IntType,
			},
			want:    makeInt8(123),
			wantErr: false,
		},
		{
			name: "cast to int - invalid",
			fields: fields{
				bts: []byte("not an int"),
			},
			args: args{
				t: types.IntType,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "cast to text",
			fields: fields{
				bts: []byte("hello world"),
			},
			args: args{
				t: types.TextType,
			},
			want:    makeText("hello world"),
			wantErr: false,
		},
		{
			name: "cast to bytea - same type",
			fields: fields{
				bts: []byte{0x01, 0x02, 0x03},
			},
			args: args{
				t: types.ByteaType,
			},
			want: &blobValue{
				bts: []byte{0x01, 0x02, 0x03},
			},
			wantErr: false,
		},
		{
			name: "cast to unsupported type",
			fields: fields{
				bts: []byte("data"),
			},
			args: args{
				t: types.BoolType,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "cast to numeric - not supported",
			fields: fields{
				bts: []byte("123.45"),
			},
			args: args{
				t: types.NumericType,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "cast to uuid - not supported",
			fields: fields{
				bts: []byte("550e8400-e29b-41d4-a716-446655440000"),
			},
			args: args{
				t: types.UUIDType,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "cast to array type - not supported",
			fields: fields{
				bts: []byte("test"),
			},
			args: args{
				t: types.TextArrayType,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "cast empty blob to int",
			fields: fields{
				bts: []byte(""),
			},
			args: args{
				t: types.IntType,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "cast zero int",
			fields: fields{
				bts: []byte("0"),
			},
			args: args{
				t: types.IntType,
			},
			want:    makeInt8(0),
			wantErr: false,
		},
		{
			name: "cast negative int",
			fields: fields{
				bts: []byte("-42"),
			},
			args: args{
				t: types.IntType,
			},
			want:    makeInt8(-42),
			wantErr: false,
		},
		{
			name: "cast max int64",
			fields: fields{
				bts: []byte("9223372036854775807"),
			},
			args: args{
				t: types.IntType,
			},
			want:    makeInt8(9223372036854775807),
			wantErr: false,
		},
		{
			name: "cast overflow int64",
			fields: fields{
				bts: []byte("9223372036854775808"),
			},
			args: args{
				t: types.IntType,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &blobValue{
				bts: tt.fields.bts,
			}
			got, err := b.Cast(tt.args.t)
			if (err != nil) != tt.wantErr {
				t.Errorf("blobValue.Cast() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("blobValue.Cast() = %v, want %v", got, tt.want)
			}
		})
	}
}
