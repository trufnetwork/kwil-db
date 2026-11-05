package types

import (
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptrEq[T any](t *testing.T, v T, a any) {
	assert.EqualValues(t, &v, a)
}

func TestEncodedValue_EdgeCases(t *testing.T) {
	t.Run("encode max int64", func(t *testing.T) {
		exp := int64(9223372036854775807)
		ev, err := EncodeValue(exp)
		require.NoError(t, err)
		decoded, err := ev.Decode()
		require.NoError(t, err)
		assert.Equal(t, &exp, decoded)
	})

	t.Run("encode nil int64", func(t *testing.T) {
		var i *int64
		ev, err := EncodeValue(i)
		require.NoError(t, err)

		decoded, err := ev.Decode()
		require.NoError(t, err)

		assert.Nil(t, decoded)
	})

	t.Run("encode 0 int64 ptr", func(t *testing.T) {
		i := int64(0)
		ev, err := EncodeValue(&i)
		require.NoError(t, err)

		decoded, err := ev.Decode()
		require.NoError(t, err)

		i64, ok := decoded.(*int64)
		require.True(t, ok)

		assert.Equal(t, i, *i64)
	})

	t.Run("encode min int64", func(t *testing.T) {
		exp := int64(-9223372036854775808)
		ev, err := EncodeValue(exp)
		require.NoError(t, err)
		decoded, err := ev.Decode()
		require.NoError(t, err)
		assert.Equal(t, &exp, decoded)
	})

	t.Run("encode empty string", func(t *testing.T) {
		ev, err := EncodeValue("")
		require.NoError(t, err)
		decoded, err := ev.Decode()
		require.NoError(t, err)
		ptrEq(t, "", decoded)
		ptrEq(t, "", decoded)
	})

	t.Run("encode empty byte slice", func(t *testing.T) {
		ev, err := EncodeValue([]byte{})
		require.NoError(t, err)
		decoded, err := ev.Decode()
		require.NoError(t, err)
		ptrEq(t, []byte{}, decoded)
	})

	t.Run("encode nil byte slice", func(t *testing.T) {
		var b []byte
		ev, err := EncodeValue(b)
		require.NoError(t, err)
		decoded, err := ev.Decode()
		require.NoError(t, err)
		assert.Nil(t, decoded)
	})

	// THIS IS INCORRECT WITH scientific notation e.g 1e-28
	t.Run("encode decimal with max precision", func(t *testing.T) {
		d, err := NewDecimalFromBigInt(new(big.Int).SetInt64(1), -6)
		require.NoError(t, err)
		ev, err := EncodeValue(d)
		require.NoError(t, err)
		decoded, err := ev.Decode()
		require.NoError(t, err)
		assert.Equal(t, d.String(), decoded.(*Decimal).String())
	})

	t.Run("encode mixed array types should fail", func(t *testing.T) {
		_, err := EncodeValue([]interface{}{"string", 42})
		assert.Error(t, err)
	})

	t.Run("decode invalid type", func(t *testing.T) {
		ev := &EncodedValue{
			Type: DataType{Name: "invalid_type"},
			Data: [][]byte{{1, 2, 3}},
		}
		_, err := ev.Decode()
		assert.Error(t, err)
	})

	t.Run("decode invalid int length", func(t *testing.T) {
		ev := &EncodedValue{
			Type: DataType{Name: IntType.Name},
			Data: [][]byte{{1, 2, 3}},
		}
		_, err := ev.Decode()
		assert.Error(t, err)
	})

	t.Run("decode invalid uuid length", func(t *testing.T) {
		ev := &EncodedValue{
			Type: DataType{Name: UUIDType.Name},
			Data: [][]byte{{1, 2, 3}},
		}
		_, err := ev.Decode()
		assert.Error(t, err)
	})

	t.Run("encode/decode decimal array", func(t *testing.T) {
		d1, _ := ParseDecimal("100")
		d2, _ := ParseDecimal("200")
		arr := DecimalArray{d1, d2}

		ev, err := EncodeValue(arr)
		require.NoError(t, err)

		decoded, err := ev.Decode()
		require.NoError(t, err)

		decodedArr, ok := decoded.([]*Decimal)
		require.True(t, ok)
		assert.Equal(t, arr[0].String(), decodedArr[0].String())
		assert.Equal(t, arr[1].String(), decodedArr[1].String())
	})

	// encode/decode pointer of arrays
	t.Run("encode/decode pointer of arrays", func(t *testing.T) {
		a := int64(1)
		b := int64(2)
		arr := []*int64{&a, &b, nil}

		ev, err := EncodeValue(arr)
		require.NoError(t, err)

		decoded, err := ev.Decode()
		require.NoError(t, err)

		decodedArr, ok := decoded.([]*int64)
		require.True(t, ok)

		for i := range arr {
			assert.Equal(t, arr[i], decodedArr[i])
		}
	})

	t.Run("array of all null", func(t *testing.T) {
		ev, err := EncodeValue([]*string{nil, nil, nil})
		require.NoError(t, err)

		decoded, err := ev.Decode()
		require.NoError(t, err)

		assert.Equal(t, []any{nil, nil, nil}, decoded)
	})

	t.Run("encode array of pointers", func(t *testing.T) {
		a := int64(1)
		b := int64(2)
		arr := []*int64{&a, &b}

		ev, err := EncodeValue(arr)
		require.NoError(t, err)

		decoded, err := ev.Decode()
		require.NoError(t, err)

		decodedArr, ok := decoded.([]*int64)
		require.True(t, ok)

		for i := range arr {
			assert.Equal(t, arr[i], decodedArr[i])
		}
	})
}

func TestDecodeArrayTypes(t *testing.T) {
	t.Run("decode text array", func(t *testing.T) {
		e := &EncodedValue{
			Type: DataType{Name: TextType.Name, IsArray: true},
			Data: [][]byte{append([]byte{1}, []byte("hello")...), append([]byte{1}, []byte("world")...)},
		}
		decoded, err := e.Decode()
		require.NoError(t, err)
		h := "hello"
		w := "world"
		assert.EqualValues(t, []*string{&h, &w}, decoded)
	})

	t.Run("decode int array", func(t *testing.T) {
		e := &EncodedValue{
			Type: DataType{Name: IntType.Name, IsArray: true},
			Data: [][]byte{
				binary.BigEndian.AppendUint64([]byte{1}, 123),
				binary.BigEndian.AppendUint64([]byte{1}, 456),
			},
		}
		decoded, err := e.Decode()
		require.NoError(t, err)
		o123 := int64(123)
		o456 := int64(456)
		assert.EqualValues(t, []*int64{&o123, &o456}, decoded)
	})

	t.Run("decode blob array", func(t *testing.T) {
		e := &EncodedValue{
			Type: DataType{Name: ByteaType.Name, IsArray: true},
			Data: [][]byte{{1, 1, 2, 3}, {1, 4, 5, 6}},
		}
		decoded, err := e.Decode()
		require.NoError(t, err)
		assert.Equal(t, []*[]byte{{1, 2, 3}, {4, 5, 6}}, decoded)
	})

	t.Run("decode partially null blob array", func(t *testing.T) {
		e := &EncodedValue{
			Type: DataType{Name: ByteaType.Name, IsArray: true},
			Data: [][]byte{{1, 1, 2, 3}, {0}},
		}
		decoded, err := e.Decode()
		require.NoError(t, err)
		assert.Equal(t, []*[]byte{{1, 2, 3}, nil}, decoded)
	})

	t.Run("decode bool array", func(t *testing.T) {
		e := &EncodedValue{
			Type: DataType{Name: BoolType.Name, IsArray: true},
			Data: [][]byte{{1, 1}, {1, 0}},
		}
		decoded, err := e.Decode()
		require.NoError(t, err)
		tr := true
		f := false
		assert.Equal(t, []*bool{&tr, &f}, decoded)
	})

	t.Run("decode null array", func(t *testing.T) {
		e := &EncodedValue{
			Type: DataType{Name: NullType.Name, IsArray: true},
			Data: [][]byte{encodeNull(), encodeNull()},
		}
		v, err := e.Decode()
		require.NoError(t, err)

		assert.Equal(t, []any{nil, nil}, v)
	})

	t.Run("decode array with invalid element", func(t *testing.T) {
		e := &EncodedValue{
			Type: DataType{Name: IntType.Name, IsArray: true},
			Data: [][]byte{encodeNotNull([]byte("123")), encodeNotNull([]byte("invalid"))},
		}
		_, err := e.Decode()
		require.Error(t, err)
	})

	t.Run("decode empty array", func(t *testing.T) {
		e := &EncodedValue{
			Type: DataType{Name: TextType.Name, IsArray: true},
			Data: [][]byte{},
		}
		decoded, err := e.Decode()
		require.NoError(t, err)
		assert.Equal(t, []*string{}, decoded)
	})
}

// malformedEncodedValues returns values that no encoder in this package
// produces but that a client can still send, through a binary payload or
// through JSON. Decode must return an error for each of them and must never
// panic.
func malformedEncodedValues() map[string]*EncodedValue {
	numeric := [2]uint16{10, 2}
	scalar := func(name string, md [2]uint16, data ...[]byte) *EncodedValue {
		return &EncodedValue{Type: DataType{Name: name, Metadata: md}, Data: data}
	}
	array := func(name string, md [2]uint16, data ...[]byte) *EncodedValue {
		return &EncodedValue{Type: DataType{Name: name, IsArray: true, Metadata: md}, Data: data}
	}

	cases := map[string]*EncodedValue{
		// A bool with the not-null marker and no value byte.
		"bool marker only":       scalar("bool", [2]uint16{}, []byte{1}),
		"boolean marker only":    scalar("boolean", [2]uint16{}, []byte{1}),
		"bool array marker only": array("bool", [2]uint16{}, []byte{1, 1}, []byte{1}),

		// Wrong number of elements for a scalar.
		"text no elements":  scalar("text", [2]uint16{}),
		"text two elements": scalar("text", [2]uint16{}, []byte{1, 'a'}, []byte{1, 'b'}),

		// Bad null marker byte.
		"text marker 2":              scalar("text", [2]uint16{}, []byte{2, 'a'}),
		"text null with extra bytes": scalar("text", [2]uint16{}, []byte{0, 'a'}),
		"null type marker 1":         scalar("null", [2]uint16{}, []byte{1}),
		"null type two elements":     scalar("null", [2]uint16{}, []byte{0}, []byte{0}),

		// Fixed size values with the wrong length.
		"int short":        scalar("int8", [2]uint16{}, []byte{1, 0, 0, 0}),
		"int long":         scalar("int8", [2]uint16{}, append([]byte{1}, make([]byte, 9)...)),
		"int marker only":  scalar("int8", [2]uint16{}, []byte{1}),
		"uuid short":       scalar("uuid", [2]uint16{}, append([]byte{1}, make([]byte, 15)...)),
		"uuid long":        scalar("uuid", [2]uint16{}, append([]byte{1}, make([]byte, 17)...)),
		"uuid marker only": scalar("uuid", [2]uint16{}, []byte{1}),
		"int array short":  array("int8", [2]uint16{}, binary.BigEndian.AppendUint64([]byte{1}, 7), []byte{1, 0}),
		"uuid array short": array("uuid", [2]uint16{}, []byte{1, 0}),

		// Numeric values that do not fit their type metadata.
		"numeric marker only":    scalar("numeric", numeric, []byte{1}),
		"numeric not a number":   scalar("numeric", numeric, []byte{1, 'x'}),
		"numeric precision 0":    scalar("numeric", [2]uint16{0, 0}, []byte{1, '1'}),
		"numeric scale too big":  scalar("numeric", [2]uint16{5, 6}, []byte{1, '1'}),
		"numeric precision 1001": scalar("numeric", [2]uint16{1001, 0}, []byte{1, '1'}),

		// Types that cannot be decoded.
		"unknown type":    scalar("nope", [2]uint16{}, []byte{1, 'a'}),
		"int4 scalar":     scalar("int4", [2]uint16{}, binary.BigEndian.AppendUint32([]byte{1}, 7)),
		"int4 array":      array("int4", [2]uint16{}, binary.BigEndian.AppendUint32([]byte{1}, 7)),
		"upper case name": scalar("BOOL", [2]uint16{}, []byte{1, 1}),
	}

	// An empty or nil data element has no null marker byte. Check it for
	// every type name a client can send, as a scalar and inside an array.
	for _, name := range []string{"text", "string", "int8", "int", "bigint", "bool", "boolean", "bytea", "blob", "uuid", "numeric", "decimal", "int4"} {
		var md [2]uint16
		if name == "numeric" || name == "decimal" {
			md = numeric
		}
		cases[name+" empty element"] = scalar(name, md, []byte{})
		cases[name+" nil element"] = scalar(name, md, nil)
		cases[name+" array empty element"] = array(name, md, []byte{0}, []byte{})
		cases[name+" array nil element"] = array(name, md, []byte{0}, nil)
	}

	return cases
}

func TestEncodedValue_DecodeMalformed(t *testing.T) {
	for name, ev := range malformedEncodedValues() {
		t.Run(name, func(t *testing.T) {
			var err error
			require.NotPanics(t, func() { _, err = ev.Decode() })
			require.Error(t, err)
		})
	}
}

// TestEncodedValue_DecodeMalformedPayloads sends each malformed value through
// the binary payloads that carry action and statement arguments. The payloads
// do not check values, so each one must still unmarshal, and then Decode must
// return an error.
func TestEncodedValue_DecodeMalformedPayloads(t *testing.T) {
	decodeAll := func(t *testing.T, args []*EncodedValue) {
		t.Helper()
		require.Len(t, args, 1)
		var err error
		require.NotPanics(t, func() { _, err = args[0].Decode() })
		require.Error(t, err)
	}

	for name, ev := range malformedEncodedValues() {
		t.Run(name, func(t *testing.T) {
			t.Run("ActionCall", func(t *testing.T) {
				bts, err := ActionCall{Namespace: "main", Action: "a", Arguments: []*EncodedValue{ev}}.MarshalBinary()
				require.NoError(t, err)
				var got ActionCall
				require.NoError(t, got.UnmarshalBinary(bts))
				decodeAll(t, got.Arguments)
			})

			t.Run("ActionExecution", func(t *testing.T) {
				bts, err := ActionExecution{Namespace: "main", Action: "a", Arguments: [][]*EncodedValue{{ev}}}.MarshalBinary()
				require.NoError(t, err)
				var got ActionExecution
				require.NoError(t, got.UnmarshalBinary(bts))
				require.Len(t, got.Arguments, 1)
				decodeAll(t, got.Arguments[0])
			})

			t.Run("MAAExec", func(t *testing.T) {
				bts, err := MAAExec{MAAAddress: make([]byte, 20), Namespace: "main", Action: "a", Arguments: []*EncodedValue{ev}}.MarshalBinary()
				require.NoError(t, err)
				var got MAAExec
				require.NoError(t, got.UnmarshalBinary(bts))
				decodeAll(t, got.Arguments)
			})

			t.Run("RawStatement", func(t *testing.T) {
				bts, err := RawStatement{Statement: "SELECT $p", Parameters: []*NamedValue{{Name: "$p", Value: ev}}}.MarshalBinary()
				require.NoError(t, err)
				var got RawStatement
				require.NoError(t, got.UnmarshalBinary(bts))
				require.Len(t, got.Parameters, 1)
				decodeAll(t, []*EncodedValue{got.Parameters[0].Value})
			})
		})
	}
}

// TestEncodedValue_DecodeMalformedJSON covers the query parameters, which
// arrive as JSON and are decoded without a binary payload in between.
func TestEncodedValue_DecodeMalformedJSON(t *testing.T) {
	for name, js := range map[string]string{
		"bool marker only":   `{"type":{"name":"bool","is_array":false,"metadata":[0,0]},"data":["AQ=="]}`,
		"bool empty element": `{"type":{"name":"bool","is_array":false,"metadata":[0,0]},"data":[""]}`,
		"text nil element":   `{"type":{"name":"text","is_array":false,"metadata":[0,0]},"data":[null]}`,
		"int array empty":    `{"type":{"name":"int8","is_array":true,"metadata":[0,0]},"data":["AA==",""]}`,
		"uuid no elements":   `{"type":{"name":"uuid","is_array":false,"metadata":[0,0]},"data":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var ev EncodedValue
			require.NoError(t, json.Unmarshal([]byte(js), &ev))
			var err error
			require.NotPanics(t, func() { _, err = ev.Decode() })
			require.Error(t, err)
		})
	}
}

// TestEncodedValue_RoundTrip checks that values from EncodeValue survive the
// binary encoding and decode to the same Go values.
func TestEncodedValue_RoundTrip(t *testing.T) {
	str := func(s string) *string { return &s }
	i64 := func(i int64) *int64 { return &i }
	boolp := func(b bool) *bool { return &b }
	u := NewUUIDV5([]byte("round trip"))
	dec := MustParseDecimalExplicit("12.34", 10, 2)

	tests := []struct {
		name string
		in   any
		want any
	}{
		{"true", true, boolp(true)},
		{"false", false, boolp(false)},
		{"text", "hello", str("hello")},
		{"empty text", "", str("")},
		{"int", int64(-42), i64(-42)},
		{"bytea", []byte{0, 1, 2}, &[]byte{0, 1, 2}},
		{"empty bytea", []byte{}, &[]byte{}},
		{"uuid", *u, u},
		{"numeric", dec, dec},
		{"nil", nil, nil},
		{"bool array", []*bool{boolp(true), nil, boolp(false)}, []*bool{boolp(true), nil, boolp(false)}},
		{"text array", []string{"a", ""}, []*string{str("a"), str("")}},
		{"int array", []*int64{i64(1), nil}, []*int64{i64(1), nil}},
		{"uuid array", []*UUID{u, nil}, []*UUID{u, nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := EncodeValue(tt.in)
			require.NoError(t, err)

			bts, err := ev.MarshalBinary()
			require.NoError(t, err)
			var got EncodedValue
			require.NoError(t, got.UnmarshalBinary(bts))

			decoded, err := got.Decode()
			require.NoError(t, err)
			if d, ok := tt.want.(*Decimal); ok {
				require.IsType(t, d, decoded)
				assert.Equal(t, d.String(), decoded.(*Decimal).String())
				return
			}
			assert.Equal(t, tt.want, decoded)
		})
	}
}

// TestEncodedValue_BoolReadsFirstValueByte pins how a bool with a value byte
// decodes: only the first value byte counts, and it is true only when it is
// 1. Transactions whose arguments decode today must keep their results, so
// these bytes keep decoding as they did.
func TestEncodedValue_BoolReadsFirstValueByte(t *testing.T) {
	for _, tt := range []struct {
		data []byte
		want bool
	}{
		{[]byte{1, 1}, true},
		{[]byte{1, 0}, false},
		{[]byte{1, 2}, false},
		{[]byte{1, 1, 9}, true},
	} {
		ev := &EncodedValue{Type: DataType{Name: BoolType.Name}, Data: [][]byte{tt.data}}
		decoded, err := ev.Decode()
		require.NoError(t, err)
		assert.Equal(t, &tt.want, decoded, "data %v", tt.data)
	}
}
