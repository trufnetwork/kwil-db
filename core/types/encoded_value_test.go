package types

import (
	"encoding/binary"
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

	t.Run("decode empty element", func(t *testing.T) {
		ev := &EncodedValue{
			Type: *TextType,
			Data: [][]byte{{}},
		}
		_, err := ev.Decode()
		require.Error(t, err)

		payload, err := ActionExecution{
			Namespace: "main",
			Action:    "act",
			Arguments: [][]*EncodedValue{{ev}},
		}.MarshalBinary()
		require.NoError(t, err)
		require.Error(t, ValidatePayloadEncoding(PayloadTypeExecute, payload))
	})

	t.Run("decode short bool", func(t *testing.T) {
		ev := &EncodedValue{
			Type: *BoolType,
			Data: [][]byte{{1}},
		}
		_, err := ev.Decode()
		require.Error(t, err)
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
