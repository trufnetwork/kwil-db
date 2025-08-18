package pg

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ArrayEncodeDecodeNULLs(t *testing.T) {
	arr := []string{"a", "b", "c", "NULL"}
	res, err := serializeArray(arr, 4, func(s string) ([]byte, error) {
		if s == "NULL" {
			return nil, nil
		}
		return []byte(s), nil
	})
	require.NoError(t, err)

	// use deserializePtrArray to handle NULL values
	res2, err := deserializePtrArray[string](res, 4, func(b []byte) (any, error) {
		if b == nil {
			return nil, nil
		}
		return string(b), nil
	})
	require.NoError(t, err)

	require.Equal(t, len(arr), len(res2))

	for i := range res2 {
		if res2[i] == nil {
			require.Equal(t, arr[i], "NULL")
			continue
		}

		require.Equal(t, arr[i], *res2[i])
	}
}

// don't use this in product code, it doesn't handle NULL values.
// this is only a test helper when not testing arrays with NULLs.
func deserializeTestArray[T any](buf []byte, lengthSize uint8, deserialize func([]byte) (any, error)) ([]T, error) {
	ptrs, err := deserializePtrArray[T](buf, lengthSize, deserialize)
	if err != nil {
		return nil, err
	}
	var vals []T
	for _, ptr := range ptrs {
		if ptr == nil {
			var vt T
			vals = append(vals, vt)
		} else {
			vals = append(vals, *ptr)
		}
	}
	return vals, nil
}

func Test_ArrayEncodeDecode(t *testing.T) {
	arr := []string{"a", "b", "c"}
	res, err := serializeArray(arr, 4, func(s string) ([]byte, error) {
		return []byte(s), nil
	})
	require.NoError(t, err)

	res2, err := deserializeTestArray[string](res, 4, func(b []byte) (any, error) {
		return string(b), nil
	})
	require.NoError(t, err)

	require.EqualValues(t, arr, res2)

	arr2 := []int64{1, 2, 3}
	res, err = serializeArray(arr2, 1, func(i int64) ([]byte, error) {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(i))
		return buf, nil
	})
	require.NoError(t, err)

	res3, err := deserializeTestArray[int64](res, 1, func(b []byte) (any, error) {
		return int64(binary.LittleEndian.Uint64(b)), nil
	})
	require.NoError(t, err)

	require.EqualValues(t, arr2, res3)
}

func TestSplitString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{""},
		},
		{
			name:     "single value",
			input:    "hello",
			expected: []string{"hello"},
		},
		{
			name:     "simple values",
			input:    "a,b,c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "quoted strings with commas",
			input:    `"hello,world",next,"another,value"`,
			expected: []string{`hello,world`, "next", `another,value`},
		},
		{
			name:     "escaped quotes",
			input:    `value1,"escaped\"quote",value3`,
			expected: []string{"value1", `escaped"quote`, "value3"},
		},
		{
			name:     "escaped backslashes",
			input:    `normal,with\\backslashes,"quoted\\with\\backslashes"`,
			expected: []string{"normal", `with\backslashes`, `quoted\with\backslashes`},
		},
		{
			name:     "trailing backslash",
			input:    `value1,value2\`,
			expected: []string{"value1", "value2\\"},
		},
		{
			name:     "mixed escapes and quotes",
			input:    `simple,"quoted,value",escaped\\comma\,,"quoted\"escape\\chars"`,
			expected: []string{"simple", "quoted,value", `escaped\comma,`, `quoted"escape\chars`},
		},
		{ // well formed arrays from pg should no have whitespace outside of quotes...
			name:     "whitespace handling",
			input:    ` spaced , "quoted space" ,nospace`,
			expected: []string{" spaced ", " quoted space ", "nospace"},
		},
		{
			name:     "empty elements",
			input:    "first,,last",
			expected: []string{"first", "", "last"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pgStringArraySplit(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func Test_Int4TypeEncodeDecode(t *testing.T) {
	t.Run("int4 encoding and decoding", func(t *testing.T) {
		// Test encoding
		encoded, err := int4Type.EncodeInferred(int32(42))
		require.NoError(t, err)
		require.Equal(t, int32(42), encoded)

		// Test decoding
		decoded, err := int4Type.Decode(int64(42))
		require.NoError(t, err)
		require.Equal(t, int32(42), decoded)
	})

	t.Run("int4 range validation on decode", func(t *testing.T) {
		// Test max value
		decoded, err := int4Type.Decode(int64(MaxInt4))
		require.NoError(t, err)
		require.Equal(t, int32(MaxInt4), decoded)

		// Test min value
		decoded, err = int4Type.Decode(int64(MinInt4))
		require.NoError(t, err)
		require.Equal(t, int32(MinInt4), decoded)

		// Test overflow
		_, err = int4Type.Decode(int64(MaxInt4 + 1))
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range for INT4")

		// Test underflow
		_, err = int4Type.Decode(int64(MinInt4 - 1))
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range for INT4")
	})

	t.Run("int4 changeset serialization", func(t *testing.T) {
		// Test valid value
		data, err := int4Type.SerializeChangeset("42")
		require.NoError(t, err)
		require.Equal(t, 4, len(data))

		// Verify the bytes
		expected := make([]byte, 4)
		binary.LittleEndian.PutUint32(expected, uint32(42))
		require.Equal(t, expected, data)

		// Test NULL
		data, err = int4Type.SerializeChangeset("NULL")
		require.NoError(t, err)
		require.Nil(t, data)

		// Test range validation
		_, err = int4Type.SerializeChangeset("2147483648") // MaxInt4 + 1
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range for INT4")

		_, err = int4Type.SerializeChangeset("-2147483649") // MinInt4 - 1
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range for INT4")

		// Test invalid number
		_, err = int4Type.SerializeChangeset("not_a_number")
		require.Error(t, err)
	})

	t.Run("int4 changeset deserialization", func(t *testing.T) {
		// Test valid value
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, uint32(42))

		decoded, err := int4Type.DeserializeChangeset(data)
		require.NoError(t, err)
		require.Equal(t, int32(42), decoded)

		// Test NULL (empty slice)
		decoded, err = int4Type.DeserializeChangeset([]byte{})
		require.NoError(t, err)
		require.Nil(t, decoded)

		// Test invalid length
		_, err = int4Type.DeserializeChangeset([]byte{1, 2, 3}) // Wrong length
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid int32")
	})
}

func Test_Int4ArrayType(t *testing.T) {
	t.Run("int4 array serialization round-trip", func(t *testing.T) {
		values := []int32{-2147483648, -1, 0, 1, 2147483647}

		// Convert to string array for serialization test
		stringValues := make([]string, len(values))
		for i, v := range values {
			stringValues[i] = fmt.Sprintf("%d", v)
		}

		// Serialize
		data, err := serializeArray(stringValues, 1, int4Type.SerializeChangeset)
		require.NoError(t, err)

		// Deserialize
		decoded, err := deserializePtrArray[int32](data, 1, int4Type.DeserializeChangeset)
		require.NoError(t, err)

		// Verify
		require.Equal(t, len(values), len(decoded))
		for i, v := range values {
			require.NotNil(t, decoded[i])
			require.Equal(t, v, *decoded[i])
		}
	})

	t.Run("int4 array with NULLs", func(t *testing.T) {
		stringValues := []string{"42", "NULL", "-100", "NULL"}
		expected := []int32{42, 0, -100, 0} // Note: we assert nil pointers for NULL entries below

		// Serialize
		data, err := serializeArray(stringValues, 1, int4Type.SerializeChangeset)
		require.NoError(t, err)

		// Deserialize
		decoded, err := deserializePtrArray[int32](data, 1, int4Type.DeserializeChangeset)
		require.NoError(t, err)

		// Verify
		require.Equal(t, len(stringValues), len(decoded))
		require.NotNil(t, decoded[0])
		require.Equal(t, expected[0], *decoded[0])
		require.Nil(t, decoded[1]) // NULL
		require.NotNil(t, decoded[2])
		require.Equal(t, expected[2], *decoded[2])
		require.Nil(t, decoded[3]) // NULL
	})
}

func Test_Int4TypeRegistration(t *testing.T) {
	t.Run("int4 type is registered but not for Go types yet", func(t *testing.T) {
		// INT4 type should be registered but not handle Go int32/uint32 types yet
		// for backward compatibility
		_, ok := dataTypesByMatch[reflect.TypeOf(int32(0))]
		require.True(t, ok) // Should still be handled by intType

		// int32 should still be handled by intType (backward compatibility)
		dt, ok := dataTypesByMatch[reflect.TypeOf(int32(0))]
		require.True(t, ok)
		require.Equal(t, intType, dt) // Not int4Type yet!
	})

	t.Run("int4 array type is registered but not for Go types yet", func(t *testing.T) {
		// int32 arrays should still be handled by intArrayType (backward compatibility)
		dt, ok := dataTypesByMatch[reflect.TypeOf([]int32{})]
		require.True(t, ok)
		require.Equal(t, intArrayType, dt) // Not int4ArrayType yet!

		dt, ok = dataTypesByMatch[reflect.TypeOf([]*int32{})]
		require.True(t, ok)
		require.Equal(t, intArrayType, dt) // Not int4ArrayType yet!
	})

	t.Run("scalar to array mapping", func(t *testing.T) {
		arrayType, ok := scalarToArray[int4Type]
		require.True(t, ok)
		require.Equal(t, int4ArrayType, arrayType)
	})
}

// Test for OID duplication
func Test_OidTypesMap_Int4Ownership(t *testing.T) {
	t.Run("check for OID duplication panic", func(t *testing.T) {
		// This test will panic if there are duplicate OIDs registered
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("OID duplication panic detected: %v", r)
			}
		}()

		// Try to build the OID map - this should not panic
		oidMap := OidTypesMap(nil)

		// Verify INT4 OID is owned by int4Type
		dt, exists := oidMap[int4Type.OID(nil)]
		require.True(t, exists, "INT4 OID should be registered")
		require.Equal(t, int4Type, dt, "INT4 OID should be owned by int4Type")

		// Verify INT4 Array OID is owned by int4ArrayType
		dt, exists = oidMap[int4ArrayType.OID(nil)]
		require.True(t, exists, "INT4 Array OID should be registered")
		require.Equal(t, int4ArrayType, dt, "INT4 Array OID should be owned by int4ArrayType")
	})
}

// Test buffer overflow protection in deserializePtrArray
func Test_DeserializePtrArray_BufferOverflow(t *testing.T) {
	t.Run("buffer overflow protection", func(t *testing.T) {
		// Create a malformed buffer that claims to have an element of length 10
		// but only has 3 bytes remaining after the length field

		// Format: [null flag (1 byte)] [length (1 byte)] [data (insufficient bytes)]
		malformedBuffer := []byte{
			1,       // Not null
			10,      // Claims 10 bytes follow
			1, 2, 3, // Only 3 bytes provided
		}

		_, err := deserializePtrArray[int32](malformedBuffer, 1, func(b []byte) (any, error) {
			// Simple deserializer that would panic on buffer overflow without the fix
			if len(b) < 4 {
				return nil, fmt.Errorf("need at least 4 bytes, got %d", len(b))
			}
			return int32(binary.LittleEndian.Uint32(b[:4])), nil
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "element length exceeds buffer")
	})

	t.Run("valid buffer works", func(t *testing.T) {
		// Create a valid buffer with proper length
		validBuffer := []byte{
			1,          // Not null
			4,          // 4 bytes follow
			1, 0, 0, 0, // 4 bytes of data (little-endian int32: 1)
		}

		result, err := deserializePtrArray[int32](validBuffer, 1, func(b []byte) (any, error) {
			if len(b) < 4 {
				return nil, fmt.Errorf("need at least 4 bytes, got %d", len(b))
			}
			return int32(binary.LittleEndian.Uint32(b[:4])), nil
		})

		require.NoError(t, err)
		require.Len(t, result, 1)
		require.NotNil(t, result[0])
		require.Equal(t, int32(1), *result[0])
	})
}
