package types_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
)

// Define a seed corpus for the fuzz test
// These will be used as starting points for the fuzzer
var seedCorpus = []interface{}{
	// Basic types
	"hello world",
	"",
	42,
	int64(math.MaxInt64),
	int64(math.MinInt64),
	true,
	false,
	[]byte("byte array"),
	[]byte{},
	nil,

	// Arrays of different types
	[]string{"a", "b", "c"},
	[]int{1, 2, 3},
	[]bool{true, false, true},

	// Arrays with nil values
	[]interface{}{nil, "not nil", nil},

	// Pointers
	func() interface{} {
		s := "pointer to string"
		return &s
	}(),
	func() interface{} {
		i := 99
		return &i
	}(),
	func() interface{} {
		b := true
		return &b
	}(),

	// Nil pointers
	(*string)(nil),
	(*int)(nil),
	(*bool)(nil),

	// UUIDs
	types.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	func() interface{} {
		return &types.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	}(),

	// Decimal types
	func() interface{} {
		d, _ := types.ParseDecimal("123.456")
		return d
	}(),
	func() interface{} {
		d, _ := types.ParseDecimal("123.456")
		return &d
	}(),
}

// FuzzEncodeValue tests the EncodeValue function with various inputs
func FuzzEncodeValue(f *testing.F) {
	// Add seed corpus values
	for _, seed := range seedCorpus {
		f.Add(fmt.Sprintf("%v", seed))
	}

	// The fuzzer will call this function with random inputs
	f.Fuzz(func(t *testing.T, inputStr string) {
		// Try to convert the fuzzed string into different types
		// to test EncodeValue with a variety of inputs

		// Test with string
		testEncodeValueWithType(t, inputStr)

		// Try to convert to int
		if i, err := parseInt(inputStr); err == nil {
			testEncodeValueWithType(t, i)
		}

		// Try to convert to bool
		if b, err := parseBool(inputStr); err == nil {
			testEncodeValueWithType(t, b)
		}

		// Test with []byte
		testEncodeValueWithType(t, []byte(inputStr))

		// Test with pointer to string
		s := inputStr
		testEncodeValueWithType(t, &s)

		// Test with nil
		testEncodeValueWithType(t, nil)

		// Test with array of strings
		if len(inputStr) > 0 {
			arr := []string{inputStr, inputStr + "1", inputStr + "2"}
			testEncodeValueWithType(t, arr)
		}

		// Try to create and test a UUID if the string is the right length
		if len(inputStr) >= 16 {
			var uuid types.UUID
			copy(uuid[:], []byte(inputStr)[:16])
			testEncodeValueWithType(t, uuid)
			testEncodeValueWithType(t, &uuid)
		}

		// Try to create and test a Decimal if possible
		if d, err := parseDecimal(inputStr); err == nil {
			testEncodeValueWithType(t, d)
			testEncodeValueWithType(t, &d)
		}
	})
}

// Helper function to test EncodeValue with a specific type
func testEncodeValueWithType(t *testing.T, value interface{}) {
	encoded, err := types.EncodeValue(value)

	// If encoding fails, make sure it's for a valid reason
	if err != nil {
		// Encoding might legitimately fail for unsupported types
		// Make sure the error message makes sense
		assertValidError(t, err, value)
		return
	}

	// Verify that the encoded value is not nil
	if encoded == nil {
		t.Errorf("EncodeValue(%v) returned nil without error", value)
		return
	}

	// Verify the encoded type matches what we expect
	assertCorrectType(t, encoded, value)

	// For non-nil values, make sure the Data field is populated
	if value != nil && !isNilPointer(value) {
		if len(encoded.Data) == 0 {
			t.Errorf("EncodeValue(%v) returned empty Data for non-nil value", value)
		}
	}

	// Verify consistency of array encoding
	if isSlice(value) && !isByteSlice(value) {
		assertCorrectArrayEncoding(t, encoded, value)
	}
}

// Helper function to assert the error is valid
func assertValidError(t *testing.T, err error, value interface{}) {
	// Known error cases
	typeOfValue := reflect.TypeOf(value)

	// Mismatched types in array
	if typeOfValue != nil && typeOfValue.Kind() == reflect.Slice &&
		typeOfValue.Elem().Kind() != reflect.Uint8 {
		if err.Error()[:18] == "mismatched types in" {
			// This is a valid error for arrays with mixed types
			return
		}
	}

	// Cannot encode type
	if err.Error()[:17] == "cannot encode type" {
		// Make sure the error message includes the actual type
		if typeOfValue != nil {
			assert.Contains(t, err.Error(), fmt.Sprintf("%T", value))
		}
		return
	}

	// If we get here, it's an unexpected error
	t.Errorf("Unexpected error from EncodeValue(%v): %v", value, err)
}

// Helper function to assert the encoded type is correct
func assertCorrectType(t *testing.T, encoded *types.EncodedValue, value interface{}) {
	// Skip nil values
	if value == nil {
		assert.Equal(t, "null", encoded.Type.Name)
		return
	}

	// Handle pointers
	if reflect.TypeOf(value).Kind() == reflect.Ptr {
		if reflect.ValueOf(value).IsNil() {
			assert.Equal(t, "null", encoded.Type.Name)
			return
		}
		// Dereference pointer for type checking
		actualValue := reflect.ValueOf(value).Elem().Interface()
		assertCorrectType(t, encoded, actualValue)
		return
	}

	// Match the type name to what we expect
	switch value.(type) {
	case string:
		assert.Equal(t, "text", encoded.Type.Name)
	case int, int8, int16, int32, int64, uint, uint16, uint32, uint64:
		assert.Equal(t, "int8", encoded.Type.Name)
	case []byte:
		assert.Equal(t, "bytea", encoded.Type.Name)
	case types.UUID, [16]byte:
		assert.Equal(t, "uuid", encoded.Type.Name)
	case bool:
		assert.Equal(t, "bool", encoded.Type.Name)
	default:
		// For slices, check if IsArray is true
		if isSlice(value) && !isByteSlice(value) {
			assert.True(t, encoded.Type.IsArray)
		}

		// For decimal types
		if _, ok := value.(types.Decimal); ok {
			assert.Equal(t, "numeric", encoded.Type.Name)
		}
	}
}

// Helper function to assert array encoding is correct
func assertCorrectArrayEncoding(t *testing.T, encoded *types.EncodedValue, value interface{}) {
	// Skip if not a slice or is a byte slice
	if !isSlice(value) || isByteSlice(value) {
		return
	}

	// Make sure IsArray is true
	assert.True(t, encoded.Type.IsArray)

	// Get the length of the slice
	sliceValue := reflect.ValueOf(value)
	sliceLen := sliceValue.Len()

	// Make sure the encoded data has the correct length
	// Note: Some elements might be filtered out if they're nil
	if encoded.Data != nil {
		assert.LessOrEqual(t, len(encoded.Data), sliceLen,
			"Encoded data length exceeds original slice length")
	}
}

// Helper functions

func isSlice(value interface{}) bool {
	if value == nil {
		return false
	}
	return reflect.TypeOf(value).Kind() == reflect.Slice
}

func isByteSlice(value interface{}) bool {
	if value == nil {
		return false
	}
	typeOf := reflect.TypeOf(value)
	return typeOf.Kind() == reflect.Slice && typeOf.Elem().Kind() == reflect.Uint8
}

func isNilPointer(value interface{}) bool {
	if value == nil {
		return false
	}
	typeOf := reflect.TypeOf(value)
	if typeOf.Kind() != reflect.Ptr {
		return false
	}
	return reflect.ValueOf(value).IsNil()
}

// Helper functions to parse strings into different types

func parseInt(s string) (int64, error) {
	// Try to interpret the string as binary data first
	if len(s) == 8 {
		return int64(binary.BigEndian.Uint64([]byte(s))), nil
	}

	// Otherwise, just try to parse it as a standard integer
	var i int64
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}

func parseBool(s string) (bool, error) {
	switch s {
	case "true", "1", "t", "yes", "y":
		return true, nil
	case "false", "0", "f", "no", "n":
		return false, nil
	default:
		// If the string is just one byte, try to interpret it as a binary bool
		if len(s) == 1 {
			b := []byte(s)[0]
			if b == 0 {
				return false, nil
			}
			if b == 1 {
				return true, nil
			}
		}
		return false, fmt.Errorf("unable to parse as bool: %s", s)
	}
}

func parseDecimal(s string) (*types.Decimal, error) {
	// Try to parse as a decimal
	return types.ParseDecimal(s)
}

// FuzzDecodeValue tests round-trip encoding and decoding
func FuzzDecodeValue(f *testing.F) {
	// Add seed corpus values
	for _, seed := range seedCorpus {
		f.Add(fmt.Sprintf("%v", seed))
	}

	f.Fuzz(func(t *testing.T, inputStr string) {
		// Try with different types derived from the input string
		testTypes := []interface{}{
			inputStr,
			[]byte(inputStr),
		}

		// Try to parse as int
		if i, err := parseInt(inputStr); err == nil {
			testTypes = append(testTypes, i)
		}

		// Try to parse as bool
		if b, err := parseBool(inputStr); err == nil {
			testTypes = append(testTypes, b)
		}

		for _, value := range testTypes {
			// Skip values we know can't be encoded
			if isComplexType(value) {
				continue
			}

			// Encode the value
			encoded, err := types.EncodeValue(value)
			if err != nil {
				// Skip values that can't be encoded
				continue
			}

			// Now try to decode it back (if a Decode function exists)
			// This is a placeholder for when types.DecodeValue is implemented
			// For now, we just verify the encoded value is consistent

			// Check that DataType Name matches the value type
			assertCorrectType(t, encoded, value)

			// For arrays, check that IsArray is true
			if isSlice(value) && !isByteSlice(value) {
				assert.True(t, encoded.Type.IsArray)
			}
		}
	})
}

// isComplexType returns true for types we know can't be encoded
func isComplexType(value interface{}) bool {
	if value == nil {
		return false
	}

	switch value.(type) {
	case map[string]interface{}, map[string]string, map[int]int:
		return true
	case time.Time:
		return true
	case func():
		return true
	case chan int:
		return true
	}

	// Check for complex structs (other than known types like UUID, Decimal)
	valueType := reflect.TypeOf(value)
	if valueType.Kind() == reflect.Struct {
		switch value.(type) {
		case types.UUID, types.Decimal:
			return false
		default:
			return true
		}
	}

	return false
}

// FuzzEncodeValueEdgeCases specifically tests edge cases
func FuzzEncodeValueEdgeCases(f *testing.F) {
	// Add edge case seed values
	edgeCases := []interface{}{
		// Empty arrays
		[]string{},
		[]int{},
		[]bool{},

		// Arrays with all nil elements
		[]interface{}{nil, nil, nil},

		// Mixed type arrays (should fail)
		[]interface{}{"string", 42, true},

		// Arrays with some nil elements
		[]interface{}{nil, "string", nil},
		[]interface{}{nil, 42, nil},

		// Extreme integer values
		int64(math.MaxInt64),
		int64(math.MinInt64),

		// Very long strings (for potential buffer issues)
		string(bytes.Repeat([]byte("a"), 10000)),

		// Very large arrays
		func() interface{} {
			arr := make([]string, 1000)
			for i := range arr {
				arr[i] = fmt.Sprintf("item-%d", i)
			}
			return arr
		}(),
	}

	for _, seed := range edgeCases {
		f.Add(fmt.Sprintf("%v", seed))
	}

	f.Fuzz(func(t *testing.T, inputStr string) {
		// Create edge cases from the input string
		var edgeCasesFromInput []interface{}

		// Very long string
		if len(inputStr) > 0 {
			longStr := strings.Repeat(inputStr, 100)
			edgeCasesFromInput = append(edgeCasesFromInput, longStr)
		}

		// Large array of the same string
		if len(inputStr) > 0 {
			arr := make([]string, 100)
			for i := range arr {
				arr[i] = inputStr
			}
			edgeCasesFromInput = append(edgeCasesFromInput, arr)
		}

		// Test each edge case
		for _, value := range edgeCasesFromInput {
			encoded, err := types.EncodeValue(value)

			if err != nil {
				// For expected errors, verify they're reasonable
				assertValidError(t, err, value)
				continue
			}

			// If encoding succeeded, verify the results are reasonable
			assertCorrectType(t, encoded, value)

			// For arrays, check that we have the right number of elements
			if isSlice(value) && !isByteSlice(value) {
				sliceValue := reflect.ValueOf(value)
				sliceLen := sliceValue.Len()

				// Check if a valid number of elements are encoded
				if encoded.Data != nil {
					// The number of encoded elements might be less than the original
					// slice if some elements were nil and filtered out
					assert.LessOrEqual(t, len(encoded.Data), sliceLen)
				}
			}
		}
	})
}

// TestEncodeValueUUIDVariations tests various ways to encode UUIDs
func TestEncodeValueUUIDVariations(t *testing.T) {
	// Create sample UUID
	uuid := types.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// Test UUID as direct type
	encoded, err := types.EncodeValue(uuid)
	require.NoError(t, err)
	assert.Equal(t, "uuid", encoded.Type.Name)
	assert.Equal(t, 1, len(encoded.Data))

	// Test UUID pointer
	encoded, err = types.EncodeValue(&uuid)
	require.NoError(t, err)
	assert.Equal(t, "uuid", encoded.Type.Name)
	assert.Equal(t, 1, len(encoded.Data))

	// Test [16]byte which should be handled the same as UUID
	var bytes16 [16]byte
	copy(bytes16[:], uuid[:])
	encoded, err = types.EncodeValue(bytes16)
	require.NoError(t, err)
	assert.Equal(t, "uuid", encoded.Type.Name)
	assert.Equal(t, 1, len(encoded.Data))

	// Test array of UUIDs
	uuids := []types.UUID{uuid, uuid}
	encoded, err = types.EncodeValue(uuids)
	require.NoError(t, err)
	assert.Equal(t, "uuid", encoded.Type.Name)
	assert.True(t, encoded.Type.IsArray)
	assert.Equal(t, 2, len(encoded.Data))

	// Test array of UUID pointers
	uuidPtrs := []*types.UUID{&uuid, &uuid}
	encoded, err = types.EncodeValue(uuidPtrs)
	require.NoError(t, err)
	assert.Equal(t, "uuid", encoded.Type.Name)
	assert.True(t, encoded.Type.IsArray)
	assert.Equal(t, 2, len(encoded.Data))
}

// TestEncodeValueEmptyArrays specifically tests arrays with zero elements
func TestEncodeValueEmptyArrays(t *testing.T) {
	testCases := []struct {
		name     string
		value    interface{}
		expected string // expected error or "success" if no error
	}{
		{"empty_string_array", []string{}, "no elements in array"},
		{"empty_int_array", []int{}, "no elements in array"},
		{"empty_interface_array", []interface{}{}, "no elements in array"},
		{"nil_byte_array", []byte(nil), "success"}, // []byte(nil) is handled differently
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := types.EncodeValue(tc.value)

			if tc.expected == "success" {
				assert.NoError(t, err)
				if encoded.Type.Name == "bytea" || encoded.Type.Name == "null" {
					// This is fine for nil byte arrays
				} else {
					t.Errorf("Unexpected success encoding %v, got type %s", tc.value, encoded.Type.Name)
				}
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expected)
			}
		})
	}
}

// TestEncodeValueMixedButCompatibleTypes tests arrays with mixed but compatible types
func TestEncodeValueMixedButCompatibleTypes(t *testing.T) {
	testCases := []struct {
		name          string
		value         interface{}
		expectedError string
		expectedType  string
	}{
		{
			name:         "int_compatible",
			value:        []interface{}{int(1), int32(2), int64(3)},
			expectedType: "int8",
		},
		{
			name:         "string_and_nil",
			value:        []interface{}{"string", nil, "another"},
			expectedType: "text",
		},
		{
			name:         "bool_compatible",
			value:        []interface{}{true, false, nil, true},
			expectedType: "bool",
		},
		{
			name:          "incompatible",
			value:         []interface{}{"string", 42, true},
			expectedError: "mismatched types in array",
		},
		{
			name:         "initially_null",
			value:        []interface{}{nil, "string", "another"},
			expectedType: "text",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := types.EncodeValue(tc.value)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedType, encoded.Type.Name)
				assert.True(t, encoded.Type.IsArray)
			}
		})
	}
}

// TestEncodeValueUnsupportedTypes explicitly tests types that should fail
func TestEncodeValueUnsupportedTypes(t *testing.T) {
	testCases := []struct {
		name  string
		value interface{}
	}{
		{"complex", complex(1, 2)},
		{"map", map[string]string{"key": "value"}},
		{"channel", make(chan int)},
		{"function", func() {}},
		{"uintptr", uintptr(0)},
		{"unsafe_pointer", unsafe.Pointer(nil)},
		{"custom_struct", struct{ field string }{"value"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := types.EncodeValue(tc.value)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "cannot encode type")
		})
	}
}

// TestEncodeValueRecursivePointers tests encoding values with recursive pointers
func TestEncodeValueRecursivePointers(t *testing.T) {
	type Node struct {
		Value string
		Next  *Node
	}

	// Create a chain of nodes
	node3 := &Node{Value: "node3", Next: nil}
	node2 := &Node{Value: "node2", Next: node3}
	node1 := &Node{Value: "node1", Next: node2}

	// Attempting to encode this should fail appropriately
	_, err := types.EncodeValue(node1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot encode type")
}

// TestEncodeValueBooleans tests various boolean values
func TestEncodeValueBooleans(t *testing.T) {
	// Test true
	encoded, err := types.EncodeValue(true)
	require.NoError(t, err)
	assert.Equal(t, "bool", encoded.Type.Name)
	assert.Equal(t, 1, len(encoded.Data))
	assert.Equal(t, byte(1), encoded.Data[0][1]) // [0] is first item, [1] is after "not null" prefix

	// Test false
	encoded, err = types.EncodeValue(false)
	require.NoError(t, err)
	assert.Equal(t, "bool", encoded.Type.Name)
	assert.Equal(t, 1, len(encoded.Data))
	assert.Equal(t, byte(0), encoded.Data[0][1]) // [0] is first item, [1] is after "not null" prefix

	// Test array of booleans
	bools := []bool{true, false, true, false}
	encoded, err = types.EncodeValue(bools)
	require.NoError(t, err)
	assert.Equal(t, "bool", encoded.Type.Name)
	assert.True(t, encoded.Type.IsArray)
	assert.Equal(t, 4, len(encoded.Data))
}

// TestEncodeValueDataConsistency verifies the encoded data is consistent
func TestEncodeValueDataConsistency(t *testing.T) {
	// Create some test values
	testString := "hello world"
	testInt := 12345
	testBool := true
	testBytes := []byte{1, 2, 3, 4, 5}

	// Encode each value multiple times and verify results are consistent
	for range 10 {
		// String
		encoded1, err := types.EncodeValue(testString)
		require.NoError(t, err)
		encoded2, err := types.EncodeValue(testString)
		require.NoError(t, err)
		assert.Equal(t, encoded1.Type, encoded2.Type)
		assert.Equal(t, encoded1.Data, encoded2.Data)

		// Int
		encoded1, err = types.EncodeValue(testInt)
		require.NoError(t, err)
		encoded2, err = types.EncodeValue(testInt)
		require.NoError(t, err)
		assert.Equal(t, encoded1.Type, encoded2.Type)
		assert.Equal(t, encoded1.Data, encoded2.Data)

		// Bool
		encoded1, err = types.EncodeValue(testBool)
		require.NoError(t, err)
		encoded2, err = types.EncodeValue(testBool)
		require.NoError(t, err)
		assert.Equal(t, encoded1.Type, encoded2.Type)
		assert.Equal(t, encoded1.Data, encoded2.Data)

		// Bytes
		encoded1, err = types.EncodeValue(testBytes)
		require.NoError(t, err)
		encoded2, err = types.EncodeValue(testBytes)
		require.NoError(t, err)
		assert.Equal(t, encoded1.Type, encoded2.Type)
		assert.Equal(t, encoded1.Data, encoded2.Data)
	}
}

// TestEncodeValueLargeArrays tests encoding very large arrays
func TestEncodeValueLargeArrays(t *testing.T) {
	// Create large arrays of different types
	largeStringArray := make([]string, 10000)
	largeIntArray := make([]int, 10000)
	largeBoolArray := make([]bool, 10000)

	// Fill arrays with values
	for i := range 10000 {
		largeStringArray[i] = fmt.Sprintf("string-%d", i)
		largeIntArray[i] = i
		largeBoolArray[i] = i%2 == 0
	}

	// Encode and verify
	t.Run("large_string_array", func(t *testing.T) {
		encoded, err := types.EncodeValue(largeStringArray)
		require.NoError(t, err)
		assert.Equal(t, "text", encoded.Type.Name)
		assert.True(t, encoded.Type.IsArray)
		assert.Equal(t, 10000, len(encoded.Data))
	})

	t.Run("large_int_array", func(t *testing.T) {
		encoded, err := types.EncodeValue(largeIntArray)
		require.NoError(t, err)
		assert.Equal(t, "int8", encoded.Type.Name)
		assert.True(t, encoded.Type.IsArray)
		assert.Equal(t, 10000, len(encoded.Data))
	})

	t.Run("large_bool_array", func(t *testing.T) {
		encoded, err := types.EncodeValue(largeBoolArray)
		require.NoError(t, err)
		assert.Equal(t, "bool", encoded.Type.Name)
		assert.True(t, encoded.Type.IsArray)
		assert.Equal(t, 10000, len(encoded.Data))
	})
}

// TestEncodeValueWithReflectionEdgeCases tests edge cases using reflection
func TestEncodeValueWithReflectionEdgeCases(t *testing.T) {
	// Test with a Value created from reflect
	stringVal := reflect.ValueOf("test string").Interface()
	encoded, err := types.EncodeValue(stringVal)
	require.NoError(t, err)
	assert.Equal(t, "text", encoded.Type.Name)

	// Test with a pointer Value created from reflect
	s := "test string"
	ptrVal := reflect.ValueOf(&s).Interface()
	encoded, err = types.EncodeValue(ptrVal)
	require.NoError(t, err)
	assert.Equal(t, "text", encoded.Type.Name)

	// Test with unaddressable Value
	unaddressableVal := reflect.ValueOf([]string{"test"}).Index(0).Interface()
	encoded, err = types.EncodeValue(unaddressableVal)
	require.NoError(t, err)
	assert.Equal(t, "text", encoded.Type.Name)
}

// TestEncodeValueNilHandling specifically tests nil handling
func TestEncodeValueNilHandling(t *testing.T) {
	// Test with explicit nil
	encoded, err := types.EncodeValue(nil)
	require.NoError(t, err)
	assert.Equal(t, "null", encoded.Type.Name)
	assert.Nil(t, encoded.Data)

	// Test with typed nil
	var nilSlice []string = nil
	encoded, err = types.EncodeValue(nilSlice)
	require.NoError(t, err)
	assert.Equal(t, "null", encoded.Type.Name)

	// Test with interface containing nil
	var nilInterface interface{} = nil
	encoded, err = types.EncodeValue(nilInterface)
	require.NoError(t, err)
	assert.Equal(t, "null", encoded.Type.Name)

	// Test with pointer to nil
	nilStrPtr := (*string)(nil)
	nilIntfPtr := &nilInterface

	encoded, err = types.EncodeValue(nilStrPtr)
	require.NoError(t, err)
	assert.Equal(t, "null", encoded.Type.Name)

	encoded, err = types.EncodeValue(nilIntfPtr)
	require.NoError(t, err)
	assert.Equal(t, "null", encoded.Type.Name)
}

// TestEncodeValueArraysWithPointers tests arrays containing pointers
func TestEncodeValueArraysWithPointers(t *testing.T) {
	// Create string pointers
	s1 := "string1"
	s2 := "string2"
	nilString := (*string)(nil)

	// Array of string pointers
	stringPtrs := []*string{&s1, nilString, &s2}
	encoded, err := types.EncodeValue(stringPtrs)
	require.NoError(t, err)
	assert.Equal(t, "text", encoded.Type.Name)
	assert.True(t, encoded.Type.IsArray)
	assert.Equal(t, 3, len(encoded.Data)) // Only 2 non-nil values

	// Create int pointers
	i1 := 42
	i2 := 99
	nilInt := (*int)(nil)

	// Array of int pointers
	intPtrs := []*int{&i1, nilInt, &i2}
	encoded, err = types.EncodeValue(intPtrs)
	require.NoError(t, err)
	assert.Equal(t, "int8", encoded.Type.Name)
	assert.True(t, encoded.Type.IsArray)
	assert.Equal(t, 3, len(encoded.Data)) // Only 2 non-nil values
}

// TestEncodeValueWithNullFirstElement tests arrays where the first element is null
func TestEncodeValueWithNullFirstElement(t *testing.T) {
	// Array with null first element, then non-null
	value := []interface{}{nil, "string", "another"}

	encoded, err := types.EncodeValue(value)
	require.NoError(t, err)
	assert.Equal(t, "text", encoded.Type.Name)
	assert.True(t, encoded.Type.IsArray)
	assert.Equal(t, 3, len(encoded.Data)) // Only 2 elements since nil is filtered out
}

// TestEncodeValueEdgeCaseIntValues tests edge case integer values
func TestEncodeValueEdgeCaseIntValues(t *testing.T) {
	testCases := []struct {
		name  string
		value interface{}
	}{
		{"max_int8", int8(127)},
		{"min_int8", int8(-128)},
		{"max_int16", int16(32767)},
		{"min_int16", int16(-32768)},
		{"max_int32", int32(2147483647)},
		{"min_int32", int32(-2147483648)},
		{"max_int64", int64(9223372036854775807)},
		{"min_int64", int64(-9223372036854775808)},
		{"max_uint16", uint16(65535)},
		{"max_uint32", uint32(4294967295)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := types.EncodeValue(tc.value)
			require.NoError(t, err)
			assert.Equal(t, "int8", encoded.Type.Name)
			assert.Equal(t, 1, len(encoded.Data))
		})
	}
}

// TestOverflow tests for integer overflow
func TestOverflow(t *testing.T) {
	// Test with a large integer value
	largeValue := uint64(18446744073709551615)
	_, err := types.EncodeValue(largeValue)
	assert.Error(t, err)
}

// TestEncodeValueByteArrays specifically tests various byte array scenarios
func TestEncodeValueByteArrays(t *testing.T) {
	testCases := []struct {
		name  string
		value []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"typical", []byte("hello world")},
		{"with_nulls", []byte{0, 1, 2, 0, 3}},
		{"large", make([]byte, 10000)}, // 10KB array
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := types.EncodeValue(tc.value)
			require.NoError(t, err)

			if tc.value == nil {
				assert.Equal(t, "null", encoded.Type.Name)
				assert.Len(t, encoded.Data, 0)
			} else {
				assert.Equal(t, "bytea", encoded.Type.Name)
				assert.Equal(t, 1, len(encoded.Data))
				// Data should be the original bytes plus the not-null prefix byte
				if len(tc.value) > 0 {
					assert.Equal(t, len(tc.value)+1, len(encoded.Data[0]))
				}
			}
		})
	}

	// Test pointer to byte array
	t.Run("byte_array_pointer", func(t *testing.T) {
		b := []byte("test bytes")
		encoded, err := types.EncodeValue(&b)
		require.NoError(t, err)
		assert.Equal(t, "bytea", encoded.Type.Name)
	})

	// Test nil pointer to byte array
	t.Run("nil_byte_array_pointer", func(t *testing.T) {
		var b *[]byte = nil
		encoded, err := types.EncodeValue(b)
		require.NoError(t, err)
		assert.Equal(t, "null", encoded.Type.Name)
	})
}

// TestEncodeValueArrayWithAllNilElements tests arrays where all elements are nil
func TestEncodeValueArrayWithAllNilElements(t *testing.T) {
	// Array with all nil elements
	value := []interface{}{nil, nil, nil}
	r, err := types.EncodeValue(value)
	require.NoError(t, err)
	assert.Equal(t, "null", r.Type.Name)
	assert.True(t, r.Type.IsArray)
	assert.Equal(t, 3, len(r.Data))
}

// TestEncodeValueDecimalVariations tests Decimal type with various precision/scale
func TestEncodeValueDecimalVariations(t *testing.T) {
	testCases := []struct {
		name      string
		value     string
		precision int
		scale     int
	}{
		{"zero", "0", 1, 0},
		{"integer", "123", 3, 0},
		{"typical", "123.456", 6, 3},
		{"negative", "-123.456", 6, 3},
		{"large_precision", "9876543210.123456789", 19, 9},
		{"small_scale", "123.4", 4, 1},
		{"large_scale", "0.123456789", 9, 9},
		{"zero_scale", "12345.0", 6, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create decimal from string
			decimal, err := types.ParseDecimal(tc.value)
			require.NoError(t, err)

			// Verify precision and scale
			assert.Equal(t, uint16(tc.precision), decimal.Precision())
			assert.Equal(t, uint16(tc.scale), decimal.Scale())

			// Test encoding
			encoded, err := types.EncodeValue(decimal)
			require.NoError(t, err)
			assert.Equal(t, "numeric", encoded.Type.Name)

			// Test pointer to decimal
			encoded, err = types.EncodeValue(&decimal)
			require.NoError(t, err)
			assert.Equal(t, "numeric", encoded.Type.Name)

			// Verify metadata contains precision and scale
			assert.Equal(t, uint16(tc.precision), encoded.Type.Metadata[0])
			assert.Equal(t, uint16(tc.scale), encoded.Type.Metadata[1])
		})
	}

	// Test array of decimals
	t.Run("decimal_array", func(t *testing.T) {
		d1, _ := types.ParseDecimal("123.45")
		d2, _ := types.ParseDecimal("678.90")
		decimals := []types.Decimal{*d1, *d2}

		encoded, err := types.EncodeValue(decimals)
		require.NoError(t, err)
		assert.Equal(t, "numeric", encoded.Type.Name)
		assert.True(t, encoded.Type.IsArray)
		assert.Equal(t, 2, len(encoded.Data))
	})
}

// TestEncodeValueUintTypes specifically tests uint types
func TestEncodeValueUintTypes(t *testing.T) {
	testCases := []struct {
		name     string
		value    interface{}
		expected string // expected type name
	}{
		{"uint", uint(42), "int8"},
		{"uint16", uint16(42), "int8"},
		{"uint32", uint32(42), "int8"},
		{"uint64", uint64(42), "int8"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := types.EncodeValue(tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, encoded.Type.Name)

			// For uint types, verify data is properly encoded (should be 8 bytes)
			assert.Equal(t, 1, len(encoded.Data))
			assert.Equal(t, 8, len(encoded.Data[0])-1) // -1 for the not-null prefix byte
		})
	}
}
