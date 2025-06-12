package interpreter

import (
	"testing"

	"github.com/kwilteam/kwil-db/core/types"
	"github.com/stretchr/testify/require"
)

// TestArrayAppend_ArrayOfNulls exercises the array_append built-in when the
// left-hand array is an "arrayOfNulls" (i.e. created from the literal
// `array[]`).  This is the main branch that was added/modified in the recent
// patch.  We cover two critical paths:
//  1. appending NULL -> should stay an arrayOfNulls and length should grow by 1.
//  2. appending a non-null scalar -> should produce a concrete, typed array with
//     the correct length and elements.
func TestArrayAppend_ArrayOfNulls(t *testing.T) {
	// ------------------------------------------------------------------
	// Case 1: array_append(array[], NULL)
	// ------------------------------------------------------------------
	arr := &arrayOfNulls{length: 0} // represents literal array[]
	nullScalar := &nullValue{}

	res, err := builtInScalarFuncs["array_append"]([]value{arr, nullScalar})
	require.NoError(t, err)

	// Result should still be an arrayOfNulls and length == 1 (off-by-one
	// regressions would give us 2).
	aon, ok := res.(*arrayOfNulls)
	require.True(t, ok, "expected arrayOfNulls result, got %T", res)
	require.Equal(t, int32(1), aon.Len())

	// ------------------------------------------------------------------
	// Case 2: array_append(array[NULL], 5)
	// ------------------------------------------------------------------
	// Start with an arrayOfNulls with one NULL inside.
	arr2 := &arrayOfNulls{length: 1}
	five := makeInt8(5) // non-null scalar

	res2, err := builtInScalarFuncs["array_append"]([]value{arr2, five})
	require.NoError(t, err)

	// Should now be a concrete int[] array with two elements: NULL, 5
	require.True(t, res2.Type().Equals(types.IntArrayType), "expected int[] type, got %s", res2.Type())

	intArr, ok := res2.(arrayValue)
	require.True(t, ok)
	require.Equal(t, int32(2), intArr.Len())

	// First element is NULL
	v1, err := intArr.Get(1)
	require.NoError(t, err)
	require.True(t, v1.Null())

	// Second element is 5
	v2, err := intArr.Get(2)
	require.NoError(t, err)
	require.False(t, v2.Null())
	require.Equal(t, int64(5), v2.RawValue().(int64))
}
