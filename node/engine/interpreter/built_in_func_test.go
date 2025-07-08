package interpreter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_BuiltInScalars(t *testing.T) {
	type testcase struct {
		name     string
		function string
		args     []any
		expected any
		err      bool
	}

	testcases := []testcase{
		{
			name:     "array_append",
			function: "array_append",
			args: []any{
				[]int64{1, 2, 3},
				int64(4),
			},
			expected: ptrArr([]int64{1, 2, 3, 4}),
		},
		{
			name:     "array_append - null array",
			function: "array_append",
			args: []any{
				nil,
				int64(4),
			},
			expected: ptrArr([]int64{4}),
		},
		{
			name:     "array_append - null Value",
			function: "array_append",
			args: []any{
				[]int64{1, 2, 3},
				nil,
			},
			expected: []*int64{ptr(int64(1)), ptr(int64(2)), ptr(int64(3)), nil},
		},
		{
			name:     "array_prepend",
			function: "array_prepend",
			args: []any{
				[]int64{1, 2, 3},
				int64(4),
			},
			expected: ptrArr([]int64{4, 1, 2, 3}),
		},
		{
			name:     "array_prepend - null array",
			function: "array_prepend",
			args: []any{
				nil,
				int64(4),
			},
			expected: ptrArr([]int64{4}),
		},
		{
			name:     "array_prepend - null Value",
			function: "array_prepend",
			args: []any{
				[]int64{1, 2, 3},
				nil,
			},
			expected: []*int64{nil, ptr(int64(1)), ptr(int64(2)), ptr(int64(3))},
		},
		{
			name:     "array_cat",
			function: "array_cat",
			args: []any{
				[]int64{1, 2, 3},
				[]int64{4, 5, 6},
			},
			expected: ptrArr([]int64{1, 2, 3, 4, 5, 6}),
		},
		{
			name:     "array_cat - null array",
			function: "array_cat",
			args: []any{
				nil,
				[]int64{4, 5, 6},
			},
			expected: ptrArr([]int64{4, 5, 6}),
		},
		{
			name:     "array_cat - null array 2",
			function: "array_cat",
			args: []any{
				[]int64{1, 2, 3},
				nil,
			},
			expected: ptrArr([]int64{1, 2, 3}),
		},
		{
			name:     "array_cat - null arrays",
			function: "array_cat",
			args: []any{
				nil,
				nil,
			},
			expected: nil,
		},
		{
			name:     "array_length",
			function: "array_length",
			args: []any{
				[]int64{1, 2, 3},
			},
			expected: int64(3),
		},
		{
			name:     "array_length - null array",
			function: "array_length",
			args: []any{
				nil,
			},
			expected: nil,
		},
		{
			name:     "array_length - empty array",
			function: "array_length",
			args: []any{
				[]int64{},
			},
			expected: int64(0),
		},
		{
			name:     "array_remove",
			function: "array_remove",
			args: []any{
				[]int64{1, 2, 3, 4},
				int64(2),
			},
			expected: ptrArr([]int64{1, 3, 4}),
		},
		{
			name:     "array_remove - null array",
			function: "array_remove",
			args: []any{
				nil,
				int64(2),
			},
			expected: nil,
		},
		{
			name:     "array_remove - null Value",
			function: "array_remove",
			args: []any{
				[]int64{1, 2, 3, 4},
				nil,
			},
			expected: ptrArr([]int64{1, 2, 3, 4}),
		},
		{
			name:     "array_remove - Value not in array",
			function: "array_remove",
			args: []any{
				[]int64{1, 2, 3, 4},
				int64(5),
			},
			expected: ptrArr([]int64{1, 2, 3, 4}),
		},
		{
			name:     "array_remove - empty array",
			function: "array_remove",
			args: []any{
				[]int64{},
				int64(5),
			},
			expected: []*int64{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			fn, ok := builtInScalarFuncs[tc.function]
			require.True(t, ok, "function not found")

			vals := make([]Value, len(tc.args))
			for i, arg := range tc.args {
				var err error
				vals[i], err = NewValue(arg)
				require.NoError(t, err)
			}

			actual, err := fn(vals)
			if tc.err {
				if err == nil {
					t.Errorf("expected error, got nil")
				}

				return // success
			}
			require.NoError(t, err)
			raw := actual.RawValue()
			require.EqualValues(t, tc.expected, raw)
		})
	}
}
