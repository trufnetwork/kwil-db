package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufnetwork/kwil-db/core/types"
)

func TestUNNESTFunction(t *testing.T) {
	tests := []struct {
		name     string
		args     []*types.DataType
		wantErr  bool
		expected []NamedType
	}{
		{
			name: "single integer array",
			args: []*types.DataType{
				{Name: "int8", IsArray: true},
			},
			wantErr: false,
			expected: []NamedType{
				{Name: "unnest", Type: &types.DataType{Name: "int8"}},
			},
		},
		{
			name: "multiple arrays",
			args: []*types.DataType{
				{Name: "int8", IsArray: true},
				{Name: "text", IsArray: true},
			},
			wantErr: false,
			expected: []NamedType{
				{Name: "unnest_1", Type: &types.DataType{Name: "int8"}},
				{Name: "unnest_2", Type: &types.DataType{Name: "text"}},
			},
		},
		{
			name: "non-array argument",
			args: []*types.DataType{
				{Name: "int8", IsArray: false},
			},
			wantErr: true,
		},
		{
			name:    "no arguments",
			args:    []*types.DataType{},
			wantErr: true,
		},
	}

	unnestFn, ok := Functions["unnest"].(*TableValuedFunctionDefinition)
	assert.True(t, ok, "UNNEST should be a table-valued function")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := unnestFn.ValidateArgsFunc(tt.args)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, len(tt.expected), len(result))

			for i, expected := range tt.expected {
				assert.Equal(t, expected.Name, result[i].Name)
				assert.Equal(t, expected.Type.Name, result[i].Type.Name)
				assert.Equal(t, expected.Type.IsArray, result[i].Type.IsArray)
			}
		})
	}
}

func TestUNNESTPGFormat(t *testing.T) {
	unnestFn := Functions["unnest"].(*TableValuedFunctionDefinition)

	tests := []struct {
		name     string
		inputs   []string
		expected string
	}{
		{
			name:     "single array",
			inputs:   []string{"$1"},
			expected: "UNNEST($1)",
		},
		{
			name:     "multiple arrays",
			inputs:   []string{"$1", "$2"},
			expected: "UNNEST($1, $2)",
		},
		{
			name:     "three arrays",
			inputs:   []string{"$stream_ids", "$stream_types", "$stream_values"},
			expected: "UNNEST($stream_ids, $stream_types, $stream_values)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := unnestFn.PGFormatFunc(tt.inputs)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
