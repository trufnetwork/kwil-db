package order_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufnetwork/kwil-db/core/utils/order"
)

func TestOrderMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[int]string
		expected []*order.KVPair[int, string]
	}{
		{
			name:     "empty map",
			input:    map[int]string{},
			expected: []*order.KVPair[int, string]{},
		},
		{
			name: "single item",
			input: map[int]string{
				1: "one",
			},
			expected: []*order.KVPair[int, string]{
				{Key: 1, Value: "one"},
			},
		},
		{
			name: "multiple items unordered",
			input: map[int]string{
				3: "three",
				1: "one",
				2: "two",
			},
			expected: []*order.KVPair[int, string]{
				{Key: 1, Value: "one"},
				{Key: 2, Value: "two"},
				{Key: 3, Value: "three"},
			},
		},
		{
			name: "negative numbers",
			input: map[int]string{
				-2: "minus two",
				0:  "zero",
				-1: "minus one",
				1:  "one",
			},
			expected: []*order.KVPair[int, string]{
				{Key: -2, Value: "minus two"},
				{Key: -1, Value: "minus one"},
				{Key: 0, Value: "zero"},
				{Key: 1, Value: "one"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := order.OrderMap(tt.input)
			assert.Equal(t, len(tt.expected), len(result))
			for i, pair := range result {
				assert.Equal(t, tt.expected[i].Key, pair.Key)
				assert.Equal(t, tt.expected[i].Value, pair.Value)
			}
		})
	}
}

func TestOrderMapString(t *testing.T) {
	input := map[string]int{
		"c": 3,
		"a": 1,
		"b": 2,
	}

	expected := []*order.KVPair[string, int]{
		{Key: "a", Value: 1},
		{Key: "b", Value: 2},
		{Key: "c", Value: 3},
	}

	result := order.OrderMap(input)
	assert.Equal(t, len(expected), len(result))
	for i, pair := range result {
		assert.Equal(t, expected[i].Key, pair.Key)
		assert.Equal(t, expected[i].Value, pair.Value)
	}
}
