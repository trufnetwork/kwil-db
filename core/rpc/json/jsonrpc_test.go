package jsonrpc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_stdID(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected any
	}{
		{
			name:     "float64 to int64",
			input:    float64(123.0),
			expected: int64(123),
		},
		{
			name:     "string remains string",
			input:    "test-id",
			expected: "test-id",
		},
		{
			name:     "int remains int",
			input:    42,
			expected: 42,
		},
		{
			name:     "int64 remains int64",
			input:    int64(9223372036854775807),
			expected: int64(9223372036854775807),
		},
		{
			name:     "uint remains uint",
			input:    uint(123),
			expected: uint(123),
		},
		{
			name:     "nil remains nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "float64 with fraction is not truncated",
			input:    float64(123.45),
			expected: float64(123.45),
		},
		{
			name:     "float64 at 2^63 is not saturated to MinInt64",
			input:    float64(1 << 63),
			expected: float64(1 << 63),
		},
		{
			name:     "float64 beyond int64 is not saturated to MinInt64",
			input:    float64(1e20),
			expected: float64(1e20),
		},
		{
			name:     "float64 at MinInt64 converts",
			input:    float64(-1 << 63),
			expected: int64(-1 << 63),
		},
		{
			name:     "float64 negative integer converts",
			input:    float64(-5),
			expected: int64(-5),
		},
		{
			name:     "custom type converts to string",
			input:    struct{ name string }{"test"},
			expected: "{test}",
		},
		{
			name:     "uint8 remains uint8",
			input:    uint8(255),
			expected: uint8(255),
		},
		{
			name:     "uintptr remains uintptr",
			input:    uintptr(0xFFFF),
			expected: uintptr(0xFFFF),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stdID(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNewResponse(t *testing.T) {
	tests := []struct {
		name        string
		id          any
		result      any
		expected    *Response
		expectError bool
	}{
		{
			name:   "valid response with string id",
			id:     "test-123",
			result: map[string]string{"status": "ok"},
			expected: &Response{
				JSONRPC: "2.0",
				ID:      "test-123",
				Result:  []byte(`{"status":"ok"}`),
			},
			expectError: false,
		},
		{
			name:        "invalid zero id",
			id:          0,
			result:      "test",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid result that cannot be marshaled",
			id:          123,
			result:      make(chan int),
			expected:    nil,
			expectError: true,
		},
		{
			name:   "response with complex nested result",
			id:     456,
			result: map[string]interface{}{"data": []int{1, 2, 3}, "meta": map[string]bool{"valid": true}},
			expected: &Response{
				JSONRPC: "2.0",
				ID:      456,
				Result:  []byte(`{"data":[1,2,3],"meta":{"valid":true}}`),
			},
			expectError: false,
		},
		{
			name:   "response with float id converted to int64",
			id:     float64(789.0),
			result: "success",
			expected: &Response{
				JSONRPC: "2.0",
				ID:      int64(789),
				Result:  []byte(`"success"`),
			},
			expectError: false,
		},
		{
			name:   "response with null result",
			id:     "null-test",
			result: nil,
			expected: &Response{
				JSONRPC: "2.0",
				ID:      "null-test",
				Result:  []byte("null"),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := NewResponse(tt.id, tt.result)
			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, response)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected.JSONRPC, response.JSONRPC)
				require.Equal(t, tt.expected.ID, response.ID)
				require.JSONEq(t, string(tt.expected.Result), string(response.Result))
			}
		})
	}
}
