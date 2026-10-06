package jsonrpc

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// stdID keeps an id it cannot convert exactly: a json.Number, and a float64
// that is not a whole number in the int64 range, including an infinity and NaN.
func Test_stdIDKeepsInexactNumbers(t *testing.T) {
	for _, tt := range []struct {
		name     string
		input    any
		expected any
	}{
		{"json.Number is kept", json.Number("9007199254740993"), json.Number("9007199254740993")},
		{"json.Number with a fraction is kept", json.Number("1.5"), json.Number("1.5")},
		{"infinity is kept", math.Inf(1), math.Inf(1)},
		{"negative infinity is kept", math.Inf(-1), math.Inf(-1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, stdID(tt.input))
		})
	}

	t.Run("NaN is kept", func(t *testing.T) {
		result, ok := stdID(math.NaN()).(float64)
		require.True(t, ok)
		require.True(t, math.IsNaN(result))
	})
}
