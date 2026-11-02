package parse

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func nest(open, inner, close string, n int) string {
	return strings.Repeat(open, n) + inner + strings.Repeat(close, n)
}

func Test_MaxDepth(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		tooDeep bool
	}{
		{name: "nested parentheses", sql: "SELECT " + nest("(", "1", ")", 200)},
		{name: "long operator chain", sql: "SELECT 1" + strings.Repeat(" + 1", 900)},
		{name: "too many parentheses", sql: "SELECT " + nest("(", "1", ")", maxParseDepth), tooDeep: true},
		{name: "too many NOTs", sql: "SELECT " + strings.Repeat("NOT ", maxParseDepth) + "true", tooDeep: true},
		{name: "too many unary minuses", sql: "SELECT " + strings.Repeat("- ", maxParseDepth) + "1", tooDeep: true},
		{name: "too many arrays", sql: "SELECT " + nest("ARRAY[", "1", "]", maxParseDepth), tooDeep: true},
		{name: "too many subqueries", sql: nest("SELECT * FROM (", "SELECT 1", ") t", maxParseDepth), tooDeep: true},
		{name: "too long operator chain", sql: "SELECT 1" + strings.Repeat(" + 1", 2*maxParseDepth), tooDeep: true},
		{name: "too long AND chain", sql: "SELECT true" + strings.Repeat(" AND true", 2*maxParseDepth), tooDeep: true},
		{name: "too many nested IFs", sql: "CREATE ACTION a() public {" + nest("IF true {", "", "}", maxParseDepth) + "}", tooDeep: true},
		{name: "too long action expression chain", sql: "CREATE ACTION a() public { $x := 1" + strings.Repeat(" + 1", 2*maxParseDepth) + "; }", tooDeep: true},
		// the MYT-14 payload: before the limit, 2.5 MB of parentheses
		// overflowed the Go stack, which kills the process
		{name: "stack overflow payload", sql: "SELECT " + nest("(", "1", ")", 1_250_000), tooDeep: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.sql)
			if tt.tooDeep {
				require.ErrorIs(t, err, ErrMaxDepth)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
