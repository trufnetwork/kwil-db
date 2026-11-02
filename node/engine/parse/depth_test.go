package parse

import (
	"strings"
	"testing"

	"github.com/antlr4-go/antlr/v4"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/node/engine/parse/gen"
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

// treeDepth parses sql without any depth limit and returns the depth of the
// deepest rule in the parse tree, counted the way checkTreeDepth counts it.
func treeDepth(t *testing.T, sql string) int {
	lexer := gen.NewKuneiformLexer(antlr.NewInputStream(sql))
	parser := gen.NewKuneiformParser(antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel))
	parser.RemoveErrorListeners()
	errs := newErrorListener("test")
	parser.AddErrorListener(errs)
	tree := parser.Entry()
	require.NoError(t, errs.Err())

	var walk func(ctx antlr.ParserRuleContext, depth int) int
	walk = func(ctx antlr.ParserRuleContext, depth int) int {
		deepest := depth
		for _, child := range ctx.GetChildren() {
			if c, ok := child.(antlr.ParserRuleContext); ok {
				deepest = max(deepest, walk(c, depth+1))
			}
		}
		return deepest
	}
	return walk(tree, 1)
}

// Test_MaxDepthBoundary checks that a tree exactly maxParseDepth deep parses
// and one level deeper does not, for both checks: parentheses are stopped by
// depthLimiter while parsing, operator chains by checkTreeDepth afterwards.
func Test_MaxDepthBoundary(t *testing.T) {
	tests := []struct {
		name string
		sql  func(n int) string
	}{
		{name: "parentheses", sql: func(n int) string { return "SELECT " + nest("(", "1", ")", n) + ";" }},
		{name: "operator chain", sql: func(n int) string { return "SELECT 1" + strings.Repeat(" + 1", n) + ";" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// each repetition adds the same number of levels, so solve for
			// the repetition count that reaches maxParseDepth exactly
			base := treeDepth(t, tt.sql(1))
			step := treeDepth(t, tt.sql(2)) - base
			require.Equal(t, 1, step, "boundary test assumes one level per repetition")

			n := 1 + maxParseDepth - base
			require.Equal(t, maxParseDepth, treeDepth(t, tt.sql(n)))

			_, err := Parse(tt.sql(n))
			require.NoError(t, err, "a tree exactly maxParseDepth deep must parse")

			_, err = Parse(tt.sql(n + 1))
			require.ErrorIs(t, err, ErrMaxDepth, "a tree one level deeper must be rejected")
		})
	}
}
