package interpreter

import (
	"strings"
	"unicode"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/node/engine"
)

func engineTrace(exec *executionContext) *common.EngineTrace {
	if exec == nil || exec.engineCtx == nil || exec.engineCtx.TxContext == nil {
		return nil
	}
	return exec.engineCtx.TxContext.EngineTrace
}

func startEngineTrace(exec *executionContext, kind, namespace, name string) func() {
	tr := engineTrace(exec)
	if tr == nil {
		return func() {}
	}
	if namespace == "" && exec.scope != nil {
		namespace = exec.scope.namespace
	}
	return tr.Start(kind, namespace, name, tr.ParentName())
}

func observeExecutable(exec *executionContext, namespace string, def *executable, args []Value, fn resultFunc) error {
	if def == nil {
		return engine.ErrUnknownAction
	}
	if def.Type != executableTypeAction && def.Type != executableTypePrecompile {
		return def.Func(exec, args, fn)
	}
	kind := common.EngineTraceKindAction
	if def.Type == executableTypePrecompile {
		kind = common.EngineTraceKindPrecompile
	}
	done := startEngineTrace(exec, kind, namespace, def.Name)
	defer done()
	return def.Func(exec, args, fn)
}

// observeSQL must check for a tracer before naming the stage: sqlVerbTable
// tokenizes the whole statement, and untraced callers (read-only RPC and
// authenticated queries) run this on every statement they execute.
func observeSQL(exec *executionContext, sql string) func() {
	if engineTrace(exec) == nil {
		return func() {}
	}
	return startEngineTrace(exec, common.EngineTraceKindSQL, "", sqlVerbTable(sql))
}

func sqlVerbTable(sql string) string {
	tokens := sqlIdentTokens(sql)
	if len(tokens) == 0 {
		return "sql"
	}
	verb := strings.ToLower(tokens[0])
	table := ""
	switch verb {
	case "insert":
		table = tokenAfter(tokens, "into")
		verb = "insert"
	case "update":
		if len(tokens) > 1 {
			table = tokens[1]
		}
		verb = "update"
	case "delete":
		table = tokenAfter(tokens, "from")
		verb = "delete"
	case "select", "with":
		table = tokenAfter(tokens, "from")
		verb = "select"
	default:
		return "sql"
	}
	table = unqualifyTable(table)
	if table == "" {
		return verb
	}
	return verb + ":" + table
}

func sqlIdentTokens(sql string) []string {
	s := stripSQLComments(sql)
	var tokens []string
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		tokens = append(tokens, b.String())
		b.Reset()
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return tokens
}

func stripSQLComments(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))
	for i := 0; i < len(sql); i++ {
		if i+1 < len(sql) && sql[i] == '-' && sql[i+1] == '-' {
			i += 2
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			continue
		}
		if i+1 < len(sql) && sql[i] == '/' && sql[i+1] == '*' {
			i += 2
			for i+1 < len(sql) && !(sql[i] == '*' && sql[i+1] == '/') {
				i++
			}
			if i+1 < len(sql) {
				i++
			}
			continue
		}
		b.WriteByte(sql[i])
	}
	return b.String()
}

func tokenAfter(tokens []string, keyword string) string {
	for i, tok := range tokens {
		if strings.EqualFold(tok, keyword) && i+1 < len(tokens) {
			return tokens[i+1]
		}
	}
	return ""
}

func unqualifyTable(name string) string {
	if name == "" {
		return ""
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 && i+1 < len(name) {
		return strings.ToLower(name[i+1:])
	}
	return strings.ToLower(name)
}
