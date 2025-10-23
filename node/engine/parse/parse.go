// package parse contains logic for parsing SQL, DDL, and Actions,
// and SQL.
package parse

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"

	"github.com/antlr4-go/antlr/v4"
	"github.com/trufnetwork/kwil-db/node/engine/parse/gen"
)

// ParseResult is the result of parsing a SQL statement.
// It can be any statement, including:
// - CREATE TABLE
// - SELECT/INSERT/UPDATE/DELETE
// - CREATE ACTION
// - etc.
type ParseResult struct {
	// Statements are the individual statements, in the order they were encountered.
	Statements []TopLevelStatement `json:"statements,omitempty"`
	// ParseErrs is the error listener that contains all the errors that occurred during parsing.
	ParseErrs ParseErrs `json:"parse_errs,omitempty"`
}

func (r *ParseResult) Err() error {
	return r.ParseErrs.Err()
}

// Parse parses a statement or set of statements separated by semicolons.
func Parse(sql string) (t []TopLevelStatement, err error) {
	defer func() {
		if r := recover(); r != nil {
			switch x := r.(type) {
			case error:
				err = x
			default:
				err = fmt.Errorf("panic: %v", r)
			}
		}
	}()

	res, err := ParseWithErrListener(sql)
	if err != nil {
		return nil, err
	}

	if res.Err() != nil {
		return nil, res.Err()
	}

	return res.Statements, nil
}

// ParseWithErrListener parses a statement or set of statements separated by semicolons.
// It returns the parsed statements, as well as an error listener with position information.
// Public consumers should opt for Parse instead, unless there is a specific need for the error listener.
func ParseWithErrListener(sql string) (p *ParseResult, err error) {
	parser, errLis, parseVisitor, deferFn, err := setupParser(sql)
	if err != nil {
		return nil, err
	}
	p = &ParseResult{
		ParseErrs: errLis,
	}

	defer func() {
		err2 := deferFn(recover())
		if err2 != nil {
			err = err2
		}
	}()

	p.Statements = parser.Entry().Accept(parseVisitor).([]TopLevelStatement)

	return p, nil
}

func setupParser(sql string) (parser *gen.KuneiformParser, errList *errorListener, parserVisitor *schemaVisitor, deferFn func(any) error, err error) {
	// trim whitespace
	sql = strings.TrimSpace(sql)

	// add semicolon to the end of the statement, if it is not there
	if !strings.HasSuffix(sql, ";") {
		sql += ";"
	}

	errList = newErrorListener("sql")
	stream := antlr.NewInputStream(sql)

	lexer := gen.NewKuneiformLexer(stream)
	tokens := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	parser = gen.NewKuneiformParser(tokens)
	errList.toks = tokens

	// remove defaults
	lexer.RemoveErrorListeners()
	parser.RemoveErrorListeners()
	lexer.AddErrorListener(errList)
	parser.AddErrorListener(errList)

	parser.BuildParseTrees = true

	deferFn = func(e any) (err error) {
		if e != nil {
			var ok bool
			err, ok = e.(error)
			if !ok {
				err = fmt.Errorf("panic: %v", e)
			}
		}

		// if there is a panic, it may be due to a syntax error.
		// therefore, we should check for syntax errors first and if
		// any occur, swallow the panic and return the syntax errors.
		// If the issue persists past syntax errors, the else block
		// will return the error.
		if errList.Err() != nil {
			return nil
		} else if err != nil {
			// stack trace since this is a core bug or unexpected error
			buf := make([]byte, 1<<16)

			stackSize := runtime.Stack(buf, false)
			err = fmt.Errorf("%w\n\n%s", err, buf[:stackSize])

			return err
		}

		return nil
	}

	parserVisitor = newSchemaVisitor(stream, errList)

	return parser, errList, parserVisitor, deferFn, err
}

// RecursivelyVisitPositions traverses a structure recursively, visiting all position struct types.
// It is used in both parsing tools, as well as in tests.
// WARNING: This function should NEVER be used in consensus, since it is non-deterministic.
func RecursivelyVisitPositions(v any, fn func(GetPositioner)) {

	visited := make(map[uintptr]struct{})
	visitRecursive(reflect.ValueOf(v), reflect.TypeFor[GetPositioner](), func(v reflect.Value) {
		if v.CanInterface() {
			a := v.Interface().(GetPositioner)
			fn(a)
		}
	}, visited)
}

// visitRecursive is a recursive function that visits all types that implement the target interface.
func visitRecursive(v reflect.Value, target reflect.Type, fn func(reflect.Value), visited map[uintptr]struct{}) {
	if v.Type().Implements(target) {
		// check if the value is nil
		if !v.IsNil() {
			fn(v)
		}
	}

	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return
		}

		visitRecursive(v.Elem(), target, fn, visited)
	case reflect.Ptr:
		if v.IsNil() {
			return
		}

		// check if we have visited this pointer before
		ptr := v.Pointer()
		if _, ok := visited[ptr]; ok {
			return
		}
		visited[ptr] = struct{}{}

		visitRecursive(v.Elem(), target, fn, visited)
	case reflect.Struct:
		for i := range v.NumField() {
			visitRecursive(v.Field(i), target, fn, visited)
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			visitRecursive(v.Index(i), target, fn, visited)
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			visitRecursive(v.MapIndex(key), target, fn, visited)
		}
	}
}
