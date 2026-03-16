package parse

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/antlr4-go/antlr/v4"
)

// WrapErrors wraps a collection of ParseErrors
func WrapErrors(errs ...*ParseError) ParseErrs {
	return &errorListener{errs: errs}
}

// ParseError is an error that occurred during parsing.
type ParseError struct {
	ParserName string    `json:"parser_name,omitempty"`
	Err        error     `json:"error"`
	Message    string    `json:"message,omitempty"`
	Position   *Position `json:"position,omitempty"`
}

// MarshalJSON marshals the error to JSON.
func (p *ParseError) MarshalJSON() ([]byte, error) {
	type Alias struct {
		ParserName string    `json:"parser_name"`
		Message    string    `json:"message"`
		Position   *Position `json:"position"`
	}

	a := &Alias{
		ParserName: p.ParserName,
		Message:    p.Message,
		Position:   p.Position,
	}

	return json.Marshal(struct {
		Error string `json:"error"`
		*Alias
	}{
		Error: p.Err.Error(),
		Alias: a,
	})
}

// Unwrap() allows errors.Is and errors.As to find wrapped errors.
func (p ParseError) Unwrap() error {
	return p.Err
}

// Error satisfies the standard library error interface.
func (p *ParseError) Error() string {
	// Add 1 to the column numbers to make them 1-indexed, since antlr-go is 0-indexed
	// for columns.

	if p.Position.nilEnd() {
		if p.Position.nilStart() {
			return fmt.Sprintf("(%s) %s: %s", p.ParserName, p.Err.Error(), p.Message)
		}
		return fmt.Sprintf("(%s) %s: %s\n  location %d:%d", p.ParserName, p.Err.Error(), p.Message,
			*p.Position.StartLine, *p.Position.StartCol+1)
	}

	return fmt.Sprintf("(%s) %s: %s\n  start %d:%d end %d:%d", p.ParserName, p.Err.Error(), p.Message,
		*p.Position.StartLine, *p.Position.StartCol+1,
		*p.Position.EndLine, *p.Position.EndCol+1)
}

// ParseErrs is a collection of parse errors.
type ParseErrs interface {
	Err() error
	Errors() []*ParseError
	Add(...*ParseError)
	MarshalJSON() ([]byte, error)
}

// errorListener listens to errors emitted by Antlr, and also collects
// errors from Kwil's native validation logic.
type errorListener struct {
	errs []*ParseError
	name string
	toks *antlr.CommonTokenStream
}

var _ antlr.ErrorListener = (*errorListener)(nil)
var _ ParseErrs = (*errorListener)(nil)

// newErrorListener creates a new error listener with the given options.
func newErrorListener(name string) *errorListener {
	return &errorListener{
		errs: make([]*ParseError, 0),
		name: name,
	}
}

// Err returns the error if there are any, otherwise it returns nil.
func (e *errorListener) Err() error {
	if len(e.errs) == 0 {
		return nil
	}
	switch len(e.errs) {
	case 1:
		return e.errs[0]
	default:
		var errChain error
		for i, err := range e.errs {
			if i == 0 {
				errChain = numberErr(err, i)
				continue
			}
			errChain = fmt.Errorf("%w\n %w", errChain, numberErr(err, i))
		}

		return fmt.Errorf("detected multiple parse errors:\n %w", errChain)
	}
}

func numberErr(err error, i int) error {
	return fmt.Errorf("error %d: %w", i+1, err)
}

// Add adds errors to the collection.
func (e *errorListener) Add(errs ...*ParseError) {
	e.errs = append(e.errs, errs...)
}

// Errors returns the errors that have been collected.
func (e *errorListener) Errors() []*ParseError {
	return e.errs
}

// MarshalJSON marshals the errors to JSON.
func (e *errorListener) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.errs)
}

// AddErr adds an error to the error listener.
func (e *errorListener) AddErr(node GetPositioner, err error, msg string, v ...any) {
	if len(v) > 0 {
		// Almost always incorrect to "printf" a format string with no args. Any
		// "%" in the string will result in an error string.
		// https://go-review.googlesource.com/c/tools/+/585795
		// https://github.com/golang/go/issues/60529
		//
		// Even with this workaround, it would arguably be better to have the
		// caller do the formatting since lint cannot identify invalid format
		// specifiers (number or type). Leaving API the same for now.
		msg = fmt.Sprintf(msg, v...)
	}
	e.errs = append(e.errs, &ParseError{
		ParserName: e.name,
		Err:        err,
		Message:    msg,
		Position:   node.GetPosition(),
	})
}

// TokenErr adds an error that comes from an Antlr token.
func (e *errorListener) TokenErr(t antlr.Token, err error, msg string, v ...any) {
	if len(v) > 0 {
		msg = fmt.Sprintf(msg, v...)
	}
	e.errs = append(e.errs, &ParseError{
		ParserName: e.name,
		Err:        err,
		Message:    msg,
		Position:   unaryNode(t.GetLine(), t.GetColumn()),
	})
}

// RuleErr adds an error that comes from a Antlr parser rule.
func (e *errorListener) RuleErr(ctx antlr.ParserRuleContext, err error, msg string, v ...any) {
	node := &Position{}
	node.Set(ctx)
	if len(v) > 0 {
		msg = fmt.Sprintf(msg, v...)
	}
	e.errs = append(e.errs, &ParseError{
		ParserName: e.name,
		Err:        err,
		Message:    msg,
		Position:   node,
	})
}

// SyntaxError implements the Antlr error listener interface.
func (e *errorListener) SyntaxError(recognizer antlr.Recognizer, offendingSymbol any, line, column int,
	msg string, ex antlr.RecognitionException) {

	pos := unaryNode(line, column)
	// if there is a previous token, we should note the error starting from there
	if e.toks != nil {
		// since we are somewhat hacking the error position, we should catch panics and ignore them
		// all we are doing here is adding extra info to the error position, so if it fails, we can ignore it
		func() {
			defer func() {
				recover()
			}()
			prev := e.toks.LB(1)
			if prev != nil {
				col := prev.GetColumn()
				lin := prev.GetLine()
				pos.StartCol = &col
				pos.StartLine = &lin
			}
		}()
	}

	e.errs = append(e.errs, &ParseError{
		ParserName: e.name,
		Err:        ErrSyntax,
		Message:    msg,
		Position:   pos,
	})
}

// We do not need to do anything in the below methods because they are simply Antlr's way of reporting.
// We may want to add warnings in the future, but for now, we will ignore them.
// https://stackoverflow.com/questions/71056312/antlr-how-to-avoid-reportattemptingfullcontext-and-reportambiguity

// ReportAmbiguity implements the Antlr error listener interface.
func (e *errorListener) ReportAmbiguity(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex int,
	exact bool, ambigAlts *antlr.BitSet, configs *antlr.ATNConfigSet) {
}

// ReportAttemptingFullContext implements the Antlr error listener interface.
func (e *errorListener) ReportAttemptingFullContext(recognizer antlr.Parser, dfa *antlr.DFA, startIndex,
	stopIndex int, conflictingAlts *antlr.BitSet, configs *antlr.ATNConfigSet) {
}

// ReportContextSensitivity implements the Antlr error listener interface.
func (e *errorListener) ReportContextSensitivity(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex,
	prediction int, configs *antlr.ATNConfigSet) {
}

var (
	ErrSyntax                    = errors.New("syntax error")
	ErrType                      = errors.New("type error")
	ErrTableDefinition           = errors.New("table definition error")
	ErrUnknownColumn             = errors.New("unknown column reference")
	ErrDuplicateParameterName    = errors.New("duplicate parameter name")
	ErrDuplicateResultColumnName = errors.New("duplicate result column name")
	ErrIdentifier                = errors.New("identifier error")
	ErrCollation                 = errors.New("collation error")
	ErrNoPrimaryKey              = errors.New("missing primary key")
	ErrRedeclaredPrimaryKey      = errors.New("redeclare primary key")
	ErrRedeclaredConstraint      = errors.New("redeclared constraint")
	ErrGrantOrRevoke             = errors.New("grant or revoke error")
)
