package interpreter

import (
	"fmt"

	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

type comparisonOp uint8

// constants in this file begin with _ to avoid export

const (
	_EQUAL comparisonOp = iota
	_LESS_THAN
	_GREATER_THAN
	_IS
	_IS_DISTINCT_FROM
)

type unaryOp uint8

const (
	_NOT unaryOp = iota
	_NEG
	_POS
)

func (op unaryOp) String() string {
	switch op {
	case _NOT:
		return "NOT"
	case _NEG:
		return "-"
	case _POS:
		return "+"
	}

	panic(fmt.Sprintf("unknown unary operator: %d", op))
}

type arithmeticOp uint8

const (
	_ADD arithmeticOp = iota
	_SUB
	_MUL
	_DIV
	_MOD
	_EXP
	_CONCAT
)

func (op arithmeticOp) String() string {
	switch op {
	case _ADD:
		return "+"
	case _SUB:
		return "-"
	case _MUL:
		return "*"
	case _DIV:
		return "/"
	case _MOD:
		return "%"
	case _EXP:
		return "^"
	case _CONCAT:
		return "||"
	}

	panic(fmt.Sprintf("unknown arithmetic operator: %d", op))
}

func (op comparisonOp) String() string {
	switch op {
	case _EQUAL:
		return "="
	case _LESS_THAN:
		return "<"
	case _GREATER_THAN:
		return ">"
	case _IS:
		return "IS"
	case _IS_DISTINCT_FROM:
		return "IS DISTINCT FROM"
	}

	panic(fmt.Sprintf("unknown comparison operator: %d", op))
}

// convertComparisonOps gets the engine comparison operators for the given parse operator.
// Since the interpreter has a restricted subset of comparison operators compared to the parser,
// it is possible that one parser operator maps to multiple interpreter operators (which should be
// combined using OR). It also returns a boolean indicating if the operator should be negated.
func convertComparisonOps(op parse.ComparisonOperator) (ops []comparisonOp, negate bool) {
	switch op {
	case parse.ComparisonOperatorEqual:
		return []comparisonOp{_EQUAL}, false
	case parse.ComparisonOperatorNotEqual:
		return []comparisonOp{_EQUAL}, true
	case parse.ComparisonOperatorLessThan:
		return []comparisonOp{_LESS_THAN}, false
	case parse.ComparisonOperatorLessThanOrEqual:
		return []comparisonOp{_LESS_THAN, _EQUAL}, false
	case parse.ComparisonOperatorGreaterThan:
		return []comparisonOp{_GREATER_THAN}, false
	case parse.ComparisonOperatorGreaterThanOrEqual:
		return []comparisonOp{_GREATER_THAN, _EQUAL}, false
	}

	panic(fmt.Sprintf("unknown ast comparison operator: %v", op))
}

// convertArithmeticOp converts an arithmetic operator from the parser to the interpreter.
func convertArithmeticOp(op parse.ArithmeticOperator) arithmeticOp {
	ar, ok := arithmeticOps[op]
	if !ok {
		panic(fmt.Sprintf("unknown ast arithmetic operator: %v", op))
	}
	return ar
}

// convertUnaryOp converts a unary operator from the parser to the interpreter.
func convertUnaryOp(op parse.UnaryOperator) unaryOp {
	ar, ok := unaryOps[op]
	if !ok {
		panic(fmt.Sprintf("unknown ast unary operator: %v", op))
	}

	return ar
}

var arithmeticOps = map[parse.ArithmeticOperator]arithmeticOp{
	parse.ArithmeticOperatorAdd:      _ADD,
	parse.ArithmeticOperatorSubtract: _SUB,
	parse.ArithmeticOperatorMultiply: _MUL,
	parse.ArithmeticOperatorDivide:   _DIV,
	parse.ArithmeticOperatorModulo:   _MOD,
	parse.ArithmeticOperatorConcat:   _CONCAT,
	parse.ArithmeticOperatorExponent: _EXP,
}

var unaryOps = map[parse.UnaryOperator]unaryOp{
	parse.UnaryOperatorNot: _NOT,
	parse.UnaryOperatorNeg: _NEG,
	parse.UnaryOperatorPos: _POS,
}
