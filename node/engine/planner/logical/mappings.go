package logical

import (
	"fmt"

	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

// the following maps map constants from parse to their logical
// equivalents. I thought about just using the parse constants,
// but decided to have clean separation so that other parts of the
// planner don't have to rely on the parse package.

var stringComparisonOps = map[parse.StringComparisonOperator]ComparisonOperator{
	parse.StringComparisonOperatorLike:  Like,
	parse.StringComparisonOperatorILike: ILike,
}

var logicalOps = map[parse.LogicalOperator]LogicalOperator{
	parse.LogicalOperatorAnd: And,
	parse.LogicalOperatorOr:  Or,
}

var arithmeticOps = map[parse.ArithmeticOperator]ArithmeticOperator{
	parse.ArithmeticOperatorAdd:      Add,
	parse.ArithmeticOperatorSubtract: Subtract,
	parse.ArithmeticOperatorMultiply: Multiply,
	parse.ArithmeticOperatorDivide:   Divide,
	parse.ArithmeticOperatorModulo:   Modulo,
	parse.ArithmeticOperatorConcat:   Concat,
}

var unaryOps = map[parse.UnaryOperator]UnaryOperator{
	parse.UnaryOperatorNeg: Negate,
	parse.UnaryOperatorNot: Not,
	parse.UnaryOperatorPos: Positive,
}

var joinTypes = map[parse.JoinType]JoinType{
	parse.JoinTypeInner: InnerJoin,
	parse.JoinTypeLeft:  LeftOuterJoin,
	parse.JoinTypeRight: RightOuterJoin,
	parse.JoinTypeFull:  FullOuterJoin,
}

var compoundTypes = map[parse.CompoundOperator]SetOperationType{
	parse.CompoundOperatorUnion:     Union,
	parse.CompoundOperatorUnionAll:  UnionAll,
	parse.CompoundOperatorIntersect: Intersect,
	parse.CompoundOperatorExcept:    Except,
}

var orderAsc = map[parse.OrderType]bool{
	parse.OrderTypeAsc:  true,
	parse.OrderTypeDesc: false,
	"":                  true, // default to ascending
}

var orderNullsLast = map[parse.NullOrder]bool{
	parse.NullOrderFirst: false,
	parse.NullOrderLast:  true,
	"":                   true, // default to nulls last
}

// get retrieves a value from a map, and panics if the key is not found.
// it is used to catch internal errors if we add new nodes to the AST
// without updating the planner.
func get[A comparable, B any](m map[A]B, a A) B {
	if v, ok := m[a]; ok {
		return v
	}
	panic(fmt.Sprintf("key %v not found in map %v", a, m))
}
