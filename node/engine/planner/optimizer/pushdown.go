package optimizer

import (
	"errors"
	"fmt"

	"github.com/trufnetwork/kwil-db/node/engine/planner/logical"
)

// PushdownPredicates pushes down filters to the lowest possible level.
// It rewrites the logical plan to push down filters as far as possible.
// The returned plan should always be used, and the original plan should be discarded,
// as it might be in an inconsistent state.
func PushdownPredicates(n logical.Plan) (logical.Plan, error) {
	// we start by pushing down filters
	plan, err := push(n, nil)
	if err != nil {
		return nil, err
	}

	return plan, nil
}

// push is a recursive function that pushes down filters.
// It passes the filter expression to the next node.
// The expr can be nil if there is no filter to push.
// It returns the expression that could not be pushed down,
// which should be set as the filter.
func push(n logical.Plan, expr logical.Expression) (logical.Plan, error) {
	// pushLeftRight is a helper function that determines whether or not an
	// expression can be pushed down either side of a join.
	// It is defined separately here because the logic is used both in Join
	// and CartesianProduct.
	pushLeftRight := func(left, right logical.Plan, expr logical.Expression) (logical.Plan, logical.Plan, logical.Expression, error) {
		if expr == nil {
			return left, right, nil, nil
		}

		ands := splitAnds(expr)
		var leftover logical.Expression

		for _, and := range ands {
			cols := findColumns(and)

			var leftCount, rightCount int

			// if all columns are from one side, push down the filter to that side.
			// otherwise, apply the filter to the join condition.
			leftRel := left.Relation()
			for _, field := range leftRel.Fields {
				if _, ok := cols[[2]string{field.Parent, field.Name}]; ok {
					leftCount++
				}
			}

			rightRel := right.Relation()
			for _, field := range rightRel.Fields {
				if _, ok := cols[[2]string{field.Parent, field.Name}]; ok {
					rightCount++
				}
			}

			switch {
			case leftCount == 0 && rightCount == 0:
				// we can't push down the filter
				return nil, nil, nil, errCannotPush
			case leftCount == 0 && rightCount > 0:
				// push down to the right side
				res, err := push(right, and)
				if err != nil {
					return nil, nil, nil, err
				}

				right = res
			case leftCount > 0 && rightCount == 0:
				// push down to the left side
				res, err := push(left, and)
				if err != nil {
					return nil, nil, nil, err
				}

				left = res
			case leftCount > 0 && rightCount > 0:
				// apply the filter to the join condition
				leftover = makeAnd(leftover, and)
			default:
				panic("unexpected column count case")
			}
		}

		return left, right, leftover, nil
	}

	// we need to make sure that for all children, we visit the subplans.
	// We will already rewrite for all logical.Plan nodes, but we need to
	// rewrite for all expressions as well.
	for _, child := range n.Children() {
		if expr, ok := child.(logical.Expression); ok {
			for _, plan := range expr.Plans() {
				res, err := push(plan, nil)
				if err != nil {
					return nil, err
				}

				if res != plan {
					return nil, fmt.Errorf("unhandled rewrite: tried to rewrite a %T as a child of a %T", res, n)
				}
			}
		}
	}

	// we also perform a switch to directly rewrite each logical.Plan node.
	switch n := n.(type) {
	case *logical.Filter:
		if expr != nil {
			return nil, errCannotPush
		}

		if _, ok := n.Child.(*logical.Aggregate); ok {
			// we can't push down filters to aggregates
			return n, nil
		}

		fin, err := push(n.Child, n.Condition)
		if err != nil {
			return nil, err
		}

		// since we no longer have a condition, we can just return the child
		return fin, nil
	case *logical.Join:
		left, right, leftover, err := pushLeftRight(n.Left, n.Right, expr)
		if err != nil {
			return nil, err
		}

		n.Left = left
		n.Right = right
		n.Condition = makeAnd(n.Condition, leftover)

		return n, nil
	case *logical.Scan:
		n.Filter = makeAnd(n.Filter, expr)
		return n, nil
	case *logical.Project:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Child, nil)
		if err != nil {
			return nil, err
		}

		n.Child = res
		return n, nil
	case *logical.CartesianProduct:
		if expr == nil {
			return n, nil
		}

		left, right, leftover, err := pushLeftRight(n.Left, n.Right, expr)
		if err != nil {
			return nil, err
		}

		n.Left = left
		n.Right = right

		// if leftover is not nil, then we can rewrite as a join
		if leftover == nil {
			return n, nil
		}

		return &logical.Join{
			Left:      left,
			Right:     right,
			Condition: leftover,
		}, nil
	case *logical.Aggregate:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Child, nil)
		if err != nil {
			return nil, err
		}

		n.Child = res
		return n, nil
	case *logical.Sort:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Child, nil)
		if err != nil {
			return nil, err
		}

		n.Child = res
		return n, nil
	case *logical.Limit:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Child, nil)
		if err != nil {
			return nil, err
		}

		n.Child = res
		return n, nil
	case *logical.Distinct:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Child, nil)
		if err != nil {
			return nil, err
		}

		n.Child = res
		return n, nil
	case *logical.Window:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Child, nil)
		if err != nil {
			return nil, err
		}

		n.Child = res
		return n, nil
	case *logical.SetOperation:
		if expr != nil {
			return nil, errCannotPush
		}

		left, err := push(n.Left, nil)
		if err != nil {
			return nil, err
		}

		right, err := push(n.Right, nil)
		if err != nil {
			return nil, err
		}

		n.Left = left
		n.Right = right

		return n, nil
	case *logical.Subplan:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Plan, nil)
		if err != nil {
			return nil, err
		}

		n.Plan = res
		return n, nil
	case *logical.Return:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Child, nil)
		if err != nil {
			return nil, err
		}

		n.Child = res
		return n, nil
	case *logical.Insert:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.InsertionValues, nil)
		if err != nil {
			return nil, err
		}

		n.InsertionValues = res.(*logical.Tuples)

		if n.ConflictResolution != nil {
			res, err = push(n.ConflictResolution, nil)
			if err != nil {
				return nil, err
			}

			n.ConflictResolution = res.(logical.ConflictResolution)
		}

		return n, nil
	case *logical.Update:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Child, expr)
		if err != nil {
			return nil, err
		}

		n.Child = res
		return n, nil
	case *logical.Delete:
		if expr != nil {
			return nil, errCannotPush
		}

		res, err := push(n.Child, expr)
		if err != nil {
			return nil, err
		}

		n.Child = res
		return n, nil
	case *logical.ConflictDoNothing:
		if expr != nil {
			return nil, errCannotPush
		}

		return n, nil
	case *logical.ConflictUpdate:
		if expr != nil {
			return nil, errCannotPush
		}

		return n, nil
	default:
		panic(fmt.Sprintf("unhandled node type %T", n))
	}
}

// errCannotPush is used when a predicate cannot be pushed down.
// It is used to signal that the calling function should not attempt to rewrite the plan.
var errCannotPush = errors.New("cannot push down predicate")

// makeAnd combines two expressions with an AND operator.
// If either expression is nil, the other expression is returned.
func makeAnd(left, right logical.Expression) logical.Expression {
	if left == nil {
		return right
	}

	if right == nil {
		return left
	}

	return &logical.LogicalOp{
		Left:  left,
		Op:    logical.And,
		Right: right,
	}
}

// findColumns returns all columns in the expression.
// It does not search for columns in subqueries.
func findColumns(expr logical.Expression) map[[2]string]*logical.ColumnRef {
	cols := make(map[[2]string]*logical.ColumnRef)
	logical.Traverse(expr, func(node logical.Traversable) bool {
		switch node := node.(type) {
		case *logical.ColumnRef:
			cols[[2]string{node.Parent, node.ColumnName}] = node
			return false
		case *logical.SubqueryExpr:
			return false
		}
		return true
	})

	return cols
}

// splitAnds splits a tree of AND expressions into a list of expressions.
func splitAnds(expr logical.Expression) []logical.Expression {
	and, ok := expr.(*logical.LogicalOp)
	if !ok {
		return []logical.Expression{expr}
	}

	if and.Op != logical.And {
		return []logical.Expression{expr}
	}

	return append(splitAnds(and.Left), splitAnds(and.Right)...)
}
