package logical

import (
	"fmt"

	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

// RewriteConfig is a configuration for the rewriter.
type RewriteConfig struct {
	// ExprCallback is the function that will be called on each expression.
	// It returns the new node, which will replace the old node,
	// a boolean, which indicates whether the nodes children should be visited,
	// and an error, which will be returned if an error occurs.
	ExprCallback func(Expression) (Expression, bool, error)
	// PlanCallback is the function that will be called on each plan
	// It returns the new node, which will replace the old node,
	// a boolean, which indicates whether the nodes children should be visited,
	// and an error, which will be returned if an error occurs.
	PlanCallback func(Plan) (Plan, bool, error)
	// ScanSourceCallback is the function that will be called on each scan source
	// It returns the new node, which will replace the old node,
	// a boolean, which indicates whether the nodes children should be visited,
	// and an error, which will be returned if an error occurs.
	ScanSourceCallback func(ScanSource) (ScanSource, bool, error)
}

// Rewrite rewrites a logical plan using the given configuration.
// It returns the rewritten plan, but it also modifies the original plan in place.
// The returned plan should always be used.
func Rewrite(node LogicalNode, cfg *RewriteConfig) (lp LogicalNode, err error) {
	defer func() {
		if r := recover(); r != nil {
			err2, ok := r.(error)
			if !ok {
				err = fmt.Errorf("%v", r)
			} else {
				err = err2
			}
		}
	}()

	v := &rewriteVisitor{
		exprCallback:       cfg.ExprCallback,
		planCallback:       cfg.PlanCallback,
		scanSourceCallback: cfg.ScanSourceCallback,
	}
	if v.exprCallback == nil {
		v.exprCallback = func(e Expression) (Expression, bool, error) {
			return e, true, nil
		}
	}
	if v.planCallback == nil {
		v.planCallback = func(p Plan) (Plan, bool, error) {
			return p, true, nil
		}
	}
	if v.scanSourceCallback == nil {
		v.scanSourceCallback = func(s ScanSource) (ScanSource, bool, error) {
			return s, true, nil
		}
	}

	return node.Accept(v).(LogicalNode), nil
}

// rewriteVisitor is a visitor that can be used to rewrite a logical plan.
// For all visits, functions can be given to determine the order in which
// fields are visited in. They should be passed in post-order (e.g. in the same
// order as they would need to be visited to evaluate the relation).
type rewriteVisitor struct {
	// exprCallback is the function that will be called on each expression
	exprCallback func(Expression) (Expression, bool, error)
	// planCallback is the function that will be called on each plan
	planCallback func(Plan) (Plan, bool, error)
	// scanSourceCallback is the function that will be called on each scan source
	scanSourceCallback func(ScanSource) (ScanSource, bool, error)
	// if true, the node is visited in post order
	// if false, the node is visited in pre order
	postOrder bool
	// if true, then fields are visited in the reverse order of their logic.
	// For example, if true in a projection, the fields representing the projected
	// expressions are visited before the child. If false, the child is visited first.
	reverseFieldOrder bool
}

func (r *rewriteVisitor) VisitTableScanSource(p0 *TableScanSource) any {
	return r.scanSource(p0, func() {})
}

func (r *rewriteVisitor) VisitTableFunctionScanSource(p0 *TableFunctionScanSource) any {
	return r.scanSource(p0, func() {})
}

func (r *rewriteVisitor) VisitRelationTableFunction(p0 *parse.RelationTableFunction) any {
	// The rewriter operates on logical plans, not parse AST nodes.
	// RelationTableFunction nodes are handled during logical planning phase,
	// not during rewriting. This visitor should not be called in practice.
	return p0
}

func (r *rewriteVisitor) slice(v any) {
	if v == nil {
		return
	}
	switch v := v.(type) {
	case []Plan:
		for i := range v {
			v[i] = v[i].Accept(r).(Plan)
		}
	case []Expression:
		for i := range v {
			v[i] = v[i].Accept(r).(Expression)
		}
	}
}

func (r *rewriteVisitor) VisitProcedureScanSource(p0 *ProcedureScanSource) any {
	return r.scanSource(p0, func() {
		r.slice(p0.ContextualArgs)
		r.slice(p0.Args)
	})
}

func (r *rewriteVisitor) VisitSubquery(p0 *Subquery) any {
	return r.scanSource(p0, r.subqueryFuncs(p0)...)
}

// defining this separately since we use it in several places
func (r *rewriteVisitor) subqueryFuncs(p0 *Subquery) []func() {
	return []func(){func() {
		p0.Plan.Plan = p0.Plan.Plan.Accept(r).(Plan)
	}}
}

func (r *rewriteVisitor) VisitEmptyScan(p0 *EmptyScan) any {
	return r.plan(p0, func() {})
}

func (r *rewriteVisitor) VisitScan(p0 *Scan) any {
	return r.plan(p0,
		func() { p0.Source = p0.Source.Accept(r).(ScanSource) },
		func() {
			if p0.Filter != nil {
				p0.Filter = p0.Filter.Accept(r).(Expression)
			}
		},
	)
}

func (r *rewriteVisitor) VisitProject(p0 *Project) any {
	return r.plan(p0,
		func() { p0.Child = p0.Child.Accept(r).(Plan) },
		func() { r.slice(p0.Expressions) },
	)
}

func (r *rewriteVisitor) VisitFilter(p0 *Filter) any {
	return r.plan(p0,
		func() { p0.Child = p0.Child.Accept(r).(Plan) },
		func() {
			if p0.Condition != nil { // can be nil case of pushdown
				p0.Condition = p0.Condition.Accept(r).(Expression)
			}
		},
	)
}

func (r *rewriteVisitor) VisitJoin(p0 *Join) any {
	return r.plan(p0,
		func() { p0.Left = p0.Left.Accept(r).(Plan) },
		func() { p0.Right = p0.Right.Accept(r).(Plan) },
		func() { p0.Condition = p0.Condition.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitSort(p0 *Sort) any {
	return r.plan(p0,
		func() { p0.Child = p0.Child.Accept(r).(Plan) },
		func() {
			for _, sort := range p0.SortExpressions {
				sort.Expr = sort.Expr.Accept(r).(Expression)
			}
		},
	)
}

func (r *rewriteVisitor) VisitLimit(p0 *Limit) any {
	return r.plan(p0, func() {
		p0.Child = p0.Child.Accept(r).(Plan)
		p0.Limit = p0.Limit.Accept(r).(Expression)
		p0.Offset = p0.Offset.Accept(r).(Expression)
	})
}

func (r *rewriteVisitor) VisitDistinct(p0 *Distinct) any {
	return r.plan(p0,
		func() { p0.Child = p0.Child.Accept(r).(Plan) },
	)
}

func (r *rewriteVisitor) VisitSetOperation(p0 *SetOperation) any {
	return r.plan(p0,
		func() { p0.Left = p0.Left.Accept(r).(Plan) },
		func() { p0.Right = p0.Right.Accept(r).(Plan) },
	)
}

func (r *rewriteVisitor) VisitAggregate(p0 *Aggregate) any {
	return r.plan(p0,
		func() { p0.Child = p0.Child.Accept(r).(Plan) },
		func() { r.slice(p0.GroupingExpressions) },
		func() { r.slice(p0.AggregateExpressions) },
	)
}

func (r *rewriteVisitor) VisitSubplan(p0 *Subplan) any {
	return r.plan(p0,
		func() { p0.Plan = p0.Plan.Accept(r).(Plan) },
	)
}

func (r *rewriteVisitor) VisitLiteral(p0 *Literal) any {
	return r.expr(p0, func() {})
}

func (r *rewriteVisitor) VisitVariable(p0 *Variable) any {
	return r.expr(p0, func() {})
}

func (r *rewriteVisitor) VisitColumnRef(p0 *ColumnRef) any {
	return r.expr(p0, func() {})
}

func (r *rewriteVisitor) VisitAggregateFunctionCall(p0 *AggregateFunctionCall) any {
	return r.expr(p0,
		func() { r.slice(p0.Args) },
		func() { r.slice(p0.OrderBy) },
	)
}

func (r *rewriteVisitor) VisitScalarFunctionCall(p0 *ScalarFunctionCall) any {
	return r.expr(p0,
		func() { r.slice(p0.Args) },
	)
}

func (r *rewriteVisitor) VisitArithmeticOp(p0 *ArithmeticOp) any {
	return r.expr(p0,
		func() { p0.Left = p0.Left.Accept(r).(Expression) },
		func() { p0.Right = p0.Right.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitComparisonOp(p0 *ComparisonOp) any {
	return r.expr(p0,
		func() { p0.Left = p0.Left.Accept(r).(Expression) },
		func() { p0.Right = p0.Right.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitLogicalOp(p0 *LogicalOp) any {
	return r.expr(p0,
		func() { p0.Left = p0.Left.Accept(r).(Expression) },
		func() { p0.Right = p0.Right.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitUnaryOp(p0 *UnaryOp) any {
	return r.expr(p0,
		func() { p0.Expr = p0.Expr.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitTypeCast(p0 *TypeCast) any {
	return r.expr(p0,
		func() { p0.Expr = p0.Expr.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitAliasExpr(p0 *AliasExpr) any {
	return r.expr(p0,
		func() { p0.Expr = p0.Expr.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitArrayAccess(p0 *ArrayAccess) any {
	return r.expr(p0,
		func() { p0.Array = p0.Array.Accept(r).(Expression) },
		func() { p0.Index = p0.Index.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitArrayConstructor(p0 *ArrayConstructor) any {
	return r.expr(p0,
		func() { r.slice(p0.Elements) },
	)
}

func (r *rewriteVisitor) VisitFieldAccess(p0 *FieldAccess) any {
	return r.expr(p0,
		func() { p0.Object = p0.Object.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitSubqueryExpr(p0 *SubqueryExpr) any {
	return r.expr(p0,
		func() {},
	)
}

func (r *rewriteVisitor) VisitCollate(p0 *Collate) any {
	return r.expr(p0,
		func() { p0.Expr = p0.Expr.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitIsIn(p0 *IsIn) any {
	return r.expr(p0,
		func() { p0.Left = p0.Left.Accept(r).(Expression) },
		func() {
			if p0.Subquery != nil {
				for _, fn := range r.subqueryFuncs(p0.Subquery.Query) {
					fn()
				}
			} else {
				r.slice(p0.Expressions)
			}
		},
	)
}

func (r *rewriteVisitor) VisitCase(p0 *Case) any {
	return r.expr(p0,
		func() { p0.Value = p0.Value.Accept(r).(Expression) },
		func() {
			for _, whenThen := range p0.WhenClauses {
				whenThen[0] = whenThen[0].Accept(r).(Expression)
				whenThen[1] = whenThen[1].Accept(r).(Expression)
			}
		},
		func() { p0.Else = p0.Else.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitExprRef(p0 *ExprRef) any {
	return r.expr(p0,
		func() {
			p0.Identified.Expr = p0.Identified.Expr.Accept(r).(Expression)
		},
	)
}

func (r *rewriteVisitor) VisitIdentifiedExpr(p0 *IdentifiedExpr) any {
	return r.expr(p0,
		func() { p0.Expr = p0.Expr.Accept(r).(Expression) },
	)
}

func (r *rewriteVisitor) VisitReturn(p0 *Return) any {
	return r.plan(p0, func() {
		p0.Child = p0.Child.Accept(r).(Plan)
	})
}

func (r *rewriteVisitor) VisitCartesianProduct(p0 *CartesianProduct) any {
	return r.plan(p0,
		func() { p0.Left = p0.Left.Accept(r).(Plan) },
		func() { p0.Right = p0.Right.Accept(r).(Plan) },
	)
}

func (r *rewriteVisitor) VisitUpdate(p0 *Update) any {
	return r.plan(p0, func() {
		p0.Child = p0.Child.Accept(r).(Plan)
	})
}

func (r *rewriteVisitor) VisitDelete(p0 *Delete) any {
	return r.plan(p0, func() {
		p0.Child = p0.Child.Accept(r).(Plan)
	})
}

func (r *rewriteVisitor) VisitInsert(p0 *Insert) any {
	return r.plan(p0,
		func() {
			p0.InsertionValues = p0.InsertionValues.Accept(r).(*Tuples)
		},
		func() {
			if p0.ConflictResolution != nil {
				p0.ConflictResolution = p0.ConflictResolution.Accept(r).(ConflictResolution)
			}
		},
	)
}

func (r *rewriteVisitor) VisitConflictDoNothing(p0 *ConflictDoNothing) any {
	// we don't currently allow callbacks for conflicts because there is no need
	return p0
}

func (r *rewriteVisitor) VisitConflictUpdate(p0 *ConflictUpdate) any {
	// we don't currently allow callbacks for conflicts because there is no need
	for i := range p0.Assignments {
		p0.Assignments[i].Value = p0.Assignments[i].Value.Accept(r).(Expression)
	}

	if p0.ConflictFilter != nil {
		p0.ConflictFilter = p0.ConflictFilter.Accept(r).(Expression)
	}

	return p0
}

func (r *rewriteVisitor) VisitTuples(p0 *Tuples) any {
	// tuples do not have callbacks
	for i := range p0.Values {
		for j := range p0.Values[i] {
			p0.Values[i][j] = p0.Values[i][j].Accept(r).(Expression)
		}
	}
	return p0
}

func (r *rewriteVisitor) VisitWindow(p0 *Window) any {
	return r.plan(p0,
		func() { p0.Child = p0.Child.Accept(r).(Plan) },
		func() { r.slice(p0.PartitionBy) },
		func() { r.slice(p0.OrderBy) },
	)
}

func (r *rewriteVisitor) VisitWindowFunction(p0 *WindowFunction) any {
	return r.expr(p0,
		func() { r.slice(p0.Args) },
		func() {
			if p0.Filter != nil {
				p0.Filter = p0.Filter.Accept(r).(Expression)
			}
		},
	)
}

// execFields executes the given fields in the correct order.
func (r *rewriteVisitor) execFields(fields []func()) {
	if r.reverseFieldOrder {
		for i := len(fields) - 1; i >= 0; i-- {
			fields[i]()
		}
	} else {
		for _, f := range fields {
			f()
		}
	}
}

// expr is a helper method for traversing expressions.
func (r *rewriteVisitor) expr(node Expression, fn ...func()) Expression {
	return rewriteInOrder(r, r.exprCallback, fn, node)
}

// plan is a helper method for traversing plans.
// It takes a list of functions which should be passed in their pre-order order.
func (r *rewriteVisitor) plan(node Plan, fn ...func()) Plan {
	return rewriteInOrder(r, r.planCallback, fn, node)
}

// scanSource is a helper method for traversing scan sources.
func (r *rewriteVisitor) scanSource(node ScanSource, fn ...func()) ScanSource {
	return rewriteInOrder(r, r.scanSourceCallback, fn, node)
}

// rewriteInOrder is a generic function for executing a rewrite based on a certain order.
func rewriteInOrder[T Traversable](r *rewriteVisitor, callback func(T) (T, bool, error), fields []func(), node T) T {
	if r.postOrder {
		r.execFields(fields)

		res, visitFields, err := callback(node)
		if visitFields {
			panic("cannot decline to visit fields when callback is called after visiting fields")
		}
		if err != nil {
			panic(err)
		}

		return res
	}

	res, visitFields, err := callback(node)
	if err != nil {
		panic(err)
	}
	if !visitFields {
		return res
	}

	r.execFields(fields)
	return res
}
