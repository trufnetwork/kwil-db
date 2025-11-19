package logical

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

// GetVarTypeFunc is a function that gets the type of a variable.
type GetVarTypeFunc = func(varName string) (dataType *types.DataType, err error)

// GetObjectFieldTypeFunc is a function that gets the type of a field in an object.
type GetObjectFunc = func(objName string) (obj map[string]*types.DataType, err error)

// GetTableFunc is a function that gets a table by name.
// It can also be given a namespace to search in. If no namespace is given (passed as ""), it will search in the default namespace.
type GetTableFunc = func(namespace string, tableName string) (table *engine.Table, err error)

// IsActionFunc returns true if the passed function is an action
type IsActionFunc = func(funcName string) bool

// CreateLogicalPlan creates a logical plan from a SQL statement.
// If applyDefaultOrdering is true, it will rewrite the query to apply default ordering.
// Default ordering will modify the passed query.
// If defaultNamespace is not empty, it will be used as the default namespace for all tables.
func CreateLogicalPlan(statement *parse.SQLStatement, tables GetTableFunc,
	vars GetVarTypeFunc, objects GetObjectFunc, isAction IsActionFunc, applyDefaultOrdering bool, defaultNamespace string,
) (analyzed *AnalyzedPlan, err error) {
	defer func() {
		if r := recover(); r != nil {
			err2, ok := r.(error)
			if !ok {
				err2 = fmt.Errorf("%v", r)
			}
			err = err2
		}
	}()

	ctx := &planContext{
		Tables:               tables,
		CTEs:                 make(map[string]*Relation),
		Variables:            vars,
		Objects:              objects,
		IsAction:             isAction,
		applyDefaultOrdering: applyDefaultOrdering,
		defaultNamespace:     defaultNamespace,
	}

	scope := &scopeContext{
		plan:          ctx,
		OuterRelation: &Relation{},
		// intentionally leave preGroupRelation nil
		onWindowFuncExpr: func(ewfc *parse.ExpressionWindowFunctionCall, _ *Relation, _ map[string]*IdentifiedExpr) (Expression, *Field, error) {
			return nil, nil, fmt.Errorf("%w: cannot use window functions in this context", ErrIllegalWindowFunction)
		},
		onAggregateFuncExpr: func(efc *parse.ExpressionFunctionCall, agg *engine.AggregateFunctionDefinition, _ map[string]*IdentifiedExpr) (Expression, *Field, error) {
			return nil, nil, fmt.Errorf("%w: cannot use aggregate functions in this context", ErrIllegalAggregate)
		},
	}

	plan, err := scope.sqlStmt(statement)
	if err != nil {
		return nil, err
	}

	return &AnalyzedPlan{
		Plan: plan,
		CTEs: ctx.CTEPlans,
	}, nil
}

// AnalyzedPlan is the full result of a logical plan that has been analyzed.
type AnalyzedPlan struct {
	// Plan is the plan of the query.
	Plan Plan
	// CTEs are plans for the common table expressions in the query.
	// They are in the order that they were defined.
	CTEs []*Subplan
}

// Format formats the plan into a human-readable string.
func (a *AnalyzedPlan) Format() string {
	res := Format(a.Plan)

	str := strings.Builder{}
	str.WriteString(res)

	// we will copy and reverse the cte list for printing, so that
	// any CTE that references another CTE will be above it.
	// This matches the printing of subqueries.
	cte2 := slices.Clone(a.CTEs)
	slices.Reverse(cte2)

	printSubplans(&str, cte2)

	return str.String()
}

// planContext holds information that is needed during the planning process.
type planContext struct {
	// Tables are the tables that the query can reference.
	Tables GetTableFunc
	// CTEs are the common table expressions in the query.
	// This field should be updated as the query planner
	// processes the query.
	CTEs map[string]*Relation
	// CTEPlans are the logical plans for the common table expressions
	// in the query. This field should be updated as the query planner
	// processes the query.
	CTEPlans []*Subplan
	// Variables are the variables in the query.
	Variables GetVarTypeFunc
	// Objects are the objects in the query.
	// Kwil supports one-dimensional objects, so this would be
	// accessible via objname.fieldname.
	Objects GetObjectFunc
	// IsAction returns true if the passed function is an action.
	IsAction IsActionFunc
	// SubqueryCount is the number of subqueries in the query.
	// This field should be updated as the query planner
	// processes the query.
	SubqueryCount int
	// ReferenceCount is the number of references in the query.
	// This field should be updated as the query planner
	// processes the query.
	ReferenceCount int
	// applyDefaultOrdering is true if the query should be rewritten
	// to apply default ordering.
	applyDefaultOrdering bool
	// defaultNamespace is the default namespace (schema in Postgres) for all tables.
	defaultNamespace string
}

// scopeContext contains information about the current scope of the query.
type scopeContext struct {
	// plan is the larger plan context that applies to the entire query.
	plan *planContext
	// OuterRelation is the relation of all outer queries that can be
	// referenced from a subquery.
	OuterRelation *Relation
	// preGroupRelation is the relation that is used before grouping.
	// It is simply used to give more helpful error messages.
	preGroupRelation *Relation
	// Correlations are the fields that are correlated to an outer query.
	Correlations []*Field
	// onWindowFuncExpr is a function that is called when evaluating a window function.
	onWindowFuncExpr func(*parse.ExpressionWindowFunctionCall, *Relation, map[string]*IdentifiedExpr) (Expression, *Field, error)
	// onAggregateFuncExpr is a function that is called when evaluating an aggregate function.
	// It is NOT called if the aggregate function is being used as a window function; in this case,
	// onWindowFuncExpr is called.
	onAggregateFuncExpr func(*parse.ExpressionFunctionCall, *engine.AggregateFunctionDefinition, map[string]*IdentifiedExpr) (Expression, *Field, error)
	// aggViolationColumn is the column that is causing an aggregate violation.
	aggViolationColumn string
	cteCtx             cteContext
}

// cteContext contains information about the common table expression context.
type cteContext struct {
	// statementCanBeRecursive is true if the current statement can be recursive
	// and we are processing a CTE.
	statementCanBeRecursive bool
	// recursiveCTEShape is the shape of the current CTE.
	// It is set based off of the relation of the first select core.
	// If it is nil, then the recursive CTE cannot be referenced here.
	recursiveCTEShape *Relation
	// currentCTEName is the current CTE being processed.
	currentCTEName string
	// usedRecursiveCTE is true if the recursive CTE has been used.
	usedRecursiveCTE bool
}

type QuerySection string

const (
	querySectionUnknown  QuerySection = "UNKNOWN"
	querySectionWhere    QuerySection = "WHERE"
	querySectionGroupBy  QuerySection = "GROUP BY"
	querySectionJoin     QuerySection = "JOIN"
	querySectionWindow   QuerySection = "WINDOW"
	querySectionHaving   QuerySection = "HAVING"
	querySectionOrderBy  QuerySection = "ORDER BY"
	querySectionLimit    QuerySection = "LIMIT"
	querySectionOffset   QuerySection = "OFFSET"
	querySectionResults  QuerySection = "RESULTS"
	querySectionCompound QuerySection = "COMPOUND"
)

// sqlStmt builds a logical plan for a top-level SQL statement.
func (s *scopeContext) sqlStmt(node *parse.SQLStatement) (TopLevelPlan, error) {
	if node.Recursive {
		s.cteCtx.statementCanBeRecursive = true
	}
	for _, cte := range node.CTEs {
		s.cteCtx.currentCTEName = cte.Name
		if err := s.cte(cte); err != nil {
			return nil, err
		}
	}
	s.cteCtx = cteContext{} // reset the CTE context

	switch node := node.SQL.(type) {
	default:
		panic(fmt.Sprintf("unexpected SQL statement type %T", node))
	case *parse.SelectStatement:
		plan, res, err := s.selectStmt(node)
		if err != nil {
			return nil, err
		}

		for _, field := range res.Fields {
			if field.Name == "" {
				field.Name = "?column?"
			}
		}

		return &Return{
			Child:  plan,
			Fields: res.Fields,
		}, nil
	case *parse.UpdateStatement:
		return s.update(node)
	case *parse.DeleteStatement:
		return s.delete(node)
	case *parse.InsertStatement:
		return s.insert(node)
	}
}

// cte builds a common table expression.
func (s *scopeContext) cte(node *parse.CommonTableExpression) error {
	s.cteCtx.usedRecursiveCTE = false
	defer func() {
		s.cteCtx.usedRecursiveCTE = false
	}()
	plan, rel, err := s.selectStmt(node.Query)
	if err != nil {
		return err
	}

	var extraInfo string // debug info

	// if there are columns specific, we need to check that the columns are valid
	// and rename the relation fields
	if len(node.Columns) > 0 {
		if len(node.Columns) != len(rel.Fields) {
			panic(fmt.Sprintf(`cte "%s" has %d columns, but %d were specified`, node.Name, len(rel.Fields), len(node.Columns)))
		}

		for i, col := range node.Columns {
			extraInfo += fmt.Sprintf(" [%s.%s -> %s]", rel.Fields[i].Parent, rel.Fields[i].Name, col)

			rel.Fields[i].Parent = node.Name
			rel.Fields[i].Name = col
		}
	} else {
		// otherwise, we need to rename the relation parents
		// to the CTE's name
		for _, field := range rel.Fields {
			extraInfo += fmt.Sprintf(" [%s.%s -> %s]", field.Parent, field.Name, field.Name)
			field.Parent = node.Name
		}
	}

	subplanType := SubplanTypeCTE
	if s.cteCtx.usedRecursiveCTE {
		subplanType = SubplanTypeRecursiveCTE
	}

	s.plan.CTEs[node.Name] = rel
	s.plan.CTEPlans = append(s.plan.CTEPlans, &Subplan{
		Plan:      plan,
		ID:        node.Name,
		Type:      subplanType,
		extraInfo: extraInfo,
	})

	return nil
}

// joinUnique joins two relations, but won't allow duplicate columns.
func joinUnique(left, right *Relation) *Relation {
	// 1st element is the relation name, 2nd element is the field name
	foundSet := make(map[[2]string]struct{})
	var unique []*Field
	for _, field := range left.Fields {
		foundSet[[2]string{field.Parent, field.Name}] = struct{}{}
		unique = append(unique, field)
	}

	for _, field := range right.Fields {
		if _, ok := foundSet[[2]string{field.Parent, field.Name}]; ok {
			continue
		}
		foundSet[[2]string{field.Parent, field.Name}] = struct{}{}

		unique = append(unique, field)
	}

	return &Relation{
		Fields: unique,
	}
}

// select builds a logical plan for a select statement.
func (s *scopeContext) selectStmt(node *parse.SelectStatement) (plan Plan, rel *Relation, err error) {
	if len(node.SelectCores) == 0 {
		panic("no select cores")
	}

	// isRecursive is true if the statement is recursive
	isRecursive := false

	var projectFunc func(Plan) Plan
	var preProjectRel, resultRel *Relation
	var groupingTerms map[string]*IdentifiedExpr
	plan, preProjectRel, groupingTerms, resultRel, projectFunc, err = s.selectCore(node.SelectCores[0])
	if err != nil {
		return nil, nil, err
	}

	logSection := false // basic flag to help us log the statement section when an error occurs
	querySection := querySectionUnknown
	defer func() {
		// the resulting relation will always be resultRel, regardless of ordering and limiting
		rel = resultRel
		if logSection {
			if err != nil {
				err = makeSectionErr(querySection, err)
			}
		}
	}()
	// if there is one select core, thenr the sorting and limiting can refer
	// to both the preProjectRel and the resultRel. If it is a compound query,
	// then the sorting and resultRel can only refer to the resultRel.
	sortAndOrderRel := resultRel
	if len(node.SelectCores) == 1 {
		sortAndOrderRel = joinUnique(preProjectRel, resultRel)
		defer func() {
			// we need to make sure we project only the returned columns
			// after sorting and limiting, so we defer the projection
			plan = projectFunc(plan)
		}()
	} else {
		// otherwise, apply immediately so that we can apply the set operation(s)
		plan = projectFunc(plan)

		// we need to remove the parent from the fields, since when a set operation
		// is performed, only the columns from the left side can be referenced.
		// e.g. in "select id, name from users union select id2, content from posts"
		// we can only order by "name" and "id", not "content" or "id2" or "users.id" or "users.name"
		for _, field := range resultRel.Fields {
			field.Parent = ""
		}

		querySection = querySectionCompound
		for i, core := range node.SelectCores[1:] {
			// if we are in the first UNION / INTERSECT / EXCEPT, we can reference a recursive CTE
			if i == 0 && s.cteCtx.statementCanBeRecursive {
				s.cteCtx.recursiveCTEShape = resultRel
				isRecursive = true
			} else {
				s.cteCtx.recursiveCTEShape = nil
			}

			// if a compound query, then old group by terms cannot be referenced in ORDER / LIMIT / OFFSET
			groupingTerms = nil

			logSection = false // in case of error, the select core will log the section, so we don't want to log it again
			rightPlan, _, _, rightRel, projectFunc, err := s.selectCore(core)
			if err != nil {
				return nil, nil, err
			}
			logSection = true

			// project the result values to match the left side
			rightPlan = projectFunc(rightPlan)

			if err := equalShape(resultRel, rightRel); err != nil {
				return nil, nil, fmt.Errorf("%w: %s", ErrSetIncompatibleSchemas, err)
			}

			plan = &SetOperation{
				Left:   plan,
				Right:  rightPlan,
				OpType: get(compoundTypes, node.CompoundOperators[i]),
			}
		}
	}
	logSection = true // will be true for the rest of the function

	// if applyDefaultOrdering is true, we need to order all results.
	// In postgres, this is simply done by adding ORDER BY 1, 2, 3, ...
	// We don't apply default ordering to recursive CTEs, since they are
	// not allowed to have an ORDER BY clause. This is ok, because they cannot
	// be limited either, and so any referencing query will select the recursive
	// cte's full result set and have its own ORDER BY clause.
	if s.plan.applyDefaultOrdering && !isRecursive {
		for i := range resultRel.Fields {
			node.Ordering = append(node.Ordering, &parse.OrderingTerm{
				Expression: &parse.ExpressionLiteral{
					Value: i + 1, // 1-indexed
					Type:  types.IntType.Copy(),
				},
			})
		}
	}

	// if it is recursive, we need to enforce no ORDER BY, LIMIT
	if isRecursive {
		if len(node.Ordering) > 0 {
			return nil, nil, errors.New("recursive CTEs cannot have an ORDER BY clause")
		}
		if node.Limit != nil {
			return nil, nil, errors.New("recursive CTEs cannot have a LIMIT clause")
		}
	}

	querySection = querySectionOrderBy
	// apply order by, limit, and offset
	if len(node.Ordering) > 0 {
		sort, err := s.buildSort(plan, sortAndOrderRel, node.Ordering, groupingTerms)
		if err != nil {
			return nil, nil, err
		}

		plan = sort
	}

	querySection = querySectionLimit
	if node.Limit != nil {
		limitExpr, limitField, err := s.expr(node.Limit, sortAndOrderRel, groupingTerms)
		if err != nil {
			return nil, nil, err
		}

		scalar, err := limitField.Scalar()
		if err != nil {
			return nil, nil, err
		}

		if !scalar.Equals(types.IntType) {
			return nil, nil, fmt.Errorf("LIMIT must be an int")
		}

		lim := &Limit{
			Child: plan,
			Limit: limitExpr,
		}

		if node.Offset != nil {
			querySection = querySectionOffset
			offsetExpr, offsetField, err := s.expr(node.Offset, sortAndOrderRel, groupingTerms)
			if err != nil {
				return nil, nil, err
			}

			scalar, err := offsetField.Scalar()
			if err != nil {
				return nil, nil, err
			}

			if !scalar.Equals(types.IntType) {
				return nil, nil, fmt.Errorf("OFFSET must be an int")
			}

			lim.Offset = offsetExpr
		}

		plan = lim
	}

	return plan, rel, nil
}

// ordering builds a logical plan for an ordering.
func (s *scopeContext) buildSort(plan Plan, rel *Relation, ordering []*parse.OrderingTerm, groupingTerms map[string]*IdentifiedExpr) (*Sort, error) {
	sort := &Sort{
		Child: plan,
	}

	for _, order := range ordering {
		// ordering term can be of any type
		sortExpr, _, err := s.expr(order.Expression, rel, groupingTerms)
		if err != nil {
			return nil, err
		}

		sort.SortExpressions = append(sort.SortExpressions, &SortExpression{
			Expr:      sortExpr,
			Ascending: get(orderAsc, order.Order),
			NullsLast: get(orderNullsLast, order.Nulls),
		})
	}

	return sort, nil
}

// makeSectionErr creates an error for a section of a query.
func makeSectionErr(sec QuerySection, err error) error {
	return fmt.Errorf("error in %s section of sql statement: %w", sec, err)
}

// selectCore builds a logical plan for a select core.
// The order of building is:
// 1. from (combining any joins into single source plan)
// 2. where
// 3. group by(can use reference from select)
// 4. having(can use reference from select)
// 5. select (project)
// 6. distinct
// It returns a logical plan and relation that are PRIOR to any projection,
// the relation resulting from the projection, a function that will apply a projection to the plan,
// and an error if one occurred.
// It returns these because we need to handle conditionally
// adding projection. If a query has a SET (a.k.a. compound) operation, we want to project before performing
// the set. If a query has one select, then we want to project after sorting and limiting.
// To give a concrete example of this, imagine a table users (id int, name text) with the queries:
// 1.
// "SELECT name FROM users ORDER BY id" - this is valid in Postgres, and since we can access "id", projection
// should be done after sorting.
// 2.
// "SELECT name FROM users UNION 'hello' ORDER BY id" - this is invalid in Postgres, since "id" is not in the
// result set. We need to project before the UNION.
func (s *scopeContext) selectCore(node *parse.SelectCore) (preProjectPlan Plan, preProjectRel *Relation, groupingTerms map[string]*IdentifiedExpr, resultRel *Relation,
	projectFunc func(Plan) Plan, err error) {
	querySection := querySectionUnknown
	defer func() {
		if err != nil {
			err = makeSectionErr(querySection, err)
		}
	}()

	// if there is no from, we just project the columns and return
	if node.From == nil {
		querySection = querySectionResults
		return s.selectCoreWithoutFrom(node.Columns, node.Distinct)
	}

	// applyPreProject is a set of functions that are run right before the projection.
	var applyPreProject []func()

	// otherwise, we need to build the from and join clauses
	scan, rel, err := s.table(node.From)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	var plan Plan = scan

	querySection = querySectionJoin
	for _, join := range node.Joins {
		plan, rel, err = s.join(plan, rel, join)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}

	querySection = querySectionWhere
	if node.Where != nil {
		whereExpr, whereType, err := s.expr(node.Where, rel, map[string]*IdentifiedExpr{})
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		scalar, err := whereType.Scalar()
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		if !scalar.Equals(types.BoolType) {
			return nil, nil, nil, nil, nil, errors.New("WHERE must be a boolean")
		}

		plan = &Filter{
			Child:     plan,
			Condition: whereExpr,
		}
	}

	querySection = querySectionUnknown
	// wildcards expand all columns found at this point.
	// For example, if we have a table "users" with columns "id" and "name",
	// "SELECT * FROM USERS GROUP BY id" is selecting both "id" and "name" (which will fail, but that's not the point).
	results, err := s.expandResultCols(rel, node.Columns)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// we have expanded the columns, so we can replace them with the expanded columns
	node.Columns = make([]parse.ResultColumn, len(results))
	for i, result := range results {
		node.Columns[i] = result
	}

	// we need to build the group by and having clauses.
	// This means that for all result columns, we need to rewrite any
	// column references or aggregate usage as columnrefs to the aggregate
	// functions matching term.
	aggTerms := make(map[string]*exprFieldPair[*IdentifiedExpr]) // any aggregate function used in the result or having
	groupingTerms = make(map[string]*IdentifiedExpr)             // any grouping term used in the GROUP BY
	aggregateRel := &Relation{}                                  // the relation resulting from the aggregation

	aggPlan := &Aggregate{ // defined separately so we can reference it in the below clauses
		Child: plan,
	}
	hasGroupBy := false

	oldPreGroupRel := s.preGroupRelation
	s.preGroupRelation = rel
	applyPreProject = append(applyPreProject, func() { s.preGroupRelation = oldPreGroupRel })

	querySection = querySectionGroupBy
	for _, groupTerm := range node.GroupBy {
		hasGroupBy = true
		// we do not pass the grouping terms yet because they cannot be referenced in the group by
		groupExpr, field, err := s.expr(groupTerm, rel, map[string]*IdentifiedExpr{})
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		// if this group term already exists, we can skip it to avoid duplicate columns
		_, ok := groupingTerms[groupExpr.String()]
		if ok {
			continue
		}

		// we should identify it so it can be referenced
		identified := &IdentifiedExpr{
			Expr: groupExpr,
			ID:   s.plan.uniqueRefIdentifier(),
		}
		aggPlan.GroupingExpressions = append(aggPlan.GroupingExpressions, identified)

		aggregateRel.Fields = append(aggregateRel.Fields, field)

		groupingTerms[groupExpr.String()] = identified
	}

	if hasGroupBy {
		plan = aggPlan
		rel = aggregateRel
	}

	// if we use an agg without group by, we will have to later alter the plan to include the aggregate node
	usesAggWithoutGroupBy := false

	// on each aggregate function, we will rewrite it to be a reference, and place the actual function itself on the Aggregate node
	oldOnAggregate := s.onAggregateFuncExpr
	applyPreProject = append(applyPreProject, func() { s.onAggregateFuncExpr = oldOnAggregate })
	newOnAggregate := s.makeOnAggregateFunc(aggTerms, &aggPlan.AggregateExpressions)
	s.onAggregateFuncExpr = func(efc *parse.ExpressionFunctionCall, afd *engine.AggregateFunctionDefinition, grouping map[string]*IdentifiedExpr) (Expression, *Field, error) {
		if !hasGroupBy {
			usesAggWithoutGroupBy = true
		}
		return newOnAggregate(efc, afd, grouping)
	}

	querySection = querySectionHaving
	if node.Having != nil {
		havingExpr, field, err := s.expr(node.Having, rel, groupingTerms)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		scalar, err := field.Scalar()
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		if !scalar.Equals(types.BoolType) {
			return nil, nil, nil, nil, nil, errors.New("HAVING must evaluate to a boolean")
		}

		plan = &Filter{
			Child:     plan,
			Condition: havingExpr,
		}
	}

	// now we plan all window functions
	windows := make(map[string]*Window)
	unappliedWindows := []*Window{} // we wait to apply these to the plan until after evaluating all, since subsequent windows cannot reference previous ones
	querySection = querySectionWindow
	for _, window := range node.Windows {
		_, ok := windows[window.Name]
		if ok {
			return nil, nil, nil, nil, nil, fmt.Errorf(`%w: window "%s" is already defined`, ErrWindowAlreadyDefined, window.Name)
		}

		win, err := s.planWindow(plan, rel, window.Window, groupingTerms, window.Name)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		windows[window.Name] = win

		unappliedWindows = append(unappliedWindows, win)
	}

	// on each window function, we will rewrite it to be a reference, and add the window function to
	// the corresponding window node. If no window node exists (if the window is defined inline with the function),
	// we will create a new window node.
	oldOnWindow := s.onWindowFuncExpr
	applyPreProject = append(applyPreProject, func() { s.onWindowFuncExpr = oldOnWindow })
	s.onWindowFuncExpr = s.makeOnWindowFunc(&unappliedWindows, windows, plan)

	// now we can evaluate all return columns.

	querySection = querySectionResults
	resultFields := make([]*Field, len(results))
	resultColExprs := make([]Expression, len(results))
	for i, resultCol := range results {
		expr, field, err := s.expr(resultCol.Expression, rel, groupingTerms)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		if resultCol.Alias != "" {
			expr = &AliasExpr{
				Expr:  expr,
				Alias: resultCol.Alias,
			}
			field.Name = resultCol.Alias
			field.Parent = ""
		}

		resultColExprs[i] = expr
		resultFields[i] = field
	}

	if usesAggWithoutGroupBy {
		// we need to add the aggregate node to the plan
		plan = aggPlan
	}

	// apply the unnamed window functions
	for _, window := range unappliedWindows {
		window.Child = plan
		plan = window
	}

	return plan, rel, groupingTerms, &Relation{
			Fields: resultFields,
		}, func(lp Plan) Plan {

			for _, apply := range applyPreProject {
				apply()
			}

			var p Plan = &Project{
				Child:       lp,
				Expressions: resultColExprs,
			}

			if node.Distinct {
				p = &Distinct{
					Child: p,
				}
			}

			return p
		}, nil
}

// makeOnWindowFunc makes a function that can be used as the callback for onWindowFuncExpr.
// The passed in unnamedWindows will be used to store any windows that are defined inline with the function.
// The namedWindows should be any windows that were defined in the SELECT statement.
// Callers of this function should pass an empty slice which can be written to.
func (s *scopeContext) makeOnWindowFunc(unnamedWindows *[]*Window, namedWindows map[string]*Window, plan Plan) func(*parse.ExpressionWindowFunctionCall, *Relation, map[string]*IdentifiedExpr) (Expression, *Field, error) {
	return func(ewfc *parse.ExpressionWindowFunctionCall, rel *Relation, groupingTerms map[string]*IdentifiedExpr) (Expression, *Field, error) {
		// the referenced function here must be either an aggregate
		// or a window function.
		// We don't simply call expr on the function because we want to ensure
		// it is a window and handle it differently.
		funcDef, ok := engine.Functions[ewfc.FunctionCall.Name]
		if !ok {
			return nil, nil, fmt.Errorf(`%w: "%s"`, ErrFunctionDoesNotExist, ewfc.FunctionCall.Name)
		}

		if ewfc.FunctionCall.Star {
			return nil, nil, fmt.Errorf(`%w: window functions do not support "*"`, ErrInvalidWindowFunction)
		}
		if ewfc.FunctionCall.Distinct {
			return nil, nil, fmt.Errorf(`%w: window functions do not support DISTINCT`, ErrInvalidWindowFunction)
		}

		switch funcDef.(type) {
		case *engine.AggregateFunctionDefinition, *engine.WindowFunctionDefinition:
			// intentionally do nothing
		default:
			return nil, nil, fmt.Errorf(`function "%s" is not a window function`, ewfc.FunctionCall.Name)
		}

		var args []Expression
		var fields []*Field
		for _, arg := range ewfc.FunctionCall.Args {
			expr, field, err := s.expr(arg, rel, groupingTerms)
			if err != nil {
				return nil, nil, err
			}

			args = append(args, expr)
			fields = append(fields, field)
		}

		dataTypes, err := dataTypes(fields)
		if err != nil {
			return nil, nil, err
		}

		returnType, err := funcDef.ValidateArgs(dataTypes)
		if err != nil {
			return nil, nil, err
		}

		// if a filter exists, ensure it is a boolean
		var filterExpr Expression
		if ewfc.Filter != nil {
			var filterField *Field
			filterExpr, filterField, err = s.expr(ewfc.Filter, rel, groupingTerms)
			if err != nil {
				return nil, nil, err
			}

			scalar, err := filterField.Scalar()
			if err != nil {
				return nil, nil, err
			}

			if !scalar.Equals(types.BoolType) {
				return nil, nil, errors.New("filter expression evaluate to a boolean")
			}
		}

		// the window can either reference an already declared window, or it can be anonymous.
		// If referencing an already declared window, we simply add the window function to that window.
		// If it is anonymous, we create a new window node and add the function to that.
		var identified *IdentifiedExpr
		switch win := ewfc.Window.(type) {
		default:
			panic(fmt.Sprintf("unexpected window type %T", ewfc.Window))
		case *parse.WindowImpl:
			// it is an anonymous window, so we need to create a new window node
			window, err := s.planWindow(plan, rel, win, groupingTerms, ewfc.FunctionCall.Name)
			if err != nil {
				return nil, nil, err
			}
			identified = &IdentifiedExpr{
				Expr: &WindowFunction{
					Name:       ewfc.FunctionCall.Name,
					Args:       args,
					Filter:     filterExpr,
					returnType: returnType,
				},
				ID: s.plan.uniqueRefIdentifier(),
			}

			window.Functions = append(window.Functions, identified)
			*unnamedWindows = append(*unnamedWindows, window)
		case *parse.WindowReference:
			// it must be a reference to a window that has already been declared
			window, ok := namedWindows[win.Name]
			if !ok {
				return nil, nil, fmt.Errorf(`%w: window "%s" is not defined`, ErrWindowNotDefined, win.Name)
			}

			identified = &IdentifiedExpr{
				Expr: &WindowFunction{
					Name:       ewfc.FunctionCall.Name,
					Args:       args,
					Filter:     filterExpr,
					returnType: returnType,
				},
				ID: s.plan.uniqueRefIdentifier(),
			}

			window.Functions = append(window.Functions, identified)
		}

		return &ExprRef{
				Identified: identified,
			}, &Field{
				Name:        ewfc.FunctionCall.Name,
				val:         returnType,
				ReferenceID: identified.ID,
			}, nil
	}
}

// makeOnAggregateFunc makes a function that can be used as the callback for onAggregateFuncExpr.
// The passed in aggTerms will be both read from and written to.
// The passed in aggregateExpressions slice will be written to with any new aggregate expressions.
func (s *scopeContext) makeOnAggregateFunc(aggTerms map[string]*exprFieldPair[*IdentifiedExpr], aggregateExpression *[]*IdentifiedExpr) func(*parse.ExpressionFunctionCall, *engine.AggregateFunctionDefinition, map[string]*IdentifiedExpr) (Expression, *Field, error) {
	return func(efc *parse.ExpressionFunctionCall, afd *engine.AggregateFunctionDefinition, groupingTerms map[string]*IdentifiedExpr) (Expression, *Field, error) {
		// if it matches any aggregate function, we should reference it.
		// Otherwise, register it as a new aggregate

		if s.preGroupRelation == nil {
			return nil, nil, errors.New("cannot use aggregate functions in this part of the query")
		}

		args := make([]Expression, len(efc.Args))
		argTypes := make([]*types.DataType, len(efc.Args))
		for i, arg := range efc.Args {
			expr, fields, err := s.expr(arg, s.preGroupRelation, groupingTerms)
			if err != nil {
				return nil, nil, err
			}

			args[i] = expr
			argTypes[i], err = fields.Scalar()
			if err != nil {
				return nil, nil, err
			}
		}

		returnType, err := afd.ValidateArgs(argTypes)
		if err != nil {
			return nil, nil, err
		}

		// Process ORDER BY terms if present
		var orderByTerms []*SortExpression
		if len(efc.OrderBy) > 0 {
			orderByTerms = make([]*SortExpression, len(efc.OrderBy))
			for i, orderTerm := range efc.OrderBy {
				// Process the ORDER BY expression
				orderExpr, _, err := s.expr(orderTerm.Expression, s.preGroupRelation, groupingTerms)
				if err != nil {
					return nil, nil, err
				}

				orderByTerms[i] = &SortExpression{
					Expr:      orderExpr,
					Ascending: get(orderAsc, orderTerm.Order),
					NullsLast: get(orderNullsLast, orderTerm.Nulls),
				}
			}
		}

		rawExpr := &AggregateFunctionCall{
			FunctionName: efc.Name,
			Args:         args,
			Star:         efc.Star,
			Distinct:     efc.Distinct,
			OrderBy:      orderByTerms,
			returnType:   returnType,
		}

		identified, ok := aggTerms[rawExpr.String()]
		// if found, just use the reference
		if ok {
			return &ExprRef{
				Identified: identified.Expr,
			}, identified.Field, nil
		}

		// otherwise, register it as a new aggregate
		newIdentified := &IdentifiedExpr{
			Expr: rawExpr,
			ID:   s.plan.uniqueRefIdentifier(),
		}

		// add the expression to the aggregate node
		*aggregateExpression = append(*aggregateExpression, newIdentified)

		field := newIdentified.Field()
		aggTerms[rawExpr.String()] = &exprFieldPair[*IdentifiedExpr]{
			Expr:  newIdentified,
			Field: field,
		}

		return &ExprRef{
			Identified: newIdentified,
		}, field, nil
	}
}

// selectCoreWithoutFrom builds a logical plan for a select core without a FROM clause.
func (s *scopeContext) selectCoreWithoutFrom(cols []parse.ResultColumn, isDistinct bool) (preProjectPlan Plan, preProjectRel *Relation, groupingTerms map[string]*IdentifiedExpr, resultRel *Relation,
	projectFunc func(Plan) Plan, err error) {
	var exprs []Expression
	rel := &Relation{}

	for _, resultCol := range cols {
		switch resultCol := resultCol.(type) {
		default:
			panic(fmt.Sprintf("unexpected result column type %T", resultCol))
		case *parse.ResultColumnExpression:
			expr, field, err := s.expr(resultCol.Expression, rel, nil)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}

			if resultCol.Alias != "" {
				expr = &AliasExpr{
					Expr:  expr,
					Alias: resultCol.Alias,
				}
				field.Parent = ""
				field.Name = resultCol.Alias
			}

			exprs = append(exprs, expr)
			rel.Fields = append(rel.Fields, field)
		case *parse.ResultColumnWildcard:
			// if there is no from, we cannot expand the wildcard
			return nil, nil, nil, nil, nil, fmt.Errorf(`wildcard "*" cannot be used without a FROM clause`)
		}
	}

	return &EmptyScan{}, rel, map[string]*IdentifiedExpr{}, rel, func(lp Plan) Plan {
		var p Plan = &Project{
			Child:       lp,
			Expressions: exprs,
		}

		if isDistinct {
			p = &Distinct{
				Child: p,
			}
		}

		return p
	}, nil
}

// planWindow plans a window function.
func (s *scopeContext) planWindow(plan Plan, rel *Relation, win *parse.WindowImpl, groupingTerms map[string]*IdentifiedExpr, function string) (*Window, error) {
	var partitionBy []Expression
	for _, partition := range win.PartitionBy {
		partition, _, err := s.expr(partition, rel, groupingTerms)
		if err != nil {
			return nil, err
		}

		partitionBy = append(partitionBy, partition)
	}

	// Adding ordering to a window function actually changes the definition of the window,
	// and thus deviates from the user's intent. This is due to how window functions
	// take into account "peer rows", which is best defined in the Apache Drill documentation:
	// https://drill.apache.org/docs/sql-window-functions-introduction/
	// Therefore, we only apply default ordering if the function is strictly a window function.
	// If it is an aggregate, we do not need to apply default ordering.

	// to add default ordering, we need to order by every column in the target relation.
	// This is extremely inefficient, but it is the only way to guarantee that the default ordering
	// is applied.
	if s.plan.applyDefaultOrdering {
		isWindow := false

		// if the function is an aggregate, we do not apply default ordering
		if fn, ok := engine.Functions[function]; ok {
			if _, ok := fn.(*engine.WindowFunctionDefinition); ok {
				isWindow = true
			}
		}

		if isWindow {
			for _, field := range rel.Fields {
				win.OrderBy = append(win.OrderBy, &parse.OrderingTerm{
					Expression: &parse.ExpressionColumn{
						Table:  field.Parent,
						Column: field.Name,
					},
				})
			}
		}
	}

	var orderBy []*SortExpression
	if len(win.OrderBy) > 0 {
		sort, err := s.buildSort(plan, rel, win.OrderBy, groupingTerms)
		if err != nil {
			return nil, err
		}

		orderBy = sort.SortExpressions
	}

	return &Window{
		PartitionBy: partitionBy,
		OrderBy:     orderBy,
		Child:       plan,
	}, nil
}

// exprFieldPair is a helper struct that pairs an expression with a field.
// It uses a generic because there are some times where we want to guarantee
// that the expression is an IdentifiedExpr, and other times where we don't
// care about the concrete type.
type exprFieldPair[T Expression] struct {
	Expr  T
	Field *Field
}

// rewriteGroupingTerms rewrites all known grouping terms to be references.
// For example, in the query "SELECT name FROM users GROUP BY name", it rewrites the logical tree to be
// "SELECT #REF(A) FROM USERS GROUP BY name->#REF(A)".
func (s *scopeContext) rewriteGroupingTerms(expr Expression, groupingTerms map[string]*IdentifiedExpr) (Expression, error) {
	node, err := Rewrite(expr, &RewriteConfig{
		ExprCallback: func(le Expression) (Expression, bool, error) {
			// if it matches any group by term, we need to rewrite it
			if identified, ok := groupingTerms[le.String()]; ok {
				return &ExprRef{
					Identified: identified,
				}, false, nil
			}

			switch le := le.(type) {
			default:
				return le, true, nil
			case *ColumnRef:
				// if it is a column reference, then it was not found in the group by
				return nil, false, fmt.Errorf(`%w: column "%s" must appear in the GROUP BY clause or be used in an aggregate function`, ErrIllegalAggregate, le.String())
			case *AggregateFunctionCall:
				// if it is an aggregate, we dont need to keep searching because it does not need to be rewritten
				return le, false, nil
			}
		},
	})
	if err != nil {
		return nil, err
	}

	return node.(Expression), nil
}

// expandResultCols expands all wildcards to their respective column references.
func (s *scopeContext) expandResultCols(rel *Relation, cols []parse.ResultColumn) ([]*parse.ResultColumnExpression, error) {
	var res []*parse.ResultColumnExpression
	for _, col := range cols {
		switch col := col.(type) {
		default:
			panic(fmt.Sprintf("unexpected result column type %T", col))
		case *parse.ResultColumnExpression:
			res = append(res, col)
		case *parse.ResultColumnWildcard:
			var newFields []*Field
			if col.Table != "" {
				newFields = rel.ColumnsByParent(col.Table)
			} else {
				newFields = rel.Fields
			}

			for _, field := range newFields {
				res = append(res, &parse.ResultColumnExpression{
					Expression: &parse.ExpressionColumn{
						Table:  col.Table,
						Column: field.Name,
					},
				})
			}
		}
	}

	return res, nil
}

// expr visits an expression node.
// It returns the logical plan for the expression, the field that the expression represents,
// and an error if one occurred. The Expression and Field will be nil if an error occurred.
// If a group by is present, expressions will be rewritten to reference the group by terms.
// nil can be passed for the groupingTerms if there is no group by.
func (s *scopeContext) expr(node parse.Expression, currentRel *Relation, groupingTerms map[string]*IdentifiedExpr) (Expression, *Field, error) {
	if groupingTerms == nil {
		groupingTerms = make(map[string]*IdentifiedExpr)
	}

	e, f, r, err := s.exprWithAggRewrite(node, currentRel, groupingTerms)
	if err != nil {
		return nil, nil, err
	}

	// if we should rewrite, then we will traverse the expression and see if we can rewrite it.
	// We do this to ensure that we match the longest possible rewrite tree.
	if r {
		e2, err := s.rewriteGroupingTerms(e, groupingTerms)
		return e2, f, err
	}

	return e, f, nil
}

func (s *scopeContext) exprWithAggRewrite(node parse.Expression, currentRel *Relation, groupingTerms map[string]*IdentifiedExpr,
) (resExpr Expression, resField *Field, shouldRewrite bool, err error) {
	// cast is a helper function for type casting results based on the current node
	cast := func(expr Expression, field *Field) (Expression, *Field, bool, error) {
		castable, ok := node.(interface{ GetTypeCast() *types.DataType })
		if !ok {
			return expr, field, shouldRewrite, nil
		}

		if castable.GetTypeCast() != nil {
			field2 := field.Copy()
			field2.val = castable.GetTypeCast()

			return &TypeCast{
				Expr: expr,
				Type: castable.GetTypeCast(),
			}, field2, shouldRewrite, nil
		}

		return expr, field, shouldRewrite, nil
	}

	// rExpr is a helper function that should be used to recursively call expr().
	// The returned boolean indicates whether the expression violates grouping rules, and should
	// attempt to rewrite the expression to reference the group by terms before failing.
	rExpr := func(node parse.Expression) (Expression, *Field, error) {
		e, f, r, err2 := s.exprWithAggRewrite(node, currentRel, groupingTerms)
		if err2 != nil {
			return nil, nil, err2
		}

		if r {
			// // if we should rewrite, we should try to match the expression to a group by term
			// // if successful, we can tell the caller to not rewrite
			// // if not, we tell the caller to attempt to rewrite
			// grouped, ok := groupingTerms[e.String()]
			// if ok {
			// 	s.aggViolationColumn = ""
			// 	return &ExprRef{
			// 		Identified: grouped,
			// 	}, f, nil
			// }

			// if we could not find the expression in the group by terms, we should rewrite.
			// This will tell the caller to rewrite the returned expression
			shouldRewrite = true
		}

		return e, f, nil
	}

	switch node := node.(type) {
	default:
		panic(fmt.Sprintf("unexpected expression type %T", node))
	case *parse.ExpressionLiteral:
		return cast(&Literal{
			Value: node.Value,
			Type:  node.Type,
		}, anonField(node.Type))
	case *parse.ExpressionFunctionCall:
		// if it is an action, we should return an error
		if s.plan.IsAction(node.Name) {
			return nil, nil, false, fmt.Errorf(`%w: "%s"`, ErrActionInSQLStmt, node.Name)
		}

		funcDef, ok := engine.Functions[node.Name]
		if !ok {
			return nil, nil, false, fmt.Errorf(`%w: "%s"`, ErrFunctionDoesNotExist, node.Name)
		}

		// if it is an aggregate function, we need to handle it differently
		// now we need to apply rules depending on if it is aggregate or not
		if aggFn, ok := funcDef.(*engine.AggregateFunctionDefinition); ok {
			expr, field, err := s.onAggregateFuncExpr(node, aggFn, groupingTerms)
			if err != nil {
				return nil, nil, false, err
			}

			return cast(expr, field)
		}

		var args []Expression
		var fields []*Field
		for _, arg := range node.Args {
			expr, field, err := rExpr(arg)
			if err != nil {
				return nil, nil, false, err
			}

			args = append(args, expr)
			fields = append(fields, field)
		}

		// it is a built-in function

		types, err := dataTypes(fields)
		if err != nil {
			return nil, nil, false, err
		}

		returnVal, err := funcDef.ValidateArgs(types)
		if err != nil {
			return nil, nil, false, err
		}

		returnField := &Field{
			Name: node.Name,
			val:  returnVal,
		}

		if node.Star {
			return nil, nil, false, fmt.Errorf("star (*) not allowed in non-aggregate function calls")
		}
		if node.Distinct {
			return nil, nil, false, fmt.Errorf("DISTINCT not allowed in non-aggregate function calls")
		}

		return cast(&ScalarFunctionCall{
			FunctionName: node.Name,
			Args:         args,
			returnType:   returnVal,
		}, returnField)
	case *parse.ExpressionWindowFunctionCall:
		wind, field, err := s.onWindowFuncExpr(node, currentRel, groupingTerms)
		if err != nil {
			return nil, nil, false, err
		}

		return cast(wind, field)
	case *parse.ExpressionVariable:
		var val any // can be a data type or object
		dt, err := s.plan.Variables(node.Name)
		if errors.Is(err, engine.ErrUnknownVariable) {
			// might be an object
			obj, err := s.plan.Objects(node.Name)
			if err != nil {
				return nil, nil, false, err
			}

			val = obj
		} else if err != nil {
			return nil, nil, false, err
		} else {
			val = dt
		}

		return cast(&Variable{
			VarName:  node.Name,
			dataType: val,
		}, &Field{val: val})
	case *parse.ExpressionArrayAccess:
		array, field, err := rExpr(node.Array)
		if err != nil {
			return nil, nil, false, err
		}

		// Handle range access (slice) like arr[1:5]
		if node.FromTo != nil {
			var start, end Expression
			var startField, endField *Field

			if node.FromTo[0] != nil {
				start, startField, err = rExpr(node.FromTo[0])
				if err != nil {
					return nil, nil, false, err
				}

				scalar, err := startField.Scalar()
				if err != nil {
					return nil, nil, false, err
				}

				if !scalar.Equals(types.IntType) {
					return nil, nil, false, fmt.Errorf("array slice start index must be an int")
				}
			}

			if node.FromTo[1] != nil {
				end, endField, err = rExpr(node.FromTo[1])
				if err != nil {
					return nil, nil, false, err
				}

				scalar, err := endField.Scalar()
				if err != nil {
					return nil, nil, false, err
				}

				if !scalar.Equals(types.IntType) {
					return nil, nil, false, fmt.Errorf("array slice end index must be an int")
				}
			}

			// Array slicing returns the same array type
			return cast(&ArraySlice{
				Array: array,
				Start: start,
				End:   end,
			}, field)

			// Handle single index access like arr[1]
		} else if node.Index != nil {
			index, idxField, err := rExpr(node.Index)
			if err != nil {
				return nil, nil, false, err
			}

			scalar, err := idxField.Scalar()
			if err != nil {
				return nil, nil, false, err
			}

			if !scalar.Equals(types.IntType) {
				return nil, nil, false, fmt.Errorf("array index must be an int")
			}

			field2 := field.Copy()
			scalar2, err := field2.Scalar()
			if err != nil {
				return nil, nil, false, err
			}

			scalar2.IsArray = false // since we are accessing an array, it is no longer an array

			return cast(&ArrayAccess{
				Array: array,
				Index: index,
			}, field2)
		} else {
			return nil, nil, false, fmt.Errorf("array access must have either Index or FromTo specified")
		}
	case *parse.ExpressionMakeArray:
		if len(node.Values) == 0 {
			// if there are no values, we cannot determine the type unless
			// it is type casted
			if node.TypeCast == nil {
				return nil, nil, false, fmt.Errorf("%w: Try type casting to the desired type, for example ARRAY[]::TEXT[]", ErrUntypedEmptyArray)
			}

			return cast(&ArrayConstructor{}, anonField(node.TypeCast))
		}

		var exprs []Expression
		var fields []*Field
		for _, val := range node.Values {
			expr, field, err := rExpr(val)
			if err != nil {
				return nil, nil, false, err
			}

			exprs = append(exprs, expr)
			fields = append(fields, field)
		}

		firstVal, err := fields[0].Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		for _, field := range fields[1:] {
			scalar, err := field.Scalar()
			if err != nil {
				return nil, nil, false, err
			}

			if !firstVal.Equals(scalar) {
				return nil, nil, false, fmt.Errorf("array constructor must have elements of the same type")
			}
		}

		firstValCopy := firstVal.Copy()
		firstValCopy.IsArray = true

		return cast(&ArrayConstructor{
			Elements: exprs,
		}, &Field{
			val: firstValCopy,
		})
	case *parse.ExpressionFieldAccess:
		obj, field, err := rExpr(node.Record)
		if err != nil {
			return nil, nil, false, err
		}

		objType, err := field.Object()
		if err != nil {
			return nil, nil, false, err
		}

		fieldType, ok := objType[node.Field]
		if !ok {
			return nil, nil, false, fmt.Errorf(`object "%s" does not have field "%s"`, field.Name, node.Field)
		}

		return cast(&FieldAccess{
			Object: obj,
			Key:    node.Field,
		}, &Field{
			val: fieldType,
		})
	case *parse.ExpressionParenthesized:
		expr, field, err := rExpr(node.Inner)
		if err != nil {
			return nil, nil, false, err
		}

		return cast(expr, field)
	case *parse.ExpressionComparison:
		left, leftField, err := rExpr(node.Left)
		if err != nil {
			return nil, nil, false, err
		}

		right, rightField, err := rExpr(node.Right)
		if err != nil {
			return nil, nil, false, err
		}

		leftScalar, err := leftField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		rightScalar, err := rightField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		if !leftScalar.Equals(rightScalar) {
			return nil, nil, false, fmt.Errorf("comparison operands must be of the same type. %s != %s", leftScalar, rightScalar)
		}

		var op []ComparisonOperator
		negate := false
		switch node.Operator {
		case parse.ComparisonOperatorEqual:
			op = []ComparisonOperator{Equal}
		case parse.ComparisonOperatorNotEqual:
			op = []ComparisonOperator{Equal}
			negate = true
		case parse.ComparisonOperatorLessThan:
			op = []ComparisonOperator{LessThan}
		case parse.ComparisonOperatorLessThanOrEqual:
			op = []ComparisonOperator{LessThan, Equal}
		case parse.ComparisonOperatorGreaterThan:
			op = []ComparisonOperator{GreaterThan}
		case parse.ComparisonOperatorGreaterThanOrEqual:
			op = []ComparisonOperator{GreaterThan, Equal}
		}

		expr := applyOps(left, right, op, negate)

		return expr, anonField(types.BoolType.Copy()), shouldRewrite, nil
	case *parse.ExpressionLogical:
		left, leftField, err := rExpr(node.Left)
		if err != nil {
			return nil, nil, false, err
		}

		right, rightField, err := rExpr(node.Right)
		if err != nil {
			return nil, nil, false, err
		}

		scalar, err := leftField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		if !scalar.Equals(types.BoolType) {
			return nil, nil, false, fmt.Errorf("logical operators must be applied to boolean types")
		}

		scalar, err = rightField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		if !scalar.Equals(types.BoolType) {
			return nil, nil, false, fmt.Errorf("logical operators must be applied to boolean types")
		}

		return &LogicalOp{
			Left:  left,
			Right: right,
			Op:    get(logicalOps, node.Operator),
		}, anonField(types.BoolType.Copy()), shouldRewrite, nil
	case *parse.ExpressionArithmetic:
		left, leftField, err := rExpr(node.Left)
		if err != nil {
			return nil, nil, false, err
		}

		right, rightField, err := rExpr(node.Right)
		if err != nil {
			return nil, nil, false, err
		}

		leftScalar, err := leftField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		rightScalar, err := rightField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		if !leftScalar.Equals(rightScalar) {
			return nil, nil, false, fmt.Errorf("arithmetic operands must be of the same type. %s != %s", leftScalar, rightScalar)
		}

		return &ArithmeticOp{
			Left:  left,
			Right: right,
			Op:    get(arithmeticOps, node.Operator),
		}, &Field{val: leftField.val}, shouldRewrite, nil
	case *parse.ExpressionUnary:
		expr, field, err := rExpr(node.Expression)
		if err != nil {
			return nil, nil, false, err
		}

		op := get(unaryOps, node.Operator)

		scalar, err := field.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		switch op {
		case Negate:
			if !scalar.IsNumeric() {
				return nil, nil, false, fmt.Errorf("negation can only be applied to numeric types")
			}
		case Not:
			if !scalar.Equals(types.BoolType) {
				return nil, nil, false, fmt.Errorf("logical negation can only be applied to boolean types")
			}
		case Positive:
			if !scalar.IsNumeric() {
				return nil, nil, false, fmt.Errorf("positive can only be applied to numeric types")
			}
		}

		// surprisingly, Postgres won't return a columns name
		// if it is wrapped in a unary operator
		return &UnaryOp{
			Expr: expr,
			Op:   op,
		}, &Field{val: field.val}, shouldRewrite, nil
	case *parse.ExpressionColumn:
		field, err := currentRel.Search(node.Table, node.Column)
		// if no error, then we found the column in the current relation
		// and can return it
		if err == nil {
			scalar, err := field.Scalar()
			if err != nil {
				return nil, nil, false, err
			}

			casted, castField, rewrite, err := cast(&ColumnRef{
				Parent:     field.Parent,
				ColumnName: field.Name,
				dataType:   scalar,
			}, field)
			if err != nil {
				return nil, nil, false, err
			}

			// if the column is in the group by, then we should rewrite it.
			_, ok := groupingTerms[field.String()]

			return casted, castField, rewrite || ok, nil
		}
		// If the error is not that the column was not found, check if
		// the column is in the outer relation
		if errors.Is(err, ErrColumnNotFound) {
			// might be in the outer relation, correlated
			field, err = s.OuterRelation.Search(node.Table, node.Column)
			if errors.Is(err, ErrColumnNotFound) {
				if s.preGroupRelation == nil {
					return nil, nil, false, fmt.Errorf(`%w: unknown column reference "%s"`, ErrColumnNotFound, node.String())
				}

				// if not found, see if it is in the relation but not grouped
				field, err2 := s.preGroupRelation.Search(node.Table, node.Column)
				// if the column exist in the outer relation, then it might be part of an expression
				// contained in the group by. We should tell the caller to attempt to rewrite the expression
				if err2 == nil {
					// we return the column because the caller might try to handle the error
					scalar, err := field.Scalar()
					if err != nil {
						return nil, nil, false, err
					}

					s.aggViolationColumn = node.String()
					return &ColumnRef{
						Parent:     field.Parent,
						ColumnName: field.Name,
						dataType:   scalar,
					}, field, true, nil
				}
				return nil, nil, false, err
			} else if err != nil {
				return nil, nil, false, err
			}

			scalar, err := field.Scalar()
			if err != nil {
				return nil, nil, false, err
			}

			// mark as correlated
			s.Correlations = append(s.Correlations, field)

			return cast(&ColumnRef{
				Parent:     field.Parent,
				ColumnName: field.Name,
				dataType:   scalar,
			}, field)
		}
		// otherwise, return the error
		return nil, nil, false, err
	case *parse.ExpressionCollate:
		expr, field, err := rExpr(node.Expression)
		if err != nil {
			return nil, nil, false, err
		}

		scalar, err := field.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		c := &Collate{
			Expr: expr,
		}

		switch strings.ToLower(node.Collation) {
		case "nocase":
			c.Collation = NoCaseCollation

			if !scalar.Equals(types.TextType) {
				return nil, nil, false, fmt.Errorf("NOCASE collation can only be applied to text types")
			}
		default:
			return nil, nil, false, fmt.Errorf(`unknown collation "%s"`, node.Collation)
		}

		// return the whole field since collations don't overwrite the return value's name
		return c, field, shouldRewrite, nil
	case *parse.ExpressionStringComparison:
		left, leftField, err := rExpr(node.Left)
		if err != nil {
			return nil, nil, false, err
		}

		right, rightField, err := rExpr(node.Right)
		if err != nil {
			return nil, nil, false, err
		}

		leftScalar, err := leftField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		rightScalar, err := rightField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		if !leftScalar.Equals(types.TextType) || !rightScalar.Equals(types.TextType) {
			return nil, nil, false, fmt.Errorf("string comparison operands must be of type string. %s != %s", leftScalar, rightScalar)
		}

		expr := applyOps(left, right, []ComparisonOperator{get(stringComparisonOps, node.Operator)}, node.Not)

		return expr, anonField(types.BoolType.Copy()), shouldRewrite, nil
	case *parse.ExpressionIs:
		op := Is
		if node.Distinct {
			op = IsDistinctFrom
		}

		left, leftField, err := rExpr(node.Left)
		if err != nil {
			return nil, nil, false, err
		}

		right, rightField, err := rExpr(node.Right)
		if err != nil {
			return nil, nil, false, err
		}

		leftScalar, err := leftField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		rightScalar, err := rightField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		if node.Distinct {
			if !leftScalar.Equals(rightScalar) {
				return nil, nil, false, fmt.Errorf("IS DISTINCT FROM requires operands of the same type. %s != %s", leftScalar, rightScalar)
			}
		} else {
			if !rightScalar.Equals(types.NullType) {
				return nil, nil, false, fmt.Errorf("IS requires the right operand to be NULL")
			}
		}

		var expr Expression = &ComparisonOp{
			Left:  left,
			Right: right,
			Op:    op,
		}

		if node.Not {
			expr = &UnaryOp{
				Expr: expr,
				Op:   Not,
			}
		}

		return expr, anonField(types.BoolType.Copy()), shouldRewrite, nil
	case *parse.ExpressionIn:
		left, lField, err := rExpr(node.Expression)
		if err != nil {
			return nil, nil, false, err
		}

		lScalar, err := lField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		in := &IsIn{
			Left: left,
		}

		if node.Subquery != nil {
			subq, rel, err := s.planSubquery(node.Subquery, currentRel)
			if err != nil {
				return nil, nil, false, err
			}

			if len(rel.Fields) != 1 {
				return nil, nil, false, fmt.Errorf("subquery must return exactly one column")
			}

			scalar, err := rel.Fields[0].Scalar()
			if err != nil {
				return nil, nil, false, err
			}

			if !lScalar.Equals(scalar) {
				return nil, nil, false, fmt.Errorf("IN subquery must return the same type as the left expression. %s != %s", lScalar, scalar)
			}

			in.Subquery = &SubqueryExpr{
				Query: subq,
			}
		} else {
			var right []Expression
			var rFields []*Field
			for _, expr := range node.List {
				r, rField, err := rExpr(expr)
				if err != nil {
					return nil, nil, false, err
				}

				right = append(right, r)
				rFields = append(rFields, rField)
			}

			for _, r := range rFields {
				scalar, err := r.Scalar()
				if err != nil {
					return nil, nil, false, err
				}

				if !lScalar.Equals(scalar) {
					return nil, nil, false, fmt.Errorf("IN list must contain elements of the same type as the left expression. %s != %s", lScalar, scalar)
				}
			}

			in.Expressions = right
		}

		var expr Expression = in

		if node.Not {
			expr = &UnaryOp{
				Expr: expr,
				Op:   Not,
			}
		}

		return expr, anonField(types.BoolType.Copy()), shouldRewrite, nil
	case *parse.ExpressionBetween:
		leftOps, rightOps := []ComparisonOperator{GreaterThan}, []ComparisonOperator{LessThan}
		if !node.Not {
			leftOps = append(leftOps, Equal)
			rightOps = append(rightOps, Equal)
		}

		left, exprField, err := rExpr(node.Expression)
		if err != nil {
			return nil, nil, false, err
		}

		exprScalar, err := exprField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		lower, lowerField, err := rExpr(node.Lower)
		if err != nil {
			return nil, nil, false, err
		}

		lowerScalar, err := lowerField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		upper, upperField, err := rExpr(node.Upper)
		if err != nil {
			return nil, nil, false, err
		}

		upScalar, err := upperField.Scalar()
		if err != nil {
			return nil, nil, false, err
		}

		if !exprScalar.Equals(lowerScalar) {
			return nil, nil, false, fmt.Errorf("BETWEEN lower bound must be of the same type as the expression. %s != %s", exprScalar, lowerScalar)
		}

		if !exprScalar.Equals(upScalar) {
			return nil, nil, false, fmt.Errorf("BETWEEN upper bound must be of the same type as the expression. %s != %s", exprScalar, upScalar)
		}

		return &LogicalOp{
			Left:  applyOps(left, lower, leftOps, false),
			Right: applyOps(left, upper, rightOps, false),
			Op:    And,
		}, anonField(types.BoolType.Copy()), shouldRewrite, nil
	case *parse.ExpressionCase:
		c := &Case{}

		// all whens must be bool unless an expression is used before CASE
		expectedWhenType := types.BoolType.Copy()
		if node.Case != nil {
			caseExpr, field, err := rExpr(node.Case)
			if err != nil {
				return nil, nil, false, err
			}

			c.Value = caseExpr
			expectedWhenType, err = field.Scalar()
			if err != nil {
				return nil, nil, false, err
			}
		}

		var returnType *types.DataType
		for _, whenThen := range node.WhenThen {
			whenExpr, whenField, err := rExpr(whenThen[0])
			if err != nil {
				return nil, nil, false, err
			}

			thenExpr, thenField, err := rExpr(whenThen[1])
			if err != nil {
				return nil, nil, false, err
			}

			thenType, err := thenField.Scalar()
			if err != nil {
				return nil, nil, false, err
			}
			if returnType == nil {
				returnType = thenType
			} else {
				if !returnType.Equals(thenType) {
					return nil, nil, false, fmt.Errorf(`all THEN expressions must be of the same type %s, received %s`, returnType, thenType)
				}
			}

			whenScalar, err := whenField.Scalar()
			if err != nil {
				return nil, nil, false, err
			}

			if !expectedWhenType.Equals(whenScalar) {
				return nil, nil, false, fmt.Errorf(`WHEN expression must be of type %s, received %s`, expectedWhenType, whenScalar)
			}

			c.WhenClauses = append(c.WhenClauses, [2]Expression{whenExpr, thenExpr})
		}

		if node.Else != nil {
			elseExpr, elseField, err := rExpr(node.Else)
			if err != nil {
				return nil, nil, false, err
			}

			elseType, err := elseField.Scalar()
			if err != nil {
				return nil, nil, false, err
			}

			if !returnType.Equals(elseType) {
				return nil, nil, false, fmt.Errorf(`ELSE expression must be of the same type of THEN expressions %s, received %s`, returnType, elseExpr)
			}

			c.Else = elseExpr
		}

		return c, anonField(returnType), shouldRewrite, nil
	case *parse.ExpressionSubquery:
		subq, rel, err := s.planSubquery(node.Subquery, currentRel)
		if err != nil {
			return nil, nil, false, err
		}

		subqExpr := &SubqueryExpr{
			Query: subq,
		}
		if node.Exists {
			subqExpr.Exists = true

			var plan Expression = subqExpr
			if node.Not {
				plan = &UnaryOp{
					Expr: plan,
					Op:   Not,
				}
			}

			return plan, anonField(types.BoolType.Copy()), shouldRewrite, nil
		} else {
			if len(rel.Fields) != 1 {
				return nil, nil, false, fmt.Errorf("scalar subquery must return exactly one column")
			}
		}

		return cast(subqExpr, rel.Fields[0])
	}
}

// planSubquery plans a subquery.
// It takes the relation of the calling query to allow for correlated subqueries.
func (s *scopeContext) planSubquery(node *parse.SelectStatement, currentRel *Relation) (*Subquery, *Relation, error) {
	// for a subquery, we will add the current relation to the outer relation,
	// to allow for correlated subqueries
	oldOuter := s.OuterRelation
	oldCorrelations := s.Correlations

	s.OuterRelation = &Relation{
		Fields: append(s.OuterRelation.Fields, currentRel.Fields...),
	}
	// we don't need access to the old correlations since we will simply
	// recognize them as correlated again if they are used in the subquery
	s.Correlations = []*Field{}

	defer func() {
		s.OuterRelation = oldOuter
		s.Correlations = oldCorrelations
	}()

	query, rel, err := s.selectStmt(node)
	if err != nil {
		return nil, nil, err
	}

	// for all new correlations, we need to check if they are present on
	// the oldOuter relation. If so, then we simply add them as correlated
	// to the subplan. If not, then we also need to pass them back to the
	// oldCorrelations so that they can be used in the outer query (in the case
	// of a multi-level correlated subquery)
	oldMap := make(map[[2]string]struct{})
	for _, cor := range oldCorrelations {
		oldMap[[2]string{cor.Parent, cor.Name}] = struct{}{}
	}
	for _, cor := range s.Correlations {
		_, err = currentRel.Search(cor.Parent, cor.Name)
		// if no error, it is correlated to this query, do nothing
		if err == nil {
			continue
		}

		// if the column is not found in the current relation, then we need to
		// pass it back to the oldCorrelations
		if errors.Is(err, ErrColumnNotFound) {
			// if not known to the outer correlation, then add it
			_, ok := oldMap[[2]string{cor.Parent, cor.Name}]
			if !ok {
				oldCorrelations = append(oldCorrelations, cor)
				continue
			}
		}
		// some other error occurred
		return nil, nil, err

	}

	plan := &Subplan{
		Plan: query,
		ID:   strconv.Itoa(s.plan.SubqueryCount),
		Type: SubplanTypeSubquery,
	}

	s.plan.SubqueryCount++

	// the returned relation should not have any parent tables
	for _, col := range rel.Fields {
		col.Parent = ""
	}

	return &Subquery{
		Plan:       plan,
		Correlated: s.Correlations,
	}, rel, nil
}

// applyComparisonOps applies a series of comparison operators to the left and right expressions.
// If negate is true, then the final expression is negated.
func applyOps(left, right Expression, ops []ComparisonOperator, negate bool) Expression {
	var expr Expression = &ComparisonOp{
		Left:  left,
		Right: right,
		Op:    ops[0],
	}
	for _, op := range ops[1:] {
		expr = &LogicalOp{
			Left: expr,
			Right: &ComparisonOp{
				Left:  left,
				Right: right,
				Op:    op,
			},
			Op: Or,
		}
	}

	if negate {
		expr = &UnaryOp{
			Expr: expr,
			Op:   Not,
		}
	}

	return expr
}

// anonField creates an anonymous field with the given data type.
func anonField(dt *types.DataType) *Field {
	return &Field{
		val: dt,
	}
}

// table takes a parse.Table interface and returns the plan and relation
// for the table.
func (s *scopeContext) table(node parse.Table) (*Scan, *Relation, error) {
	switch node := node.(type) {
	default:
		panic(fmt.Sprintf("unexpected parse table type %T", node))
	case *parse.RelationTableFunction:
		return s.tableFunction(node)
	case *parse.RelationTable:
		// either a CTE or a physical table
		alias := node.Table
		if node.Alias != "" {
			alias = node.Alias
		}

		var scanTblType TableSourceType
		var rel *Relation

		// we first check if it is a recursive CTE, then any CTE, then a physical table
		if node.Table == s.cteCtx.currentCTEName && node.Namespace == "" {
			// if the shape is nil, then we are in a recursive CTE but we cannot reference it here.
			// For example, this might be the case if we have:
			// WITH RECURSIVE cte AS (SELECT * FROM cte) ...
			// In this case, the recursive CTE cannot reference itself in the subquery, because
			// it needs a base case followed by a UNION ALL to reference itself.
			if s.cteCtx.recursiveCTEShape == nil {
				return nil, nil, fmt.Errorf("recursive CTE %s cannot reference itself in this context", node.Table)
			}

			scanTblType = TableSourceCTE
			rel = s.cteCtx.recursiveCTEShape
			s.cteCtx.usedRecursiveCTE = true
		} else if cte, ok := s.plan.CTEs[node.Table]; ok && node.Namespace == "" { // only use a cte if no namespace is specified
			scanTblType = TableSourceCTE
			rel = cte
		} else {
			// if it is a physical table, then we need to qualify it
			if node.Namespace == "" {
				node.Namespace = s.plan.defaultNamespace
			}

			physicalTbl, err := s.plan.Tables(node.Namespace, node.Table)
			if err != nil {
				return nil, nil, err
			}

			scanTblType = TableSourcePhysical
			rel = relationFromTable(physicalTbl)
		}

		for _, col := range rel.Fields {
			col.Parent = alias
		}

		return &Scan{
			Source: &TableScanSource{
				Namespace: node.Namespace,
				TableName: node.Table,
				Type:      scanTblType,
				rel:       rel.Copy(),
			},
			RelationName: alias,
		}, rel, nil
	case *parse.RelationSubquery:
		if node.Alias == "" {
			return nil, nil, fmt.Errorf("join against subquery must have an alias")
		}

		// we pass an empty relation because the subquery can't
		// refer to the current relation, but they can be correlated against some
		// outer relation.
		// for example, "select * from users u inner join (select * from posts where posts.id = u.id) as p on u.id=p.id;"
		// is invalid, but
		// "select * from users where id = (select posts.id from posts inner join (select * from posts where id = users.id) as s on s.id=posts.id);"
		// is valid
		subq, rel, err := s.planSubquery(node.Subquery, &Relation{})
		if err != nil {
			return nil, nil, err
		}

		for _, col := range rel.Fields {
			col.Parent = node.Alias
		}

		return &Scan{
			Source:       subq,
			RelationName: node.Alias,
		}, rel, nil
	}
}

// join wraps the given plan in a join node.
func (s *scopeContext) join(child Plan, childRel *Relation, join *parse.Join) (Plan, *Relation, error) {
	tbl, tblRel, err := s.table(join.Relation)
	if err != nil {
		return nil, nil, err
	}

	newRel := joinRels(childRel, tblRel)

	onExpr, joinField, err := s.expr(join.On, newRel, nil)
	if err != nil {
		return nil, nil, err
	}

	scalar, err := joinField.Scalar()
	if err != nil {
		return nil, nil, err
	}

	if !scalar.Equals(types.BoolType) {
		return nil, nil, fmt.Errorf("JOIN condition must be of type boolean, received %s", scalar)
	}

	plan := &Join{
		Left:      child,
		Right:     tbl,
		Condition: onExpr,
		JoinType:  get(joinTypes, join.Type),
	}

	return plan, newRel, nil
}

// update builds a plan for an update
func (s *scopeContext) update(node *parse.UpdateStatement) (*Update, error) {
	plan, targetRel, cartesianRel, err := s.cartesian(node.Table, node.Alias, node.From, node.Joins, node.Where)
	if err != nil {
		return nil, err
	}

	assigns, err := s.assignments(node.SetClause, targetRel, cartesianRel)
	if err != nil {
		return nil, err
	}

	return &Update{
		Child:       plan,
		Assignments: assigns,
		Table:       node.Table,
	}, nil
}

// delete builds a plan for a delete
func (s *scopeContext) delete(node *parse.DeleteStatement) (*Delete, error) {
	plan, _, _, err := s.cartesian(node.Table, node.Alias, node.From, node.Joins, node.Where)
	if err != nil {
		return nil, err
	}

	return &Delete{
		Child: plan,
		Table: node.Table,
	}, nil
}

// insert builds a plan for an insert
func (s *scopeContext) insert(node *parse.InsertStatement) (*Insert, error) {
	ins := &Insert{
		Table:        node.Table,
		ReferencedAs: node.Alias,
	}

	tbl, err := s.plan.Tables("", node.Table)
	if err != nil {
		return nil, err
	}

	// orderAndFillNulls is a helper function that orders logical expressions
	// according to their position in the table, and fills in nulls for any
	// columns that were not specified in the insert. It starts as being empty,
	// since it only needs logic if the user specifies columns.
	orderAndFillNulls := func(exprs []*exprFieldPair[Expression]) []*exprFieldPair[Expression] {
		return exprs
	}

	// if Columns are specified, then the second dimension of the Values
	// must exactly match the number of columns. Otherwise, the second
	// dimension of Values must exactly match the number of columns in the table.
	var expectedColLen int
	var expectedColTypes []*types.DataType
	if len(node.Columns) > 0 {
		expectedColLen = len(node.Columns)

		// check if the columns are valid
		var err error
		expectedColTypes, err = checkNullableColumns(tbl, node.Columns)
		if err != nil {
			return nil, err
		}

		// we need to set the orderAndFillNulls function
		// We will do this by creating a map of the position
		// of a specified column's position to its column index in the table.

		// first, we will create a map of the table's columns
		tableColPos := make(map[string]int, len(tbl.Columns))
		for i, col := range tbl.Columns {
			tableColPos[col.Name] = i
		}

		colPos := make(map[int]int, len(node.Columns))
		for i, col := range node.Columns {
			colPos[i] = tableColPos[col]
		}

		orderAndFillNulls = func(exprs []*exprFieldPair[Expression]) []*exprFieldPair[Expression] {
			newExprs := make([]*exprFieldPair[Expression], len(tbl.Columns))

			for i, expr := range exprs {
				newExprs[colPos[i]] = expr
			}

			for i, col := range tbl.Columns {
				if newExprs[i] != nil {
					continue
				}

				newExprs[i] = &exprFieldPair[Expression]{
					Expr: &Literal{
						Value: nil,
						Type:  types.NullType.Copy(),
					},
					Field: &Field{
						Parent: tbl.Name,
						Name:   col.Name,
						val:    col.DataType.Copy(),
					},
				}
			}

			return newExprs
		}
	} else {
		expectedColLen = len(tbl.Columns)
		for _, col := range tbl.Columns {
			expectedColTypes = append(expectedColTypes, col.DataType.Copy())
		}
	}

	rel := relationFromTable(tbl)
	ins.Columns = rel.Fields

	if node.Select != nil {
		// if a select statement is present, we need to plan it
		plan, _, err := s.selectStmt(node.Select)
		if err != nil {
			return nil, err
		}

		// we don't need to check the number / type of columns and compare them
		// to the table. Postgres will catch this error and return a much more
		// helpful error message, so we leave it. We simply call the select
		// statement above to ensure it is deterministic.

		ins.InsertionValues = plan
	} else {
		tup := &Tuples{
			rel: &Relation{},
		}
		// check the value types and lengths
		for i, vals := range node.Values {
			if len(vals) != expectedColLen {
				return nil, fmt.Errorf(`insert has %d columns but %d values were supplied`, expectedColLen, len(vals))
			}

			var row []*exprFieldPair[Expression]

			for j, val := range vals {
				expr, field, err := s.expr(val, rel, nil)
				if err != nil {
					return nil, err
				}

				scalar, err := field.Scalar()
				if err != nil {
					return nil, err
				}

				if !scalar.Equals(expectedColTypes[j]) {
					return nil, fmt.Errorf(`insert value %d must be of type %s, received %s`, j+1, expectedColTypes[j], field.val)
				}

				field.Name = tbl.Columns[j].Name
				field.Parent = tbl.Name
				row = append(row, &exprFieldPair[Expression]{
					Expr:  expr,
					Field: field,
				})
			}

			pairs := orderAndFillNulls(row)
			var newRow []Expression
			for _, pair := range pairs {
				newRow = append(newRow, pair.Expr)

				// if we are on the first row, we should build the tuple's relation
				if i == 0 {
					tup.rel.Fields = append(tup.rel.Fields, pair.Field)
				}
			}

			tup.Values = append(tup.Values, newRow)
		}
		ins.InsertionValues = tup
	}

	// finally, we need to check if there is an ON CONFLICT clause,
	// and if so, we need to process it.
	if node.OnConflict != nil {
		conflict, err := s.buildUpsert(node.OnConflict, tbl, ins.InsertionValues)
		if err != nil {
			return nil, err
		}

		ins.ConflictResolution = conflict
	}

	return ins, nil
}

// buildUpsert builds the conflict resolution for an upsert statement.
// It takes the upsert clause, the table, and the plan that is being inserted (either VALUES or SELECT).
func (s *scopeContext) buildUpsert(node *parse.OnConflict, table *engine.Table, insertFrom Plan) (ConflictResolution, error) {
	// all DO UPDATE upserts need to have an arbiter index.
	// DO NOTHING can optionally have one, but it is not required.
	var arbiterIndex Index
	switch len(node.ConflictColumns) {
	// must be a unique index or pk that exactly matches the columns
	case 0:
		// do nothing
	case 1:
		// check the column for a unique or pk constraint, as well as all indexes
		col, ok := table.Column(node.ConflictColumns[0])
		if !ok {
			return nil, fmt.Errorf(`conflict column "%s" not found in table`, node.ConflictColumns[0])
		}

		if table.HasPrimaryKey(col.Name) {
			arbiterIndex = &IndexColumnConstraint{
				Table:          table.Name,
				Column:         col.Name,
				ConstraintType: PrimaryKeyConstraintIndex,
			}
		} else {
			done := false
			// check all indexes for unique indexes that match the column
			for _, idx := range table.Indexes {
				if (idx.Type == engine.UNIQUE_BTREE || idx.Type == engine.PRIMARY) && len(idx.Columns) == 1 && idx.Columns[0] == col.Name {
					arbiterIndex = &IndexNamed{
						Name: idx.Name,
					}
					done = true
					break
				}
			}

			if !done {
				// check all constraints for unique constraints that match the column
				for _, con := range table.Constraints {
					if con.Type == engine.ConstraintUnique && len(con.Columns) == 1 && con.Columns[0] == col.Name {
						arbiterIndex = &IndexColumnConstraint{
							Table:          table.Name,
							Column:         col.Name,
							ConstraintType: UniqueConstraintIndex,
						}
						break
					}
				}
			}
		}

		if arbiterIndex == nil {
			return nil, fmt.Errorf(`%w: conflict column "%s" must have a unique index or be a primary key`, ErrIllegalConflictArbiter, node.ConflictColumns[0])
		}
	default:
		// colsMatch checks if two slices of strings are equal
		// It is order-independent
		colsMatch := func(want, have []string) bool {
			if len(want) != len(have) {
				return false
			}

			found := make(map[string]struct{}, len(want))
			for _, col := range want {
				found[col] = struct{}{}
			}

			for _, col := range have {
				_, ok := found[col]
				if !ok {
					return false
				}
			}

			return true
		}

		// check that the table has all the columns
		for _, col := range node.ConflictColumns {
			_, ok := table.Column(col)
			if !ok {
				return nil, fmt.Errorf(`%w: conflict column "%s" not found in table`, ErrColumnNotFound, col)
			}
		}

		found := false

		// check all indexes for a unique or pk index that matches the columns
		for _, idx := range table.Indexes {
			if idx.Type != engine.UNIQUE_BTREE && idx.Type != engine.PRIMARY {
				continue
			}

			if !colsMatch(node.ConflictColumns, idx.Columns) {
				continue
			}

			arbiterIndex = &IndexNamed{
				Name: idx.Name,
			}
			break
		}

		if !found {
			// check all constraints for a unique constraint that matches the columns
			for name, con := range table.Constraints {
				if con.Type != engine.ConstraintUnique {
					continue
				}

				if !colsMatch(node.ConflictColumns, con.Columns) {
					continue
				}

				arbiterIndex = &IndexNamed{
					Name: name,
				}
				break
			}
		}

		if arbiterIndex == nil {
			return nil, fmt.Errorf(`conflict columns must have a unique index or primary key`)
		}
	}

	if len(node.DoUpdate) == 0 {
		return &ConflictDoNothing{
			ArbiterIndex: arbiterIndex,
		}, nil
	}
	if node.ConflictWhere != nil {
		// This would be "ON CONFLICT(id) [WHERE ...] DO UPDATE SET ..."
		// This is the `index_predicate`, specified here:
		// https://www.postgresql.org/docs/current/sql-insert.html
		// IDK why our syntax supports this, there is literally not a way
		// somebody could make use of this within Kwil right now.
		return nil, errors.New("engine does not yet support index predicates on upsert. Try using a WHERE constraint after the SET clause")
	}
	if arbiterIndex == nil {
		return nil, fmt.Errorf("conflict column must be specified for DO UPDATE")
	}

	res := &ConflictUpdate{
		ArbiterIndex: arbiterIndex,
	}

	rel := relationFromTable(table)

	// we need to use the tuples to create a "excluded" relation
	// https://www.jooq.org/doc/latest/manual/sql-building/sql-statements/insert-statement/insert-on-conflict-excluded/
	excluded := insertFrom.Relation()
	for _, col := range excluded.Fields {
		col.Parent = "excluded"
	}

	referenceRel := joinRels(rel, excluded)

	var err error
	res.Assignments, err = s.assignments(node.DoUpdate, rel, referenceRel)
	if err != nil {
		return nil, err
	}

	if node.UpdateWhere != nil {
		conflictFilter, field, err := s.expr(node.UpdateWhere, referenceRel, nil)
		if err != nil {
			return nil, err
		}

		scalar, err := field.Scalar()
		if err != nil {
			return nil, err
		}

		if !scalar.Equals(types.BoolType) {
			return nil, fmt.Errorf("conflict filter must be of type bool, received %s", field)
		}

		res.ConflictFilter = conflictFilter
	}

	return res, nil
}

// checkNullableColumns takes a table and a slice of column names, and checks
// if the columns are nullable. If they are not nullable, it returns an error.
// If they are nullable, it returns their data types in the order that they
// were passed in.
func checkNullableColumns(tbl *engine.Table, cols []string) ([]*types.DataType, error) {
	specifiedColSet := make(map[string]struct{}, len(cols))
	for _, col := range cols {
		specifiedColSet[col] = struct{}{}
	}

	pkSet := make(map[string]struct{})
	for _, col := range tbl.Columns {
		if col.IsPrimaryKey {
			pkSet[col.Name] = struct{}{}
		}
	}

	// we will build a set of columns to decrease the time complexity
	// for checking if a column is in the set.
	tblColSet := make(map[string]*types.DataType, len(tbl.Columns))
	for _, col := range tbl.Columns {
		tblColSet[col.Name] = col.DataType.Copy()

		_, ok := specifiedColSet[col.Name]
		if ok {
			continue
		}

		// the column is not in the set, so we need to check if it is nullable
		// All columns are nullable unless they are specified as not null
		// or they are part of the primary key.
		_, isPk := pkSet[col.Name]
		if !col.Nullable && isPk {
			return nil, fmt.Errorf(`%w: column "%s" must be specified as an insert column`, ErrNotNullableColumn, col.Name)
		}

		// it is also possible that a primary index contains the column
		_, ok = pkSet[col.Name]
		if ok {
			return nil, fmt.Errorf(`%w: column "%s" must be specified as an insert column`, ErrNotNullableColumn, col.Name)
		}
		// otherwise, we are good
	}

	dataTypeArr := make([]*types.DataType, len(cols))
	// now we need to check if all columns in the set are in the table
	for i, col := range cols {
		colType, ok := tblColSet[col]
		if !ok {
			return nil, fmt.Errorf(`column "%s" not found in table`, col)
		}

		dataTypeArr[i] = colType
	}

	return dataTypeArr, nil
}

// cartesian builds a cartesian product for several relations. It is meant to be used
// explicitly for update and delete, where we start by planning a cartesian join between the
// target table and the FROM + JOIN tables, and later optimize the filter.
// It returns the plan for the join, the relation that is being targeted, the relation that is the cartesian join
// between the target and the FROM + JOIN tables, and an error if one occurred.
func (s *scopeContext) cartesian(targetTable, alias string, from parse.Table, joins []*parse.Join,
	filter parse.Expression) (plan Plan, targetRel *Relation, cartesianRel *Relation, err error) {
	tbl, err := s.plan.Tables("", targetTable)
	if err != nil {
		return nil, nil, nil, err
	}
	if alias == "" {
		alias = targetTable
	}

	targetRel = relationFromTable(tbl)
	// copy that can be overwritten
	rel := targetRel.Copy()

	// plan the target table
	var targetPlan Plan = &Scan{
		Source: &TableScanSource{
			Namespace: s.plan.defaultNamespace, // target table of update or delete is always in the default namespace
			TableName: targetTable,
			Type:      TableSourcePhysical,
			rel:       rel.Copy(),
		},
		RelationName: alias,
	}

	// if there is no FROM clause, we can simply apply the filter and return
	if from == nil {
		if filter != nil {
			expr, field, err := s.expr(filter, rel, nil)
			if err != nil {
				return nil, nil, nil, err
			}

			scalar, err := field.Scalar()
			if err != nil {
				return nil, nil, nil, err
			}

			if !scalar.Equals(types.BoolType) {
				return nil, nil, nil, fmt.Errorf("WHERE clause must be of type boolean, received %s", field)
			}

			return &Filter{
				Child:     targetPlan,
				Condition: expr,
			}, rel, rel, nil
		}

		return targetPlan, rel, rel, nil
	}

	// update and delete statements with a FROM require a WHERE clause,
	// otherwise it is impossible to optimize the query to not be a cartesian product
	if filter == nil {
		return nil, nil, nil, ErrUpdateOrDeleteWithoutWhere
	}

	// plan the FROM clause

	var sourceRel Plan
	var fromRel *Relation
	sourceRel, fromRel, err = s.table(from)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, join := range joins {
		sourceRel, fromRel, err = s.join(sourceRel, fromRel, join)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// build a cartesian product and apply the filter
	targetPlan = &CartesianProduct{
		Left:  targetPlan,
		Right: sourceRel,
	}

	rel = joinRels(fromRel, rel)

	expr, field, err := s.expr(filter, rel, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	scalar, err := field.Scalar()
	if err != nil {
		return nil, nil, nil, err
	}

	if !scalar.Equals(types.BoolType) {
		return nil, nil, nil, fmt.Errorf("WHERE clause must be of type boolean, received %s", field)
	}

	return &Filter{
		Child:     targetPlan,
		Condition: expr,
	}, targetRel, rel, nil
}

// assignments builds the assignments for update and conflict clauses.
// It takes a list of update set clauses, the target relation (where columns are being assigned),
// and a relation that can be referenced in the assigning expressions.
func (s *scopeContext) assignments(assignments []*parse.UpdateSetClause, targetRel *Relation, referenceRel *Relation) ([]*Assignment, error) {
	assigns := make([]*Assignment, len(assignments))
	for i, assign := range assignments {
		field, err := targetRel.Search("", assign.Column)
		if err != nil {
			return nil, err
		}

		expr, assignType, err := s.expr(assign.Value, referenceRel, nil)
		if err != nil {
			return nil, err
		}

		scalarField, err := assignType.Scalar()
		if err != nil {
			return nil, err
		}

		scalarAssign, err := field.Scalar()
		if err != nil {
			return nil, err
		}

		if !scalarField.Equals(scalarAssign) {
			return nil, fmt.Errorf(`cannot assign type %s to column "%s", expected type %s`, scalarField, field.Name, scalarAssign)
		}

		assigns[i] = &Assignment{
			Column: field.Name,
			Value:  expr,
		}
	}

	return assigns, nil
}

const (
	alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	base     = len(alphabet)
)

// uniqueRefIdentifier generates a unique reference identifier for an expression.
// This is used to avoid conflicts when referencing expressions in the query.
// It uses letters instead of numbers to avoid confusion with subplan references.
// It uses a base 26 system, where A = 0, B = 1, ..., Z = 25, AA = 26, AB = 27, etc.
func (p *planContext) uniqueRefIdentifier() string {
	if p.ReferenceCount == 0 {
		p.ReferenceCount++
		return string(alphabet[0])
	}

	n := p.ReferenceCount

	var sb strings.Builder
	for n > 0 {
		remainder := n % base
		sb.WriteByte(alphabet[remainder])
		n = n / base
	}

	// Reverse the string because the current order is backward
	result := sb.String()
	runes := []rune(result)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	p.ReferenceCount++

	return string(runes)
}

// tableFunction handles table-valued function calls like UNNEST
func (s *scopeContext) tableFunction(node *parse.RelationTableFunction) (*Scan, *Relation, error) {
	// Check if this is a known table-valued function
	fn, ok := engine.Functions[node.FunctionCall.Name]
	if !ok {
		return nil, nil, fmt.Errorf(`%w: "%s"`, ErrFunctionDoesNotExist, node.FunctionCall.Name)
	}

	tableFn, ok := fn.(*engine.TableValuedFunctionDefinition)
	if !ok {
		return nil, nil, fmt.Errorf("function %s is not a table-valued function", node.FunctionCall.Name)
	}

	// Enforce that table-valued functions must provide an explicit alias
	if node.Alias == "" {
		return nil, nil, fmt.Errorf("table-valued function %s must have an explicit alias", node.FunctionCall.Name)
	}

	// Validate function arguments and get table schema
	argTypes := make([]*types.DataType, len(node.FunctionCall.Args))
	for i, arg := range node.FunctionCall.Args {
		_, field, err := s.expr(arg, s.OuterRelation, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("error evaluating argument %d: %w", i+1, err)
		}
		dataType, err := field.Scalar()
		if err != nil {
			return nil, nil, fmt.Errorf("argument %d is not scalar: %w", i+1, err)
		}
		argTypes[i] = dataType
	}

	tableSchema, err := tableFn.ValidateArgsFunc(argTypes)
	if err != nil {
		return nil, nil, fmt.Errorf("table function validation failed: %w", err)
	}

	// Add ordinality column if WITH ORDINALITY was specified
	if node.WithOrdinality {
		tableSchema = append(tableSchema, &engine.NamedType{
			Name: "ordinality",
			Type: types.IntType,
		})
	}

	// Use the explicit alias
	alias := node.Alias

	// Enforce column alias count to match table schema width (Postgres-compatible)
	if len(node.ColumnAliases) > 0 && len(node.ColumnAliases) != len(tableSchema) {
		return nil, nil, fmt.Errorf("column alias count (%d) must match table function schema width (%d)", len(node.ColumnAliases), len(tableSchema))
	}

	rel := &Relation{}
	for i, field := range tableSchema {
		colName := field.Name
		// Use column aliases if provided
		if len(node.ColumnAliases) > i {
			colName = node.ColumnAliases[i]
		}

		rel.Fields = append(rel.Fields, &Field{
			Parent: alias,
			Name:   colName,
			val:    field.Type,
		})
	}

	// Create table function scan source
	scanSource := &TableFunctionScanSource{
		FunctionCall: node.FunctionCall,
		rel:          rel,
	}

	scan := &Scan{
		Source:       scanSource,
		RelationName: alias,
	}

	return scan, rel, nil
}
