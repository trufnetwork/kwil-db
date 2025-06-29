package logical

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/trufnetwork/kwil-db/core/types"
)

/*
	This file contains the nodes necessary to construct logical plans. These are made up of
	- LogicalPlan: a node in the logical plan tree, which returns a relation
	- LogicalExpr: an expression that can be used in a logical plan, which returns a data type

	The nodes are purely representative of a transformed query, and natively do not have any
	understanding of the underlying data or schema. When context of the underlying data is needed
	(e.g. to determine the data type of a column reference), a SchemaContext is passed in.

	The Relation() method of LogicalPlan returns the structure of the relation that the plan represents.
	This is NOT equivalent to the set of reference-able columns in the plan. Reference-able columns are
	tracked in the passed context, where the called method will modify the passed ctx. For example, if we were
	evaluating the query "SELECT name from users where id = 1", the returned relation would be a single
	column "name", but the reference-able columns would be "name" and "id" (and any other columns in the "users" table).
*/

// Traversable is an interface for nodes that can be traversed.
type Traversable interface {
	// Children returns the children of the node.
	// These are all LogicalPlans and LogicalExprs that are
	// referenced by the node.
	Children() []Traversable
	// Plans returns all the logical plans that are referenced
	// by the node (or the nearest node that contains them).
	Plans() []Plan
	// Accept is used to traverse the node.
	Accept(Visitor) any
	// Equal is used to compare two nodes.
	// Equal(other Traversable) bool
}

// I am unsure if equal is needed, and so I am commenting it out for now.
// Its quite hard to implement, so I do not want to delete yet, but will leave it
// unused for now.
// This function allows us to keep the equal functionality in the nodes themselves,
// while removing it from the interface.
func eq(a, b Traversable) bool {
	aEq, ok := a.(interface{ Equal(other Traversable) bool })
	if !ok {
		panic("equal called, but it is not implemented")
	}

	_, ok = b.(interface{ Equal(other Traversable) bool })
	if !ok {
		panic("equal called, but it is not implemented")
	}

	return aEq.Equal(b)
}

// ScanSource is a source of data that a Scan can be performed on.
// This is either a physical table, an action call that returns a table,
// or a subquery.
type ScanSource interface {
	Traversable
	FormatScan() string
	Relation() *Relation
}

// TableScanSource represents a scan of a physical table or a CTE.
type TableScanSource struct {
	// Namespace is the namespace of the table being scanned.
	Namespace string
	// TableName is the name of the table being scanned.
	TableName string
	Type      TableSourceType

	// rel is the relation that the table scan source represents.
	// It is set during the evaluation phase.
	rel *Relation
}

func (s *TableScanSource) Accept(v Visitor) any {
	return v.VisitTableScanSource(s)
}
func (t *TableScanSource) Children() []Traversable {
	return nil
}

func (t *TableScanSource) FormatScan() string {
	str := strings.Builder{}
	if t.Namespace != "" {
		str.WriteString(t.Namespace)
		str.WriteString(".")
	}
	str.WriteString(t.TableName + " [" + t.Type.String() + "]")
	return str.String()
}

func (t *TableScanSource) Plans() []Plan {
	return nil
}

func (t *TableScanSource) Relation() *Relation {
	// we will copy it since this is meant to be re-useable,
	// but some callers may modify it
	return t.rel.Copy()
}

func (t *TableScanSource) Equal(other Traversable) bool {
	o, ok := other.(*TableScanSource)
	if !ok {
		return false
	}

	return t.TableName == o.TableName && t.Type == o.Type && t.Namespace == o.Namespace
}

type TableSourceType int

const (
	TableSourcePhysical TableSourceType = iota // physical table (default)
	TableSourceCTE                             // common table expression
	// if/when we support views, we will add a view type here
)

func (t TableSourceType) String() string {
	switch t {
	case TableSourcePhysical:
		return "physical"
	case TableSourceCTE:
		return "cte"
	default:
		panic(fmt.Sprintf("unknown table source type %d", t))
	}
}

// ProcedureScanSource represents a scan of a function.
// It can call either a local procedure or foreign procedure
// that returns a table.
type ProcedureScanSource struct {
	// ProcedureName is the name of the procedure being targeted.
	ProcedureName string
	// Args are the base arguments to the procedure.
	Args []Expression
	// ContextualArgs are the arguments that are passed in if
	// the procedure is a foreign procedure.
	ContextualArgs []Expression
	// IsForeign is true if the function is a foreign procedure.
	IsForeign bool
	// rel is the relation that the procedure scan source represents.
	// It is set during the evaluation phase.
	rel *Relation
}

func (s *ProcedureScanSource) Accept(v Visitor) any {
	return v.VisitProcedureScanSource(s)
}
func (f *ProcedureScanSource) Children() []Traversable {
	var c []Traversable
	for _, arg := range f.Args {
		c = append(c, arg)
	}

	for _, arg := range f.ContextualArgs {
		c = append(c, arg)
	}

	return c
}

func (f *ProcedureScanSource) FormatScan() string {
	str := strings.Builder{}
	str.WriteString("[foreign=")
	str.WriteString(strconv.FormatBool(f.IsForeign))
	str.WriteString("] ")
	if f.IsForeign {
		str.WriteString("[namespace=")
		str.WriteString(f.ContextualArgs[0].String())
		str.WriteString("] ")
		str.WriteString("[proc=")
		str.WriteString(f.ContextualArgs[1].String())
		str.WriteString("] ")
	}
	str.WriteString(f.ProcedureName)
	str.WriteString("(")
	for i, arg := range f.Args {
		if i > 0 {
			str.WriteString(", ")
		}
		str.WriteString(arg.String())
	}
	str.WriteString(")")
	return str.String()
}

func (f *ProcedureScanSource) Plans() []Plan {
	var plans []Plan

	for _, arg := range f.Args {
		plans = append(plans, arg.Plans()...)
	}

	for _, arg := range f.ContextualArgs {
		plans = append(plans, arg.Plans()...)
	}

	return plans
}

func (f *ProcedureScanSource) Relation() *Relation {
	return f.rel.Copy()
}

func (f *ProcedureScanSource) Equal(other Traversable) bool {
	o, ok := other.(*ProcedureScanSource)
	if !ok {
		return false
	}

	if f.ProcedureName != o.ProcedureName || f.IsForeign != o.IsForeign {
		return false
	}

	if len(f.Args) != len(o.Args) || len(f.ContextualArgs) != len(o.ContextualArgs) {
		return false
	}

	for i, arg := range f.Args {
		if !eq(arg, o.Args[i]) {
			return false
		}
	}

	for i, arg := range f.ContextualArgs {
		if !eq(arg, o.ContextualArgs[i]) {
			return false
		}
	}

	return true
}

// Subquery holds information for a subquery.
// It is a TableSource that can be used in a Scan, but
// also can be used within expressions. If ReturnsRelation
// is true, it is a TableSource. If false, it is a scalar
// subquery (used in expressions).
type Subquery struct {
	// Plan is the logical plan for the subquery.
	Plan *Subplan

	// Everything below this is set during evaluation.

	// Correlated is the list of columns that are correlated
	// to the outer query. If empty, the subquery is uncorrelated.
	Correlated []*Field
}

func (s *Subquery) Accept(v Visitor) any {
	return v.VisitSubquery(s)
}
func (s *Subquery) Children() []Traversable {
	return []Traversable{s.Plan}
}

func (s *Subquery) FormatScan() string {
	return ""
}

func (s *Subquery) Plans() []Plan {
	return []Plan{s.Plan}
}

func (s *Subquery) Relation() *Relation {
	return s.Plan.Relation()
}

func (s *Subquery) Equal(other Traversable) bool {
	o, ok := other.(*Subquery)
	if !ok {
		return false
	}

	if len(s.Correlated) != len(o.Correlated) {
		return false
	}

	if !s.Plan.Equal(o.Plan) {
		return false
	}

	for i, col := range s.Correlated {
		if !col.Equals(o.Correlated[i]) {
			return false
		}
	}

	return true
}

type LogicalNode interface {
	fmt.Stringer
	Traversable
}

type Plan interface {
	LogicalNode
	Relation() *Relation
	plan()
}

type baseLogicalPlan struct{}

func (b *baseLogicalPlan) plan() {}

type EmptyScan struct {
	baseLogicalPlan
}

func (s *EmptyScan) Accept(v Visitor) any {
	return v.VisitEmptyScan(s)
}
func (n *EmptyScan) Children() []Traversable {
	return nil
}

func (n *EmptyScan) Plans() []Plan {
	return nil
}

func (n *EmptyScan) String() string {
	return "Empty Scan"
}

func (n *EmptyScan) Relation() *Relation {
	return &Relation{}
}

func (n *EmptyScan) Equal(other Traversable) bool {
	_, ok := other.(*EmptyScan)
	return ok
}

type Scan struct {
	baseLogicalPlan
	Source ScanSource
	// RelationName will always be set.
	// If the scan is a table scan and no alias was specified,
	// the RelationName will be the table name.
	// All other scan types (functions and subqueries) require an alias.
	RelationName string
	// Filter holds the optional filter condition that can be
	// pushed down to the scan operation. This allows filtering data
	// during the scan, which can improve query performance by reducing
	// the amount of data processed in subsequent operations.
	// This field won't ever be set in the initial logical plan, but
	// can be set during the optimization phase.
	Filter Expression
}

func (s *Scan) Accept(v Visitor) any {
	return v.VisitScan(s)
}
func (s *Scan) Children() []Traversable {
	return s.Source.Children()
}

func (s *Scan) Plans() []Plan {
	return s.Source.Plans()
}

func (s *Scan) String() string {
	alias := fmt.Sprintf(` [alias="%s"]`, s.RelationName)

	filter := ""
	if s.Filter != nil {
		filter = fmt.Sprintf(" filter=[%s]", s.Filter.String())
	}

	str := strings.Builder{}
	switch t := s.Source.(type) {
	case *TableScanSource:
		// if relation name == table name, remove the alias because it is redundant
		if t.TableName == s.RelationName {
			alias = ""
		}

		str.WriteString(fmt.Sprintf(`Scan Table%s: %s`, alias, s.Source.FormatScan()))
	case *ProcedureScanSource:
		str.WriteString(fmt.Sprintf(`Scan Procedure%s: %s`, alias, s.Source.FormatScan()))
	case *Subquery:
		str.WriteString(fmt.Sprintf(`Scan Subquery%s: [subplan_id=%s]`, alias, t.Plan.ID))
		if len(t.Correlated) > 0 {
			str.WriteString(" (correlated: ")
			for i, col := range t.Correlated {
				if i > 0 {
					str.WriteString(", ")
				}
				str.WriteString(col.String())
			}
			str.WriteString(")")
		} else {
			str.WriteString(" (uncorrelated)")
		}
	default:
		panic(fmt.Sprintf("unknown scan source type %T", s.Source))
	}

	str.WriteString(filter)

	return str.String()
}

func (s *Scan) Relation() *Relation {
	rel := s.Source.Relation()

	for _, col := range rel.Fields {
		col.Parent = s.RelationName
	}

	return rel
}

func (s *Scan) Equal(other Traversable) bool {
	o, ok := other.(*Scan)
	if !ok {
		return false
	}

	if s.RelationName != o.RelationName {
		return false
	}

	return eq(s.Source, o.Source)
}

type Project struct {
	baseLogicalPlan

	// Expressions are the expressions that are projected.
	Expressions []Expression
	Child       Plan
}

func (s *Project) Accept(v Visitor) any {
	return v.VisitProject(s)
}
func (p *Project) Children() []Traversable {
	var c []Traversable
	for _, expr := range p.Expressions {
		c = append(c, expr)
	}
	c = append(c, p.Child)

	return c
}

func (p *Project) Plans() []Plan {
	c := []Plan{p.Child}
	for _, expr := range p.Expressions {
		c = append(c, expr.Plans()...)
	}

	return c
}

func (p *Project) String() string {
	str := strings.Builder{}
	str.WriteString("Project: ")

	for i, expr := range p.Expressions {
		if i > 0 {
			str.WriteString("; ")
		}
		str.WriteString(expr.String())
	}

	return str.String()
}

func (p *Project) Relation() *Relation {
	var fields []*Field

	for _, expr := range p.Expressions {
		fields = append(fields, expr.Field())
	}

	return &Relation{Fields: fields}
}

func (p *Project) Equal(other Traversable) bool {
	o, ok := other.(*Project)
	if !ok {
		return false
	}

	if len(p.Expressions) != len(o.Expressions) {
		return false
	}

	for i, expr := range p.Expressions {
		if !eq(expr, o.Expressions[i]) {
			return false
		}
	}

	return eq(p.Child, o.Child)
}

type Filter struct {
	baseLogicalPlan
	Condition Expression
	Child     Plan
}

func (s *Filter) Accept(v Visitor) any {
	return v.VisitFilter(s)
}
func (f *Filter) Children() []Traversable {
	return []Traversable{f.Child, f.Condition}
}

func (f *Filter) String() string {
	return fmt.Sprintf("Filter: %s", f.Condition.String())
}

func (f *Filter) Plans() []Plan {
	return append([]Plan{f.Child}, f.Condition.Plans()...)
}

func (f *Filter) Relation() *Relation {
	return f.Child.Relation()
}

func (f *Filter) Equal(other Traversable) bool {
	o, ok := other.(*Filter)
	if !ok {
		return false
	}

	return eq(f.Condition, o.Condition) && eq(f.Child, o.Child)
}

type Join struct {
	baseLogicalPlan
	Left      Plan
	Right     Plan
	JoinType  JoinType
	Condition Expression
}

func (s *Join) Accept(v Visitor) any {
	return v.VisitJoin(s)
}
func (j *Join) Children() []Traversable {
	return []Traversable{j.Left, j.Right, j.Condition}
}

func (j *Join) String() string {
	str := strings.Builder{}
	str.WriteString("Join [")
	str.WriteString(j.JoinType.String())
	str.WriteString("]: ")

	str.WriteString(j.Condition.String())
	return str.String()
}

func (j *Join) Plans() []Plan {
	return append([]Plan{j.Left, j.Right}, j.Condition.Plans()...)
}

func (j *Join) Relation() *Relation {
	left := j.Left.Relation()
	right := j.Right.Relation()

	return &Relation{
		Fields: append(left.Fields, right.Fields...),
	}
}

func (j *Join) Equal(other Traversable) bool {
	o, ok := other.(*Join)
	if !ok {
		return false
	}

	if j.JoinType != o.JoinType {
		return false
	}

	if !eq(j.Condition, o.Condition) {
		return false
	}

	return eq(j.Left, o.Left) && eq(j.Right, o.Right)
}

type Sort struct {
	baseLogicalPlan
	SortExpressions []*SortExpression
	Child           Plan
}

type SortExpression struct {
	Expr      Expression
	Ascending bool
	NullsLast bool
}

func (s *SortExpression) String() string {
	str := strings.Builder{}
	str.WriteString("")
	str.WriteString(s.Expr.String())
	str.WriteString(" ")
	if s.Ascending {
		str.WriteString("asc ")
	} else {
		str.WriteString("desc ")
	}
	if s.NullsLast {
		str.WriteString("nulls last")
	} else {
		str.WriteString("nulls first")
	}

	return str.String()
}

func (s *Sort) String() string {
	str := strings.Builder{}
	str.WriteString("Sort: ")
	for i, sortExpr := range s.SortExpressions {
		if i > 0 {
			str.WriteString("; ")
		}

		str.WriteString(sortExpr.String())
	}
	return str.String()
}

func (s *Sort) Accept(v Visitor) any {
	return v.VisitSort(s)
}
func (s *Sort) Children() []Traversable {
	var c []Traversable
	for _, sortExpr := range s.SortExpressions {
		c = append(c, sortExpr.Expr)
	}
	c = append(c, s.Child)

	return c
}

func (s *Sort) Plans() []Plan {
	c := []Plan{s.Child}
	for _, sortExpr := range s.SortExpressions {
		c = append(c, sortExpr.Expr.Plans()...)
	}

	return c
}

func (s *Sort) Relation() *Relation {
	return s.Child.Relation()
}

func (s *Sort) Equal(other Traversable) bool {
	o, ok := other.(*Sort)
	if !ok {
		return false
	}

	if len(s.SortExpressions) != len(o.SortExpressions) {
		return false
	}

	for i, sortExpr := range s.SortExpressions {
		if sortExpr.Ascending != o.SortExpressions[i].Ascending {
			return false
		}

		if sortExpr.NullsLast != o.SortExpressions[i].NullsLast {
			return false
		}

		if !eq(sortExpr.Expr, o.SortExpressions[i].Expr) {
			return false
		}
	}

	return eq(s.Child, o.Child)
}

type Limit struct {
	baseLogicalPlan
	Child  Plan
	Limit  Expression
	Offset Expression
}

func (s *Limit) Accept(v Visitor) any {
	return v.VisitLimit(s)
}
func (l *Limit) Children() []Traversable {
	r := []Traversable{l.Child, l.Limit}
	if l.Offset != nil {
		r = append(r, l.Offset)
	}

	return r
}

func (l *Limit) String() string {
	str := strings.Builder{}
	str.WriteString("Limit")
	if l.Offset != nil {
		str.WriteString(" [offset=")
		str.WriteString(l.Offset.String())
		str.WriteString("]")
	}
	str.WriteString(": ")
	str.WriteString(l.Limit.String())

	return str.String()
}

func (l *Limit) Plans() []Plan {
	c := []Plan{l.Child}
	if l.Limit != nil {
		c = append(c, l.Limit.Plans()...)
	}
	if l.Offset != nil {
		c = append(c, l.Offset.Plans()...)
	}
	return c
}

func (l *Limit) Relation() *Relation {
	return l.Child.Relation()
}

func (l *Limit) Equal(other Traversable) bool {
	o, ok := other.(*Limit)
	if !ok {
		return false
	}

	if l.Limit != nil && !eq(l.Limit, o.Limit) {
		return false
	}

	if l.Offset != nil && !eq(l.Offset, o.Offset) {
		return false
	}

	return eq(l.Child, o.Child)
}

type Distinct struct {
	baseLogicalPlan
	Child Plan
}

func (s *Distinct) Accept(v Visitor) any {
	return v.VisitDistinct(s)
}
func (d *Distinct) Children() []Traversable {
	return []Traversable{d.Child}
}

func (d *Distinct) String() string {
	return "Distinct"
}

func (d *Distinct) Plans() []Plan {
	return []Plan{d.Child}
}

func (d *Distinct) Relation() *Relation {
	return d.Child.Relation()
}

func (d *Distinct) Equal(other Traversable) bool {
	_, ok := other.(*Distinct)
	if !ok {
		return false
	}

	return eq(d.Child, other)
}

type SetOperation struct {
	baseLogicalPlan
	Left   Plan
	Right  Plan
	OpType SetOperationType
}

// SetOperation
func (s *SetOperation) Accept(v Visitor) any {
	return v.VisitSetOperation(s)
}
func (s *SetOperation) Children() []Traversable {
	return []Traversable{s.Left, s.Right}
}

func (s *SetOperation) Plans() []Plan {
	return []Plan{s.Left, s.Right}
}

func (s *SetOperation) String() string {
	str := strings.Builder{}
	str.WriteString("Set: ")
	str.WriteString(s.OpType.String())
	return str.String()
}

func (s *SetOperation) Relation() *Relation {
	// the relation returned from a set operation
	// is the left relation without the parent
	left := s.Left.Relation()

	for _, field := range left.Fields {
		field.Parent = ""
	}

	return left
}

func (s *SetOperation) Equal(other Traversable) bool {
	o, ok := other.(*SetOperation)
	if !ok {
		return false
	}

	return s.OpType == o.OpType && eq(s.Left, o.Left) && eq(s.Right, o.Right)
}

type Aggregate struct {
	baseLogicalPlan
	// GroupingExpressions are the expressions used
	// in the GROUP BY clause.
	GroupingExpressions []Expression
	// AggregateExpressions are the expressions used
	// in the SELECT clause (e.g. SUM(x), COUNT(y)).
	AggregateExpressions []*IdentifiedExpr
	// Child is the input to the aggregation
	// (e.g. a Project node).
	Child Plan
}

func (s *Aggregate) Accept(v Visitor) any {
	return v.VisitAggregate(s)
}
func (a *Aggregate) Children() []Traversable {
	var c []Traversable
	for _, expr := range a.GroupingExpressions {
		c = append(c, expr)
	}
	for _, expr := range a.AggregateExpressions {
		c = append(c, expr)
	}
	c = append(c, a.Child)

	return c
}

func (a *Aggregate) Plans() []Plan {
	c := []Plan{a.Child}
	for _, expr := range a.GroupingExpressions {
		c = append(c, expr.Plans()...)
	}

	for _, expr := range a.AggregateExpressions {
		c = append(c, expr.Plans()...)
	}

	return c
}

func (a *Aggregate) String() string {
	str := strings.Builder{}
	str.WriteString("Aggregate")

	for _, expr := range a.GroupingExpressions {
		str.WriteString(" [")
		str.WriteString(expr.String())
		str.WriteString("]")
	}
	if len(a.AggregateExpressions) == 0 {
		return str.String()
	}

	str.WriteString(": ")

	for i, expr := range a.AggregateExpressions {
		if i > 0 {
			str.WriteString("; ")
		}
		str.WriteString(expr.String())
	}

	return str.String()
}

func (a *Aggregate) Relation() *Relation {
	// we return the grouping expressions and the aggregate expressions
	var fields []*Field
	for _, expr := range a.GroupingExpressions {
		fields = append(fields, expr.Field())
	}

	for _, expr := range a.AggregateExpressions {
		fields = append(fields, expr.Field())
	}

	return &Relation{Fields: fields}
}

func (a *Aggregate) Equal(other Traversable) bool {
	o, ok := other.(*Aggregate)
	if !ok {
		return false
	}

	if len(a.GroupingExpressions) != len(o.GroupingExpressions) {
		return false
	}

	if len(a.AggregateExpressions) != len(o.AggregateExpressions) {
		return false
	}

	for i, expr := range a.GroupingExpressions {
		if !eq(expr, o.GroupingExpressions[i]) {
			return false
		}
	}

	for i, expr := range a.AggregateExpressions {
		if !eq(expr, o.AggregateExpressions[i]) {
			return false
		}
	}

	return eq(a.Child, o.Child)
}

// Window is a logical plan node that represents a window function.
// It applies the window function to the input relation, and returns
// both the input relation and the window function result as a single
// relation.
type Window struct {
	baseLogicalPlan
	// PartitionBy are the expressions used in the PARTITION BY clause.
	PartitionBy []Expression
	// OrderBy are the expressions used in the ORDER BY clause.
	OrderBy []*SortExpression
	// Functions are the window functions that are applied.
	Functions []*IdentifiedExpr
	// Frames are not yet supported, but when they are, they will
	// be added here.
	Child Plan
}

func (s *Window) Accept(v Visitor) any {
	return v.VisitWindow(s)
}

func (w *Window) Children() []Traversable {
	var c []Traversable
	for _, expr := range w.PartitionBy {
		c = append(c, expr)
	}
	for _, expr := range w.OrderBy {
		c = append(c, expr.Expr.Children()...)
	}

	for _, wf := range w.Functions {
		c = append(c, wf.Children()...)
	}

	c = append(c, w.Child)

	return c
}

func (w *Window) Plans() []Plan {
	var c []Plan

	for _, expr := range w.PartitionBy {
		c = append(c, expr.Plans()...)
	}

	for _, expr := range w.OrderBy {
		c = append(c, expr.Expr.Plans()...)
	}

	for _, wf := range w.Functions {
		c = append(c, wf.Plans()...)
	}

	c = append(c, w.Child)

	return c
}

func (w *Window) String() string {
	str := strings.Builder{}
	str.WriteString("Window")

	if len(w.PartitionBy) > 0 {
		str.WriteString(" [partition_by=")
		for i, expr := range w.PartitionBy {
			if i > 0 {
				str.WriteString(", ")
			}
			str.WriteString(expr.String())
		}
		str.WriteString("]")
	}

	if len(w.OrderBy) > 0 {
		str.WriteString(" [order_by=")
		for i, expr := range w.OrderBy {
			if i > 0 {
				str.WriteString(", ")
			}
			str.WriteString(expr.String())
		}
		str.WriteString("]")
	}

	if len(w.Functions) > 0 {
		str.WriteString(": ")
		for i, wf := range w.Functions {
			if i > 0 {
				str.WriteString("; ")
			}
			str.WriteString(wf.String())
		}
	}

	return str.String()
}

func (w *Window) Relation() *Relation {
	// we return the input relation and the window function results
	// as a single relation
	r := w.Child.Relation()
	for _, wf := range w.Functions {
		r.Fields = append(r.Fields, wf.Field())
	}

	return r
}

// WindowFunction references a function being applied in a window.
type WindowFunction struct {
	// Name is the function being applied.
	Name string
	// Args are the arguments to the function.
	Args []Expression
	// Filter is the optional filter condition that can be applied to the function.
	Filter Expression
	// returnType is the return type of the window function.
	returnType *types.DataType
}

func (w *WindowFunction) Field() *Field {
	return &Field{
		Name: w.Name,
		val:  w.returnType.Copy(),
	}
}

func (w *WindowFunction) String() string {
	str := strings.Builder{}
	str.WriteString(w.Name)
	str.WriteString("(")
	for i, arg := range w.Args {
		if i > 0 {
			str.WriteString(", ")
		}
		str.WriteString(arg.String())
	}
	str.WriteString(")")

	if w.Filter != nil {
		str.WriteString(" filter=[")
		str.WriteString(w.Filter.String())
		str.WriteString("]")
	}

	return str.String()
}

func (w *WindowFunction) Children() []Traversable {
	var c []Traversable
	for _, arg := range w.Args {
		c = append(c, arg)
	}

	if w.Filter != nil {
		c = append(c, w.Filter)
	}

	return c
}

func (w *WindowFunction) Plans() []Plan {
	var c []Plan
	for _, arg := range w.Args {
		c = append(c, arg.Plans()...)
	}

	if w.Filter != nil {
		c = append(c, w.Filter.Plans()...)
	}

	return c
}

func (w *WindowFunction) Accept(v Visitor) any {
	return v.VisitWindowFunction(w)
}

type JoinType int

const (
	InnerJoin JoinType = iota
	LeftOuterJoin
	RightOuterJoin
	FullOuterJoin
)

func (j JoinType) String() string {
	switch j {
	case InnerJoin:
		return "inner"
	case LeftOuterJoin:
		return "left"
	case RightOuterJoin:
		return "right"
	case FullOuterJoin:
		return "outer"
	default:
		panic(fmt.Sprintf("unknown join type %d", j))
	}
}

type SetOperationType int

const (
	Union SetOperationType = iota
	UnionAll
	Intersect
	Except
)

func (s SetOperationType) String() string {
	switch s {
	case Union:
		return "union"
	case UnionAll:
		return "union all"
	case Intersect:
		return "intersect"
	case Except:
		return "except"
	default:
		panic(fmt.Sprintf("unknown set operation type %d", s))
	}
}

type Subplan struct {
	baseLogicalPlan
	Plan Plan
	ID   string
	Type SubplanType

	// extraInfo is used to print additional information about the subplan.
	// It shouldn't be used for planning purposes, and should only be used
	// for debugging.
	extraInfo string
}

func (s *Subplan) Accept(v Visitor) any {
	return v.VisitSubplan(s)
}
func (s *Subplan) Children() []Traversable {
	return []Traversable{s.Plan}
}

func (s *Subplan) Plans() []Plan {
	return []Plan{s.Plan}
}

func (s *Subplan) String() string {
	str := strings.Builder{}
	str.WriteString("Subplan [")
	str.WriteString(s.Type.String())
	str.WriteString("] [id=")
	str.WriteString(s.ID)
	str.WriteString("]")
	str.WriteString(s.extraInfo)

	return str.String()
}

func (s *Subplan) Relation() *Relation {
	return s.Plan.Relation()
}

func (s *Subplan) Equal(other Traversable) bool {
	o, ok := other.(*Subplan)
	if !ok {
		return false
	}

	return s.ID == o.ID && s.Type == o.Type && eq(s.Plan, o.Plan)
}

type SubplanType int

const (
	SubplanTypeSubquery SubplanType = iota
	SubplanTypeCTE
	SubplanTypeRecursiveCTE
)

func (s SubplanType) String() string {
	switch s {
	case SubplanTypeSubquery:
		return "subquery"
	case SubplanTypeCTE:
		return "cte"
	case SubplanTypeRecursiveCTE:
		return "recursive cte"
	default:
		panic(fmt.Sprintf("unknown subplan type %d", s))
	}
}

// CartesianProduct is a logical plan node that represents a cartesian product
// between two relations. This is used in joins and set operations.
// Kwil doesn't actually allow cartesian products to be executed, but it is a necessary
// intermediate step for planning complex updates and deletes.
type CartesianProduct struct {
	baseLogicalPlan
	Left  Plan
	Right Plan
}

func (c *CartesianProduct) String() string {
	return "Cartesian Product"
}

func (s *CartesianProduct) Accept(v Visitor) any {
	return v.VisitCartesianProduct(s)
}
func (c *CartesianProduct) Children() []Traversable {
	return []Traversable{c.Left, c.Right}
}

func (c *CartesianProduct) Plans() []Plan {
	return []Plan{c.Left, c.Right}
}

func (c *CartesianProduct) Relation() *Relation {
	// we return the relation of the left side of the cartesian product
	return &Relation{
		Fields: append(c.Left.Relation().Fields, c.Right.Relation().Fields...),
	}
}

func (c *CartesianProduct) Equal(other Traversable) bool {
	o, ok := other.(*CartesianProduct)
	if !ok {
		return false
	}

	return eq(c.Left, o.Left) && eq(c.Right, o.Right)
}

/*
	###########################
	#                         #
	#   	Expressions		  #
	#                         #
	###########################
*/

type Expression interface {
	LogicalNode
	Field() *Field
}

// Literal value
type Literal struct {
	Value interface{}
	Type  *types.DataType
}

func (l *Literal) String() string {
	switch c := l.Value.(type) {
	case string:
		return "'" + c + "'"
	case []byte:
		return "0x" + hex.EncodeToString(c)
	case nil:
		return "NULL"
	case fmt.Stringer:
		return c.String()
	default:
		return fmt.Sprintf("%v", l.Value)
	}
}

func (s *Literal) Accept(v Visitor) any {
	return v.VisitLiteral(s)
}
func (l *Literal) Children() []Traversable {
	return nil
}

func (l *Literal) Plans() []Plan {
	return nil
}

func (l *Literal) Field() *Field {
	return anonField(l.Type.Copy())
}

func (l *Literal) Equal(other Traversable) bool {
	o, ok := other.(*Literal)
	if !ok {
		return false
	}

	if !l.Type.EqualsStrict(o.Type) {
		return false
	}

	typeOf := reflect.TypeOf(l.Value)
	typeOfOther := reflect.TypeOf(o.Value)

	if typeOf.Kind() != typeOfOther.Kind() {
		return false
	}

	if typeOf.Kind() == reflect.Ptr {
		return reflect.ValueOf(l.Value).Pointer() == reflect.ValueOf(o.Value).Pointer()
	}

	return l.Value == o.Value
}

// Variable reference
type Variable struct {
	// name is something like $id, @caller, etc.
	VarName string
	// dataType is the data type, which is detected
	// during the evaluation phase.
	// it is either a *types.DataType or map[string]*types.DataType
	dataType any
}

func (v *Variable) String() string {
	return v.VarName
}

func (s *Variable) Accept(v Visitor) any {
	return v.VisitVariable(s)
}
func (v *Variable) Children() []Traversable {
	return nil
}

func (v *Variable) Plans() []Plan {
	return nil
}

func (v *Variable) Field() *Field {
	return &Field{
		val: v.dataType,
	}
}

func (v *Variable) Equal(other Traversable) bool {
	o, ok := other.(*Variable)
	if !ok {
		return false
	}

	return v.VarName == o.VarName
}

// Column reference
type ColumnRef struct {
	// Parent relation name, can be empty.
	// If not specified by user, it will be qualified
	// during the planning phase.
	Parent     string
	ColumnName string
	// dataType is the data type, which is detected
	// during the evaluation phase.
	dataType *types.DataType
}

func (c *ColumnRef) String() string {
	if c.Parent != "" {
		return fmt.Sprintf(`%s.%s`, c.Parent, c.ColumnName)
	}
	return c.ColumnName
}

func (s *ColumnRef) Accept(v Visitor) any {
	return v.VisitColumnRef(s)
}
func (c *ColumnRef) Children() []Traversable {
	return nil
}

func (c *ColumnRef) Plans() []Plan {
	return nil
}

func (c *ColumnRef) Field() *Field {
	return &Field{
		Parent: c.Parent,
		Name:   c.ColumnName,
		val:    c.dataType,
	}
}

func (c *ColumnRef) Equal(other Traversable) bool {
	o, ok := other.(*ColumnRef)
	if !ok {
		return false
	}

	return c.Parent == o.Parent && c.ColumnName == o.ColumnName
}

type AggregateFunctionCall struct {
	FunctionName string
	Args         []Expression
	Star         bool
	Distinct     bool
	// returnType is the data type of the return value.
	// It is set during the evaluation phase.
	returnType *types.DataType
}

func (a *AggregateFunctionCall) String() string {
	var buf bytes.Buffer

	buf.WriteString(a.FunctionName)
	buf.WriteString("(")
	if a.Star {
		buf.WriteString("*")
	} else {
		for i, arg := range a.Args {
			if i > 0 {
				buf.WriteString(", ")
			} else if a.Distinct {
				buf.WriteString("distinct ")
			}
			buf.WriteString(arg.String())
		}
	}
	buf.WriteString(")")
	return buf.String()
}

func (s *AggregateFunctionCall) Accept(v Visitor) any {
	return v.VisitAggregateFunctionCall(s)
}
func (a *AggregateFunctionCall) Children() []Traversable {
	var c []Traversable
	for _, arg := range a.Args {
		c = append(c, arg)
	}
	return c
}

func (a *AggregateFunctionCall) Plans() []Plan {
	var c []Plan
	for _, arg := range a.Args {
		c = append(c, arg.Plans()...)
	}
	return c
}

func (a *AggregateFunctionCall) Field() *Field {
	return &Field{
		Name: a.FunctionName,
		val:  a.returnType.Copy(),
	}
}

func (a *AggregateFunctionCall) Equal(other Traversable) bool {
	o, ok := other.(*AggregateFunctionCall)
	if !ok {
		return false
	}

	if a.FunctionName != o.FunctionName {
		return false
	}

	if a.Star != o.Star {
		return false
	}

	if a.Distinct != o.Distinct {
		return false
	}

	if len(a.Args) != len(o.Args) {
		return false
	}

	for i, arg := range a.Args {
		if !eq(arg, o.Args[i]) {
			return false
		}
	}

	return true
}

// Function call
type ScalarFunctionCall struct {
	FunctionName string
	Args         []Expression
	// returnType is the data type of the return value.
	// It is set during the evaluation phase.
	returnType *types.DataType
}

func (f *ScalarFunctionCall) String() string {
	var buf bytes.Buffer
	buf.WriteString(f.FunctionName)
	buf.WriteString("(")
	for i, arg := range f.Args {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(arg.String())
	}
	buf.WriteString(")")
	return buf.String()
}

func (s *ScalarFunctionCall) Accept(v Visitor) any {
	return v.VisitScalarFunctionCall(s)
}
func (f *ScalarFunctionCall) Children() []Traversable {
	var c []Traversable
	for _, arg := range f.Args {
		c = append(c, arg)
	}
	return c
}

func (f *ScalarFunctionCall) Plans() []Plan {
	var c []Plan
	for _, arg := range f.Args {
		c = append(c, arg.Plans()...)
	}
	return c
}

func (f *ScalarFunctionCall) Field() *Field {
	return &Field{
		Name: f.FunctionName,
		val:  f.returnType.Copy(),
	}
}

func (f *ScalarFunctionCall) Equal(other Traversable) bool {
	o, ok := other.(*ScalarFunctionCall)
	if !ok {
		return false
	}

	if f.FunctionName != o.FunctionName {
		return false
	}

	if len(f.Args) != len(o.Args) {
		return false
	}

	for i, arg := range f.Args {
		if !eq(arg, o.Args[i]) {
			return false
		}
	}

	return true
}

type ArithmeticOp struct {
	Left  Expression
	Right Expression
	Op    ArithmeticOperator
}

type ArithmeticOperator uint8

const (
	Add ArithmeticOperator = iota
	Subtract
	Multiply
	Divide
	Modulo
	Concat
)

func (a *ArithmeticOp) String() string {
	var op string
	switch a.Op {
	case Add:
		op = "+"
	case Subtract:
		op = "-"
	case Multiply:
		op = "*"
	case Divide:
		op = "/"
	case Modulo:
		op = "%"
	case Concat:
		op = "||"
	}

	return fmt.Sprintf("%s %s %s", a.Left.String(), op, a.Right.String())
}

func (s *ArithmeticOp) Accept(v Visitor) any {
	return v.VisitArithmeticOp(s)
}
func (a *ArithmeticOp) Children() []Traversable {
	return []Traversable{a.Left, a.Right}
}

func (a *ArithmeticOp) Plans() []Plan {
	return append(a.Left.Plans(), a.Right.Plans()...)
}

func (a *ArithmeticOp) Field() *Field {
	scalar, err := a.Left.Field().Scalar()
	if err != nil {
		panic(err)
	}

	return anonField(scalar.Copy())
}

func (a *ArithmeticOp) Equal(other Traversable) bool {
	o, ok := other.(*ArithmeticOp)
	if !ok {
		return false
	}

	return a.Op == o.Op && eq(a.Left, o.Left) && eq(a.Right, o.Right)
}

type ComparisonOp struct {
	Left  Expression
	Right Expression
	Op    ComparisonOperator
}

type ComparisonOperator uint8

const (
	// operators can have 3 types of classifications:
	// - sargable
	// - not sargable
	// - rarely sarable
	// https://en.wikipedia.org/wiki/Sargable
	// for the purposes of our planner, we will treat rarely
	// sargable as not sargable
	Equal       ComparisonOperator = iota // sargable
	LessThan                              // sargable
	GreaterThan                           // sargable
	// IS and IS NOT are rarely sargable because they can only be used
	// with NULL values or BOOLEAN values
	Is             // rarely sargable
	IsDistinctFrom // not sargable
	Like           // not sargable
	ILike          // not sargable
)

func (c ComparisonOperator) String() string {
	switch c {
	case Equal:
		return "="
	case LessThan:
		return "<"
	case GreaterThan:
		return ">"
	case Is:
		return "IS"
	case IsDistinctFrom:
		return "IS DISTINCT FROM"
	case Like:
		return "LIKE"
	case ILike:
		return "ILIKE"
	default:
		panic(fmt.Sprintf("unknown comparison operator %d", c))
	}
}

func (s *ComparisonOp) Accept(v Visitor) any {
	return v.VisitComparisonOp(s)
}
func (c *ComparisonOp) Children() []Traversable {
	return []Traversable{c.Left, c.Right}
}

func (c *ComparisonOp) Plans() []Plan {
	return append(c.Left.Plans(), c.Right.Plans()...)
}

func (c *ComparisonOp) String() string {
	return fmt.Sprintf("%s %s %s", c.Left.String(), c.Op.String(), c.Right.String())
}

func (c *ComparisonOp) Field() *Field {
	return anonField(types.BoolType.Copy())
}

func (c *ComparisonOp) Equal(other Traversable) bool {
	o, ok := other.(*ComparisonOp)
	if !ok {
		return false
	}

	return c.Op == o.Op && eq(c.Left, o.Left) && eq(c.Right, o.Right)
}

type LogicalOp struct {
	Left  Expression
	Right Expression
	Op    LogicalOperator
}

type LogicalOperator uint8

const (
	And LogicalOperator = iota
	Or
)

func (l *LogicalOp) String() string {
	var op string
	switch l.Op {
	case And:
		op = "AND"
	case Or:
		op = "OR"
	}

	return fmt.Sprintf("%s %s %s", l.Left.String(), op, l.Right.String())
}

func (s *LogicalOp) Accept(v Visitor) any {
	return v.VisitLogicalOp(s)
}
func (l *LogicalOp) Children() []Traversable {
	return []Traversable{l.Left, l.Right}
}

func (l *LogicalOp) Plans() []Plan {
	return append(l.Left.Plans(), l.Right.Plans()...)
}

func (l *LogicalOp) Field() *Field {
	return anonField(types.BoolType.Copy())
}

func (l *LogicalOp) Equal(other Traversable) bool {
	o, ok := other.(*LogicalOp)
	if !ok {
		return false
	}

	return l.Op == o.Op && eq(l.Left, o.Left) && eq(l.Right, o.Right)
}

type UnaryOp struct {
	Expr Expression
	Op   UnaryOperator
}

type UnaryOperator uint8

const (
	Negate UnaryOperator = iota
	Not
	Positive
)

func (u UnaryOperator) String() string {
	switch u {
	case Negate:
		return "-"
	case Not:
		return "NOT "
	case Positive:
		return "+"
	default:
		panic(fmt.Sprintf("unknown unary operator %d", u))
	}
}

func (u UnaryOp) String() string {
	return fmt.Sprintf("%s%s", u.Op.String(), u.Expr.String())
}

func (s *UnaryOp) Accept(v Visitor) any {
	return v.VisitUnaryOp(s)
}
func (u *UnaryOp) Children() []Traversable {
	return []Traversable{u.Expr}
}

func (u *UnaryOp) Plans() []Plan {
	return u.Expr.Plans()
}

func (u *UnaryOp) Field() *Field {
	return u.Expr.Field()
}

func (u *UnaryOp) Equal(other Traversable) bool {
	o, ok := other.(*UnaryOp)
	if !ok {
		return false
	}

	return u.Op == o.Op && eq(u.Expr, o.Expr)
}

type TypeCast struct {
	Expr Expression
	Type *types.DataType
}

func (t *TypeCast) String() string {
	return fmt.Sprintf("%s::%s", t.Expr.String(), t.Type.Name)
}

func (s *TypeCast) Accept(v Visitor) any {
	return v.VisitTypeCast(s)
}
func (t *TypeCast) Children() []Traversable {
	return []Traversable{t.Expr}
}

func (t *TypeCast) Plans() []Plan {
	return t.Expr.Plans()
}

func (t *TypeCast) Field() *Field {
	return anonField(t.Type.Copy())
}

func (t *TypeCast) Equal(other Traversable) bool {
	o, ok := other.(*TypeCast)
	if !ok {
		return false
	}

	return t.Type.EqualsStrict(o.Type) && eq(t.Expr, o.Expr)
}

type AliasExpr struct {
	Expr  Expression
	Alias string
}

func (a *AliasExpr) String() string {
	return fmt.Sprintf("%s AS %s", a.Expr.String(), a.Alias)
}

func (s *AliasExpr) Accept(v Visitor) any {
	return v.VisitAliasExpr(s)
}
func (a *AliasExpr) Children() []Traversable {
	return []Traversable{a.Expr}
}

func (a *AliasExpr) Plans() []Plan {
	return a.Expr.Plans()
}

func (a *AliasExpr) Field() *Field {
	f := a.Expr.Field()
	f.Name = a.Alias
	return f
}

func (a *AliasExpr) Equal(other Traversable) bool {
	o, ok := other.(*AliasExpr)
	if !ok {
		return false
	}

	return a.Alias == o.Alias && eq(a.Expr, o.Expr)
}

type ArrayAccess struct {
	Array Expression
	Index Expression
}

func (a *ArrayAccess) String() string {
	return fmt.Sprintf("%s[%s]", a.Array.String(), a.Index.String())
}

func (s *ArrayAccess) Accept(v Visitor) any {
	return v.VisitArrayAccess(s)
}
func (a *ArrayAccess) Children() []Traversable {
	return []Traversable{a.Array, a.Index}
}

func (a *ArrayAccess) Plans() []Plan {
	return append(a.Array.Plans(), a.Index.Plans()...)
}

func (a *ArrayAccess) Field() *Field {
	scalar, err := a.Array.Field().Scalar()
	if err != nil {
		panic(err)
	}

	scalar.IsArray = false
	return anonField(scalar.Copy())
}

func (a *ArrayAccess) Equal(other Traversable) bool {
	o, ok := other.(*ArrayAccess)
	if !ok {
		return false
	}

	return eq(a.Array, o.Array) && eq(a.Index, o.Index)
}

type ArrayConstructor struct {
	Elements []Expression
}

func (a *ArrayConstructor) String() string {
	var buf bytes.Buffer
	buf.WriteString("[")
	for i, elem := range a.Elements {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(elem.String())
	}
	buf.WriteString("]")
	return buf.String()
}

func (s *ArrayConstructor) Accept(v Visitor) any {
	return v.VisitArrayConstructor(s)
}
func (a *ArrayConstructor) Children() []Traversable {
	var c []Traversable
	for _, elem := range a.Elements {
		c = append(c, elem)
	}
	return c
}

func (a *ArrayConstructor) Plans() []Plan {
	var c []Plan
	for _, elem := range a.Elements {
		c = append(c, elem.Plans()...)
	}
	return c
}

func (a *ArrayConstructor) Field() *Field {
	if len(a.Elements) == 0 {
		// should get caught several times before this point
		panic("empty array constructor")
	}

	scalar, err := a.Elements[0].Field().Scalar()
	if err != nil {
		panic(err)
	}

	scalar.IsArray = true
	return anonField(scalar.Copy())
}

func (a *ArrayConstructor) Equal(other Traversable) bool {
	o, ok := other.(*ArrayConstructor)
	if !ok {
		return false
	}

	if len(a.Elements) != len(o.Elements) {
		return false
	}

	for i, elem := range a.Elements {
		if !eq(elem, o.Elements[i]) {
			return false
		}
	}

	return true
}

type FieldAccess struct {
	Object Expression
	Key    string
}

func (f *FieldAccess) String() string {
	return fmt.Sprintf("%s.%s", f.Object.String(), f.Key)
}

func (s *FieldAccess) Accept(v Visitor) any {
	return v.VisitFieldAccess(s)
}
func (f *FieldAccess) Children() []Traversable {
	return []Traversable{f.Object}
}

func (f *FieldAccess) Plans() []Plan {
	return f.Object.Plans()
}

func (f *FieldAccess) Field() *Field {
	scalar, err := f.Object.Field().Object()
	if err != nil {
		panic(err)
	}

	val, ok := scalar[f.Key]
	if !ok {
		panic(fmt.Sprintf("field %s not found in object", f.Key))
	}

	return anonField(val.Copy())
}

func (f *FieldAccess) Equal(other Traversable) bool {
	o, ok := other.(*FieldAccess)
	if !ok {
		return false
	}

	return f.Key == o.Key && eq(f.Object, o.Object)
}

type SubqueryExpr struct {
	Query *Subquery
	// If Exists is true, we are checking if the subquery returns any rows.
	// Otherwise, the subquery will return a single value.
	// If the query is a NOT EXISTS, a unary negation will wrap this expression.
	Exists bool
}

var _ Expression = (*SubqueryExpr)(nil)

func (s *SubqueryExpr) String() string {
	str := strings.Builder{}
	str.WriteString("[subquery (")

	if s.Exists {
		str.WriteString("exists")
	} else {
		str.WriteString("scalar")
	}

	str.WriteString(") (subplan_id=")
	str.WriteString(s.Query.Plan.ID)
	str.WriteString(") ")

	if len(s.Query.Correlated) == 0 {
		str.WriteString("(uncorrelated)")
	} else {
		str.WriteString("(correlated: ")

		for i, field := range s.Query.Correlated {
			if i > 0 {
				str.WriteString(", ")
			}
			if field.Parent != "" {
				str.WriteString(field.Parent)
				str.WriteString(".")
			}

			str.WriteString(field.Name)
		}
		str.WriteString(")")
	}

	str.WriteString("]")

	return str.String()
}

func (s *SubqueryExpr) Accept(v Visitor) any {
	return v.VisitSubqueryExpr(s)
}
func (s *SubqueryExpr) Children() []Traversable {
	return []Traversable{s.Query.Plan}
}

func (s *SubqueryExpr) Plans() []Plan {
	return s.Query.Plans()
}

func (s *SubqueryExpr) Field() *Field {
	if s.Exists {
		return anonField(types.BoolType.Copy())
	}

	return s.Query.Plan.Relation().Fields[0]
}

func (s *SubqueryExpr) Equal(other Traversable) bool {
	o, ok := other.(*SubqueryExpr)
	if !ok {
		return false
	}

	return s.Query.Plan.ID == o.Query.Plan.ID && s.Exists == o.Exists
}

type Collate struct {
	Expr      Expression
	Collation CollationType
}

func (c *Collate) String() string {
	return fmt.Sprintf("%s COLLATE %s", c.Expr.String(), c.Collation.String())
}

func (s *Collate) Accept(v Visitor) any {
	return v.VisitCollate(s)
}
func (c *Collate) Children() []Traversable {
	return []Traversable{c.Expr}
}

func (c *Collate) Plans() []Plan {
	return c.Expr.Plans()
}

func (c *Collate) Field() *Field {
	return c.Expr.Field()
}

func (c *Collate) Equal(other Traversable) bool {
	o, ok := other.(*Collate)
	if !ok {
		return false
	}

	return c.Collation == o.Collation && eq(c.Expr, o.Expr)
}

type CollationType uint8

const (
	// NoCaseCollation is a collation that is case-insensitive.
	NoCaseCollation CollationType = iota
)

func (c CollationType) String() string {
	switch c {
	case NoCaseCollation:
		return "nocase"
	default:
		panic(fmt.Sprintf("unknown collation type %d", c))
	}
}

type IsIn struct {
	// Left is the expression that is being compared.
	Left Expression

	// IsIn can have either a list of expressions or a subquery.
	// Either Expressions or Subquery will be set, but not both.

	Expressions []Expression
	Subquery    *SubqueryExpr
}

func (i *IsIn) String() string {
	str := strings.Builder{}
	str.WriteString(i.Left.String())

	str.WriteString(" IN (")
	if i.Expressions != nil {
		for j, expr := range i.Expressions {
			if j > 0 {
				str.WriteString(", ")
			}
			str.WriteString(expr.String())
		}
	} else {
		str.WriteString(i.Subquery.String())
	}
	str.WriteString(")")

	return str.String()
}

func (s *IsIn) Accept(v Visitor) any {
	return v.VisitIsIn(s)
}
func (i *IsIn) Children() []Traversable {
	var c []Traversable
	c = append(c, i.Left)
	if i.Subquery != nil {
		c = append(c, i.Subquery)
	} else {
		for _, expr := range i.Expressions {
			c = append(c, expr)
		}
	}

	return c
}

func (i *IsIn) Plans() []Plan {
	c := i.Left.Plans()
	if i.Expressions != nil {
		for _, expr := range i.Expressions {
			c = append(c, expr.Plans()...)
		}
	} else {
		c = append(c, i.Subquery.Plans()...)
	}
	return c
}

func (i *IsIn) Field() *Field {
	return anonField(types.BoolType.Copy())
}

func (i *IsIn) Equal(other Traversable) bool {
	o, ok := other.(*IsIn)
	if !ok {
		return false
	}

	if !eq(i.Left, o.Left) {
		return false
	}

	if len(i.Expressions) != len(o.Expressions) {
		return false
	}

	for j, expr := range i.Expressions {
		if !eq(expr, o.Expressions[j]) {
			return false
		}
	}

	if i.Subquery != nil {
		if o.Subquery == nil {
			return false
		}
		return i.Subquery.Equal(o.Subquery)
	}

	return o.Subquery == nil
}

type Case struct {
	// Value is the value that is being compared.
	// Can be nil if there is no value to compare.
	Value Expression
	// WhenClauses are the list of when/then pairs.
	// The first element of each pair is the condition,
	// which must match the data type of Value. If Value
	// is nil, the condition must be a boolean.
	WhenClauses [][2]Expression
	// Else is the else clause. Can be nil.
	Else Expression
}

func (c *Case) String() string {
	str := strings.Builder{}
	str.WriteString("CASE")
	if c.Value != nil {
		str.WriteString(" [")
		str.WriteString(c.Value.String())
		str.WriteString("]")
	}
	for _, when := range c.WhenClauses {
		str.WriteString(" WHEN [")
		str.WriteString(when[0].String())
		str.WriteString("] THEN [")
		str.WriteString(when[1].String())
		str.WriteString("]")
	}
	if c.Else != nil {
		str.WriteString(" ELSE [")
		str.WriteString(c.Else.String())
		str.WriteString("]")
	}
	str.WriteString(" END")
	return str.String()
}

func (s *Case) Accept(v Visitor) any {
	return v.VisitCase(s)
}
func (c *Case) Children() []Traversable {
	var ch []Traversable
	if c.Value != nil {
		ch = append(ch, c.Value)
	}
	for _, when := range c.WhenClauses {
		ch = append(ch, when[0], when[1])
	}
	if c.Else != nil {
		ch = append(ch, c.Else)
	}
	return ch
}

func (c *Case) Plans() []Plan {
	var ch []Plan
	if c.Value != nil {
		ch = append(ch, c.Value.Plans()...)
	}
	for _, when := range c.WhenClauses {
		ch = append(ch, when[0].Plans()...)
		ch = append(ch, when[1].Plans()...)
	}
	if c.Else != nil {
		ch = append(ch, c.Else.Plans()...)
	}
	return ch
}

func (c *Case) Field() *Field {
	if c.Else != nil {
		return c.Else.Field()
	}

	if len(c.WhenClauses) == 0 {
		// should get caught before this point
		panic("case statement must have at least one when clause")
	}

	return c.WhenClauses[0][1].Field()
}

func (c *Case) Equal(other Traversable) bool {
	o, ok := other.(*Case)
	if !ok {
		return false
	}

	if c.Value != nil && o.Value != nil {
		if !eq(c.Value, o.Value) {
			return false
		}
	} else if c.Value != nil || o.Value != nil {
		return false
	}

	if len(c.WhenClauses) != len(o.WhenClauses) {
		return false
	}

	for i, when := range c.WhenClauses {
		if !eq(when[0], o.WhenClauses[i][0]) {
			return false
		}
		if !eq(when[1], o.WhenClauses[i][1]) {
			return false
		}
	}

	if c.Else != nil && o.Else != nil {
		return eq(c.Else, o.Else)
	}

	return c.Else == nil && o.Else == nil
}

// ExprRef is a reference to an expression in the query.
// It is used when a part of the query is referenced in another.
// For example, SELECT SUM(a) FROM table1 GROUP BY a HAVING SUM(a) > 10,
// both SUM(a) expressions are the same, and will reference the same ExprRef
// (which would actually occur in the Aggregate node).
type ExprRef struct {
	// Identified is the expression that is being referenced.
	// It is a pointer to the actual expression.
	Identified *IdentifiedExpr
}

func (e *ExprRef) String() string {
	return fmt.Sprintf(`{%s}`, formatRef(e.Identified.ID))
}

func formatRef(id string) string {
	return fmt.Sprintf(`#ref(%s)`, id)
}

func (e *ExprRef) Field() *Field {
	return e.Identified.Field()
}

func (s *ExprRef) Accept(v Visitor) any {
	return v.VisitExprRef(s)
}
func (e *ExprRef) Children() []Traversable {
	return []Traversable{e.Identified}
}

func (e *ExprRef) Plans() []Plan {
	return e.Identified.Plans()
}

func (e *ExprRef) Equal(other Traversable) bool {
	o, ok := other.(*ExprRef)
	if !ok {
		return false
	}

	return e.Identified.Equal(o.Identified)
}

// IdentifiedExpr is an expression that can be referenced.
type IdentifiedExpr struct {
	// ID is the unique identifier for the expression.
	ID string
	// Expr is the expression that is being identified.
	Expr Expression
}

func (i *IdentifiedExpr) String() string {
	return fmt.Sprintf(`{%s = %s}`, formatRef(i.ID), i.Expr.String())
}

func (i *IdentifiedExpr) Field() *Field {
	return i.Expr.Field()
}

func (s *IdentifiedExpr) Accept(v Visitor) any {
	return v.VisitIdentifiedExpr(s)
}
func (i *IdentifiedExpr) Children() []Traversable {
	return []Traversable{i.Expr}
}

func (i *IdentifiedExpr) Plans() []Plan {
	return i.Expr.Plans()
}

func (i *IdentifiedExpr) Equal(other Traversable) bool {
	o, ok := other.(*IdentifiedExpr)
	if !ok {
		return false
	}

	return i.ID == o.ID && eq(i.Expr, o.Expr)
}

/*
	###########################
	#                         #
	#      Top Level Ops      #
	#                         #
	###########################
*/

// TopLevelPlan is a logical plan that is at the top level of a query.
type TopLevelPlan interface {
	Plan
	topLevel()
}

type baseTopLevel struct {
	baseLogicalPlan
}

func (b *baseTopLevel) topLevel() {}

// Return is a node that plans a return operation. It specifies columns to
// return from a query. This is similar to a projection, however it cannot
// be optimized using pushdowns, since it is at the top level (and therefore
// user requested).
type Return struct {
	baseTopLevel
	// Fields are the fields to return.
	Fields []*Field
	// Child is the input to the return.
	Child Plan
}

func (r *Return) String() string {
	str := strings.Builder{}
	str.WriteString("Return: ")

	for i, expr := range r.Fields {
		if i > 0 {
			str.WriteString(", ")
		}
		str.WriteString(expr.ResultString())
	}

	return str.String()
}

func (s *Return) Accept(v Visitor) any {
	return v.VisitReturn(s)
}
func (r *Return) Children() []Traversable {
	return []Traversable{r.Child}
}

func (r *Return) Plans() []Plan {
	return []Plan{r.Child}
}

// Relation returns the relation of the child.
func (r *Return) Relation() *Relation {
	return r.Child.Relation()
}

func (r *Return) Equal(t Traversable) bool {
	o, ok := t.(*Return)
	if !ok {
		return false
	}

	if len(r.Fields) != len(o.Fields) {
		return false
	}

	for i, field := range r.Fields {
		if field != o.Fields[i] {
			return false
		}
	}

	return eq(r.Child, o.Child)
}

/*
	For modifying relations, we will use the following process:
	1. Materialize the source relation (exactly same as any SELECT).
	This is all relations specified in FROM and JOIN in UPDATE and DELETE.
	2. Produce a cartesian product of the target relation and the source relation.
	We will use the ModifiableProduct node to represent this, since we want to keep
	this logically separate from joins so that we can know which side of the join
	can be modified.
	3. Apply the filter to the cartesian product / ModifiableProduct.
*/

// Update is a node that plans an update operation.
type Update struct {
	baseTopLevel
	// Child is the input to the update.
	Child Plan
	// Table is the target table name.
	// It will always be the table name and not an alias.
	Table string
	// Assignments are the assignments to update.
	Assignments []*Assignment
}

func (u *Update) String() string {
	str := strings.Builder{}
	str.WriteString("Update [")
	str.WriteString(u.Table)
	str.WriteString("]: ")

	for i, assign := range u.Assignments {
		if i > 0 {
			str.WriteString("; ")
		}
		str.WriteString(assign.Column)
		str.WriteString(" = ")
		str.WriteString(assign.Value.String())
	}

	return str.String()
}

func (s *Update) Accept(v Visitor) any {
	return v.VisitUpdate(s)
}
func (u *Update) Children() []Traversable {
	var c []Traversable
	for _, assign := range u.Assignments {
		c = append(c, assign.Value)
	}
	c = append(c, u.Child)
	return c
}

func (u *Update) Plans() []Plan {
	var c []Plan
	for _, assign := range u.Assignments {
		c = append(c, assign.Value.Plans()...)
	}
	c = append(c, u.Child)
	return c
}

func (u *Update) Relation() *Relation {
	return &Relation{}
}

func (u *Update) Equal(t Traversable) bool {
	o, ok := t.(*Update)
	if !ok {
		return false
	}

	if u.Table != o.Table {
		return false
	}

	if len(u.Assignments) != len(o.Assignments) {
		return false
	}

	for i, assign := range u.Assignments {
		if assign.Column != o.Assignments[i].Column {
			return false
		}

		if !eq(assign.Value, o.Assignments[i].Value) {
			return false
		}
	}

	return eq(u.Child, o.Child)
}

// Delete is a node that plans a delete operation.
type Delete struct {
	baseTopLevel
	// Child is the input to the delete.
	Child Plan
	// Table is the target table name.
	// It will always be the table name and not an alias.
	Table string
}

func (d *Delete) String() string {
	return fmt.Sprintf("Delete [%s]", d.Table)
}

func (s *Delete) Accept(v Visitor) any {
	return v.VisitDelete(s)
}
func (d *Delete) Children() []Traversable {
	return []Traversable{d.Child}
}

func (d *Delete) Plans() []Plan {
	return []Plan{d.Child}
}

func (d *Delete) Relation() *Relation {
	return &Relation{}
}

func (d *Delete) Equal(t Traversable) bool {
	o, ok := t.(*Delete)
	if !ok {
		return false
	}

	if d.Table != o.Table {
		return false
	}

	return eq(d.Child, o.Child)
}

// Insert is a node that plans an insert operation.
type Insert struct {
	baseTopLevel
	// Table is the physical table to insert into.
	Table string
	// ReferencedAs is how the table is referenced in the query.
	// It is either a user-defined reference or the table name.
	ReferencedAs string
	// Columns are the columns to insert into.
	Columns []*Field
	// InsertionValues are the values to insert.
	// These can be either values specified using VALUES or a subquery.
	InsertionValues Plan
	// ConflictResolution is the conflict resolution to use if there is a conflict.
	ConflictResolution ConflictResolution
}

func (i *Insert) String() string {
	str := strings.Builder{}
	str.WriteString("Insert [")
	str.WriteString(i.Table)
	str.WriteString("]")
	if i.ReferencedAs != "" && i.ReferencedAs != i.Table {
		str.WriteString(" [alias=")
		str.WriteString(i.ReferencedAs)
		str.WriteString("]")
	}
	str.WriteString(": ")

	for i, col := range i.Columns {
		if i > 0 {
			str.WriteString(", ")
		}
		str.WriteString(col.ResultString())
	}

	return str.String()
}

func (s *Insert) Accept(v Visitor) any {
	return v.VisitInsert(s)
}
func (i *Insert) Children() []Traversable {
	c := i.InsertionValues.Children()

	if i.ConflictResolution != nil {
		c = append(c, i.ConflictResolution)
	}

	return c
}

func (i *Insert) Plans() []Plan {
	c := []Plan{i.InsertionValues}

	if i.ConflictResolution != nil {
		c = append(c, i.ConflictResolution)
	}

	return c
}

func (i *Insert) Relation() *Relation {
	return &Relation{}
}

func (i *Insert) Equal(t Traversable) bool {
	o, ok := t.(*Insert)
	if !ok {
		return false
	}

	if i.Table != o.Table || i.ReferencedAs != o.ReferencedAs {
		return false
	}

	if !eq(i.InsertionValues, o.InsertionValues) {
		return false
	}

	if i.ConflictResolution == nil && o.ConflictResolution == nil {
		return true
	}

	if i.ConflictResolution == nil || o.ConflictResolution == nil {
		return false
	}

	return eq(i.ConflictResolution, o.ConflictResolution)
}

// Tuples is a list tuple being inserted into a table.
type Tuples struct {
	baseLogicalPlan
	Values [][]Expression
	rel    *Relation
}

func (t *Tuples) Equal(other Traversable) bool {
	o, ok := other.(*Tuples)
	if !ok {
		return false
	}

	if len(t.Values) != len(o.Values) {
		return false
	}

	for i, val := range t.Values {
		if len(val) != len(o.Values[i]) {
			return false
		}

		for j, v := range val {
			if !eq(v, o.Values[i][j]) {
				return false
			}
		}
	}

	return true
}

func (t *Tuples) String() string {
	str := strings.Builder{}
	str.WriteString("Values: ")

	for i, val := range t.Values {
		if i > 0 {
			str.WriteString("; ")
		}

		str.WriteString("(")
		for j, v := range val {
			if j > 0 {
				str.WriteString(", ")
			}
			str.WriteString(v.String())
		}
		str.WriteString(")")
	}

	return str.String()
}

func (s *Tuples) Accept(v Visitor) any {
	return v.VisitTuples(s)
}

func (t *Tuples) Children() []Traversable {
	var c []Traversable
	for _, val := range t.Values {
		for _, v := range val {
			c = append(c, v)
		}
	}
	return c
}

func (t *Tuples) Plans() []Plan {
	var c []Plan
	for _, val := range t.Values {
		for _, v := range val {
			c = append(c, v.Plans()...)
		}
	}
	return c
}

func (t *Tuples) Relation() *Relation {
	return t.rel.Copy()
}

// Assignment is a struct that represents an assignment in an update statement.
type Assignment struct {
	// Column is the column to update.
	Column string
	// Value is the value to update the column to.
	Value Expression
}

type ConflictResolution interface {
	Plan
	conflictResolution()
}

// ConflictDoNothing is a struct that represents the resolution of a conflict
// using DO NOTHING.
type ConflictDoNothing struct {
	baseLogicalPlan
	// ArbiterIndex is the index to use to determine if there is a conflict.
	// If/when Kwil supports partial indexes, we will turn this into a list
	// of indexes. Can be nil when DO NOTHING is used.
	ArbiterIndex Index
}

func (c *ConflictDoNothing) conflictResolution() {}

func (c *ConflictDoNothing) Equal(other Traversable) bool {
	o, ok := other.(*ConflictDoNothing)
	if !ok {
		return false
	}

	return c.ArbiterIndex.Equal(o.ArbiterIndex)
}

func (c *ConflictDoNothing) String() string {
	str := "Conflict [nothing]"
	if c.ArbiterIndex != nil {
		str += " [arbiter=" + c.ArbiterIndex.String() + "]"
	}
	return str
}

func (s *ConflictDoNothing) Accept(v Visitor) any {
	return v.VisitConflictDoNothing(s)
}

func (c *ConflictDoNothing) Children() []Traversable {
	return nil
}

func (c *ConflictDoNothing) Plans() []Plan {
	return nil
}

func (c *ConflictDoNothing) Relation() *Relation {
	return &Relation{}
}

// ConflictUpdate is a struct that represents the resolution of a conflict
// using DO UPDATE SET.
type ConflictUpdate struct {
	baseLogicalPlan
	// ArbiterIndex is the index to use to determine if there is a conflict.
	// If/when Kwil supports partial indexes, we will turn this into a list
	// of indexes. See: https://github.com/cockroachdb/cockroach/issues/53170
	// Cannot be nil when DO UPDATE is used.
	ArbiterIndex Index
	// Assignments are the expressions to update if there is a conflict.
	// Cannot be nil.
	Assignments []*Assignment
	// ConflictFilter is a predicate that allows us to selectively
	// update or raise an error if there is a conflict.
	// Can be nil.
	ConflictFilter Expression
}

func (c *ConflictUpdate) conflictResolution() {}

func (c *ConflictUpdate) Equal(other Traversable) bool {
	o, ok := other.(*ConflictUpdate)
	if !ok {
		return false
	}

	if !c.ArbiterIndex.Equal(o.ArbiterIndex) {
		return false
	}

	if (c.ConflictFilter == nil) != (o.ConflictFilter == nil) {
		return false
	}

	if c.ConflictFilter != nil && o.ConflictFilter != nil {
		if !eq(c.ConflictFilter, o.ConflictFilter) {
			return false
		}
	}

	if len(c.Assignments) != len(o.Assignments) {
		return false
	}

	for i, assign := range c.Assignments {
		if !eq(assign.Value, o.Assignments[i].Value) {
			return false
		}
	}

	return true
}

func (c *ConflictUpdate) String() string {
	str := strings.Builder{}
	str.WriteString("Conflict [update] [arbiter=")
	str.WriteString(c.ArbiterIndex.String())
	str.WriteString("]:")

	for _, assign := range c.Assignments {
		str.WriteString(" [")
		str.WriteString(assign.Column)
		str.WriteString(" = ")
		str.WriteString(assign.Value.String())
		str.WriteString("]")
	}

	if c.ConflictFilter != nil {
		str.WriteString(" where ")
		str.WriteString("[")
		str.WriteString(c.ConflictFilter.String())
		str.WriteString("]")
	}

	return str.String()
}

func (s *ConflictUpdate) Accept(v Visitor) any {
	return v.VisitConflictUpdate(s)
}

func (c *ConflictUpdate) Children() []Traversable {
	var ch []Traversable
	for _, assign := range c.Assignments {
		ch = append(ch, assign.Value)
	}
	if c.ConflictFilter != nil {
		ch = append(ch, c.ConflictFilter)
	}
	return ch
}

func (c *ConflictUpdate) Plans() []Plan {
	var ch []Plan
	for _, assign := range c.Assignments {
		ch = append(ch, assign.Value.Plans()...)
	}
	if c.ConflictFilter != nil {
		ch = append(ch, c.ConflictFilter.Plans()...)
	}
	return ch
}

func (c *ConflictUpdate) Relation() *Relation {
	return &Relation{}
}

// Index is an interface that represents an index.
// Since Kwil's internal catalog does not individually name
// all indexes (e.g. UNIQUE and PRIMARY column constraints),
// we use this interface to represent an index.
type Index interface {
	fmt.Stringer
	index()
	Equal(Index) bool
}

type IndexColumnConstraint struct {
	// Table is the physical table that the index is on.
	Table string
	// Column is the column that the constraint is on.
	Column string
	// ConstraintType is the type of constraint that the index is.
	ConstraintType IndexConstraintType
}

func (i *IndexColumnConstraint) index() {}

func (i *IndexColumnConstraint) Equal(other Index) bool {
	o, ok := other.(*IndexColumnConstraint)
	if !ok {
		return false
	}

	return i.Table == o.Table && i.Column == o.Column && i.ConstraintType == o.ConstraintType
}

func (i *IndexColumnConstraint) String() string {
	return fmt.Sprintf("%s.%s (%s)", i.Table, i.Column, i.ConstraintType.String())
}

type IndexConstraintType uint8

const (
	UniqueConstraintIndex IndexConstraintType = iota
	PrimaryKeyConstraintIndex
)

func (i IndexConstraintType) String() string {
	switch i {
	case UniqueConstraintIndex:
		return "unique"
	case PrimaryKeyConstraintIndex:
		return "primary key"
	default:
		panic(fmt.Sprintf("unknown index constraint type %d", i))
	}
}

// IndexNamed is any index that is specified explicitly
// and has a referenceable name.
type IndexNamed struct {
	// Name is the name of the index.
	Name string
}

func (i *IndexNamed) index() {}

func (i *IndexNamed) Equal(other Index) bool {
	o, ok := other.(*IndexNamed)
	if !ok {
		return false
	}

	return i.Name == o.Name
}

func (i *IndexNamed) String() string {
	return i.Name + " (index)"
}

type Visitor interface {
	VisitTableScanSource(*TableScanSource) any
	VisitProcedureScanSource(*ProcedureScanSource) any
	VisitSubquery(*Subquery) any
	VisitEmptyScan(*EmptyScan) any
	VisitScan(*Scan) any
	VisitProject(*Project) any
	VisitFilter(*Filter) any
	VisitJoin(*Join) any
	VisitSort(*Sort) any
	VisitLimit(*Limit) any
	VisitDistinct(*Distinct) any
	VisitSetOperation(*SetOperation) any
	VisitAggregate(*Aggregate) any
	VisitWindow(*Window) any
	VisitSubplan(*Subplan) any
	VisitLiteral(*Literal) any
	VisitVariable(*Variable) any
	VisitColumnRef(*ColumnRef) any
	VisitAggregateFunctionCall(*AggregateFunctionCall) any
	VisitScalarFunctionCall(*ScalarFunctionCall) any
	VisitArithmeticOp(*ArithmeticOp) any
	VisitComparisonOp(*ComparisonOp) any
	VisitLogicalOp(*LogicalOp) any
	VisitUnaryOp(*UnaryOp) any
	VisitTypeCast(*TypeCast) any
	VisitAliasExpr(*AliasExpr) any
	VisitArrayAccess(*ArrayAccess) any
	VisitArrayConstructor(*ArrayConstructor) any
	VisitFieldAccess(*FieldAccess) any
	VisitSubqueryExpr(*SubqueryExpr) any
	VisitCollate(*Collate) any
	VisitIsIn(*IsIn) any
	VisitCase(*Case) any
	VisitExprRef(*ExprRef) any
	VisitIdentifiedExpr(*IdentifiedExpr) any
	VisitReturn(*Return) any
	VisitCartesianProduct(*CartesianProduct) any
	VisitUpdate(*Update) any
	VisitDelete(*Delete) any
	VisitInsert(*Insert) any
	VisitConflictDoNothing(*ConflictDoNothing) any
	VisitConflictUpdate(*ConflictUpdate) any
	VisitTuples(*Tuples) any
	VisitWindowFunction(*WindowFunction) any
}

/*
	###########################
	#                         #
	#          Utils          #
	#                         #
	###########################
*/

// Traverse traverses a logical plan in preorder.
// It will call the callback function for each node in the plan.
// If the callback function returns false, the traversal will not
// continue to the children of the node.
func Traverse(node Traversable, callback func(node Traversable) bool) {
	if node == nil {
		return
	}
	if !callback(node) {
		return
	}
	for _, child := range node.Children() {
		Traverse(child, callback)
	}
}

func Format(plan LogicalNode) string {
	str := strings.Builder{}
	inner, topLevel := innerFormat(plan, 0, []bool{})
	str.WriteString(inner)

	printSubplans(&str, topLevel)

	return str.String()
}

// printSubplans is a recursive function that prints the subplans
func printSubplans(str *strings.Builder, subplans []*Subplan) {
	for _, sub := range subplans {
		str.WriteString(sub.String())
		str.WriteString("\n")
		strs, subs := innerFormat(sub.Plan, 1, []bool{false})
		str.WriteString(strs)
		printSubplans(str, subs)
	}
}

// innerFormat is a function that allows us to give more complex
// formatting logic.
// It returns subplans that should be added to the top level.
func innerFormat(plan LogicalNode, count int, printLong []bool) (string, []*Subplan) {
	if sub, ok := plan.(*Subplan); ok {
		return "", []*Subplan{sub}
	}

	var msg strings.Builder
	for i := range count {
		if i == count-1 && len(printLong) > i && !printLong[i] {
			msg.WriteString("└─")
		} else if i == count-1 && len(printLong) > i && printLong[i] {
			msg.WriteString("├─")
		} else if len(printLong) > i && printLong[i] {
			msg.WriteString("│ ")
		} else {
			msg.WriteString("  ")
		}
	}
	msg.WriteString(plan.String())
	msg.WriteString("\n")
	var topLevel []*Subplan
	plans := plan.Plans()
	for i, child := range plans {
		showLong := true
		// if it is the last plan, or if the next plan is a subplan,
		// we should not show the long line
		if i == len(plans)-1 {
			showLong = false
		} else if _, ok := plans[i+1].(*Subplan); ok {
			showLong = false
		}

		str, children := innerFormat(child, count+1, append(printLong, showLong))
		msg.WriteString(str)
		topLevel = append(topLevel, children...)
	}
	return msg.String(), topLevel
}
