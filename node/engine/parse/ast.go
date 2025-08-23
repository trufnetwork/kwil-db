package parse

import (
	"encoding/hex"
	"fmt"
	"strings"

	antlr "github.com/antlr4-go/antlr/v4"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
)

// this file contains the ASTs for SQL, DDL, and actions.

// Node is a node in the AST.
type Node interface {
	Positionable
	Accept(Visitor) any
}

type GetPositioner interface {
	GetPosition() *Position
	Clear()
}

type Positionable interface {
	GetPositioner
	Set(r antlr.ParserRuleContext)
	SetToken(t antlr.Token)
}

type Typecastable struct {
	TypeCast *types.DataType
}

func (t *Typecastable) Cast(t2 *types.DataType) {
	t.TypeCast = t2
}

func (t *Typecastable) GetTypeCast() *types.DataType {
	return t.TypeCast
}

type Typecasted interface {
	GetTypeCast() *types.DataType
}

// Expression is an interface for all expressions.
type Expression interface {
	Node
}

// DefaultValue represents a literal default value for a parameter.
// Only literal values are supported for security and performance reasons.
// This struct implements the engine.ParameterDefaultValue interface.
type DefaultValue struct {
	// LiteralValue is the literal value for the default.
	// Supported types: numbers, strings, booleans, and null.
	LiteralValue any `json:"literal_value"`
}

// GetLiteralValue returns the literal value for the default.
// This implements the engine.ParameterDefaultValue interface.
func (d *DefaultValue) GetLiteralValue() any {
	return d.LiteralValue
}

// Assignable is an interface for all expressions that can be assigned to.
type Assignable interface {
	Expression
	assignable()
}

// TopLevelStatement is a top-level statement.
// By itself, it is a valid statement.
type TopLevelStatement interface {
	Node
	topLevelStatement()
}

// ExpressionLiteral is a literal expression.
type ExpressionLiteral struct {
	Position
	Typecastable
	Type *types.DataType
	// Value is the value of the literal.
	// It must be of type string, int64, bool, *decimal.Decimal,
	// or nil
	Value any
}

func (e *ExpressionLiteral) Accept(v Visitor) any {
	return v.VisitExpressionLiteral(e)
}

// String returns the string representation of the literal.
func (e *ExpressionLiteral) String() string {
	s, err := literalToString(e.Value)
	if err != nil {
		panic(err.Error() + ": " + fmt.Sprintf("%T", e.Value))
	}
	return s
}

// literalToString formats a literal value to be used in a SQL / DDL statement.
func literalToString(value any) (string, error) {
	str := strings.Builder{}
	switch v := value.(type) {
	case string: // for text type
		str.WriteString("'" + v + "'")
	case int64, int, int32: // for int type
		str.WriteString(fmt.Sprint(v))
	case *types.Decimal:
		str.WriteString(v.String())
	case bool: // for bool type
		if v {
			str.WriteString("true")
		}
		str.WriteString("false")
	case []byte:
		str.WriteString("0x" + hex.EncodeToString(v))
	case nil:
		// do nothing
	default:
		return "", fmt.Errorf("unsupported literal type: %T", v)
	}

	return str.String(), nil
}

// ExpressionFunctionCall is a function call expression.
type ExpressionFunctionCall struct {
	Position
	Typecastable
	// Namespace is the namespace/schema that the function is in.
	// It can be empty if the function is in the default namespace.
	Namespace string
	// Name is the name of the function.
	Name string
	// Args are the arguments to the function call.
	// They are passed using ()
	Args []Expression
	// Distinct is true if the function call is a DISTINCT function call.
	Distinct bool
	// Star is true if the function call is a * function call.
	// If it is set, then Args must be empty.
	Star bool
}

func (e *ExpressionFunctionCall) Accept(v Visitor) any {
	return v.VisitExpressionFunctionCall(e)
}

// ExpressionWindowFunctionCall is a window function call expression.
type ExpressionWindowFunctionCall struct {
	Position
	FunctionCall *ExpressionFunctionCall
	// Filter is the filter clause.
	// If nil, then there is no filter clause.
	Filter Expression
	// Window is the window function that is being called.
	Window Window
}

func (e *ExpressionWindowFunctionCall) Accept(v Visitor) any {
	return v.VisitExpressionWindowFunctionCall(e)
}

// Window is an interface for all window functions.
// It can either reference an exact window (e.g. OVER (partition by ... order by ...))
// or it can reference a window function name (e.g. OVER my_window).
type Window interface {
	Node
	window()
}

type WindowImpl struct {
	Position
	// PartitionBy is the partition by clause.
	PartitionBy []Expression
	// OrderBy is the order by clause.
	OrderBy []*OrderingTerm
	// In the future, when/if we support frame clauses, we can add it here.
}

func (w *WindowImpl) Accept(v Visitor) any {
	return v.VisitWindowImpl(w)
}

func (w *WindowImpl) window() {}

type WindowReference struct {
	Position
	// Name is the name of the window.
	Name string
}

func (w *WindowReference) Accept(v Visitor) any {
	return v.VisitWindowReference(w)
}

func (w *WindowReference) window() {}

// ExpressionVariable is a variable.
// This can either be $ or @ variables.
type ExpressionVariable struct {
	Position
	Typecastable
	// Name is the naem of the variable,
	// without the $ or @.
	Name string
	// Prefix is the $ or @ prefix.
	Prefix VariablePrefix
}

func (e *ExpressionVariable) Accept(v Visitor) any {
	return v.VisitExpressionVariable(e)
}

// String returns the string representation, as it was passed
// in Kuneiform.
func (e *ExpressionVariable) String() string {
	return e.Name
}

func (e *ExpressionVariable) assignable() {}

type VariablePrefix string

const (
	VariablePrefixDollar VariablePrefix = "$"
	VariablePrefixAt     VariablePrefix = "@"
)

// ExpressionArrayAccess accesses an array value.
type ExpressionArrayAccess struct {
	Position
	Typecastable
	// Array is the array that is being accessed.
	Array Expression
	// Index is the index that is being accessed.
	// Either Index or FromTo is set, but not both.
	Index Expression
	// FromTo is the range that is being accessed.
	// Either Index or FromTo is set, but not both.
	// If FromTo is set, then it is a range access.
	// If both values are set, then it is arr[FROM:TO].
	// If only From is set, then it is arr[FROM:].
	// If only To is set, then it is arr[:TO].
	// If neither are set and index is not set, then it is arr[:].
	FromTo *[2]Expression
}

func (e *ExpressionArrayAccess) Accept(v Visitor) any {
	return v.VisitExpressionArrayAccess(e)
}

func (e *ExpressionArrayAccess) assignable() {}

// ExpressionMakeArray makes a new array.
type ExpressionMakeArray struct {
	Position
	Typecastable
	Values []Expression
}

func (e *ExpressionMakeArray) Accept(v Visitor) any {
	return v.VisitExpressionMakeArray(e)
}

// ExpressionFieldAccess accesses a field in a record.
type ExpressionFieldAccess struct {
	Position
	Typecastable
	// Record is the record that is being accessed.
	Record Expression
	// Field is the field that is being accessed.
	Field string
}

func (e *ExpressionFieldAccess) Accept(v Visitor) any {
	return v.VisitExpressionFieldAccess(e)
}

// ExpressionParenthesized is a parenthesized expression.
type ExpressionParenthesized struct {
	Position
	Typecastable
	// Inner is the inner expression.
	Inner Expression
}

func (e *ExpressionParenthesized) Accept(v Visitor) any {
	return v.VisitExpressionParenthesized(e)
}

// ExpressionComparison is a comparison expression.
type ExpressionComparison struct {
	Position
	// Left is the left side of the comparison.
	Left Expression
	// Right is the right side of the comparison.
	Right Expression
	// Operator is the operator of the comparison.
	Operator ComparisonOperator
}

func (e *ExpressionComparison) Accept(v Visitor) any {
	return v.VisitExpressionComparison(e)
}

type ComparisonOperator string

const (
	ComparisonOperatorEqual              ComparisonOperator = "="
	ComparisonOperatorNotEqual           ComparisonOperator = "<>"
	ComparisonOperatorGreaterThan        ComparisonOperator = ">"
	ComparisonOperatorLessThan           ComparisonOperator = "<"
	ComparisonOperatorGreaterThanOrEqual ComparisonOperator = ">="
	ComparisonOperatorLessThanOrEqual    ComparisonOperator = "<="
)

// ExpressionLogical is a logical expression.
type ExpressionLogical struct {
	Position
	// Left is the left side of the logical expression.
	Left Expression
	// Right is the right side of the logical expression.
	Right Expression
	// Operator is the operator of the logical expression.
	Operator LogicalOperator
}

func (e *ExpressionLogical) Accept(v Visitor) any {
	return v.VisitExpressionLogical(e)
}

type LogicalOperator string

const (
	LogicalOperatorAnd LogicalOperator = "AND"
	LogicalOperatorOr  LogicalOperator = "OR"
)

// ExpressionArithmetic is an arithmetic expression.
type ExpressionArithmetic struct {
	Position
	// Left is the left side of the arithmetic expression.
	Left Expression
	// Right is the right side of the arithmetic expression.
	Right Expression
	// Operator is the operator of the arithmetic expression.
	Operator ArithmeticOperator
}

func (e *ExpressionArithmetic) Accept(v Visitor) any {
	return v.VisitExpressionArithmetic(e)
}

type ArithmeticOperator string

const (
	ArithmeticOperatorAdd      ArithmeticOperator = "+"
	ArithmeticOperatorSubtract ArithmeticOperator = "-"
	ArithmeticOperatorMultiply ArithmeticOperator = "*"
	ArithmeticOperatorDivide   ArithmeticOperator = "/"
	ArithmeticOperatorModulo   ArithmeticOperator = "%"
	ArithmeticOperatorExponent ArithmeticOperator = "^"
	ArithmeticOperatorConcat   ArithmeticOperator = "||"
)

type ExpressionUnary struct {
	Position
	// Expression is the expression that is being operated on.
	Expression Expression
	// Operator is the operator of the unary expression.
	Operator UnaryOperator
}

func (e *ExpressionUnary) Accept(v Visitor) any {
	return v.VisitExpressionUnary(e)
}

type UnaryOperator string

const (
	// Not can be either NOT or !
	UnaryOperatorNot UnaryOperator = "NOT"
	UnaryOperatorNeg UnaryOperator = "-"
	UnaryOperatorPos UnaryOperator = "+"
)

// ExpressionColumn is a column in a table.
type ExpressionColumn struct {
	Position
	Typecastable
	// Table is the table that the column is in.
	Table string // can be empty
	// Column is the name of the column.
	Column string
}

func (e *ExpressionColumn) String() string {
	if e.Table == "" {
		return e.Column
	}
	return e.Table + "." + e.Column
}

func (e *ExpressionColumn) Accept(v Visitor) any {
	return v.VisitExpressionColumn(e)
}

// ExpressionCollate is an expression with a collation.
type ExpressionCollate struct {
	Position
	// Expression is the expression that is being collated.
	Expression Expression
	// Collation is the collation that is being used.
	Collation string
}

func (e *ExpressionCollate) Accept(v Visitor) any {
	return v.VisitExpressionCollate(e)
}

// ExpressionStringComparison is a string comparison expression.
type ExpressionStringComparison struct {
	Position
	// Left is the left side of the comparison.
	Left Expression
	// Right is the right side of the comparison.
	Right Expression
	Not   bool
	// Operator is the operator of the comparison.
	Operator StringComparisonOperator
}

func (e *ExpressionStringComparison) Accept(v Visitor) any {
	return v.VisitExpressionStringComparison(e)
}

type StringComparisonOperator string

const (
	StringComparisonOperatorLike  StringComparisonOperator = "LIKE"
	StringComparisonOperatorILike StringComparisonOperator = "ILIKE"
)

// ExpressionIs is an IS expression.
type ExpressionIs struct {
	Position
	// Left is the left side of the IS expression.
	Left Expression
	// Right is the right side of the IS expression.
	Right Expression
	// Not is true if the IS expression is a NOT IS expression.
	Not bool
	// Distinct is true if the IS expression is a DISTINCT IS expression.
	Distinct bool
}

func (e *ExpressionIs) Accept(v Visitor) any {
	return v.VisitExpressionIs(e)
}

// ExpressionBetween is a BETWEEN expression.
type ExpressionBetween struct {
	Position
	// Expression is the expression that is being compared.
	Expression Expression
	// Lower is the left side of the BETWEEN expression.
	Lower Expression
	// Upper is the right side of the BETWEEN expression.
	Upper Expression
	// Not is true if the BETWEEN expression is a NOT BETWEEN expression.
	Not bool
}

func (e *ExpressionBetween) Accept(v Visitor) any {
	return v.VisitExpressionBetween(e)
}

type ExpressionIn struct {
	Position
	// Expression is the expression that is being compared.
	Expression Expression
	// List is the list of expressions that the expression is being compared to.
	// Either List or Subquery is set, but not both.
	List []Expression
	// Subquery is the subquery that the expression is being compared to.
	// Either List or Subquery is set, but not both.
	Subquery *SelectStatement
	// Not is true if the IN expression is a NOT IN expression.
	Not bool
}

func (e *ExpressionIn) Accept(v Visitor) any {
	return v.VisitExpressionIn(e)
}

// ExpressionSubquery is a subquery expression.
type ExpressionSubquery struct {
	Position
	Typecastable
	Not      bool
	Exists   bool
	Subquery *SelectStatement
}

func (e *ExpressionSubquery) Accept(v Visitor) any {
	return v.VisitExpressionSubquery(e)
}

// ExpressionCase is a CASE expression.
type ExpressionCase struct {
	Position
	Case     Expression
	WhenThen [][2]Expression
	Else     Expression
}

func (e *ExpressionCase) Accept(v Visitor) any {
	return v.VisitExpressionCase(e)
}

// CommonTableExpression is a common table expression.
type CommonTableExpression struct {
	Position
	// Name is the name of the CTE.
	Name string
	// Columns are the columns of the CTE.
	Columns []string
	// Query is the query of the CTE.
	Query *SelectStatement
}

func (c *CommonTableExpression) Accept(v Visitor) any {
	return v.VisitCommonTableExpression(c)
}

// Namespacing is a struct that can have a namespace prefix.
// This is used for top-level statements that can have a namespace prefix
// using curly braces.
type Namespacing struct {
	NamespacePrefix string
}

func (n *Namespacing) SetNamespacePrefix(prefix string) {
	n.NamespacePrefix = prefix
}

func (n *Namespacing) GetNamespacePrefix() string {
	return n.NamespacePrefix
}

type Namespaceable interface {
	TopLevelStatement
	SetNamespacePrefix(string)
	GetNamespacePrefix() string
}

// SQLStatement is a DML statement with common table expression.
type SQLStatement struct {
	Position
	Namespacing
	CTEs []*CommonTableExpression
	// Recursive is true if the RECURSIVE keyword is present.
	Recursive bool
	// SQL can be an insert, update, delete, or select statement.
	SQL SQLCore
	// raw is the raw SQL string.
	raw *string
}

func (s *SQLStatement) topLevelStatement() {}

func (s *SQLStatement) Accept(v Visitor) any {
	return v.VisitSQLStatement(s)
}

func (s *SQLStatement) Raw() (string, error) {
	if s.raw == nil {
		return "", fmt.Errorf("raw SQL is not set")
	}

	return *s.raw, nil
}

// SQLCore is a DML statement.
// It can be INSERT, UPDATE, DELETE, SELECT.
type SQLCore interface {
	Node
	sqlCore()
}

// CreateActionStatement is a CREATE ACTION statement.
type CreateActionStatement struct {
	Position
	Namespacing
	// Either IfNotExists or OrReplace can be true, but not both.
	// Both can be false.
	IfNotExists bool
	OrReplace   bool

	// Name is the name of the action.
	Name string

	// Parameters are the parameters of the action.
	Parameters []*engine.NamedType
	// Public is true if the action is public.
	// Public bool

	// Modifiers are things like VIEW, OWNER, etc.
	Modifiers []string
	// Returns specifies the return type of the action.
	// It can be nil if the action does not return anything.
	Returns *ActionReturn
	// Statements are the statements in the action.
	Statements []ActionStmt
	// Raw is the raw CREATE ACTION statement.
	Raw string
}

func (c *CreateActionStatement) topLevelStatement() {}

func (c *CreateActionStatement) Accept(v Visitor) any {
	return v.VisitCreateActionStatement(c)
}

type DropActionStatement struct {
	Position
	Namespacing
	// IfExists is true if the IF EXISTS clause is present.
	IfExists bool
	// Name is the name of the action.
	Name string
}

func (d *DropActionStatement) topLevelStatement() {}

func (d *DropActionStatement) Accept(v Visitor) any {
	return v.VisitDropActionStatement(d)
}

// ActionReturn is the return struct of the action.
type ActionReturn struct {
	Position
	// IsTable is true if the return type is a table.
	IsTable bool
	// Fields are the fields of the return type.
	Fields []*engine.NamedType
}

// CreateTableStatement is a CREATE TABLE statement.
type CreateTableStatement struct {
	Position
	Namespacing
	IfNotExists bool
	Name        string
	Columns     []*Column
	// Constraints contains the non-inline constraints
	Constraints []*OutOfLineConstraint
}

func (c *CreateTableStatement) topLevelStatement() {}

func (c *CreateTableStatement) Accept(v Visitor) any {
	return v.VisitCreateTableStatement(c)
}

// Column represents a table column.
type Column struct {
	Position

	Name        string
	Type        *types.DataType
	Constraints []InlineConstraint
}

func (c *Column) Accept(v Visitor) any {
	return v.VisitColumn(c)
}

// OutOfLineConstraint is a constraint that is not inline with the column.
// e.g. CREATE TABLE t (a INT, CONSTRAINT c CHECK (a > 0))
type OutOfLineConstraint struct {
	Position
	Name       string // can be empty if the name should be auto-generated
	Constraint OutOfLineConstraintClause
}

// InlineConstraint is a constraint that is inline with the column.
type InlineConstraint interface {
	Node
	inlineConstraint()
}

// OutOfLineConstraintClause is a constraint that is not inline with the column.
type OutOfLineConstraintClause interface {
	Node
	outOfLineConstraintClause()
	// LocalColumns returns the local columns that the constraint is applied to.
	LocalColumns() []string
}

type PrimaryKeyInlineConstraint struct {
	Position
}

func (c *PrimaryKeyInlineConstraint) inlineConstraint() {}

func (c *PrimaryKeyInlineConstraint) Accept(v Visitor) any {
	return v.VisitPrimaryKeyInlineConstraint(c)
}

type PrimaryKeyOutOfLineConstraint struct {
	Position
	Columns []string
}

func (c *PrimaryKeyOutOfLineConstraint) Accept(v Visitor) any {
	return v.VisitPrimaryKeyOutOfLineConstraint(c)
}

func (c *PrimaryKeyOutOfLineConstraint) outOfLineConstraintClause() {}

func (c *PrimaryKeyOutOfLineConstraint) LocalColumns() []string { return c.Columns }

type UniqueInlineConstraint struct {
	Position
}

func (c *UniqueInlineConstraint) Accept(v Visitor) any {
	return v.VisitUniqueInlineConstraint(c)
}

func (c *UniqueInlineConstraint) inlineConstraint() {}

type UniqueOutOfLineConstraint struct {
	Position
	Columns []string
}

func (c *UniqueOutOfLineConstraint) Accept(v Visitor) any {
	return v.VisitUniqueOutOfLineConstraint(c)
}

func (c *UniqueOutOfLineConstraint) outOfLineConstraintClause() {}

func (c *UniqueOutOfLineConstraint) LocalColumns() []string { return c.Columns }

type DefaultConstraint struct {
	Position
	Value Expression
}

func (c *DefaultConstraint) Accept(v Visitor) any {
	return v.VisitDefaultConstraint(c)
}

func (c *DefaultConstraint) inlineConstraint() {}

type NotNullConstraint struct {
	Position
}

func (c *NotNullConstraint) Accept(v Visitor) any {
	return v.VisitNotNullConstraint(c)
}

func (c *NotNullConstraint) inlineConstraint() {}

type CheckConstraint struct {
	Position
	Expression Expression
}

func (c *CheckConstraint) Accept(v Visitor) any {
	return v.VisitCheckConstraint(c)
}

func (c *CheckConstraint) inlineConstraint() {}

func (c *CheckConstraint) outOfLineConstraintClause() {}

func (c *CheckConstraint) LocalColumns() []string { return nil }

type ForeignKeyReferences struct {
	Position

	// RefTableNamespace is the qualifier of the referenced table.
	// It can be empty if the table is in the same schema.
	RefTableNamespace string
	RefTable          string
	RefColumns        []string
	Actions           []*ForeignKeyAction
}

func (c *ForeignKeyReferences) Accept(v Visitor) any {
	return v.VisitForeignKeyReferences(c)
}

func (c *ForeignKeyReferences) inlineConstraint() {}

type ForeignKeyOutOfLineConstraint struct {
	Position
	Columns    []string
	References *ForeignKeyReferences
}

func (c *ForeignKeyOutOfLineConstraint) Accept(v Visitor) any {
	return v.VisitForeignKeyOutOfLineConstraint(c)
}

func (c *ForeignKeyOutOfLineConstraint) outOfLineConstraintClause() {}

func (c *ForeignKeyOutOfLineConstraint) LocalColumns() []string { return c.Columns }

type IndexType string

const (
	// IndexTypeBTree is the default index, created by using `INDEX`.
	IndexTypeBTree IndexType = "BTREE"
	// IndexTypeUnique is a unique BTree index, created by using `UNIQUE INDEX`.
	IndexTypeUnique IndexType = "UNIQUE"
)

// ForeignKey is a foreign key in a table.
type ForeignKey struct {
	// ChildKeys are the columns that are referencing another.
	// For example, in FOREIGN KEY (a) REFERENCES tbl2(b), "a" is the child key
	ChildKeys []string `json:"child_keys"`

	// ParentKeys are the columns that are being referred to.
	// For example, in FOREIGN KEY (a) REFERENCES tbl2(b), "b" is the parent key
	ParentKeys []string `json:"parent_keys"`

	// ParentTable is the table that holds the parent columns.
	// For example, in FOREIGN KEY (a) REFERENCES tbl2(b), "tbl2" is the parent table
	ParentTable string `json:"parent_table"`

	// Action refers to what the foreign key should do when the parent is altered.
	// This is NOT the same as a database action.
	// For example, ON DELETE CASCADE is a foreign key action
	Actions []*ForeignKeyAction `json:"actions"`
}

// ForeignKeyActionOn specifies when a foreign key action should occur.
// It can be either "UPDATE" or "DELETE".
type ForeignKeyActionOn string

// ForeignKeyActionOn types
const (
	// ON_UPDATE is used to specify an action should occur when a parent key is updated
	ON_UPDATE ForeignKeyActionOn = "UPDATE"
	// ON_DELETE is used to specify an action should occur when a parent key is deleted
	ON_DELETE ForeignKeyActionOn = "DELETE"
)

// ForeignKeyActionDo specifies what should be done when a foreign key action is triggered.
type ForeignKeyActionDo string

// ForeignKeyActionDo types
const (
	// DO_NO_ACTION does nothing when a parent key is altered
	DO_NO_ACTION ForeignKeyActionDo = "NO ACTION"

	// DO_RESTRICT prevents the parent key from being altered
	DO_RESTRICT ForeignKeyActionDo = "RESTRICT"

	// DO_SET_NULL sets the child key(s) to NULL
	DO_SET_NULL ForeignKeyActionDo = "SET NULL"

	// DO_SET_DEFAULT sets the child key(s) to their default values
	DO_SET_DEFAULT ForeignKeyActionDo = "SET DEFAULT"

	// DO_CASCADE updates the child key(s) or deletes the records (depending on the action type)
	DO_CASCADE ForeignKeyActionDo = "CASCADE"
)

// ForeignKeyAction is used to specify what should occur
// if a parent key is updated or deleted
type ForeignKeyAction struct {
	// On can be either "UPDATE" or "DELETE"
	On ForeignKeyActionOn `json:"on"`

	// Do specifies what a foreign key action should do
	Do ForeignKeyActionDo `json:"do"`
}

type DropBehavior string

const (
	DropBehaviorDefault  DropBehavior = ""
	DropBehaviorCascade  DropBehavior = "CASCADE"
	DropBehaviorRestrict DropBehavior = "RESTRICT"
)

type DropTableStatement struct {
	Position
	Namespacing
	Tables   []string
	IfExists bool
	Behavior DropBehavior
}

func (s *DropTableStatement) topLevelStatement() {}

func (s *DropTableStatement) Accept(v Visitor) any {
	return v.VisitDropTableStatement(s)
}

type AlterTableAction interface {
	Node

	alterTableAction()
}

// AlterTableStatement is a ALTER TABLE statement.
type AlterTableStatement struct {
	Position
	Namespacing
	Table   string
	Actions []AlterTableAction
}

func (a *AlterTableStatement) topLevelStatement() {}

func (a *AlterTableStatement) alterTableAction() {}

func (a *AlterTableStatement) Accept(v Visitor) any {
	return v.VisitAlterTableStatement(a)
}

// ConstraintType is a constraint in a table.
type ConstraintType interface {
	String() string
	constraint()
}

// SingleColumnConstraintType is a constraint type that can only ever
// be applied to a single column. These are NOT NULL and DEFAULT.
type SingleColumnConstraintType string

func (t SingleColumnConstraintType) String() string {
	return string(t)
}

func (t SingleColumnConstraintType) constraint() {}

const (
	ConstraintTypeNotNull SingleColumnConstraintType = "NOT NULL"
	ConstraintTypeDefault SingleColumnConstraintType = "DEFAULT"
)

// MultiColumnConstraintType is a constraint type that can be applied
// to multiple columns. These are PRIMARY KEY, FOREIGN KEY, UNIQUE, and CHECK.

type MultiColumnConstraintType string

func (t MultiColumnConstraintType) String() string {
	return string(t)
}

func (t MultiColumnConstraintType) constraint() {}

const (
	ConstraintTypeUnique     MultiColumnConstraintType = "UNIQUE"
	ConstraintTypeCheck      MultiColumnConstraintType = "CHECK"
	ConstraintTypeForeignKey MultiColumnConstraintType = "FOREIGN KEY"
	ConstraintTypePrimaryKey MultiColumnConstraintType = "PRIMARY KEY"
)

// AlterColumnSet is "ALTER COLUMN ... SET ..." statement.
type AlterColumnSet struct {
	Position
	// Column is the column that is being altered.
	Column string
	// Type is the type of constraint that is being set.
	Type SingleColumnConstraintType
	// Value is the value of the constraint.
	// It is only set if the type is DEFAULT.
	Value Expression
}

func (a *AlterColumnSet) alterTableAction() {}

func (a *AlterColumnSet) Accept(v Visitor) any {
	return v.VisitAlterColumnSet(a)
}

// AlterColumnDrop is "ALTER COLUMN ... DROP ..." statement.
type AlterColumnDrop struct {
	Position
	Column string
	Type   SingleColumnConstraintType
}

func (a *AlterColumnDrop) alterTableAction() {}

func (a *AlterColumnDrop) Accept(v Visitor) any {
	return v.VisitAlterColumnDrop(a)
}

type AddColumn struct {
	Position
	Name        string
	Type        *types.DataType
	IfNotExists bool
}

func (a *AddColumn) alterTableAction() {}

func (a *AddColumn) Accept(v Visitor) any {
	return v.VisitAddColumn(a)
}

type DropColumn struct {
	Position
	Name     string
	IfExists bool
}

func (a *DropColumn) alterTableAction() {}

func (a *DropColumn) Accept(v Visitor) any {
	return v.VisitDropColumn(a)
}

type RenameColumn struct {
	Position
	OldName string
	NewName string
}

func (a *RenameColumn) alterTableAction() {}

func (a *RenameColumn) Accept(v Visitor) any {
	return v.VisitRenameColumn(a)
}

type RenameTable struct {
	Position
	Name string
}

func (a *RenameTable) alterTableAction() {}

func (a *RenameTable) Accept(v Visitor) any {
	return v.VisitRenameTable(a)
}

// AddTableConstraint is a constraint that is being added to a table.
// It is used to specify multi-column constraints.
type AddTableConstraint struct {
	Position
	Constraint *OutOfLineConstraint
}

func (a *AddTableConstraint) alterTableAction() {}

func (a *AddTableConstraint) Accept(v Visitor) any {
	return v.VisitAddTableConstraint(a)
}

type DropTableConstraint struct {
	Position
	Name     string
	IfExists bool
}

func (a *DropTableConstraint) alterTableAction() {}

func (a *DropTableConstraint) Accept(v Visitor) any {
	return v.VisitDropTableConstraint(a)
}

type CreateIndexStatement struct {
	Position
	Namespacing
	IfNotExists bool
	Name        string
	On          string
	Columns     []string
	Type        IndexType
}

func (s *CreateIndexStatement) topLevelStatement() {}

func (s *CreateIndexStatement) Accept(v Visitor) any {
	return v.VisitCreateIndexStatement(s)
}

type DropIndexStatement struct {
	Position
	Namespacing
	Name       string
	CheckExist bool
}

func (s *DropIndexStatement) topLevelStatement() {}

func (s *DropIndexStatement) Accept(v Visitor) any {
	return v.VisitDropIndexStatement(s)
}

type GrantOrRevokeStatement struct {
	Position
	// If is true if either IF GRANTED or IF NOT GRANTED is present,
	// depending on the statement.
	If bool
	// IsGrant is true if the statement is a GRANT statement.
	// If it is false, then it is a REVOKE statement.
	IsGrant bool
	// Privileges are the privileges that are being granted.
	// Either Privileges or Role must be set, but not both.
	Privileges []string
	// Namespace is the namespace that the privileges are being granted on.
	// It can be nil if they are global.
	Namespace *string
	// OnNam
	// Role is the role being granted
	// Either Privileges or Role must be set, but not both.
	GrantRole string
	// ToRole is the role being granted to.
	// Only one of ToUser, ToRole, or ToVariable must be set.
	ToRole string
	// ToUser is the user being granted to.
	// Only one of ToUser, ToRole, or ToVariable must be set.
	ToUser string
	// ToVariable is the variable being granted to.
	// Only one of ToUser, ToRole, or ToVariable must be set.
	ToVariable Expression
}

func (g *GrantOrRevokeStatement) topLevelStatement() {}

func (g *GrantOrRevokeStatement) Accept(v Visitor) any {
	return v.VisitGrantOrRevokeStatement(g)
}

type TransferOwnershipStatement struct {
	Position
	// ToUser is the user that the ownership is being transferred to.
	ToUser string
	// ToVariable is the variable that the ownership is being transferred to.
	ToVariable Expression
}

func (t *TransferOwnershipStatement) topLevelStatement() {}

func (t *TransferOwnershipStatement) Accept(v Visitor) any {
	return v.VisitTransferOwnershipStatement(t)
}

type CreateRoleStatement struct {
	Position
	// IfNotExists is true if the IF NOT EXISTS clause is present.
	IfNotExists bool
	// Role is the role that is being created or dropped.
	Role string
}

func (c *CreateRoleStatement) topLevelStatement() {}

func (c *CreateRoleStatement) Accept(v Visitor) any {
	return v.VisitCreateRoleStatement(c)
}

type DropRoleStatement struct {
	Position
	// IfExists is true if the IF EXISTS clause is present.
	IfExists bool
	// Role is the role that is being created or dropped.
	Role string
}

func (d *DropRoleStatement) topLevelStatement() {}

func (d *DropRoleStatement) Accept(v Visitor) any {
	return v.VisitDropRoleStatement(d)
}

type UseExtensionStatement struct {
	Position
	IfNotExists bool
	ExtName     string
	Config      []*struct {
		Key   string
		Value Expression
	}
	Alias string
}

func (u *UseExtensionStatement) topLevelStatement() {}

func (u *UseExtensionStatement) Accept(v Visitor) any {
	return v.VisitUseExtensionStatement(u)
}

type UnuseExtensionStatement struct {
	Position
	IfExists bool
	Alias    string
}

func (u *UnuseExtensionStatement) topLevelStatement() {}

func (u *UnuseExtensionStatement) Accept(v Visitor) any {
	return v.VisitUnuseExtensionStatement(u)
}

type CreateNamespaceStatement struct {
	Position
	// IfNotExists is true if the IF NOT EXISTS clause is present.
	IfNotExists bool
	// Namespace is the namespace that is being created.
	Namespace string
}

func (c *CreateNamespaceStatement) topLevelStatement() {}

func (c *CreateNamespaceStatement) Accept(v Visitor) any {
	return v.VisitCreateNamespaceStatement(c)
}

type DropNamespaceStatement struct {
	Position
	// IfExists is true if the IF EXISTS clause is present.
	IfExists bool
	// Namespace is the namespace that is being dropped.
	Namespace string
}

func (d *DropNamespaceStatement) topLevelStatement() {}

func (d *DropNamespaceStatement) Accept(v Visitor) any {
	return v.VisitDropNamespaceStatement(d)
}

type SetCurrentNamespaceStatement struct {
	Position
	Namespace string
}

func (s *SetCurrentNamespaceStatement) topLevelStatement() {}

func (s *SetCurrentNamespaceStatement) Accept(v Visitor) any {
	return v.VisitSetCurrentNamespaceStatement(s)
}

// SelectStatement is a SELECT statement.
type SelectStatement struct {
	Position
	SelectCores       []*SelectCore
	CompoundOperators []CompoundOperator
	Ordering          []*OrderingTerm
	Limit             Expression
	Offset            Expression
}

func (s *SelectStatement) Accept(v Visitor) any {
	return v.VisitSelectStatement(s)
}

func (SelectStatement) sqlCore() {}

type CompoundOperator string

const (
	CompoundOperatorUnion     CompoundOperator = "UNION"
	CompoundOperatorUnionAll  CompoundOperator = "UNION ALL"
	CompoundOperatorIntersect CompoundOperator = "INTERSECT"
	CompoundOperatorExcept    CompoundOperator = "EXCEPT"
)

// OrderingTerm is a term in an order by clause
type OrderingTerm struct {
	Position
	Expression Expression
	Order      OrderType
	Nulls      NullOrder
}

func (o *OrderingTerm) Accept(v Visitor) any {
	return v.VisitOrderingTerm(o)
}

type OrderType string

const (
	OrderTypeAsc  OrderType = "ASC"
	OrderTypeDesc OrderType = "DESC"
)

type NullOrder string

const (
	NullOrderFirst NullOrder = "FIRST"
	NullOrderLast  NullOrder = "LAST"
)

type SelectCore struct {
	Position
	// Distinct is true if the SELECT statement is a DISTINCT SELECT statement.
	Distinct bool
	Columns  []ResultColumn
	From     Table        // can be nil
	Joins    []*Join      // can be nil
	Where    Expression   // can be nil
	GroupBy  []Expression // can be nil
	Having   Expression   // can be nil
	Windows  []*struct {
		Name   string
		Window *WindowImpl
	} // can be nil
}

func (s *SelectCore) Accept(v Visitor) any {
	return v.VisitSelectCore(s)
}

type ResultColumn interface {
	Node
	ResultColumnType() ResultColumnType
}

type ResultColumnType string

const (
	ResultColumnTypeExpression ResultColumnType = "expression"
	ResultColumnTypeWildcard   ResultColumnType = "wildcare"
)

type ResultColumnExpression struct {
	Position

	Expression Expression
	Alias      string // can be empty
}

func (r *ResultColumnExpression) Accept(v Visitor) any {
	return v.VisitResultColumnExpression(r)
}

func (r *ResultColumnExpression) ResultColumnType() ResultColumnType {
	return ResultColumnTypeExpression
}

type ResultColumnWildcard struct {
	Position
	Table string // can be empty
}

func (r *ResultColumnWildcard) Accept(v Visitor) any {
	return v.VisitResultColumnWildcard(r)
}

func (r *ResultColumnWildcard) ResultColumnType() ResultColumnType {
	return ResultColumnTypeWildcard
}

type Table interface {
	Node
	table()
}

type RelationTable struct {
	Position
	// Namespace is the namespace of the table.
	// If it is empty, then the table is in the current namespace.
	Namespace string
	// Table is the name of the table.
	Table string
	Alias string // can be empty
}

func (r *RelationTable) Accept(v Visitor) any {
	return v.VisitRelationTable(r)
}

func (RelationTable) table() {}

type RelationSubquery struct {
	Position
	Subquery *SelectStatement
	// Alias cannot be empty, as our syntax
	// forces it for subqueries.
	Alias string
}

func (r *RelationSubquery) Accept(v Visitor) any {
	return v.VisitRelationSubquery(r)
}

func (RelationSubquery) table() {}

type RelationTableFunction struct {
	Position
	FunctionCall  *ExpressionFunctionCall
	Alias         string   // Table alias (optional)
	ColumnAliases []string // Column aliases for multi-array UNNEST (optional)
}

func (r *RelationTableFunction) Accept(v Visitor) any {
	return v.VisitRelationTableFunction(r)
}

func (RelationTableFunction) table() {}

// Join is a join in a SELECT statement.
type Join struct {
	Position
	Type     JoinType
	Relation Table
	On       Expression
}

func (j *Join) Accept(v Visitor) any {
	return v.VisitJoin(j)
}

type JoinType string

const (
	JoinTypeInner JoinType = "INNER"
	JoinTypeLeft  JoinType = "LEFT"
	JoinTypeRight JoinType = "RIGHT"
	JoinTypeFull  JoinType = "FULL"
)

type UpdateStatement struct {
	Position
	Table     string
	Alias     string // can be empty
	SetClause []*UpdateSetClause
	From      Table      // can be nil
	Joins     []*Join    // can be nil
	Where     Expression // can be nil
}

func (u *UpdateStatement) Accept(v Visitor) any {
	return v.VisitUpdateStatement(u)
}

func (u *UpdateStatement) sqlCore() {}

type UpdateSetClause struct {
	Position
	Column string
	Value  Expression
}

func (u *UpdateSetClause) Accept(v Visitor) any {
	return v.VisitUpdateSetClause(u)
}

type DeleteStatement struct {
	Position

	Table string
	Alias string     // can be empty
	From  Table      // can be nil
	Joins []*Join    // can be nil
	Where Expression // can be nil
}

func (d *DeleteStatement) Accept(v Visitor) any {
	return v.VisitDeleteStatement(d)
}

func (d *DeleteStatement) sqlCore() {}

type InsertStatement struct {
	Position
	Table   string
	Alias   string   // can be empty
	Columns []string // can be empty
	// Either Values or Select is set, but not both.
	Values     [][]Expression   // can be empty
	Select     *SelectStatement // can be nil
	OnConflict *OnConflict      // can be nil
}

func (i *InsertStatement) Accept(v Visitor) any {
	return v.VisitInsertStatement(i)
}

func (i InsertStatement) sqlCore() {}

type OnConflict struct {
	Position
	ConflictColumns []string           // can be empty
	ConflictWhere   Expression         // can be nil
	DoUpdate        []*UpdateSetClause // if nil, then do nothing
	UpdateWhere     Expression         // can be nil
}

func (u *OnConflict) Accept(v Visitor) any {
	return v.VisitUpsertClause(u)
}

// action logic ast:

// ActionStmt is a statement in a actiob.
// it is the top-level interface for all action statements.
type ActionStmt interface {
	Node
	actionStmt()
}

type baseActionStmt struct {
	Position
}

func (baseActionStmt) actionStmt() {}

// ActionStmtDeclaration is a variable declaration in an action.
type ActionStmtDeclaration struct {
	baseActionStmt
	// Variable is the variable that is being declared.
	Variable *ExpressionVariable
	Type     *types.DataType
}

func (p *ActionStmtDeclaration) Accept(v Visitor) any {
	return v.VisitActionStmtDeclaration(p)
}

// ActionStmtAssign is a variable assignment in an action.
// It should only be called on variables that have already been declared.
type ActionStmtAssign struct {
	baseActionStmt
	// Variable is the variable that is being assigned.
	Variable Assignable
	// Type is the type of the variable.
	// It can be nil if the variable is not being assigned,
	// or if the type should be inferred.
	Type *types.DataType
	// Value is the value that is being assigned.
	Value Expression
}

func (p *ActionStmtAssign) Accept(v Visitor) any {
	return v.VisitActionStmtAssignment(p)
}

// ActionStmtCall is a call to another action or built-in function.
type ActionStmtCall struct {
	baseActionStmt
	// Receivers are the variables being assigned. If nil, then the
	// receiver can be ignored.
	Receivers []*ExpressionVariable
	Call      *ExpressionFunctionCall
}

func (p *ActionStmtCall) Accept(v Visitor) any {
	return v.VisitActionStmtCall(p)
}

type ActionStmtForLoop struct {
	baseActionStmt
	// Receiver is the variable that is assigned on each iteration.
	Receiver *ExpressionVariable
	// LoopTerm is what the loop is looping through.
	LoopTerm LoopTerm
	// Body is the body of the loop.
	Body []ActionStmt
}

func (p *ActionStmtForLoop) Accept(v Visitor) any {
	return v.VisitActionStmtForLoop(p)
}

// LoopTerm what the loop is looping through.
type LoopTerm interface {
	Node
	loopTerm()
}

type baseLoopTerm struct {
	Position
}

func (baseLoopTerm) loopTerm() {}

type LoopTermRange struct {
	baseLoopTerm
	// Start is the start of the range.
	Start Expression
	// End is the end of the range.
	End Expression
}

func (e *LoopTermRange) Accept(v Visitor) interface{} {
	return v.VisitLoopTermRange(e)
}

type LoopTermSQL struct {
	baseLoopTerm
	// Statement is the Statement statement to execute.
	Statement *SQLStatement
}

func (e *LoopTermSQL) Accept(v Visitor) interface{} {
	return v.VisitLoopTermSQL(e)
}

// LoopTermExpression is a loop term that loops over an expression.
type LoopTermExpression struct {
	baseLoopTerm
	// If Array is true, then the ARRAY keyword was used, specifying that
	// the function is expected to return a single array, and we should loop
	// through each element in the array.
	Array bool
	// Expression is the expression to loop through.
	Expression Expression
}

func (e *LoopTermExpression) Accept(v Visitor) interface{} {
	return v.VisitLoopTermExpression(e)
}

type ActionStmtIf struct {
	baseActionStmt
	// IfThens are the if statements.
	// They are evaluated in order, as
	// IF ... THEN ... ELSEIF ... THEN ...
	IfThens []*IfThen
	// Else is the else statement.
	// It is evaluated if no other if statement
	// is true.
	Else []ActionStmt
}

func (p *ActionStmtIf) Accept(v Visitor) any {
	return v.VisitActionStmtIf(p)
}

type IfThen struct {
	Position
	If   Expression
	Then []ActionStmt
}

func (i *IfThen) Accept(v Visitor) any {
	return v.VisitIfThen(i)
}

type ActionStmtSQL struct {
	baseActionStmt
	SQL *SQLStatement
}

func (p *ActionStmtSQL) Accept(v Visitor) any {
	return v.VisitActionStmtSQL(p)
}

type ActionStmtLoopControl struct {
	baseActionStmt
	Type LoopControlType
}

type LoopControlType string

const (
	LoopControlTypeBreak    LoopControlType = "BREAK"
	LoopControlTypeContinue LoopControlType = "CONTINUE"
)

func (p *ActionStmtLoopControl) Accept(v Visitor) any {
	return v.VisitActionStmtLoopControl(p)
}

type ActionStmtReturn struct {
	baseActionStmt
	// Values are the values to return.
	// Either values is set or SQL is set, but not both.
	Values []Expression
	// SQL is the SQL statement to return.
	// Either values is set or SQL is set, but not both.
	SQL *SQLStatement
}

func (p *ActionStmtReturn) Accept(v Visitor) any {
	return v.VisitActionStmtReturn(p)
}

type ActionStmtReturnNext struct {
	baseActionStmt
	// Values are the values to return.
	Values []Expression
}

func (p *ActionStmtReturnNext) Accept(v Visitor) any {
	return v.VisitActionStmtReturnNext(p)
}

/*
	There are three types of visitors, all which compose on each other:
	- Visitor: top-level visitor capable of visiting actions, DDL, and SQL.
	- ActionVisitor: a visitor capable of only visiting actions and SQL. It must include
	SQL because actions themselves rely on SQL/
	- SQLVisitor: a visitor capable of only visiting SQL.
*/

// Visitor is an interface for visiting nodes in the parse tree.
type Visitor interface {
	ActionVisitor
	DDLVisitor
}

// DDLVisitor includes visit methods only needed to analyze DDL statements.
type DDLVisitor interface {
	// DDL
	VisitCreateTableStatement(*CreateTableStatement) any
	VisitAlterTableStatement(*AlterTableStatement) any
	VisitDropTableStatement(*DropTableStatement) any
	VisitCreateIndexStatement(*CreateIndexStatement) any
	VisitDropIndexStatement(*DropIndexStatement) any
	VisitGrantOrRevokeStatement(*GrantOrRevokeStatement) any
	VisitTransferOwnershipStatement(*TransferOwnershipStatement) any
	VisitAlterColumnSet(*AlterColumnSet) any
	VisitAlterColumnDrop(*AlterColumnDrop) any
	VisitAddColumn(*AddColumn) any
	VisitDropColumn(*DropColumn) any
	VisitRenameColumn(*RenameColumn) any
	VisitRenameTable(*RenameTable) any
	VisitAddTableConstraint(*AddTableConstraint) any
	VisitDropTableConstraint(*DropTableConstraint) any
	VisitColumn(*Column) any
	VisitCreateRoleStatement(*CreateRoleStatement) any
	VisitDropRoleStatement(*DropRoleStatement) any
	VisitUseExtensionStatement(*UseExtensionStatement) any
	VisitUnuseExtensionStatement(*UnuseExtensionStatement) any
	VisitCreateNamespaceStatement(*CreateNamespaceStatement) any
	VisitDropNamespaceStatement(*DropNamespaceStatement) any
	VisitSetCurrentNamespaceStatement(*SetCurrentNamespaceStatement) any
	VisitCreateActionStatement(*CreateActionStatement) any
	VisitDropActionStatement(*DropActionStatement) any
	// Constraints
	VisitPrimaryKeyInlineConstraint(*PrimaryKeyInlineConstraint) any
	VisitPrimaryKeyOutOfLineConstraint(*PrimaryKeyOutOfLineConstraint) any
	VisitUniqueInlineConstraint(*UniqueInlineConstraint) any
	VisitUniqueOutOfLineConstraint(*UniqueOutOfLineConstraint) any
	VisitDefaultConstraint(*DefaultConstraint) any
	VisitNotNullConstraint(*NotNullConstraint) any
	VisitCheckConstraint(*CheckConstraint) any
	VisitForeignKeyReferences(*ForeignKeyReferences) any
	VisitForeignKeyOutOfLineConstraint(*ForeignKeyOutOfLineConstraint) any
}

// ActionVisitor includes visit methods only needed to analyze actions.
// It does not need visit methods for structs that are for the schema or actions
type ActionVisitor interface {
	SQLVisitor
	VisitActionStmtDeclaration(*ActionStmtDeclaration) any
	VisitActionStmtAssignment(*ActionStmtAssign) any
	VisitActionStmtCall(*ActionStmtCall) any
	VisitActionStmtForLoop(*ActionStmtForLoop) any
	VisitLoopTermRange(*LoopTermRange) any
	VisitLoopTermSQL(*LoopTermSQL) any
	VisitLoopTermExpression(*LoopTermExpression) any
	VisitActionStmtIf(*ActionStmtIf) any
	VisitIfThen(*IfThen) any
	VisitActionStmtSQL(*ActionStmtSQL) any
	VisitActionStmtLoopControl(*ActionStmtLoopControl) any
	VisitActionStmtReturn(*ActionStmtReturn) any
	VisitActionStmtReturnNext(*ActionStmtReturnNext) any
}

// SQLVisitor is a visitor that only has methods for SQL nodes.
type SQLVisitor interface {
	VisitExpressionLiteral(*ExpressionLiteral) any
	VisitExpressionFunctionCall(*ExpressionFunctionCall) any
	VisitExpressionWindowFunctionCall(*ExpressionWindowFunctionCall) any
	VisitWindowImpl(*WindowImpl) any
	VisitWindowReference(*WindowReference) any
	VisitExpressionVariable(*ExpressionVariable) any
	VisitExpressionArrayAccess(*ExpressionArrayAccess) any
	VisitExpressionMakeArray(*ExpressionMakeArray) any
	VisitExpressionFieldAccess(*ExpressionFieldAccess) any
	VisitExpressionParenthesized(*ExpressionParenthesized) any
	VisitExpressionComparison(*ExpressionComparison) any
	VisitExpressionLogical(*ExpressionLogical) any
	VisitExpressionArithmetic(*ExpressionArithmetic) any
	VisitExpressionUnary(*ExpressionUnary) any
	VisitExpressionColumn(*ExpressionColumn) any
	VisitExpressionCollate(*ExpressionCollate) any
	VisitExpressionStringComparison(*ExpressionStringComparison) any
	VisitExpressionIs(*ExpressionIs) any
	VisitExpressionIn(*ExpressionIn) any
	VisitExpressionBetween(*ExpressionBetween) any
	VisitExpressionSubquery(*ExpressionSubquery) any
	VisitExpressionCase(*ExpressionCase) any
	VisitCommonTableExpression(*CommonTableExpression) any
	VisitSQLStatement(*SQLStatement) any
	VisitSelectStatement(*SelectStatement) any
	VisitSelectCore(*SelectCore) any
	VisitResultColumnExpression(*ResultColumnExpression) any
	VisitResultColumnWildcard(*ResultColumnWildcard) any
	VisitRelationTable(*RelationTable) any
	VisitRelationSubquery(*RelationSubquery) any
	VisitRelationTableFunction(*RelationTableFunction) any
	VisitJoin(*Join) any
	VisitUpdateStatement(*UpdateStatement) any
	VisitUpdateSetClause(*UpdateSetClause) any
	VisitDeleteStatement(*DeleteStatement) any
	VisitInsertStatement(*InsertStatement) any
	VisitUpsertClause(*OnConflict) any
	VisitOrderingTerm(*OrderingTerm) any
}

// UnimplementedActionVisitor is meant to be used when an implementing visitor only intends
// to implement the ActionVisitor interface. It will implement the full visitor interface,
// but will panic if any of the methods are called. It does not implement the SQLVisitor or
// ActionVisitor interfaces, so it alone cannot be used as a visitor.
type UnimplementedActionVisitor struct{}

func (s *UnimplementedActionVisitor) VisitActionStmtDeclaration(p0 *ActionStmtDeclaration) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitActionStmtAssignment(p0 *ActionStmtAssign) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitActionStmtCall(p0 *ActionStmtCall) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitActionStmtForLoop(p0 *ActionStmtForLoop) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitLoopTermRange(p0 *LoopTermRange) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitLoopTermSQL(p0 *LoopTermSQL) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitActionStmtIf(p0 *ActionStmtIf) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitIfThen(p0 *IfThen) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitActionStmtSQL(p0 *ActionStmtSQL) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitActionStmtBreak(p0 *ActionStmtLoopControl) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitActionStmtReturn(p0 *ActionStmtReturn) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

func (s *UnimplementedActionVisitor) VisitActionStmtReturnNext(p0 *ActionStmtReturnNext) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", s))
}

type UnimplementedDDLVisitor struct{}

func (u *UnimplementedDDLVisitor) VisitCreateTableStatement(p0 *CreateTableStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitAlterTableStatement(p0 *AlterTableStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitDropTableStatement(p0 *DropTableStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitCreateIndexStatement(p0 *CreateIndexStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitDropIndexStatement(p0 *DropIndexStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitGrantOrRevokeStatement(p0 *GrantOrRevokeStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitAlterColumnSet(p0 *AlterColumnSet) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitAlterColumnDrop(p0 *AlterColumnDrop) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitAddColumn(p0 *AddColumn) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitDropColumn(p0 *DropColumn) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitRenameColumn(p0 *RenameColumn) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitRenameTable(p0 *RenameTable) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitAddTableConstraint(p0 *AddTableConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitDropTableConstraint(p0 *DropTableConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitColumn(p0 *Column) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitCreateRoleStatement(p0 *CreateRoleStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitDropRoleStatement(p0 *DropRoleStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitPrimaryKeyInlineConstraint(p0 *PrimaryKeyInlineConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitPrimaryKeyOutOfLineConstraint(p0 *PrimaryKeyOutOfLineConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitUniqueInlineConstraint(p0 *UniqueInlineConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitUniqueOutOfLineConstraint(p0 *UniqueOutOfLineConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitDefaultConstraint(p0 *DefaultConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitNotNullConstraint(p0 *NotNullConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitCheckConstraint(p0 *CheckConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitForeignKeyReferences(p0 *ForeignKeyReferences) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitForeignKeyOutOfLineConstraint(p0 *ForeignKeyOutOfLineConstraint) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitCreateActionStatement(p0 *CreateActionStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitDropActionStatement(p0 *DropActionStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitUseExtensionStatement(p0 *UseExtensionStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitUnuseExtensionStatement(p0 *UnuseExtensionStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitCreateNamespaceStatement(p0 *CreateNamespaceStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}

func (u *UnimplementedDDLVisitor) VisitDropNamespaceStatement(p0 *DropNamespaceStatement) any {
	panic(fmt.Sprintf("api misuse: cannot visit %T in constrained visitor", u))
}
