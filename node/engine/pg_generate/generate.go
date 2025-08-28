// pggenerate package is responsible for generating the Postgres-compatible SQL from the AST.
package pggenerate

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

/*
	This file implements a visitor to generate Postgres compatible SQL and plpgsql
*/

type GetVarFunc func(varName string) (dataType *types.DataType, err error)

// GenerateSQL generates Postgres compatible SQL from an AST
// If orderParams is true, it will number the parameters as $1, $2, etc.
// It will return the ordered parameters in the order they appear in the statement.
// It will also qualify the table names with the pgSchema.
func GenerateSQL(ast parse.Node, pgSchema string, getVar GetVarFunc) (stmt string, params []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			// we should try to preserve any errors
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("%v", r)
			}
		}
	}()

	s := &sqlGenerator{
		pgSchema: pgSchema,
		getVar:   getVar,
	}

	stmt = ast.Accept(s).(string)
	return stmt + ";", s.orderedParams, nil
}

// sqlVisitor creates Postgres compatible SQL from an AST
type sqlGenerator struct {
	// pgSchema is the schema name to prefix to the table names
	pgSchema string
	// orderedParams is the order of parameters in the order they appear in the statement.
	// It is only set if numberParameters is true. For example, the statement SELECT $1, $2
	// would have orderedParams = ["$1", "$2"]
	orderedParams []string
	getVar        GetVarFunc
}

func (s *sqlGenerator) VisitExpressionLiteral(p0 *parse.ExpressionLiteral) any {
	str, err := formatPGLiteral(p0.Value)
	if err != nil {
		panic(err)
	}

	if p0.GetTypeCast() != nil {
		pgStr, err := p0.GetTypeCast().PGString()
		if err != nil {
			panic(err)
		}
		str += "::" + pgStr
	}

	return str
}

func (s *sqlGenerator) VisitExpressionFunctionCall(p0 *parse.ExpressionFunctionCall) any {
	str := strings.Builder{}

	args := make([]string, len(p0.Args))
	for i, arg := range p0.Args {
		args[i] = arg.Accept(s).(string)
	}

	// if this is not a built-in function, we need to prefix it with
	// the schema name, since it is a local procedure
	fn, ok := engine.Functions[p0.Name]
	if !ok {
		panic("function " + p0.Name + " not found")
	}

	var pgFmt string
	var err error
	// Disallow ORDER BY inside non-aggregate function calls
	if _, isScalar := fn.(*engine.ScalarFunctionDefinition); isScalar && len(p0.OrderBy) > 0 {
		panic(fmt.Errorf("ORDER BY is only supported inside aggregate function calls (got %s)", p0.Name))
	}

	switch fn := fn.(type) {
	case *engine.ScalarFunctionDefinition:
		pgFmt, err = fn.PGFormatFunc(args)
	case *engine.AggregateFunctionDefinition:
		pgFmt, err = fn.PGFormatFunc(args, p0.Distinct)
		if err == nil && len(p0.OrderBy) > 0 {
			// Render ORDER BY terms from parse.OrderingTerm (AST nodes)
			var ob []string
			for _, term := range p0.OrderBy {
				ob = append(ob, term.Accept(s).(string))
			}
			// Replace/append ORDER BY strictly within the function's final parentheses
			openIdx := strings.LastIndex(pgFmt, "(")
			closeIdx := strings.LastIndex(pgFmt, ")")
			if openIdx >= 0 && closeIdx > openIdx {
				inner := pgFmt[openIdx:closeIdx]
				obIdx := strings.LastIndex(inner, " ORDER BY ")
				if obIdx >= 0 {
					// replace existing ORDER BY inside the parens
					inner = inner[:obIdx] + " ORDER BY " + strings.Join(ob, ", ")
				} else {
					// append ORDER BY before closing paren
					inner = inner + " ORDER BY " + strings.Join(ob, ", ")
				}
				pgFmt = pgFmt[:openIdx] + inner + pgFmt[closeIdx:]
			} else {
				// Fallback: append ORDER BY at the end
				if strings.HasSuffix(pgFmt, ")") {
					pgFmt = strings.TrimSuffix(pgFmt, ")") + " ORDER BY " + strings.Join(ob, ", ") + ")"
				} else {
					pgFmt = pgFmt + " ORDER BY " + strings.Join(ob, ", ")
				}
			}
		}
	case *engine.WindowFunctionDefinition:
		pgFmt, err = fn.PGFormatFunc(args)
	case *engine.TableValuedFunctionDefinition:
		pgFmt, err = fn.PGFormatFunc(args)
	default:
		panic("unknown function type " + fmt.Sprintf("%T", fn))
	}
	if err != nil {
		panic(err)
	}
	str.WriteString(pgFmt)

	typeCast(p0, &str)

	return str.String()
}

// typeCast adds a typecast to the string builder if the typecast is not nil
func typeCast(t interface{ GetTypeCast() *types.DataType }, s *strings.Builder) {
	if t.GetTypeCast() != nil {
		pgStr, err := t.GetTypeCast().PGString()
		if err != nil {
			panic(err)
		}

		s.WriteString("::")
		s.WriteString(pgStr)
	}
}

func (s *sqlGenerator) VisitExpressionWindowFunctionCall(p0 *parse.ExpressionWindowFunctionCall) any {
	str := strings.Builder{}
	str.WriteString(p0.FunctionCall.Accept(s).(string))

	if p0.Filter != nil {
		str.WriteString(" FILTER (WHERE ")
		str.WriteString(p0.Filter.Accept(s).(string))
		str.WriteString(")")
	}

	str.WriteString(" OVER ")
	str.WriteString(p0.Window.Accept(s).(string))
	return str.String()
}

func (s *sqlGenerator) VisitWindowImpl(p0 *parse.WindowImpl) any {
	str := strings.Builder{}
	str.WriteString("(")

	if len(p0.PartitionBy) > 0 {
		str.WriteString("PARTITION BY ")
		for i, arg := range p0.PartitionBy {
			if i > 0 {
				str.WriteString(", ")
			}
			str.WriteString(arg.Accept(s).(string))
		}
	}

	if p0.OrderBy != nil {
		str.WriteString(" ORDER BY ")
		for i, arg := range p0.OrderBy {
			if i > 0 {
				str.WriteString(", ")
			}
			str.WriteString(arg.Accept(s).(string))
		}
	}

	str.WriteString(")")
	return str.String()
}

func (s *sqlGenerator) VisitWindowReference(p0 *parse.WindowReference) any {
	return p0.Name
}

func (s *sqlGenerator) VisitExpressionVariable(p0 *parse.ExpressionVariable) any {
	str := p0.String()
	dt, err := s.getVar(str)
	if err != nil {
		panic(err)
	}

	pgStr, err := engine.MakeTypeCast(dt)
	if err != nil {
		panic(err)
	}

	// if it already exists, we write it as that index.
	for i, v := range s.orderedParams {
		if v == str {
			return "$" + strconv.Itoa(i+1) + pgStr
		}
	}

	// otherwise, we add it to the list.
	// Postgres uses $1, $2, etc. for numbered parameters.

	s.orderedParams = append(s.orderedParams, str)

	res := strings.Builder{}
	res.WriteString("$")
	res.WriteString(strconv.Itoa(len(s.orderedParams)))
	res.WriteString(pgStr)
	typeCast(p0, &res)
	return res.String()
}

func (s *sqlGenerator) VisitExpressionArrayAccess(p0 *parse.ExpressionArrayAccess) any {
	str := strings.Builder{}
	// Parenthesize base expression to avoid Postgres syntax issues with casts, e.g. ($1::TEXT[])[idx]
	base := p0.Array.Accept(s).(string)
	str.WriteString("(")
	str.WriteString(base)
	str.WriteString(")[")
	switch {
	case p0.Index != nil:
		str.WriteString(p0.Index.Accept(s).(string))
	default:
		if p0.FromTo[0] != nil {
			str.WriteString(p0.FromTo[0].Accept(s).(string))
		}
		str.WriteString(":")
		if p0.FromTo[1] != nil {
			str.WriteString(p0.FromTo[1].Accept(s).(string))
		}
	}
	str.WriteString("]")
	typeCast(p0, &str)
	return str.String()
}

func (s *sqlGenerator) VisitExpressionMakeArray(p0 *parse.ExpressionMakeArray) any {
	str := strings.Builder{}
	str.WriteString("ARRAY[")
	for i, arg := range p0.Values {
		if i > 0 {
			str.WriteString(", ")
		}
		str.WriteString(arg.Accept(s).(string))
	}
	str.WriteString("]")
	typeCast(p0, &str)
	return str.String()
}

func (s *sqlGenerator) VisitExpressionFieldAccess(p0 *parse.ExpressionFieldAccess) any {
	str := strings.Builder{}
	str.WriteString(p0.Record.Accept(s).(string))
	str.WriteString(".")
	str.WriteString(p0.Field)
	typeCast(p0, &str)
	return str.String()
}

func (s *sqlGenerator) VisitExpressionParenthesized(p0 *parse.ExpressionParenthesized) any {
	str := strings.Builder{}
	str.WriteString("(")
	str.WriteString(p0.Inner.Accept(s).(string))
	str.WriteString(")")
	typeCast(p0, &str)
	return str.String()
}

func (s *sqlGenerator) VisitExpressionComparison(p0 *parse.ExpressionComparison) any {
	str := strings.Builder{}
	str.WriteString(p0.Left.Accept(s).(string))
	str.WriteString(" ")
	str.WriteString(string(p0.Operator))
	str.WriteString(" ")
	str.WriteString(p0.Right.Accept(s).(string))
	// compare cannot be typecasted
	return str.String()
}

func (s *sqlGenerator) VisitExpressionLogical(p0 *parse.ExpressionLogical) any {
	str := strings.Builder{}
	str.WriteString(p0.Left.Accept(s).(string))
	str.WriteString(" ")
	str.WriteString(string(p0.Operator))
	str.WriteString(" ")
	str.WriteString(p0.Right.Accept(s).(string))
	// logical cannot be typecasted
	return str.String()
}

func (s *sqlGenerator) VisitExpressionArithmetic(p0 *parse.ExpressionArithmetic) any {
	str := strings.Builder{}
	str.WriteString(p0.Left.Accept(s).(string))
	str.WriteString(" ")
	str.WriteString(string(p0.Operator))
	str.WriteString(" ")
	str.WriteString(p0.Right.Accept(s).(string))
	// cannot be typecasted
	return str.String()
}

func (s *sqlGenerator) VisitExpressionUnary(p0 *parse.ExpressionUnary) any {
	str := strings.Builder{}
	str.WriteString(string(p0.Operator))
	str.WriteString(" ")
	str.WriteString(p0.Expression.Accept(s).(string))
	// cannot be typecasted
	return str.String()
}

func (s *sqlGenerator) VisitExpressionColumn(p0 *parse.ExpressionColumn) any {
	str := strings.Builder{}
	if p0.Table != "" {
		str.WriteString(p0.Table)
		str.WriteString(".")
	}
	str.WriteString(p0.Column)
	typeCast(p0, &str)
	return str.String()
}

func (s *sqlGenerator) VisitExpressionCollate(p0 *parse.ExpressionCollate) any {
	str := strings.Builder{}
	str.WriteString(p0.Expression.Accept(s).(string))
	str.WriteString(" COLLATE ")
	str.WriteString(p0.Collation)
	return str.String()
}

func (s *sqlGenerator) VisitExpressionStringComparison(p0 *parse.ExpressionStringComparison) any {
	str := strings.Builder{}
	str.WriteString(p0.Left.Accept(s).(string))
	str.WriteString(" ")
	if p0.Not {
		str.WriteString("NOT ")
	}
	str.WriteString(string(p0.Operator))
	str.WriteString(" ")
	str.WriteString(p0.Right.Accept(s).(string))
	// compare cannot be typecasted
	return str.String()
}

func (s *sqlGenerator) VisitExpressionIs(p0 *parse.ExpressionIs) any {
	str := strings.Builder{}
	str.WriteString(p0.Left.Accept(s).(string))
	str.WriteString(" IS ")
	if p0.Not {
		str.WriteString("NOT ")
	}
	if p0.Distinct {
		str.WriteString("DISTINCT FROM ")
	}
	str.WriteString(p0.Right.Accept(s).(string))
	// cannot be typecasted
	return str.String()
}

func (s *sqlGenerator) VisitExpressionIn(p0 *parse.ExpressionIn) any {
	str := strings.Builder{}
	str.WriteString(p0.Expression.Accept(s).(string))
	if p0.Not {
		str.WriteString(" NOT")
	}
	str.WriteString(" IN (")
	if len(p0.List) > 0 {
		for i, arg := range p0.List {
			if i > 0 {
				str.WriteString(", ")
			}

			str.WriteString(arg.Accept(s).(string))
		}
	} else if p0.Subquery != nil {
		str.WriteString(p0.Subquery.Accept(s).(string))
	} else {
		panic("IN must specify list or subquery")
	}
	str.WriteString(")")

	return str.String()
}

func (s *sqlGenerator) VisitExpressionBetween(p0 *parse.ExpressionBetween) any {
	str := strings.Builder{}
	str.WriteString(p0.Expression.Accept(s).(string))
	if p0.Not {
		str.WriteString(" NOT")
	}
	str.WriteString(" BETWEEN ")

	str.WriteString(p0.Lower.Accept(s).(string))
	str.WriteString(" AND ")
	str.WriteString(p0.Upper.Accept(s).(string))

	return str.String()
}

func (s *sqlGenerator) VisitExpressionSubquery(p0 *parse.ExpressionSubquery) any {
	str := strings.Builder{}
	if p0.Exists {
		if p0.Not {
			str.WriteString("NOT ")
		}
		str.WriteString("EXISTS ")
	}

	str.WriteString("(")
	str.WriteString(p0.Subquery.Accept(s).(string))
	str.WriteString(")")
	typeCast(p0, &str)
	return str.String()
}

func (s *sqlGenerator) VisitExpressionCase(p0 *parse.ExpressionCase) any {
	str := strings.Builder{}
	str.WriteString("CASE")
	if p0.Case != nil {
		str.WriteString(" ")
		str.WriteString(p0.Case.Accept(s).(string))
	}
	for _, whenThen := range p0.WhenThen {
		str.WriteString("\n WHEN ")
		str.WriteString(whenThen[0].Accept(s).(string))
		str.WriteString("\n THEN ")
		str.WriteString(whenThen[1].Accept(s).(string))
	}
	if p0.Else != nil {
		str.WriteString("\n ELSE ")
		str.WriteString(p0.Else.Accept(s).(string))
	}
	str.WriteString("\n END")
	return str.String()
}

func (s *sqlGenerator) VisitCommonTableExpression(p0 *parse.CommonTableExpression) any {
	str := strings.Builder{}
	str.WriteString(p0.Name)
	if p0.Columns != nil {
		str.WriteString(" (")
		for i, col := range p0.Columns {
			if i > 0 {
				str.WriteString(", ")
			}
			str.WriteString(col)
		}
		str.WriteString(")")
	}
	str.WriteString(" AS (")
	str.WriteString(p0.Query.Accept(s).(string))
	str.WriteString(")")
	return str.String()
}

func (s *sqlGenerator) VisitSQLStatement(p0 *parse.SQLStatement) any {
	str := strings.Builder{}
	for i, cte := range p0.CTEs {
		if i > 0 {
			str.WriteString(", ")
		}
		if i == 0 {
			str.WriteString("WITH ")
			if p0.Recursive {
				str.WriteString("RECURSIVE ")
			}
		}
		str.WriteString(cte.Accept(s).(string))
	}
	str.WriteString("\n")

	str.WriteString(p0.SQL.Accept(s).(string))

	return str.String()
}

func (s *sqlGenerator) VisitSelectStatement(p0 *parse.SelectStatement) any {
	str := strings.Builder{}
	for i, core := range p0.SelectCores {
		if i > 0 {
			str.WriteString(" ")
			str.WriteString(string(p0.CompoundOperators[i-1]))
			str.WriteString(" ")
		}
		str.WriteString(core.Accept(s).(string))
		str.WriteString("\n")
	}

	for i, order := range p0.Ordering {
		if i == 0 {
			str.WriteString("ORDER BY ")
		} else {
			str.WriteString(", ")
		}

		str.WriteString(order.Accept(s).(string))
	}

	if p0.Limit != nil {
		str.WriteString(" LIMIT ")
		str.WriteString(p0.Limit.Accept(s).(string))
	}

	if p0.Offset != nil {
		str.WriteString(" OFFSET ")
		str.WriteString(p0.Offset.Accept(s).(string))
	}

	return str.String()
}

func (s *sqlGenerator) VisitSelectCore(p0 *parse.SelectCore) any {
	str := strings.Builder{}
	str.WriteString("SELECT ")
	if p0.Distinct {
		str.WriteString("DISTINCT ")
	}

	for i, resultColumn := range p0.Columns {
		if i > 0 {
			str.WriteString(", ")
		}
		str.WriteString(resultColumn.Accept(s).(string))
	}

	if p0.From != nil {
		str.WriteString("\nFROM ")
		str.WriteString(p0.From.Accept(s).(string))
	}

	for _, join := range p0.Joins {
		str.WriteString("\n")
		str.WriteString(join.Accept(s).(string))
	}

	if p0.Where != nil {
		str.WriteString("\nWHERE ")
		str.WriteString(p0.Where.Accept(s).(string))
	}

	if p0.GroupBy != nil {
		str.WriteString("\nGROUP BY ")
		for i, groupBy := range p0.GroupBy {
			if i > 0 {
				str.WriteString(", ")
			}
			str.WriteString(groupBy.Accept(s).(string))
		}

		if p0.Having != nil {
			str.WriteString("\nHAVING ")
			str.WriteString(p0.Having.Accept(s).(string))
		}
	}

	if len(p0.Windows) > 0 {
		str.WriteString("\nWINDOW ")
		for i, window := range p0.Windows {
			if i > 0 {
				str.WriteString(", ")
			}
			str.WriteString(window.Name)
			str.WriteString(" AS ")
			str.WriteString(window.Window.Accept(s).(string))
		}
	}

	return str.String()
}

func (s *sqlGenerator) VisitResultColumnExpression(p0 *parse.ResultColumnExpression) any {
	str := strings.Builder{}
	str.WriteString(p0.Expression.Accept(s).(string))
	if p0.Alias != "" {
		str.WriteString(" AS ")
		str.WriteString(p0.Alias)
	}
	return str.String()
}

func (s *sqlGenerator) VisitResultColumnWildcard(p0 *parse.ResultColumnWildcard) any {
	str := strings.Builder{}
	if p0.Table != "" {
		str.WriteString(p0.Table)
		str.WriteString(".")
	}
	str.WriteString("*")
	return str.String()
}

func (s *sqlGenerator) VisitRelationTable(p0 *parse.RelationTable) any {
	str := strings.Builder{}
	// we do not rely on the s.pgSchema here, since we want to this table might
	// be a common table expression. The planner qualifies the table names.
	// If no Namespace is set, it is likely a CTE
	if p0.Namespace != "" {
		str.WriteString(p0.Namespace)
		str.WriteString(".")
	}
	// we do not set the pgschema here because we want to allow for CTEs
	// Therefore, the pgschema must be set here using the planner
	str.WriteString(p0.Table)
	if p0.Alias != "" {
		str.WriteString(" AS ")
		str.WriteString(p0.Alias)
	}
	return str.String()
}

func (s *sqlGenerator) VisitRelationSubquery(p0 *parse.RelationSubquery) any {
	str := strings.Builder{}
	str.WriteString("(")
	str.WriteString(p0.Subquery.Accept(s).(string))
	str.WriteString(") ")
	if p0.Alias != "" {
		str.WriteString("AS ")
		str.WriteString(p0.Alias)
	}
	return str.String()
}

func (s *sqlGenerator) VisitRelationTableFunction(p0 *parse.RelationTableFunction) any {
	str := strings.Builder{}
	str.WriteString(p0.FunctionCall.Accept(s).(string))

	// Add WITH ORDINALITY if specified
	if p0.WithOrdinality {
		str.WriteString(" WITH ORDINALITY")
	}

	if p0.Alias != "" || len(p0.ColumnAliases) > 0 {
		str.WriteString(" AS ")
		if p0.Alias != "" {
			str.WriteString(p0.Alias)
		} else {
			str.WriteString("t") // Default table alias
		}

		if len(p0.ColumnAliases) > 0 {
			str.WriteString("(")
			str.WriteString(strings.Join(p0.ColumnAliases, ", "))
			str.WriteString(")")
		}
	}
	return str.String()
}

func (s *sqlGenerator) VisitJoin(p0 *parse.Join) any {
	str := strings.Builder{}
	str.WriteString(string(p0.Type))
	str.WriteString(" JOIN ")
	str.WriteString(p0.Relation.Accept(s).(string))
	// we do not worry about on being nil, since Kwil
	// forces the user to specify the join condition
	// to prevent cartesian products
	str.WriteString(" ON ")
	str.WriteString(p0.On.Accept(s).(string))
	return str.String()
}

func (s *sqlGenerator) VisitUpdateStatement(p0 *parse.UpdateStatement) any {
	str := strings.Builder{}
	str.WriteString("UPDATE ")
	if s.pgSchema != "" {
		str.WriteString(s.pgSchema)
		str.WriteString(".")
	}
	str.WriteString(p0.Table)
	if p0.Alias != "" {
		str.WriteString(" AS ")
		str.WriteString(p0.Alias)
	}
	str.WriteString("\nSET ")
	for i, set := range p0.SetClause {
		if i > 0 {
			str.WriteString(",\n")
		}
		str.WriteString(set.Accept(s).(string))
	}

	if p0.From != nil {
		str.WriteString("\nFROM ")
		str.WriteString(p0.From.Accept(s).(string))
	}

	for _, join := range p0.Joins {
		str.WriteString("\n")
		str.WriteString(join.Accept(s).(string))
	}

	if p0.Where != nil {
		str.WriteString("\nWHERE ")
		str.WriteString(p0.Where.Accept(s).(string))
	}

	return str.String()
}

func (s *sqlGenerator) VisitUpdateSetClause(p0 *parse.UpdateSetClause) any {
	str := strings.Builder{}
	str.WriteString(p0.Column)
	str.WriteString(" = ")
	str.WriteString(p0.Value.Accept(s).(string))
	return str.String()
}

func (s *sqlGenerator) VisitDeleteStatement(p0 *parse.DeleteStatement) any {
	str := strings.Builder{}
	str.WriteString("DELETE FROM ")

	if s.pgSchema != "" {
		str.WriteString(s.pgSchema)
		str.WriteString(".")
	}

	str.WriteString(p0.Table)
	if p0.Alias != "" {
		str.WriteString(" AS ")
		str.WriteString(p0.Alias)
	}

	if p0.From != nil {
		str.WriteString("\nFROM ")
		str.WriteString(p0.From.Accept(s).(string))
	}

	for _, join := range p0.Joins {
		str.WriteString("\n")
		str.WriteString(join.Accept(s).(string))
	}

	if p0.Where != nil {
		str.WriteString("\nWHERE ")
		str.WriteString(p0.Where.Accept(s).(string))
	}

	return str.String()
}

func (s *sqlGenerator) VisitInsertStatement(p0 *parse.InsertStatement) any {
	str := strings.Builder{}
	str.WriteString("INSERT INTO ")
	if s.pgSchema != "" {
		str.WriteString(s.pgSchema)
		str.WriteString(".")
	}

	str.WriteString(p0.Table)
	if p0.Alias != "" {
		str.WriteString(" AS ")
		str.WriteString(p0.Alias)
	}
	if len(p0.Columns) > 0 {
		str.WriteString(" (")

		for i, col := range p0.Columns {
			if i > 0 {
				str.WriteString(", ")
			}
			str.WriteString(col)
		}

		str.WriteString(") ")
	}

	str.WriteString("\n")
	if p0.Select != nil {
		str.WriteString(p0.Select.Accept(s).(string))
	} else {
		str.WriteString("VALUES ")
		for i, val := range p0.Values {
			if i > 0 {
				str.WriteString(",")
			}
			str.WriteString("\n(")
			for j, v := range val {
				if j > 0 {
					str.WriteString(", ")
				}
				str.WriteString(v.Accept(s).(string))
			}
			str.WriteString(")")
		}
	}

	if p0.OnConflict != nil {
		str.WriteString("\n")
		str.WriteString(p0.OnConflict.Accept(s).(string))
	}

	return str.String()
}

func (s *sqlGenerator) VisitUpsertClause(p0 *parse.OnConflict) any {
	str := strings.Builder{}
	str.WriteString("ON CONFLICT ")
	if len(p0.ConflictColumns) > 0 {
		str.WriteString("(")
		for i, col := range p0.ConflictColumns {
			if i > 0 {
				str.WriteString(", ")
			}
			str.WriteString(col)
		}
		str.WriteString(")\n")

		if p0.ConflictWhere != nil {
			str.WriteString("WHERE ")
			str.WriteString(p0.ConflictWhere.Accept(s).(string))
			str.WriteString("\n")
		}
	}

	str.WriteString("DO ")
	if len(p0.DoUpdate) == 0 {
		str.WriteString("NOTHING")
	} else {
		str.WriteString("UPDATE SET")
		for i, set := range p0.DoUpdate {
			if i > 0 {
				str.WriteString(",")
			}
			str.WriteString("\n	")
			str.WriteString(set.Accept(s).(string))
		}

		if p0.UpdateWhere != nil {
			str.WriteString("\nWHERE ")
			str.WriteString(p0.UpdateWhere.Accept(s).(string))
		}
	}

	return str.String()
}

func (s *sqlGenerator) VisitOrderingTerm(p0 *parse.OrderingTerm) any {
	str := strings.Builder{}
	str.WriteString(p0.Expression.Accept(s).(string))

	if p0.Order != "" {
		str.WriteString(" ")
		str.WriteString(string(p0.Order))
	}

	if p0.Nulls != "" {
		str.WriteString(" NULLS ")
		str.WriteString(string(p0.Nulls))
	}

	return str.String()
}

func (s *sqlGenerator) VisitCreateTableStatement(p0 *parse.CreateTableStatement) any {
	str := strings.Builder{}
	str.WriteString("CREATE TABLE ")
	if p0.IfNotExists {
		str.WriteString("IF NOT EXISTS ")
	}

	if s.pgSchema != "" {
		str.WriteString(s.pgSchema)
		str.WriteString(".")
	}

	str.WriteString(p0.Name)
	str.WriteString(" (\n")
	for i, col := range p0.Columns {
		if i > 0 {
			str.WriteString(",	\n")
		}

		str.WriteString(col.Accept(s).(string))
	}

	for _, con := range p0.Constraints {
		str.WriteString(",\n")

		if con.Name != "" {
			str.WriteString("CONSTRAINT ")
			str.WriteString(con.Name)
			str.WriteString(" ")
		}

		str.WriteString(con.Constraint.Accept(s).(string))
	}

	str.WriteString("\n)")
	return str.String()
}

func (s *sqlGenerator) VisitAlterTableStatement(p0 *parse.AlterTableStatement) any {
	str := strings.Builder{}
	str.WriteString("ALTER TABLE ")
	if s.pgSchema != "" {
		str.WriteString(s.pgSchema)
		str.WriteString(".")
	}
	str.WriteString(p0.Table)
	str.WriteString(" ")

	for i, action := range p0.Actions {
		if i > 0 {
			str.WriteString(",")
		}
		str.WriteString(action.Accept(s).(string))
	}

	return str.String()
}

func (s *sqlGenerator) VisitDropTableStatement(p0 *parse.DropTableStatement) any {
	str := strings.Builder{}
	str.WriteString("DROP TABLE ")
	if p0.IfExists {
		str.WriteString("IF EXISTS ")
	}

	for i, table := range p0.Tables {
		if i > 0 {
			str.WriteString(", ")
		}
		if s.pgSchema != "" {
			str.WriteString(s.pgSchema)
			str.WriteString(".")
		}
		str.WriteString(table)
	}

	switch p0.Behavior {
	case parse.DropBehaviorCascade:
		str.WriteString(" CASCADE")
	case parse.DropBehaviorRestrict:
		str.WriteString(" RESTRICT")
	case parse.DropBehaviorDefault:
		// do nothing
	default:
		panic("unknown drop behavior")
	}
	return str.String()
}

func (s *sqlGenerator) VisitCreateIndexStatement(p0 *parse.CreateIndexStatement) any {
	str := strings.Builder{}
	str.WriteString("CREATE ")

	switch p0.Type {
	case parse.IndexTypeBTree:
		str.WriteString("INDEX ")
	case parse.IndexTypeUnique:
		str.WriteString("UNIQUE INDEX ")
	default:
		// should not happen
		panic("unknown index type")
	}

	if p0.IfNotExists {
		str.WriteString("IF NOT EXISTS ")
	}
	if p0.Name != "" {
		str.WriteString(p0.Name)
		str.WriteString(" ")
	}
	str.WriteString("ON ")
	str.WriteString(s.qualify(p0.On))
	str.WriteString("(" + strings.Join(p0.Columns, ", ") + ")")

	return str.String()
}

// qualify prefixes the table name with the schema name, if it exists
func (s *sqlGenerator) qualify(p0 string) string {
	if s.pgSchema != "" {
		return s.pgSchema + "." + p0
	}
	return p0
}

func (s *sqlGenerator) VisitDropIndexStatement(p0 *parse.DropIndexStatement) any {
	str := strings.Builder{}
	str.WriteString("DROP INDEX ")
	if p0.CheckExist {
		str.WriteString("IF EXISTS ")
	}
	str.WriteString(s.qualify(p0.Name))
	return str.String()
}

func (s *sqlGenerator) VisitGrantOrRevokeStatement(p0 *parse.GrantOrRevokeStatement) any {
	panic("generate should never be called on a grant or revoke statement")
}

func (s *sqlGenerator) VisitAlterColumnSet(p0 *parse.AlterColumnSet) any {
	str := strings.Builder{}
	str.WriteString("ALTER COLUMN ")
	str.WriteString(p0.Column)
	str.WriteString(" SET ")
	str.WriteString(p0.Type.String())

	if p0.Type == parse.ConstraintTypeDefault {
		str.WriteString(" ")
		str.WriteString(p0.Value.Accept(s).(string))
	}

	return str.String()
}

func (s *sqlGenerator) VisitAlterColumnDrop(p0 *parse.AlterColumnDrop) any {
	str := strings.Builder{}
	str.WriteString("ALTER COLUMN ")
	str.WriteString(p0.Column)
	str.WriteString(" DROP ")
	str.WriteString(p0.Type.String())
	return str.String()
}

func (s *sqlGenerator) VisitAddColumn(p0 *parse.AddColumn) any {
	str := strings.Builder{}
	str.WriteString("ADD COLUMN ")
	str.WriteString(p0.Name)
	str.WriteString(" ")

	typeStr, err := p0.Type.PGString()
	if err != nil {
		panic(err)
	}

	str.WriteString(typeStr)
	return str.String()
}

func (s *sqlGenerator) VisitDropColumn(p0 *parse.DropColumn) any {
	str := strings.Builder{}
	str.WriteString("DROP COLUMN ")
	str.WriteString(p0.Name)
	return str.String()
}

func (s *sqlGenerator) VisitRenameColumn(p0 *parse.RenameColumn) any {
	str := strings.Builder{}
	str.WriteString("RENAME COLUMN ")
	str.WriteString(p0.OldName)
	str.WriteString(" TO ")
	str.WriteString(p0.NewName)
	return str.String()
}

func (s *sqlGenerator) VisitRenameTable(p0 *parse.RenameTable) any {
	str := strings.Builder{}
	str.WriteString("RENAME TO ")
	str.WriteString(p0.Name)
	return str.String()
}

func (s *sqlGenerator) VisitAddTableConstraint(p0 *parse.AddTableConstraint) any {
	str := strings.Builder{}
	str.WriteString("ADD ")
	if p0.Constraint.Name != "" {
		str.WriteString("CONSTRAINT ")
		str.WriteString(p0.Constraint.Name)
		str.WriteString(" ")
	}

	str.WriteString(p0.Constraint.Constraint.Accept(s).(string))
	return str.String()
}

func (s *sqlGenerator) VisitDropTableConstraint(p0 *parse.DropTableConstraint) any {
	str := strings.Builder{}
	str.WriteString("DROP CONSTRAINT ")
	str.WriteString(p0.Name)
	return str.String()
}

func (s *sqlGenerator) VisitColumn(p0 *parse.Column) any {
	str := strings.Builder{}
	str.WriteString(p0.Name)
	str.WriteString(" ")

	typeStr, err := p0.Type.PGString()
	if err != nil {
		panic(err)
	}

	str.WriteString(typeStr)
	for _, con := range p0.Constraints {
		str.WriteString(" ")
		str.WriteString(con.Accept(s).(string))
	}

	return str.String()
}

func (s *sqlGenerator) VisitCreateRoleStatement(p0 *parse.CreateRoleStatement) any {
	panic("create role should never be used within a generated SQL statement")
}

func (s *sqlGenerator) VisitDropRoleStatement(p0 *parse.DropRoleStatement) any {
	panic("drop role should never be used within a generated SQL statement")
}

func (s *sqlGenerator) VisitPrimaryKeyInlineConstraint(p0 *parse.PrimaryKeyInlineConstraint) any {
	return "PRIMARY KEY"
}

func (s *sqlGenerator) VisitPrimaryKeyOutOfLineConstraint(p0 *parse.PrimaryKeyOutOfLineConstraint) any {
	str := strings.Builder{}
	str.WriteString("PRIMARY KEY(")
	str.WriteString(strings.Join(p0.Columns, ", "))
	str.WriteString(")")
	return str.String()
}

func (s *sqlGenerator) VisitUniqueInlineConstraint(p0 *parse.UniqueInlineConstraint) any {
	return "UNIQUE"
}

func (s *sqlGenerator) VisitUniqueOutOfLineConstraint(p0 *parse.UniqueOutOfLineConstraint) any {
	str := strings.Builder{}
	str.WriteString("UNIQUE(")
	str.WriteString(strings.Join(p0.Columns, ", "))
	str.WriteString(")")
	return str.String()
}

func (s *sqlGenerator) VisitDefaultConstraint(p0 *parse.DefaultConstraint) any {
	str := strings.Builder{}
	str.WriteString("DEFAULT ")
	str.WriteString(p0.Value.Accept(s).(string))
	return str.String()
}

func (s *sqlGenerator) VisitNotNullConstraint(p0 *parse.NotNullConstraint) any {
	return "NOT NULL"
}

func (s *sqlGenerator) VisitCheckConstraint(p0 *parse.CheckConstraint) any {
	str := strings.Builder{}
	str.WriteString("CHECK(")
	str.WriteString(p0.Expression.Accept(s).(string))
	str.WriteString(")")
	return str.String()
}

func (s *sqlGenerator) VisitForeignKeyReferences(fk *parse.ForeignKeyReferences) any {
	str := strings.Builder{}
	str.WriteString("REFERENCES ")

	if fk.RefTableNamespace != "" {
		str.WriteString(fk.RefTableNamespace)
		str.WriteString(".")
	} else if s.pgSchema != "" {
		str.WriteString(s.pgSchema)
		str.WriteString(".")
	}

	str.WriteString(fk.RefTable)
	str.WriteString("(")
	str.WriteString(strings.Join(fk.RefColumns, ", "))
	str.WriteString(")")

	for _, action := range fk.Actions {
		str.WriteString(" ON ")
		str.WriteString(string(action.On)) // update or delete
		str.WriteString(" ")
		str.WriteString(string(action.Do)) // cascade, restrict, etc.
	}
	return str.String()
}

func (s *sqlGenerator) VisitForeignKeyOutOfLineConstraint(p0 *parse.ForeignKeyOutOfLineConstraint) any {
	str := strings.Builder{}
	str.WriteString("FOREIGN KEY(")
	str.WriteString(strings.Join(p0.Columns, ", "))
	str.WriteString(") ")
	str.WriteString(p0.References.Accept(s).(string))
	return str.String()
}

// formatPGLiteral formats a literal for user in postgres.
func formatPGLiteral(value any) (string, error) {
	str := strings.Builder{}
	switch v := value.(type) {
	case string: // for text type
		// escape single quotes
		str.WriteString("'")
		str.WriteString(strings.ReplaceAll(v, "'", "''"))
		str.WriteString("'")
	case int64, int, int32: // for int type
		str.WriteString(fmt.Sprint(v))
	case types.UUID:
		str.WriteString(v.String())
	case *types.UUID:
		str.WriteString(v.String())
	case *types.Decimal:
		str.WriteString(v.String())
	case bool: // for bool type
		if v {
			str.WriteString("true")
		} else {
			str.WriteString("false")
		}
	case []byte: // for blob type: https://dba.stackexchange.com/questions/203358/how-do-i-write-a-hex-literal-in-postgresql
		str.WriteString(fmt.Sprintf("E'\\\\x%x'", v))
	case nil:
		str.WriteString("NULL")
	case fmt.Stringer:
		str.WriteString(v.String())
	default:
		return "", fmt.Errorf("unsupported literal type: %T", v)
	}

	return str.String(), nil
}

func (s *sqlGenerator) VisitLoopTermRange(p0 *parse.LoopTermRange) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitLoopTermExpression(p0 *parse.LoopTermExpression) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitLoopTermSQL(p0 *parse.LoopTermSQL) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitProcedureStmtIf(p0 *parse.ActionStmtIf) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitIfThen(p0 *parse.IfThen) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitProcedureStmtSQL(p0 *parse.ActionStmtSQL) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitProcedureStmtBreak(p0 *parse.ActionStmtLoopControl) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitProcedureStmtReturn(p0 *parse.ActionStmtReturn) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitProcedureStmtReturnNext(p0 *parse.ActionStmtReturnNext) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitUseExtensionStatement(p0 *parse.UseExtensionStatement) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitUnuseExtensionStatement(p0 *parse.UnuseExtensionStatement) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitCreateActionStatement(p0 *parse.CreateActionStatement) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitDropActionStatement(p0 *parse.DropActionStatement) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitActionStmtDeclaration(p0 *parse.ActionStmtDeclaration) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitActionStmtAssignment(p0 *parse.ActionStmtAssign) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitActionStmtCall(p0 *parse.ActionStmtCall) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitActionStmtForLoop(p0 *parse.ActionStmtForLoop) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitActionStmtIf(p0 *parse.ActionStmtIf) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitActionStmtSQL(p0 *parse.ActionStmtSQL) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitActionStmtLoopControl(p0 *parse.ActionStmtLoopControl) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitActionStmtReturn(p0 *parse.ActionStmtReturn) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitActionStmtReturnNext(p0 *parse.ActionStmtReturnNext) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitCreateNamespaceStatement(p0 *parse.CreateNamespaceStatement) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitDropNamespaceStatement(p0 *parse.DropNamespaceStatement) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitTransferOwnershipStatement(p0 *parse.TransferOwnershipStatement) any {
	generateErr(s)
	return nil
}

func (s *sqlGenerator) VisitSetCurrentNamespaceStatement(p0 *parse.SetCurrentNamespaceStatement) any {
	generateErr(s)
	return nil
}

// generateErr is a helper function that panics when a Visit method that is unexpected is called.
func generateErr(t any) {
	panic(fmt.Sprintf("SQL generate should never be called on %T", t))
}
