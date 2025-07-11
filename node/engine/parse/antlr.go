package parse

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	antlr "github.com/antlr4-go/antlr/v4"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/core/types/validation"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/engine/parse/gen"
)

// schemaVisitor is a visitor for converting Kuneiform's ANTLR
// generated parse tree into our native schema type. It will perform
// syntax validation on actions.
type schemaVisitor struct {
	antlr.BaseParseTreeVisitor
	// errs is used for passing errors back to the caller.
	errs *errorListener
	// stream is the input stream
	stream *antlr.InputStream
}

// getTextFromStream gets the text from the input stream for a given range.
// This is a hack over a bug in the generated antlr code, where it will try
// to access index out of bounds.
func (s *schemaVisitor) getTextFromStream(start, stop int) (str string) {
	defer func() {
		if r := recover(); r != nil {
			str = ""
		}
	}()

	return s.stream.GetText(start, stop)
}

// newSchemaVisitor creates a new schema visitor.
func newSchemaVisitor(stream *antlr.InputStream, errLis *errorListener) *schemaVisitor {
	return &schemaVisitor{
		errs:   errLis,
		stream: stream,
	}
}

var _ gen.KuneiformParserVisitor = (*schemaVisitor)(nil)

func (s *schemaVisitor) VisitEntry(ctx *gen.EntryContext) any {
	var stmts []TopLevelStatement
	for _, stmt := range ctx.AllStatement() {
		stmts = append(stmts, stmt.Accept(s).(TopLevelStatement))
	}

	return stmts
}

func (s *schemaVisitor) VisitStatement(ctx *gen.StatementContext) any {
	var s2 TopLevelStatement
	switch {
	case ctx.Sql_statement() != nil:
		s2 = ctx.Sql_statement().Accept(s).(*SQLStatement)
	case ctx.Create_table_statement() != nil:
		s2 = ctx.Create_table_statement().Accept(s).(TopLevelStatement)
	case ctx.Alter_table_statement() != nil:
		s2 = ctx.Alter_table_statement().Accept(s).(TopLevelStatement)
	case ctx.Drop_table_statement() != nil:
		s2 = ctx.Drop_table_statement().Accept(s).(TopLevelStatement)
	case ctx.Create_index_statement() != nil:
		s2 = ctx.Create_index_statement().Accept(s).(TopLevelStatement)
	case ctx.Drop_index_statement() != nil:
		s2 = ctx.Drop_index_statement().Accept(s).(TopLevelStatement)
	case ctx.Create_role_statement() != nil:
		s2 = ctx.Create_role_statement().Accept(s).(TopLevelStatement)
	case ctx.Drop_role_statement() != nil:
		s2 = ctx.Drop_role_statement().Accept(s).(TopLevelStatement)
	case ctx.Grant_statement() != nil:
		s2 = ctx.Grant_statement().Accept(s).(TopLevelStatement)
	case ctx.Revoke_statement() != nil:
		s2 = ctx.Revoke_statement().Accept(s).(TopLevelStatement)
	case ctx.Transfer_ownership_statement() != nil:
		s2 = ctx.Transfer_ownership_statement().Accept(s).(TopLevelStatement)
	case ctx.Create_action_statement() != nil:
		s3 := ctx.Create_action_statement().Accept(s).(*CreateActionStatement)
		r := s.getTextFromStream(ctx.GetStart().GetStart(), ctx.GetStop().GetStop()) + ";"
		s3.Raw = r
		s2 = s3
	case ctx.Drop_action_statement() != nil:
		s2 = ctx.Drop_action_statement().Accept(s).(TopLevelStatement)
	case ctx.Create_namespace_statement() != nil:
		s2 = ctx.Create_namespace_statement().Accept(s).(TopLevelStatement)
	case ctx.Drop_namespace_statement() != nil:
		s2 = ctx.Drop_namespace_statement().Accept(s).(TopLevelStatement)
	case ctx.Use_extension_statement() != nil:
		s2 = ctx.Use_extension_statement().Accept(s).(TopLevelStatement)
	case ctx.Unuse_extension_statement() != nil:
		s2 = ctx.Unuse_extension_statement().Accept(s).(TopLevelStatement)
	case ctx.Set_current_namespace_statement() != nil:
		s2 = ctx.Set_current_namespace_statement().Accept(s).(TopLevelStatement)
	default:
		panic(fmt.Sprintf("unknown parser entry: %s", ctx.GetText()))
	}

	if ctx.GetNamespace() != nil {
		namespaceable, ok := s2.(Namespaceable)
		if !ok {
			s.errs.RuleErr(ctx, ErrSyntax, fmt.Sprintf("statement %T cannot have a namespace", s2))
		} else {
			namespaceable.SetNamespacePrefix(s.getIdent(ctx.GetNamespace()))
		}
	}

	return s2
}

func (s *schemaVisitor) VisitCreate_action_statement(ctx *gen.Create_action_statementContext) any {
	cas := &CreateActionStatement{
		IfNotExists: ctx.EXISTS() != nil,
		OrReplace:   ctx.REPLACE() != nil,
		Name:        s.getIdent(ctx.Identifier(0)),
		Parameters:  arr[*engine.NamedType](len(ctx.AllAction_parameter())),
		Statements:  arr[ActionStmt](len(ctx.AllAction_statement())),
		Raw:         s.getTextFromStream(ctx.GetStart().GetStart(), ctx.GetStop().GetStop()),
	}

	if cas.IfNotExists && cas.OrReplace {
		s.errs.RuleErr(ctx, ErrSyntax, `cannot have both "OR REPLACE" and "IF NOT EXISTS" clauses`)
		return cas
	}

	allIdents := ctx.AllIdentifier()
	foundMods := make(map[string]struct{})
	for _, id := range allIdents[1:] {
		modText := s.getIdent(id)
		if _, ok := foundMods[modText]; ok {
			s.errs.RuleErr(ctx, ErrSyntax, "modifier %s redeclared", modText)
		}
		foundMods[modText] = struct{}{}

		cas.Modifiers = append(cas.Modifiers, modText)
	}

	paramSet := make(map[string]struct{})
	for i, param := range ctx.AllAction_parameter() {
		paramCtx := param.(*gen.Action_parameterContext)
		name := s.cleanStringIdent(ctx, paramCtx.VARIABLE().GetText())

		// check for duplicate parameters
		if _, ok := paramSet[name]; ok {
			s.errs.RuleErr(ctx, ErrDuplicateParameterName, "parameter %s redeclared", name)
		}
		paramSet[name] = struct{}{}

		// parameters must start with $
		if !strings.HasPrefix(name, "$") {
			s.errs.RuleErr(ctx, ErrSyntax, "parameter name must start with $")
		}

		typ := paramCtx.Type_().Accept(s).(*types.DataType)

		// Extract default value if present
		var defaultValue engine.ParameterDefaultValue
		if paramCtx.DEFAULT() != nil && paramCtx.Action_expr() != nil {
			defaultExpr := paramCtx.Action_expr().Accept(s).(Expression)
			defaultValue = s.createDefaultValue(defaultExpr)
		}

		cas.Parameters[i] = &engine.NamedType{
			Name:         name,
			Type:         typ,
			DefaultValue: defaultValue,
		}
	}

	if ctx.Action_return() != nil {
		cas.Returns = ctx.Action_return().Accept(s).(*ActionReturn)
	}

	for i, stmt := range ctx.AllAction_statement() {
		cas.Statements[i] = stmt.Accept(s).(ActionStmt)
	}

	cas.Set(ctx)
	return cas
}

func (s *schemaVisitor) VisitDrop_action_statement(ctx *gen.Drop_action_statementContext) any {
	das := &DropActionStatement{
		IfExists: ctx.EXISTS() != nil,
		Name:     s.getIdent(ctx.Identifier()),
	}
	das.Set(ctx)
	return das
}

func (s *schemaVisitor) VisitAction_parameter(ctx *gen.Action_parameterContext) any {
	// This visitor method is required by the interface but not used
	// Parameters are handled directly in VisitCreateActionStatement
	return nil
}

func (s *schemaVisitor) VisitCreate_namespace_statement(ctx *gen.Create_namespace_statementContext) any {
	cns := &CreateNamespaceStatement{
		IfNotExists: ctx.EXISTS() != nil,
		Namespace:   s.getIdent(ctx.Identifier()),
	}

	cns.Set(ctx)
	return cns
}

func (s *schemaVisitor) VisitDrop_namespace_statement(ctx *gen.Drop_namespace_statementContext) any {
	dns := &DropNamespaceStatement{
		IfExists:  ctx.EXISTS() != nil,
		Namespace: s.getIdent(ctx.Identifier()),
	}

	dns.Set(ctx)
	return dns
}

func (s *schemaVisitor) VisitSet_current_namespace_statement(ctx *gen.Set_current_namespace_statementContext) any {
	sns := &SetCurrentNamespaceStatement{
		Namespace: s.getIdent(ctx.Identifier()),
	}

	sns.Set(ctx)
	return sns
}

// unknownExpression creates a new literal with an unknown type and null value.
// It should be used when we have to return early from a visitor method that
// returns an expression.
func unknownExpression(ctx antlr.ParserRuleContext) *ExpressionLiteral {
	e := &ExpressionLiteral{
		Type:  types.NullType,
		Value: nil,
	}

	e.Set(ctx)

	return e
}

func parseStringLiteral(s string) string {
	if !strings.HasPrefix(s, "'") || !strings.HasSuffix(s, "'") || len(s) < 2 {
		panic("invalid string literal")
	}
	return s[1 : len(s)-1]
}

func (s *schemaVisitor) VisitString_literal(ctx *gen.String_literalContext) any {
	str := parseStringLiteral(ctx.GetText())

	n := &ExpressionLiteral{
		Type:  types.TextType,
		Value: str,
	}

	n.Set(ctx)

	return n
}

var (
	maxInt64 = big.NewInt(math.MaxInt64)
	minInt64 = big.NewInt(math.MinInt64)
)

func (s *schemaVisitor) VisitInteger_literal(ctx *gen.Integer_literalContext) any {
	i := ctx.DIGITS_().GetText()
	if ctx.MINUS() != nil {
		i = "-" + i
	}

	// integer literal can only be int64
	bigNum := new(big.Int)
	_, ok := bigNum.SetString(i, 10)
	if !ok {
		s.errs.RuleErr(ctx, ErrSyntax, "invalid integer literal: %s", i)
		return unknownExpression(ctx)
	}

	if bigNum.Cmp(maxInt64) > 0 {
		s.errs.RuleErr(ctx, ErrSyntax, "integer exceeds max int8: %s", i)
		return unknownExpression(ctx)
	}
	if bigNum.Cmp(minInt64) < 0 {
		s.errs.RuleErr(ctx, ErrType, "integer literal out of range: %s", i)
		return unknownExpression(ctx)
	}

	e := &ExpressionLiteral{
		Type:  types.IntType,
		Value: bigNum.Int64(),
	}
	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitDecimal_literal(ctx *gen.Decimal_literalContext) any {
	// our decimal library can parse the decimal, so we simply pass it there
	txt := ctx.GetText()

	dec, err := types.ParseDecimal(txt)
	if err != nil {
		s.errs.RuleErr(ctx, err, "invalid decimal literal: %s", txt)
		return unknownExpression(ctx)
	}

	typ, err := types.NewNumericType(dec.Precision(), dec.Scale())
	if err != nil {
		s.errs.RuleErr(ctx, err, "invalid decimal literal: %s", txt)
		return unknownExpression(ctx)
	}

	e := &ExpressionLiteral{
		Type:  typ,
		Value: dec,
	}
	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitBoolean_literal(ctx *gen.Boolean_literalContext) any {
	var b bool
	switch {
	case ctx.TRUE() != nil:
		b = true
	case ctx.FALSE() != nil:
		b = false
	default:
		panic("unknown boolean literal")
	}

	e := &ExpressionLiteral{
		Type:  types.BoolType,
		Value: b,
	}

	e.Set(ctx)

	return e
}

func (s *schemaVisitor) VisitNull_literal(ctx *gen.Null_literalContext) any {
	e := &ExpressionLiteral{
		Type:  types.NullType,
		Value: nil,
	}
	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitBinary_literal(ctx *gen.Binary_literalContext) any {
	b := ctx.GetText()
	// trim off beginning 0x
	if b[:2] != "0x" {
		// this should get caught by the parser
		s.errs.RuleErr(ctx, ErrSyntax, "invalid blob literal: %s", b)
	}

	b = b[2:]

	decoded, err := hex.DecodeString(b)
	if err != nil {
		// this should get caught by the parser
		s.errs.RuleErr(ctx, ErrSyntax, "invalid blob literal: %s", b)
	}

	e := &ExpressionLiteral{
		Type:  types.ByteaType,
		Value: decoded,
	}
	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitIdentifier_list(ctx *gen.Identifier_listContext) any {
	var ident []string
	for _, i := range ctx.AllIdentifier() {
		ident = append(ident, s.getIdent(i))
	}

	return ident
}

func (s *schemaVisitor) VisitAllowed_identifier(ctx *gen.Allowed_identifierContext) any {
	// is directly visited by VisitIdentifier (see the next method)
	panic("Allowed_identifier should not be visited directly. This is a bug in the parser")
}

func (s *schemaVisitor) VisitIdentifier(ctx *gen.IdentifierContext) any {
	// this is to ensure we are properly calling getIdent on every instance of identifier
	panic("Identifier should not be visited directly. This is a bug in the parser")
}

var maxPrecisionOrScale = int64(1000)

func (s *schemaVisitor) VisitType(ctx *gen.TypeContext) any {
	dt := &types.DataType{
		Name: s.getIdent(ctx.Identifier()),
	}

	if ctx.LPAREN() != nil {
		// there should be 1-2 digits
		prec, err := strconv.ParseInt(ctx.GetPrecision().GetText(), 10, 64)
		if err != nil {
			s.errs.RuleErr(ctx, ErrSyntax, "invalid precision: %s", ctx.DIGITS_(0).GetText())
			return types.NullType
		}

		if prec > maxPrecisionOrScale {
			s.errs.RuleErr(ctx, ErrSyntax, "precision too large: %d", prec)
			return types.NullType
		}

		var scale uint16
		if ctx.GetScale() == nil {
			scale = 0
		} else {
			scaleint64, err := strconv.ParseInt(ctx.GetScale().GetText(), 10, 64)
			if err != nil {
				s.errs.RuleErr(ctx, ErrSyntax, "invalid scale: %s", ctx.DIGITS_(1).GetText())
				return types.NullType
			}
			if scaleint64 > maxPrecisionOrScale {
				s.errs.RuleErr(ctx, ErrSyntax, "scale too large: %d", scaleint64)
				return types.NullType
			}

			scale = uint16(scaleint64)
		}

		met := [2]uint16{uint16(prec), scale}
		dt.Metadata = met
	}

	if ctx.LBRACKET() != nil {
		dt.IsArray = true
	}

	err := dt.Clean()
	if err != nil {
		s.errs.RuleErr(ctx, err, "invalid type: %s", dt.String())
		return types.NullType
	}

	return dt
}

func (s *schemaVisitor) VisitType_cast(ctx *gen.Type_castContext) any {
	return s.Visit(ctx.Type_()).(*types.DataType)
}

func (s *schemaVisitor) VisitVariable(ctx *gen.VariableContext) any {
	var e *ExpressionVariable
	var tok antlr.ParserRuleContext
	switch {
	case ctx.VARIABLE() != nil:
		e = &ExpressionVariable{
			Name:   strings.ToLower(ctx.GetText()),
			Prefix: VariablePrefixDollar,
		}
		tok = ctx
	case ctx.CONTEXTUAL_VARIABLE() != nil:
		e = &ExpressionVariable{
			Name:   strings.ToLower(ctx.GetText()),
			Prefix: VariablePrefixAt,
		}
		tok = ctx
	default:
		panic("unknown variable")
	}

	s.validateVariableIdentifier(tok, e.Name)

	e.Set(ctx)
	return e
}

// arr will make an array of type A if the input is greater than 0
func arr[A any](b int) []A {
	if b > 0 {
		return make([]A, b)
	}
	return nil
}

func (s *schemaVisitor) VisitUse_extension_statement(ctx *gen.Use_extension_statementContext) any {
	e := &UseExtensionStatement{
		IfNotExists: ctx.EXISTS() != nil,
		ExtName:     s.getIdent(ctx.GetExtension_name()),
		Alias:       s.getIdent(ctx.GetAlias()),
	}

	allIdent := ctx.AllIdentifier()
	for i, id := range allIdent[1 : len(allIdent)-1] {
		e.Config = append(e.Config, &struct {
			Key   string
			Value Expression
		}{
			Key:   s.getIdent(id),
			Value: ctx.Action_expr(i).Accept(s).(Expression),
		})
	}
	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitUnuse_extension_statement(ctx *gen.Unuse_extension_statementContext) any {
	e := &UnuseExtensionStatement{
		IfExists: ctx.EXISTS() != nil,
		Alias:    s.getIdent(ctx.GetAlias()),
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitType_list(ctx *gen.Type_listContext) any {
	var ts []*types.DataType
	for _, t := range ctx.AllType_() {
		ts = append(ts, t.Accept(s).(*types.DataType))
	}

	return ts
}

func (s *schemaVisitor) VisitNamed_type_list(ctx *gen.Named_type_listContext) any {
	var ts []*engine.NamedType
	for i, t := range ctx.AllIdentifier() {
		ts = append(ts, &engine.NamedType{
			Name: s.getIdent(t),
			Type: ctx.Type_(i).Accept(s).(*types.DataType),
		})
	}

	return ts
}

func (s *schemaVisitor) VisitAction_return(ctx *gen.Action_returnContext) any {
	ret := &ActionReturn{}

	usesNamedFields := false
	switch {
	case ctx.GetReturn_columns() != nil:
		ret.Fields = ctx.GetReturn_columns().Accept(s).([]*engine.NamedType)
		usesNamedFields = true
	case ctx.GetUnnamed_return_types() != nil:
		ret.Fields = make([]*engine.NamedType, len(ctx.GetUnnamed_return_types().AllType_()))
		for i, t := range ctx.GetUnnamed_return_types().AllType_() {
			ret.Fields[i] = &engine.NamedType{
				Name: "",
				Type: t.Accept(s).(*types.DataType),
			}
		}
	default:
		panic("unknown return type")
	}

	if ctx.TABLE() != nil {
		ret.IsTable = true

		// if it returns a table, it _must_ use named fields
		if !usesNamedFields {
			s.errs.RuleErr(ctx, ErrSyntax, "actions returning tables must use named fields in the return clause")
		}
	}

	ret.Set(ctx)

	// validate that the return fields are unique
	seen := make(map[string]struct{})
	for _, f := range ret.Fields {
		if f.Name == "" {
			continue
		}

		if _, ok := seen[f.Name]; ok {
			s.errs.RuleErr(ctx, ErrDuplicateResultColumnName, "field %s redeclared", f.Name)
		}
		seen[f.Name] = struct{}{}
	}

	return ret
}

// VisitSql_statement visits a SQL DML statement. It is called by all nested
// sql statements (e.g. in actions)
func (s *schemaVisitor) VisitSql_statement(ctx *gen.Sql_statementContext) any {
	stmt := &SQLStatement{
		CTEs: arr[*CommonTableExpression](len(ctx.AllCommon_table_expression())),
	}

	for i, cte := range ctx.AllCommon_table_expression() {
		stmt.CTEs[i] = cte.Accept(s).(*CommonTableExpression)
	}

	if ctx.RECURSIVE() != nil {
		stmt.Recursive = true
	}

	switch {
	case ctx.Select_statement() != nil:
		stmt.SQL = ctx.Select_statement().Accept(s).(*SelectStatement)
	case ctx.Update_statement() != nil:
		stmt.SQL = ctx.Update_statement().Accept(s).(*UpdateStatement)
	case ctx.Insert_statement() != nil:
		stmt.SQL = ctx.Insert_statement().Accept(s).(*InsertStatement)
	case ctx.Delete_statement() != nil:
		stmt.SQL = ctx.Delete_statement().Accept(s).(*DeleteStatement)
	default:
		panic("unknown dml statement")
	}

	raw := s.getTextFromStream(ctx.GetStart().GetStart(), ctx.GetStop().GetStop())
	stmt.raw = &raw

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitCommon_table_expression(ctx *gen.Common_table_expressionContext) any {
	// first identifier is the table name, the rest are the columns
	cte := &CommonTableExpression{
		Name:  s.getIdent(ctx.Identifier(0)),
		Query: ctx.Select_statement().Accept(s).(*SelectStatement),
	}

	for _, id := range ctx.AllIdentifier()[1:] {
		cte.Columns = append(cte.Columns, s.getIdent(id))
	}

	cte.Set(ctx)

	return cte
}

func (s *schemaVisitor) VisitCreate_table_statement(ctx *gen.Create_table_statementContext) any {
	stmt := &CreateTableStatement{
		Name:        s.getIdent(ctx.GetName()),
		IfNotExists: ctx.EXISTS() != nil,
		Columns:     arr[*Column](len(ctx.AllTable_column_def())),
		Constraints: arr[*OutOfLineConstraint](len(ctx.AllTable_constraint_def())),
	}

	// for basic validation
	var primaryKey []string
	allColumns := make(map[string]bool)

	if len(ctx.AllTable_column_def()) == 0 {
		s.errs.RuleErr(ctx, ErrTableDefinition, "no column definitions found")
	}
	for i, c := range ctx.AllTable_column_def() {
		col := c.Accept(s).(*Column)
		stmt.Columns[i] = col
		if allColumns[col.Name] {
			s.errs.RuleErr(c, ErrCollation, "constraint name exists")
		} else {
			allColumns[col.Name] = true
		}
	}

	// we iterate through all columns to see if the primary key has been declared.
	// This allows us to check if it gets doubley declared.
	for _, column := range stmt.Columns {
		for _, constraint := range column.Constraints {
			switch constraint.(type) {
			case *PrimaryKeyInlineConstraint:
				// ensure that the primary key is not redeclared
				if len(primaryKey) != 0 {
					s.errs.AddErr(column, ErrRedeclaredPrimaryKey, "primary key redeclared")
					continue
				}
				primaryKey = []string{column.Name}
			}
		}
	}

	constraintSet := make(map[string]struct{})
	// we will validate that columns referenced in constraints exist.
	// We will also check that the primary key is not redeclared.
	for i, c := range ctx.AllTable_constraint_def() {
		constraint := c.Accept(s).(*OutOfLineConstraint)

		// if the constraint was named, we will check that it is not redeclared.
		// If not named, it will be auto-named.
		if constraint.Name != "" {
			_, ok := constraintSet[constraint.Name]
			if ok {
				s.errs.RuleErr(c, ErrRedeclaredConstraint, "constraint name exists")
			} else {
				constraintSet[constraint.Name] = struct{}{}
			}
		}

		stmt.Constraints[i] = constraint

		// if it is a primary key, we need to check that it is not redeclared
		if pk, ok := constraint.Constraint.(*PrimaryKeyOutOfLineConstraint); ok {
			if len(primaryKey) != 0 {
				s.errs.AddErr(constraint, ErrRedeclaredPrimaryKey, "primary key redeclared")
				continue
			}
			primaryKey = pk.Columns
		}

		for _, col := range constraint.Constraint.LocalColumns() {
			if !allColumns[col] {
				s.errs.RuleErr(c, ErrUnknownColumn, "constraint on unknown column")
			}
		}
	}

	if len(primaryKey) == 0 {
		s.errs.RuleErr(ctx, ErrNoPrimaryKey, "no primary key declared")
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitTable_column_def(ctx *gen.Table_column_defContext) interface{} {
	column := &Column{
		Name:        s.getIdent(ctx.Identifier()),
		Type:        ctx.Type_().Accept(s).(*types.DataType),
		Constraints: arr[InlineConstraint](len(ctx.AllInline_constraint())),
	}

	for i, c := range ctx.AllInline_constraint() {
		column.Constraints[i] = c.Accept(s).(InlineConstraint)
	}

	column.Set(ctx)
	return column
}

func (s *schemaVisitor) VisitInline_constraint(ctx *gen.Inline_constraintContext) any {
	var c InlineConstraint
	switch {
	case ctx.PRIMARY() != nil:
		c = &PrimaryKeyInlineConstraint{}
	case ctx.UNIQUE() != nil:
		c = &UniqueInlineConstraint{}
	case ctx.NOT() != nil:
		c = &NotNullConstraint{}
	case ctx.DEFAULT() != nil:
		c = &DefaultConstraint{
			Value: ctx.Action_expr().Accept(s).(Expression),
		}
	case ctx.CHECK() != nil:
		c = &CheckConstraint{
			Expression: ctx.Sql_expr().Accept(s).(Expression),
		}
	case ctx.Fk_constraint() != nil:
		c = ctx.Fk_constraint().Accept(s).(*ForeignKeyReferences)
	default:
		panic("unknown constraint")
	}

	c.Set(ctx)
	return c
}

func (s *schemaVisitor) VisitFk_constraint(ctx *gen.Fk_constraintContext) any {
	c := &ForeignKeyReferences{
		RefTable:   s.getIdent(ctx.GetTable()),
		RefColumns: ctx.Identifier_list().Accept(s).([]string),
		Actions:    arr[*ForeignKeyAction](len(ctx.AllFk_action())),
	}

	if ctx.GetNamespace() != nil {
		c.RefTableNamespace = s.getIdent(ctx.GetNamespace())
	}

	for i, a := range ctx.AllFk_action() {
		c.Actions[i] = a.Accept(s).(*ForeignKeyAction)
	}

	c.Set(ctx)
	return c
}

func (s *schemaVisitor) VisitFk_action(ctx *gen.Fk_actionContext) interface{} {
	act := &ForeignKeyAction{}
	switch {
	case ctx.UPDATE() != nil:
		act.On = ON_UPDATE
	case ctx.DELETE() != nil:
		act.On = ON_DELETE
	default:
		panic("unknown foreign key action")
	}

	switch {
	case ctx.CASCADE() != nil:
		act.Do = DO_CASCADE
	case ctx.RESTRICT() != nil:
		act.Do = DO_RESTRICT
	case ctx.SET() != nil:
		if ctx.NULL() != nil {
			act.Do = DO_SET_NULL
		} else {
			act.Do = DO_SET_DEFAULT
		}
	case ctx.NO() != nil:
		act.Do = DO_NO_ACTION
	default:
		panic("unknown foreign key action")
	}

	return act
}

func (s *schemaVisitor) VisitTable_constraint_def(ctx *gen.Table_constraint_defContext) any {
	name := ""
	if ctx.GetName() != nil {
		name = s.getIdent(ctx.GetName())
	}

	var c OutOfLineConstraintClause
	switch {
	case ctx.PRIMARY() != nil:
		c = &PrimaryKeyOutOfLineConstraint{
			Columns: ctx.Identifier_list().Accept(s).([]string),
		}
	case ctx.UNIQUE() != nil:
		c = &UniqueOutOfLineConstraint{
			Columns: ctx.Identifier_list().Accept(s).([]string),
		}
	case ctx.CHECK() != nil:
		c = &CheckConstraint{
			Expression: ctx.Sql_expr().Accept(s).(Expression),
		}
	case ctx.FOREIGN() != nil:
		c = &ForeignKeyOutOfLineConstraint{
			Columns:    ctx.Identifier_list().Accept(s).([]string),
			References: ctx.Fk_constraint().Accept(s).(*ForeignKeyReferences),
		}
	default:
		panic("unknown constraint")
	}

	c.Set(ctx)
	oolc := &OutOfLineConstraint{
		Name:       name,
		Constraint: c,
	}

	oolc.Set(ctx)

	return oolc
}

func (s *schemaVisitor) VisitDrop_table_statement(ctx *gen.Drop_table_statementContext) any {
	stmt := &DropTableStatement{
		Tables:   ctx.GetTables().Accept(s).([]string),
		IfExists: ctx.EXISTS() != nil,
	}

	if ctx.Opt_drop_behavior() != nil {
		stmt.Behavior = ctx.Opt_drop_behavior().Accept(s).(DropBehavior)
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitOpt_drop_behavior(ctx *gen.Opt_drop_behaviorContext) any {
	switch {
	case ctx.CASCADE() != nil:
		return DropBehaviorCascade
	case ctx.RESTRICT() != nil:
		return DropBehaviorRestrict
	default:
		return DropBehaviorDefault // restrict is the default
	}
}

func (s *schemaVisitor) VisitAlter_table_statement(ctx *gen.Alter_table_statementContext) any {
	stmt := &AlterTableStatement{
		Table: s.getIdent(ctx.Identifier()),
	}

	for _, a := range ctx.AllAlter_table_action() {
		stmt.Actions = append(stmt.Actions, a.Accept(s).(AlterTableAction))
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitAdd_column_constraint(ctx *gen.Add_column_constraintContext) any {
	a := &AlterColumnSet{
		Column: s.getIdent(ctx.Identifier()),
	}

	if ctx.NULL() != nil {
		a.Type = ConstraintTypeNotNull
	} else {
		a.Type = ConstraintTypeDefault

		if ctx.Action_expr() == nil {
			s.errs.RuleErr(ctx, ErrSyntax, "missing literal for default constraint")
			return a
		}

		a.Value = ctx.Action_expr().Accept(s).(Expression)
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitDrop_column_constraint(ctx *gen.Drop_column_constraintContext) any {
	a := &AlterColumnDrop{
		Column: s.getIdent(ctx.Identifier()),
	}

	switch {
	case ctx.NULL() != nil:
		a.Type = ConstraintTypeNotNull
	case ctx.DEFAULT() != nil:
		a.Type = ConstraintTypeDefault
	default:
		panic("unknown constraint")
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitAdd_column(ctx *gen.Add_columnContext) any {
	a := &AddColumn{
		Name:        s.getIdent(ctx.Identifier()),
		Type:        ctx.Type_().Accept(s).(*types.DataType),
		IfNotExists: ctx.EXISTS() != nil,
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitDrop_column(ctx *gen.Drop_columnContext) any {
	a := &DropColumn{
		Name:     s.getIdent(ctx.Identifier()),
		IfExists: ctx.EXISTS() != nil,
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitRename_column(ctx *gen.Rename_columnContext) any {
	a := &RenameColumn{
		OldName: s.getIdent(ctx.GetOld_column()),
		NewName: s.getIdent(ctx.GetNew_column()),
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitRename_table(ctx *gen.Rename_tableContext) any {
	a := &RenameTable{
		Name: s.getIdent(ctx.Identifier()),
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitAdd_table_constraint(ctx *gen.Add_table_constraintContext) any {
	a := &AddTableConstraint{
		Constraint: ctx.Table_constraint_def().Accept(s).(*OutOfLineConstraint),
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitDrop_table_constraint(ctx *gen.Drop_table_constraintContext) any {
	a := &DropTableConstraint{
		Name:     s.getIdent(ctx.Identifier()),
		IfExists: ctx.EXISTS() != nil,
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitCreate_index_statement(ctx *gen.Create_index_statementContext) any {
	a := &CreateIndexStatement{
		On:      s.getIdent(ctx.GetTable()),
		Columns: ctx.GetColumns().Accept(s).([]string),
		Type:    IndexTypeBTree,
	}

	if ctx.EXISTS() != nil {
		a.IfNotExists = true
	}

	if ctx.GetName() != nil {
		a.Name = s.getIdent(ctx.GetName())
	}

	if ctx.UNIQUE() != nil {
		a.Type = IndexTypeUnique
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitDrop_index_statement(ctx *gen.Drop_index_statementContext) interface{} {
	a := &DropIndexStatement{
		Name: s.getIdent(ctx.Identifier()),
	}

	if ctx.EXISTS() != nil {
		a.CheckExist = true
	}

	a.Set(ctx)
	return a
}

func (s *schemaVisitor) VisitCreate_role_statement(ctx *gen.Create_role_statementContext) any {
	stmt := &CreateRoleStatement{
		Role: s.getIdent(ctx.Identifier()),
	}
	if ctx.EXISTS() != nil {
		stmt.IfNotExists = true
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitDrop_role_statement(ctx *gen.Drop_role_statementContext) any {
	stmt := &DropRoleStatement{
		Role: s.getIdent(ctx.Identifier()),
	}
	if ctx.EXISTS() != nil {
		stmt.IfExists = true
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitGrant_statement(ctx *gen.Grant_statementContext) any {
	c := s.parseGrantOrRevoke(ctx)
	c.IsGrant = true
	return c
}

func (s *schemaVisitor) VisitRevoke_statement(ctx *gen.Revoke_statementContext) any {
	c := s.parseGrantOrRevoke(ctx)
	c.IsGrant = false // not necessary, but for clarity
	return c
}

// parseGrantOrRevoke parses a GRANT or REVOKE statement.
// It is the responsibility of the caller to set the correct IsGrant field.
func (s *schemaVisitor) parseGrantOrRevoke(ctx interface {
	antlr.ParserRuleContext
	IF() antlr.TerminalNode
	Privilege_list() gen.IPrivilege_listContext
	GetGrant_role() gen.IIdentifierContext
	GetRole() gen.IIdentifierContext
	GetUser() antlr.Token
	GetNamespace() gen.IIdentifierContext
	GetUser_var() gen.IAction_exprContext
}) *GrantOrRevokeStatement {
	// can be:
	// GRANT/REVOKE privilege_list/role TO/FROM role/user

	c := &GrantOrRevokeStatement{}
	switch {
	case ctx.Privilege_list() != nil:
		c.Privileges = ctx.Privilege_list().Accept(s).([]string)
	case ctx.GetGrant_role() != nil:
		c.GrantRole = s.getIdent(ctx.GetGrant_role())
	default:
		// should not happen, as this would suggest a bug in the parser
		panic("invalid grant/revoke statement")
	}

	switch {
	case ctx.GetRole() != nil:
		c.ToRole = s.getIdent(ctx.GetRole())
	case ctx.GetUser() != nil:
		c.ToUser = parseStringLiteral(ctx.GetUser().GetText())
	case ctx.GetUser_var() != nil:
		c.ToVariable = ctx.GetUser_var().Accept(s).(Expression)
	default:
		// should not happen, as this would suggest a bug in the parser
		panic("invalid grant/revoke statement")
	}
	c.Set(ctx)

	if ctx.GetNamespace() != nil {
		ns := s.getIdent(ctx.GetNamespace())
		c.Namespace = &ns
	}

	c.If = ctx.IF() != nil

	// either privileges can be granted to roles, or roles can be granted to users.
	// Other permutations are invalid.

	// if granting roles, then recipient must be a user
	if len(c.Privileges) == 0 {
		// no privileges, so we are granting a role
		if c.ToRole != "" {
			s.errs.RuleErr(ctx, ErrGrantOrRevoke, "cannot grant or revoke a role to another role")
		}

		if c.Namespace != nil {
			s.errs.RuleErr(ctx, ErrGrantOrRevoke, "cannot grant or revoke a role on a namespace")
		}
	} else {
		// if granting privileges, then recipient must be a role
		if c.ToUser != "" || c.ToVariable != nil {
			s.errs.RuleErr(ctx, ErrGrantOrRevoke, "cannot grant or revoke privileges to a user")
		}
	}

	return c
}

func (s *schemaVisitor) VisitTransfer_ownership_statement(ctx *gen.Transfer_ownership_statementContext) any {
	stmt := &TransferOwnershipStatement{}

	switch {
	case ctx.GetUser() != nil:
		stmt.ToUser = parseStringLiteral(ctx.GetUser().GetText())
	case ctx.GetUser_var() != nil:
		stmt.ToVariable = ctx.GetUser_var().Accept(s).(Expression)
	default:
		panic("invalid transfer ownership statement")
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitPrivilege_list(ctx *gen.Privilege_listContext) any {
	var privs []string
	for _, p := range ctx.AllPrivilege() {
		privs = append(privs, p.Accept(s).(string))
	}

	return privs
}

func (s *schemaVisitor) VisitPrivilege(ctx *gen.PrivilegeContext) any {
	// since there is only one token, we can just get all text
	return ctx.GetText()
}

func (s *schemaVisitor) VisitSelect_statement(ctx *gen.Select_statementContext) any {
	stmt := &SelectStatement{
		SelectCores:       arr[*SelectCore](len(ctx.AllSelect_core())),
		CompoundOperators: arr[CompoundOperator](len(ctx.AllCompound_operator())),
		Ordering:          arr[*OrderingTerm](len(ctx.AllOrdering_term())),
	}

	for i, core := range ctx.AllSelect_core() {
		stmt.SelectCores[i] = core.Accept(s).(*SelectCore)
	}

	for i, op := range ctx.AllCompound_operator() {
		stmt.CompoundOperators[i] = op.Accept(s).(CompoundOperator)
	}

	for i, ord := range ctx.AllOrdering_term() {
		stmt.Ordering[i] = ord.Accept(s).(*OrderingTerm)
	}

	if ctx.GetLimit() != nil {
		stmt.Limit = ctx.GetLimit().Accept(s).(Expression)
	}
	if ctx.GetOffset() != nil {
		stmt.Offset = ctx.GetOffset().Accept(s).(Expression)
	}

	stmt.Set(ctx)

	return stmt
}

func (s *schemaVisitor) VisitCompound_operator(ctx *gen.Compound_operatorContext) any {
	switch {
	case ctx.UNION() != nil:
		if ctx.ALL() != nil {
			return CompoundOperatorUnionAll
		}
		return CompoundOperatorUnion
	case ctx.INTERSECT() != nil:
		return CompoundOperatorIntersect
	case ctx.EXCEPT() != nil:
		return CompoundOperatorExcept
	default:
		panic("unknown compound operator")
	}
}

func (s *schemaVisitor) VisitOrdering_term(ctx *gen.Ordering_termContext) any {
	ord := &OrderingTerm{
		Expression: ctx.Sql_expr().Accept(s).(Expression),
	}

	if ctx.DESC() != nil {
		ord.Order = OrderTypeDesc
	} else if ctx.ASC() != nil {
		ord.Order = OrderTypeAsc
	}

	if ctx.FIRST() != nil {
		ord.Nulls = NullOrderFirst
	} else if ctx.LAST() != nil {
		ord.Nulls = NullOrderLast
	}

	ord.Set(ctx)

	return ord
}

func (s *schemaVisitor) VisitSelect_core(ctx *gen.Select_coreContext) any {
	stmt := &SelectCore{
		Columns: arr[ResultColumn](len(ctx.AllResult_column())),
		Joins:   arr[*Join](len(ctx.AllJoin())),
	}

	if ctx.DISTINCT() != nil {
		stmt.Distinct = true
	}

	for i, col := range ctx.AllResult_column() {
		stmt.Columns[i] = col.Accept(s).(ResultColumn)
	}

	if ctx.Relation() != nil {
		stmt.From = ctx.Relation().Accept(s).(Table)
	}

	for i, join := range ctx.AllJoin() {
		stmt.Joins[i] = join.Accept(s).(*Join)
	}

	if ctx.GetWhere() != nil {
		stmt.Where = ctx.GetWhere().Accept(s).(Expression)
	}

	if ctx.GetGroup_by() != nil {
		stmt.GroupBy = ctx.GetGroup_by().Accept(s).([]Expression)
	}

	if ctx.GetHaving() != nil {
		stmt.Having = ctx.GetHaving().Accept(s).(Expression)
	}

	if ctx.WINDOW() != nil {
		// the only Identifier used in the SELECT CORE grammar is for naming windows,
		// so we can safely get identifiers by index here.
		for i, window := range ctx.AllWindow() {
			name := s.getIdent(ctx.Identifier(i))

			win := window.Accept(s).(*WindowImpl)

			stmt.Windows = append(stmt.Windows, &struct {
				Name   string
				Window *WindowImpl
			}{
				Name:   name,
				Window: win,
			})
		}
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitTable_relation(ctx *gen.Table_relationContext) any {
	t := &RelationTable{
		Table: s.getIdent(ctx.GetTable_name()),
	}

	if ctx.GetAlias() != nil {
		t.Alias = s.getIdent(ctx.GetAlias())
	}

	if ctx.GetNamespace() != nil {
		t.Namespace = s.getIdent(ctx.GetNamespace())
	}

	t.Set(ctx)
	return t
}

func (s *schemaVisitor) VisitSubquery_relation(ctx *gen.Subquery_relationContext) any {
	t := &RelationSubquery{
		Subquery: ctx.Select_statement().Accept(s).(*SelectStatement),
	}

	// alias is technially required here, but we allow it in the grammar
	// to throw a better error message here.
	if ctx.Identifier() != nil {
		t.Alias = s.getIdent(ctx.Identifier())
	}

	t.Set(ctx)
	return t
}

func (s *schemaVisitor) VisitJoin(ctx *gen.JoinContext) any {
	j := &Join{
		Relation: ctx.Relation().Accept(s).(Table),
		On:       ctx.Sql_expr().Accept(s).(Expression),
	}
	switch {
	case ctx.LEFT() != nil:
		j.Type = JoinTypeLeft
	case ctx.RIGHT() != nil:
		j.Type = JoinTypeRight
	case ctx.FULL() != nil:
		j.Type = JoinTypeFull
	case ctx.INNER() != nil:
		j.Type = JoinTypeInner
	default:
		// default to inner join
		j.Type = JoinTypeInner
	}

	j.Set(ctx)
	return j
}

func (s *schemaVisitor) VisitExpression_result_column(ctx *gen.Expression_result_columnContext) any {
	expr := ctx.Sql_expr().Accept(s).(Expression)
	col := &ResultColumnExpression{
		Expression: expr,
	}

	if ctx.Identifier() != nil {
		col.Alias = s.getIdent(ctx.Identifier())
	}

	col.Set(ctx)
	return col
}

func (s *schemaVisitor) VisitWildcard_result_column(ctx *gen.Wildcard_result_columnContext) any {
	col := &ResultColumnWildcard{}

	if ctx.Identifier() != nil {
		col.Table = s.getIdent(ctx.Identifier())
	}

	col.Set(ctx)
	return col
}

func (s *schemaVisitor) VisitUpdate_statement(ctx *gen.Update_statementContext) any {
	up := &UpdateStatement{
		Table:     s.getIdent(ctx.GetTable_name()),
		SetClause: arr[*UpdateSetClause](len(ctx.AllUpdate_set_clause())),
		Joins:     arr[*Join](len(ctx.AllJoin())),
	}

	if ctx.GetAlias() != nil {
		up.Alias = s.getIdent(ctx.GetAlias())
	}

	for i, set := range ctx.AllUpdate_set_clause() {
		up.SetClause[i] = set.Accept(s).(*UpdateSetClause)
	}

	if ctx.Relation() != nil {
		up.From = ctx.Relation().Accept(s).(Table)
	}

	for i, join := range ctx.AllJoin() {
		up.Joins[i] = join.Accept(s).(*Join)
	}

	if ctx.GetWhere() != nil {
		up.Where = ctx.GetWhere().Accept(s).(Expression)
	}

	up.Set(ctx)
	return up
}

func (s *schemaVisitor) VisitUpdate_set_clause(ctx *gen.Update_set_clauseContext) any {
	u := &UpdateSetClause{
		Column: s.getIdent(ctx.GetColumn()),
		Value:  ctx.Sql_expr().Accept(s).(Expression),
	}

	u.Set(ctx)
	return u
}

func (s *schemaVisitor) VisitInsert_statement(ctx *gen.Insert_statementContext) any {
	ins := &InsertStatement{
		Table: s.getIdent(ctx.GetTable_name()),
	}

	// can either be INSERT INTO table VALUES (1, 2, 3) or
	// INSERT INTO table SELECT * FROM table2
	if ctx.Select_statement() != nil {
		ins.Select = ctx.Select_statement().Accept(s).(*SelectStatement)
	} else {
		for _, valList := range ctx.AllSql_expr_list() {
			ins.Values = append(ins.Values, valList.Accept(s).([]Expression))
		}
	}

	if ctx.GetAlias() != nil {
		ins.Alias = s.getIdent(ctx.GetAlias())
	}

	if ctx.Identifier_list() != nil {
		ins.Columns = ctx.Identifier_list().Accept(s).([]string)
	}

	if ctx.Upsert_clause() != nil {
		ins.OnConflict = ctx.Upsert_clause().Accept(s).(*OnConflict)
	}

	ins.Set(ctx)
	return ins
}

func (s *schemaVisitor) VisitUpsert_clause(ctx *gen.Upsert_clauseContext) any {
	u := &OnConflict{}

	if ctx.GetConflict_columns() != nil {
		u.ConflictColumns = ctx.GetConflict_columns().Accept(s).([]string)
	}

	if ctx.GetConflict_where() != nil {
		u.ConflictWhere = ctx.GetConflict_where().Accept(s).(Expression)
	}

	if ctx.UPDATE() != nil {
		for _, set := range ctx.AllUpdate_set_clause() {
			u.DoUpdate = append(u.DoUpdate, set.Accept(s).(*UpdateSetClause))
		}
	}

	if ctx.GetUpdate_where() != nil {
		u.UpdateWhere = ctx.GetUpdate_where().Accept(s).(Expression)
	}

	u.Set(ctx)
	return u
}

func (s *schemaVisitor) VisitDelete_statement(ctx *gen.Delete_statementContext) any {
	d := &DeleteStatement{
		Table: s.getIdent(ctx.GetTable_name()),
	}

	if ctx.GetAlias() != nil {
		d.Alias = s.getIdent(ctx.GetAlias())
	}

	if ctx.GetWhere() != nil {
		d.Where = ctx.GetWhere().Accept(s).(Expression)
	}

	d.Set(ctx)
	return d
}

func (s *schemaVisitor) VisitColumn_sql_expr(ctx *gen.Column_sql_exprContext) any {
	e := &ExpressionColumn{
		Column: s.getIdent(ctx.GetColumn()),
	}

	if ctx.GetTable() != nil {
		e.Table = s.getIdent(ctx.GetTable())
	}

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitLogical_sql_expr(ctx *gen.Logical_sql_exprContext) any {
	e := &ExpressionLogical{
		Left:  ctx.Sql_expr(0).Accept(s).(Expression),
		Right: ctx.Sql_expr(1).Accept(s).(Expression),
	}

	switch {
	case ctx.AND() != nil:
		e.Operator = LogicalOperatorAnd
	case ctx.OR() != nil:
		e.Operator = LogicalOperatorOr
	default:
		panic("unknown logical operator")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitArray_access_sql_expr(ctx *gen.Array_access_sql_exprContext) any {
	e := &ExpressionArrayAccess{
		Array: ctx.Sql_expr(0).Accept(s).(Expression),
	}

	s.makeArray(e, ctx.GetSingle(), ctx.GetLeft(), ctx.GetRight())

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

// makeArray modifies the passed ExpressionArrayAccess based on the single, left, and right fields.
// single: arr[1], left: arr[1:], right: arr[:1], left and right: arr[1:2], neither: arr[:]
func (s *schemaVisitor) makeArray(e *ExpressionArrayAccess, single, left, right antlr.ParserRuleContext) {
	if single != nil {
		e.Index = single.Accept(s).(Expression)
		return
	}

	var start, end Expression
	if left != nil {
		start = left.Accept(s).(Expression)
	}
	if right != nil {
		end = right.Accept(s).(Expression)
	}

	ft := [2]Expression{start, end}
	e.FromTo = &ft
}

func (s *schemaVisitor) VisitField_access_sql_expr(ctx *gen.Field_access_sql_exprContext) any {
	e := &ExpressionFieldAccess{
		Record: ctx.Sql_expr().Accept(s).(Expression),
		Field:  s.getIdent(ctx.Identifier()),
	}

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitComparison_sql_expr(ctx *gen.Comparison_sql_exprContext) any {
	e := &ExpressionComparison{
		Left:  ctx.Sql_expr(0).Accept(s).(Expression),
		Right: ctx.Sql_expr(1).Accept(s).(Expression),
	}

	switch {
	case ctx.EQUALS() != nil || ctx.EQUATE() != nil:
		e.Operator = ComparisonOperatorEqual
	case ctx.NEQ() != nil:
		e.Operator = ComparisonOperatorNotEqual
	case ctx.LT() != nil:
		e.Operator = ComparisonOperatorLessThan
	case ctx.LTE() != nil:
		e.Operator = ComparisonOperatorLessThanOrEqual
	case ctx.GT() != nil:
		e.Operator = ComparisonOperatorGreaterThan
	case ctx.GTE() != nil:
		e.Operator = ComparisonOperatorGreaterThanOrEqual
	default:
		panic("unknown comparison operator")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitLiteral_sql_expr(ctx *gen.Literal_sql_exprContext) any {
	e := ctx.Literal().Accept(s).(*ExpressionLiteral)

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitBetween_sql_expr(ctx *gen.Between_sql_exprContext) any {
	e := &ExpressionBetween{
		Expression: ctx.GetElement().Accept(s).(Expression),
		Lower:      ctx.GetLower().Accept(s).(Expression),
		Upper:      ctx.GetUpper().Accept(s).(Expression),
	}

	if ctx.NOT() != nil {
		e.Not = true
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitFunction_call_sql_expr(ctx *gen.Function_call_sql_exprContext) any {
	call := ctx.Sql_function_call().Accept(s).(*ExpressionFunctionCall)

	if ctx.Type_cast() != nil {
		call.Cast(ctx.Type_cast().Accept(s).(*types.DataType))
	}

	call.Set(ctx)

	return call
}

func (s *schemaVisitor) VisitWindow_function_call_sql_expr(ctx *gen.Window_function_call_sql_exprContext) any {
	e := &ExpressionWindowFunctionCall{
		FunctionCall: ctx.Sql_function_call().Accept(s).(*ExpressionFunctionCall),
	}

	if ctx.Identifier() != nil {
		name := s.getIdent(ctx.Identifier())
		wr := &WindowReference{
			Name: name,
		}
		wr.Set(ctx.Identifier().Allowed_identifier())
		e.Window = wr
	} else {
		e.Window = ctx.Window().Accept(s).(*WindowImpl)
	}

	if ctx.FILTER() != nil {
		e.Filter = ctx.Sql_expr().Accept(s).(Expression)
	}

	e.Set(ctx)

	return e
}

func (s *schemaVisitor) VisitParen_sql_expr(ctx *gen.Paren_sql_exprContext) any {
	e := &ExpressionParenthesized{
		Inner: ctx.Sql_expr().Accept(s).(Expression),
	}
	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}
	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitCollate_sql_expr(ctx *gen.Collate_sql_exprContext) any {
	e := &ExpressionCollate{
		Expression: ctx.Sql_expr().Accept(s).(Expression),
		Collation:  s.getIdent(ctx.Identifier()),
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitVariable_sql_expr(ctx *gen.Variable_sql_exprContext) any {
	e := ctx.Variable().Accept(s).(*ExpressionVariable)

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitIs_sql_expr(ctx *gen.Is_sql_exprContext) any {
	e := &ExpressionIs{
		Left: ctx.GetLeft().Accept(s).(Expression),
	}

	if ctx.NOT() != nil {
		e.Not = true
	}

	if ctx.DISTINCT() != nil {
		e.Distinct = true
	}

	switch {
	case ctx.NULL() != nil:
		e.Right = &ExpressionLiteral{
			Type: types.NullType,
		}
		e.Right.SetToken(ctx.NULL().GetSymbol())
	case ctx.TRUE() != nil:
		e.Right = &ExpressionLiteral{
			Type:  types.BoolType,
			Value: true,
		}
		e.Right.SetToken(ctx.TRUE().GetSymbol())
	case ctx.FALSE() != nil:
		e.Right = &ExpressionLiteral{
			Type:  types.BoolType,
			Value: false,
		}
		e.Right.SetToken(ctx.FALSE().GetSymbol())
	case ctx.GetRight() != nil:
		e.Right = ctx.GetRight().Accept(s).(Expression)
	default:
		panic("unknown right side of IS")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitLike_sql_expr(ctx *gen.Like_sql_exprContext) any {
	e := &ExpressionStringComparison{
		Left:  ctx.GetLeft().Accept(s).(Expression),
		Right: ctx.GetRight().Accept(s).(Expression),
	}

	if ctx.NOT() != nil {
		e.Not = true
	}

	switch {
	case ctx.LIKE() != nil:
		e.Operator = StringComparisonOperatorLike
	case ctx.ILIKE() != nil:
		e.Operator = StringComparisonOperatorILike
	default:
		panic("unknown string comparison operator")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitArithmetic_sql_expr(ctx *gen.Arithmetic_sql_exprContext) any {
	e := &ExpressionArithmetic{
		Left:  ctx.GetLeft().Accept(s).(Expression),
		Right: ctx.GetRight().Accept(s).(Expression),
	}

	switch {
	case ctx.PLUS() != nil:
		e.Operator = ArithmeticOperatorAdd
	case ctx.MINUS() != nil:
		e.Operator = ArithmeticOperatorSubtract
	case ctx.STAR() != nil:
		e.Operator = ArithmeticOperatorMultiply
	case ctx.DIV() != nil:
		e.Operator = ArithmeticOperatorDivide
	case ctx.MOD() != nil:
		e.Operator = ArithmeticOperatorModulo
	case ctx.CONCAT() != nil:
		e.Operator = ArithmeticOperatorConcat
	case ctx.EXP() != nil:
		e.Operator = ArithmeticOperatorExponent
	default:
		panic("unknown arithmetic operator")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitUnary_sql_expr(ctx *gen.Unary_sql_exprContext) any {
	e := &ExpressionUnary{
		Expression: ctx.Sql_expr().Accept(s).(Expression),
	}

	// this is the only known unary right now
	switch {
	case ctx.NOT() != nil:
		e.Operator = UnaryOperatorNot
	case ctx.MINUS() != nil:
		e.Operator = UnaryOperatorNeg
	case ctx.PLUS() != nil:
		e.Operator = UnaryOperatorPos
	default:
		panic("unknown unary operator")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitMake_array_sql_expr(ctx *gen.Make_array_sql_exprContext) any {
	e := &ExpressionMakeArray{}
	if ctx.Sql_expr_list() != nil {
		e.Values = ctx.Sql_expr_list().Accept(s).([]Expression)
	}

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitSubquery_sql_expr(ctx *gen.Subquery_sql_exprContext) any {
	e := &ExpressionSubquery{
		Subquery: ctx.Select_statement().Accept(s).(*SelectStatement),
	}

	if ctx.NOT() != nil {
		e.Not = true
	}

	if ctx.EXISTS() != nil {
		e.Exists = true
	}

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitCase_expr(ctx *gen.Case_exprContext) any {
	e := &ExpressionCase{}
	if ctx.GetCase_clause() != nil {
		e.Case = ctx.GetCase_clause().Accept(s).(Expression)
	}

	for i := range ctx.AllWhen_then_clause() {
		wt := ctx.AllWhen_then_clause()[i].Accept(s).([2]Expression)

		e.WhenThen = append(e.WhenThen, wt)
	}

	if ctx.GetElse_clause() != nil {
		e.Else = ctx.GetElse_clause().Accept(s).(Expression)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitWhen_then_clause(ctx *gen.When_then_clauseContext) any {
	when := ctx.Sql_expr(0).Accept(s).(Expression)
	then := ctx.Sql_expr(1).Accept(s).(Expression)
	return [2]Expression{when, then}
}

func (s *schemaVisitor) VisitIn_sql_expr(ctx *gen.In_sql_exprContext) any {
	e := &ExpressionIn{
		Expression: ctx.Sql_expr().Accept(s).(Expression),
	}

	if ctx.NOT() != nil {
		e.Not = true
	}

	if ctx.Sql_expr_list() != nil {
		e.List = ctx.Sql_expr_list().Accept(s).([]Expression)
	} else {
		e.Subquery = ctx.Select_statement().Accept(s).(*SelectStatement)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitSql_expr_list(ctx *gen.Sql_expr_listContext) any {

	var e []Expression
	for _, e2 := range ctx.AllSql_expr() {
		e = append(e, e2.Accept(s).(Expression))
	}

	return e
}

func (s *schemaVisitor) VisitNormal_call_sql(ctx *gen.Normal_call_sqlContext) any {
	call := &ExpressionFunctionCall{
		Name: s.getIdent(ctx.Identifier()),
	}

	// function calls can have either of these types for args,
	// or none at all.
	switch {
	case ctx.Sql_expr_list() != nil:
		call.Args = ctx.Sql_expr_list().Accept(s).([]Expression)
		if ctx.DISTINCT() != nil {
			call.Distinct = true
		}
	case ctx.STAR() != nil:
		call.Star = true
	}

	call.Set(ctx)
	return call
}

func (s *schemaVisitor) VisitField_access_action_expr(ctx *gen.Field_access_action_exprContext) any {
	e := &ExpressionFieldAccess{
		Record: ctx.Action_expr().Accept(s).(Expression),
		Field:  s.getIdent(ctx.Identifier()),
	}

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)

	return e
}

func (s *schemaVisitor) VisitLiteral_action_expr(ctx *gen.Literal_action_exprContext) any {
	e := ctx.Literal().Accept(s).(*ExpressionLiteral)

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitParen_action_expr(ctx *gen.Paren_action_exprContext) any {
	e := &ExpressionParenthesized{
		Inner: ctx.Action_expr().Accept(s).(Expression),
	}

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitVariable_action_expr(ctx *gen.Variable_action_exprContext) any {
	e := ctx.Variable().Accept(s).(*ExpressionVariable)

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitIs_action_expr(ctx *gen.Is_action_exprContext) any {
	e := &ExpressionIs{
		Left: ctx.Action_expr(0).Accept(s).(Expression),
	}

	if ctx.NOT() != nil {
		e.Not = true
	}

	if ctx.DISTINCT() != nil {
		e.Distinct = true
	}

	switch {
	case ctx.NULL() != nil:
		e.Right = &ExpressionLiteral{
			Type: types.NullType,
		}
		e.Right.SetToken(ctx.NULL().GetSymbol())
	case ctx.TRUE() != nil:
		e.Right = &ExpressionLiteral{
			Type:  types.BoolType,
			Value: true,
		}
		e.Right.SetToken(ctx.TRUE().GetSymbol())
	case ctx.FALSE() != nil:
		e.Right = &ExpressionLiteral{
			Type:  types.BoolType,
			Value: false,
		}
		e.Right.SetToken(ctx.FALSE().GetSymbol())
	case ctx.GetRight() != nil:
		e.Right = ctx.GetRight().Accept(s).(Expression)
	default:
		panic("unknown right side of IS")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitLogical_action_expr(ctx *gen.Logical_action_exprContext) any {
	e := &ExpressionLogical{
		Left:  ctx.Action_expr(0).Accept(s).(Expression),
		Right: ctx.Action_expr(1).Accept(s).(Expression),
	}

	switch {
	case ctx.AND() != nil:
		e.Operator = LogicalOperatorAnd
	case ctx.OR() != nil:
		e.Operator = LogicalOperatorOr
	default:
		panic("unknown logical operator")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitAction_expr_arithmetic(ctx *gen.Action_expr_arithmeticContext) any {
	e := &ExpressionArithmetic{
		Left:  ctx.Action_expr(0).Accept(s).(Expression),
		Right: ctx.Action_expr(1).Accept(s).(Expression),
	}

	switch {
	case ctx.PLUS() != nil:
		e.Operator = ArithmeticOperatorAdd
	case ctx.MINUS() != nil:
		e.Operator = ArithmeticOperatorSubtract
	case ctx.STAR() != nil:
		e.Operator = ArithmeticOperatorMultiply
	case ctx.DIV() != nil:
		e.Operator = ArithmeticOperatorDivide
	case ctx.MOD() != nil:
		e.Operator = ArithmeticOperatorModulo
	case ctx.EXP() != nil:
		e.Operator = ArithmeticOperatorExponent
	case ctx.CONCAT() != nil:
		e.Operator = ArithmeticOperatorConcat
	default:
		panic("unknown arithmetic operator")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitComparison_action_expr(ctx *gen.Comparison_action_exprContext) any {
	e := &ExpressionComparison{
		Left:  ctx.Action_expr(0).Accept(s).(Expression),
		Right: ctx.Action_expr(1).Accept(s).(Expression),
	}

	switch {
	case ctx.EQUALS() != nil || ctx.EQUATE() != nil:
		e.Operator = ComparisonOperatorEqual
	case ctx.NEQ() != nil:
		e.Operator = ComparisonOperatorNotEqual
	case ctx.LT() != nil:
		e.Operator = ComparisonOperatorLessThan
	case ctx.LTE() != nil:
		e.Operator = ComparisonOperatorLessThanOrEqual
	case ctx.GT() != nil:
		e.Operator = ComparisonOperatorGreaterThan
	case ctx.GTE() != nil:
		e.Operator = ComparisonOperatorGreaterThanOrEqual
	default:
		panic("unknown comparison operator")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitFunction_call_action_expr(ctx *gen.Function_call_action_exprContext) any {
	call := ctx.Action_function_call().Accept(s).(*ExpressionFunctionCall)

	if ctx.Type_cast() != nil {
		call.Cast(ctx.Type_cast().Accept(s).(*types.DataType))
	}

	call.Set(ctx)

	return call
}

func (s *schemaVisitor) VisitArray_access_action_expr(ctx *gen.Array_access_action_exprContext) any {
	e := &ExpressionArrayAccess{
		Array: ctx.Action_expr(0).Accept(s).(Expression),
	}

	s.makeArray(e, ctx.GetSingle(), ctx.GetLeft(), ctx.GetRight())

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitUnary_action_expr(ctx *gen.Unary_action_exprContext) any {
	e := &ExpressionUnary{
		Expression: ctx.Action_expr().Accept(s).(Expression),
	}

	// this is the only known unary right now
	switch {
	case ctx.EXCL() != nil || ctx.NOT() != nil:
		e.Operator = UnaryOperatorNot
	case ctx.MINUS() != nil:
		e.Operator = UnaryOperatorNeg
	case ctx.PLUS() != nil:
		e.Operator = UnaryOperatorPos
	default:
		panic("unknown unary operator")
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitMake_array_action_expr(ctx *gen.Make_array_action_exprContext) any {
	e := &ExpressionMakeArray{
		// golang interface assertions do not work for slices, so we simply
		// cast the result to []Expression. This comes from VisitAction_expr_list,
		// directly below.
	}

	if ctx.Action_expr_list() != nil {
		e.Values = ctx.Action_expr_list().Accept(s).([]Expression)
	}

	if ctx.Type_cast() != nil {
		e.TypeCast = ctx.Type_cast().Accept(s).(*types.DataType)
	}

	e.Set(ctx)
	return e
}

func (s *schemaVisitor) VisitAction_expr_list(ctx *gen.Action_expr_listContext) any {
	// we do not return a type ExpressionList here, since ExpressionList is SQL specific,
	// and not supported in actions. Instead, we return a slice of Expression.
	var exprs []Expression

	for _, e := range ctx.AllAction_expr() {
		exprs = append(exprs, e.Accept(s).(Expression))
	}

	return exprs
}

func (s *schemaVisitor) VisitStmt_variable_declaration(ctx *gen.Stmt_variable_declarationContext) any {
	stmt := &ActionStmtDeclaration{
		Variable: varFromTerminalNode(ctx.VARIABLE()),
	}

	if ctx.Type_() != nil {
		stmt.Type = ctx.Type_().Accept(s).(*types.DataType)
	}

	stmt.Set(ctx)
	return stmt
}

// varFromTerminalNode returns a variable from an antlr terminal node.
// If the string is not a valid variable, it panics.
// This is only meant to be used when creating expressions
// directly from the AST. It will lowercase the string to
// ensure case-insensitivity.
func varFromTerminalNode(node antlr.TerminalNode) *ExpressionVariable {
	s := node.GetText()
	e := varFromString(s)
	e.SetToken(node.GetSymbol())

	return e
}

// varFromString returns a variable from a string.
func varFromString(s string) *ExpressionVariable {
	e := &ExpressionVariable{}
	if len(s) < 2 {
		panic("invalid variable: " + s)
	}

	switch {
	case s[0] == '$':
		e.Prefix = VariablePrefixDollar
	case s[0] == '@':
		e.Prefix = VariablePrefixAt
	default:
		panic("invalid variable: " + s)
	}

	e.Name = strings.ToLower(s)

	return e
}

func (s *schemaVisitor) VisitStmt_action_call(ctx *gen.Stmt_action_callContext) any {
	stmt := &ActionStmtCall{
		Call: ctx.Action_function_call().Accept(s).(*ExpressionFunctionCall),
	}

	for i, v := range ctx.AllVariable_or_underscore() {
		// check for nil since nil pointer will fail *string type assertion
		if v.Accept(s) == nil {
			stmt.Receivers = append(stmt.Receivers, nil)
			continue
		}

		stmt.Receivers = append(stmt.Receivers, varFromString(*v.Accept(s).(*string)))
		stmt.Receivers[i].Set(v)
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitVariable_or_underscore(ctx *gen.Variable_or_underscoreContext) any {
	if ctx.UNDERSCORE() != nil {
		return nil
	}

	str := s.cleanStringIdent(ctx, ctx.VARIABLE().GetText())
	return &str
}

func (s *schemaVisitor) VisitStmt_variable_assignment(ctx *gen.Stmt_variable_assignmentContext) any {
	stmt := &ActionStmtAssign{}

	assignVariable := ctx.Action_expr(0).Accept(s).(Expression)

	assignable, ok := assignVariable.(Assignable)
	if !ok {
		s.errs.RuleErr(ctx.Action_expr(0), ErrSyntax, "cannot assign to %T", assignVariable)
	}
	stmt.Variable = assignable
	stmt.Value = ctx.Action_expr(1).Accept(s).(Expression)

	if ctx.Type_() != nil {
		// if a type is specified, the assign variable must be a variable
		switch stmt.Variable.(type) {
		case *ExpressionVariable:
			// do nothing, this is the expected type
		case *ExpressionArrayAccess:
			s.errs.RuleErr(ctx.Action_expr(0), ErrSyntax, "cannot assign new type to slice element(s)")
		default:
			panic("unknown assignable type")
		}

		stmt.Type = ctx.Type_().Accept(s).(*types.DataType)
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitStmt_for_loop(ctx *gen.Stmt_for_loopContext) any {
	stmt := &ActionStmtForLoop{
		Receiver: varFromTerminalNode(ctx.VARIABLE()),
		Body:     arr[ActionStmt](len(ctx.AllAction_statement())),
	}

	switch {
	case ctx.Range_() != nil:
		stmt.LoopTerm = ctx.Range_().Accept(s).(*LoopTermRange)
	case ctx.Action_expr() != nil:
		expr := ctx.Action_expr().Accept(s).(Expression)
		stmt.LoopTerm = &LoopTermExpression{
			Array:      ctx.ARRAY() != nil,
			Expression: expr,
		}
		stmt.LoopTerm.Set(ctx.Action_expr())
	case ctx.Sql_statement() != nil:
		sqlStmt := ctx.Sql_statement().Accept(s).(*SQLStatement)
		stmt.LoopTerm = &LoopTermSQL{
			Statement: sqlStmt,
		}
		stmt.LoopTerm.Set(ctx.Sql_statement())
	default:
		panic("unknown loop term")
	}

	for i, st := range ctx.AllAction_statement() {
		stmt.Body[i] = st.Accept(s).(ActionStmt)
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitStmt_if(ctx *gen.Stmt_ifContext) any {
	stmt := &ActionStmtIf{
		IfThens: arr[*IfThen](len(ctx.AllIf_then_block())),
		Else:    arr[ActionStmt](len(ctx.AllAction_statement())),
	}

	for i, th := range ctx.AllIf_then_block() {
		stmt.IfThens[i] = th.Accept(s).(*IfThen)
	}

	for i, st := range ctx.AllAction_statement() {
		stmt.Else[i] = st.Accept(s).(ActionStmt)
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitIf_then_block(ctx *gen.If_then_blockContext) any {
	ifthen := &IfThen{
		If:   ctx.Action_expr().Accept(s).(Expression),
		Then: arr[ActionStmt](len(ctx.AllAction_statement())),
	}

	for i, st := range ctx.AllAction_statement() {
		ifthen.Then[i] = st.Accept(s).(ActionStmt)
	}

	ifthen.Set(ctx)

	return ifthen
}

func (s *schemaVisitor) VisitStmt_sql(ctx *gen.Stmt_sqlContext) any {
	stmt := &ActionStmtSQL{
		SQL: ctx.Sql_statement().Accept(s).(*SQLStatement),
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitStmt_loop_control(ctx *gen.Stmt_loop_controlContext) any {
	stmt := &ActionStmtLoopControl{}
	switch {
	case ctx.BREAK() != nil:
		stmt.Type = LoopControlTypeBreak
	case ctx.CONTINUE() != nil:
		stmt.Type = LoopControlTypeContinue
	default:
		panic("unknown parsed loop control type")
	}
	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitStmt_return(ctx *gen.Stmt_returnContext) any {
	stmt := &ActionStmtReturn{}

	switch {
	case ctx.Sql_statement() != nil:
		stmt.SQL = ctx.Sql_statement().Accept(s).(*SQLStatement)
	case ctx.Action_expr_list() != nil:
		// loop through and add since these are Expressions, not Expressions
		exprs := ctx.Action_expr_list().Accept(s).([]Expression)
		stmt.Values = append(stmt.Values, exprs...)
		// return can be nil if an action simply wants to exit early
	}

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitStmt_return_next(ctx *gen.Stmt_return_nextContext) any {
	stmt := &ActionStmtReturnNext{}

	vals := ctx.Action_expr_list().Accept(s).([]Expression)
	stmt.Values = append(stmt.Values, vals...)

	stmt.Set(ctx)
	return stmt
}

func (s *schemaVisitor) VisitNormal_call_action(ctx *gen.Normal_call_actionContext) any {
	call := &ExpressionFunctionCall{}

	call.Name = s.getIdent(ctx.GetFunction())
	if ctx.GetNamespace() != nil {
		call.Namespace = s.getIdent(ctx.GetNamespace())
	}

	// distinct and * cannot be used in action function calls
	if ctx.Action_expr_list() != nil {
		call.Args = ctx.Action_expr_list().Accept(s).([]Expression)
	}

	call.Set(ctx)
	return call
}

func (s *schemaVisitor) VisitRange(ctx *gen.RangeContext) any {
	r := &LoopTermRange{
		Start: ctx.Action_expr(0).Accept(s).(Expression),
		End:   ctx.Action_expr(1).Accept(s).(Expression),
	}

	r.Set(ctx)
	return r
}

func (s *schemaVisitor) VisitWindow(ctx *gen.WindowContext) any {
	win := &WindowImpl{}

	if ctx.GetPartition() != nil {
		win.PartitionBy = ctx.GetPartition().Accept(s).([]Expression)
	}

	if ctx.ORDER() != nil {
		for _, o := range ctx.AllOrdering_term() {
			win.OrderBy = append(win.OrderBy, o.Accept(s).(*OrderingTerm))
		}
	}

	// currently does not support frame

	win.Set(ctx)
	return win
}

func (s *schemaVisitor) Visit(tree antlr.ParseTree) interface {
} {
	return tree.Accept(s)
}

// getIdent returns the text of an identifier.
// It checks that the identifier is not too long.
// It also converts the identifier to lowercase.
func (s *schemaVisitor) getIdent(i gen.IIdentifierContext) string {
	return strings.ToLower(s.cleanStringIdent(i, i.Allowed_identifier().GetText()))
}

func (s *schemaVisitor) cleanStringIdent(t antlr.ParserRuleContext, i string) string {
	s.validateVariableIdentifier(t, i)
	return strings.ToLower(i)
}

// validateVariableIdentifier validates that a variable's identifier is not too long.
// It doesn't check if it is a keyword, since variables have $ prefixes.
func (s *schemaVisitor) validateVariableIdentifier(i antlr.ParserRuleContext, str string) {
	if len(str) > validation.MAX_IDENT_NAME_LENGTH {
		s.errs.RuleErr(i, ErrIdentifier, "maximum identifier length is %d", maxIdentifierLength)
	}
}

// pg max is 63, but Kwil sometimes adds extra characters
var maxIdentifierLength = 32

// createDefaultValue creates a DefaultValue from an Expression.
// It optimizes simple literals by pre-evaluating them.
func (s *schemaVisitor) createDefaultValue(expr Expression) *DefaultValue {
	defaultVal := &DefaultValue{
		Expression: expr,
	}

	// Check if it's a simple literal that can be pre-evaluated
	if literal, ok := expr.(*ExpressionLiteral); ok {
		defaultVal.IsLiteralValue = true
		defaultVal.LiteralValue = literal.Value
	} else {
		defaultVal.IsLiteralValue = false
	}

	return defaultVal
}
