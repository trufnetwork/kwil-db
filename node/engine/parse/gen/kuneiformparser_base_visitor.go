// Code generated from KuneiformParser.g4 by ANTLR 4.13.1. DO NOT EDIT.

package gen // KuneiformParser
import "github.com/antlr4-go/antlr/v4"

type BaseKuneiformParserVisitor struct {
	*antlr.BaseParseTreeVisitor
}

func (v *BaseKuneiformParserVisitor) VisitEntry(ctx *EntryContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStatement(ctx *StatementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitString_literal(ctx *String_literalContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitInteger_literal(ctx *Integer_literalContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDecimal_literal(ctx *Decimal_literalContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitBoolean_literal(ctx *Boolean_literalContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitNull_literal(ctx *Null_literalContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitBinary_literal(ctx *Binary_literalContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitIdentifier(ctx *IdentifierContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitAllowed_identifier(ctx *Allowed_identifierContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitIdentifier_list(ctx *Identifier_listContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitType(ctx *TypeContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitType_cast(ctx *Type_castContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitVariable(ctx *VariableContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitTable_column_def(ctx *Table_column_defContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitType_list(ctx *Type_listContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitNamed_type_list(ctx *Named_type_listContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitInline_constraint(ctx *Inline_constraintContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitFk_action(ctx *Fk_actionContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitFk_constraint(ctx *Fk_constraintContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitAction_return(ctx *Action_returnContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitSql_statement(ctx *Sql_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitCommon_table_expression(ctx *Common_table_expressionContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitCreate_table_statement(ctx *Create_table_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitTable_constraint_def(ctx *Table_constraint_defContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitOpt_drop_behavior(ctx *Opt_drop_behaviorContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDrop_table_statement(ctx *Drop_table_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitAlter_table_statement(ctx *Alter_table_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitAdd_column_constraint(ctx *Add_column_constraintContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDrop_column_constraint(ctx *Drop_column_constraintContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitAdd_column(ctx *Add_columnContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDrop_column(ctx *Drop_columnContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitRename_column(ctx *Rename_columnContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitRename_table(ctx *Rename_tableContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitAdd_table_constraint(ctx *Add_table_constraintContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDrop_table_constraint(ctx *Drop_table_constraintContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitCreate_index_statement(ctx *Create_index_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDrop_index_statement(ctx *Drop_index_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitCreate_role_statement(ctx *Create_role_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDrop_role_statement(ctx *Drop_role_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitGrant_statement(ctx *Grant_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitRevoke_statement(ctx *Revoke_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitTransfer_ownership_statement(ctx *Transfer_ownership_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitPrivilege_list(ctx *Privilege_listContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitPrivilege(ctx *PrivilegeContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitCreate_action_statement(ctx *Create_action_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDrop_action_statement(ctx *Drop_action_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitAction_parameter(ctx *Action_parameterContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitUse_extension_statement(ctx *Use_extension_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitUnuse_extension_statement(ctx *Unuse_extension_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitCreate_namespace_statement(ctx *Create_namespace_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDrop_namespace_statement(ctx *Drop_namespace_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitSet_current_namespace_statement(ctx *Set_current_namespace_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitSelect_statement(ctx *Select_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitCompound_operator(ctx *Compound_operatorContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitOrdering_term(ctx *Ordering_termContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitSelect_core(ctx *Select_coreContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitTable_relation(ctx *Table_relationContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitSubquery_relation(ctx *Subquery_relationContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitJoin(ctx *JoinContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitExpression_result_column(ctx *Expression_result_columnContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitWildcard_result_column(ctx *Wildcard_result_columnContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitUpdate_statement(ctx *Update_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitUpdate_set_clause(ctx *Update_set_clauseContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitInsert_statement(ctx *Insert_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitUpsert_clause(ctx *Upsert_clauseContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitDelete_statement(ctx *Delete_statementContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitColumn_sql_expr(ctx *Column_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitLogical_sql_expr(ctx *Logical_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitField_access_sql_expr(ctx *Field_access_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitArray_access_sql_expr(ctx *Array_access_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitComparison_sql_expr(ctx *Comparison_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitLiteral_sql_expr(ctx *Literal_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitBetween_sql_expr(ctx *Between_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitFunction_call_sql_expr(ctx *Function_call_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitParen_sql_expr(ctx *Paren_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitCollate_sql_expr(ctx *Collate_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitMake_array_sql_expr(ctx *Make_array_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitVariable_sql_expr(ctx *Variable_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitWindow_function_call_sql_expr(ctx *Window_function_call_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitIs_sql_expr(ctx *Is_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitArithmetic_sql_expr(ctx *Arithmetic_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitLike_sql_expr(ctx *Like_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitSubquery_sql_expr(ctx *Subquery_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitUnary_sql_expr(ctx *Unary_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitCase_expr(ctx *Case_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitIn_sql_expr(ctx *In_sql_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitWindow(ctx *WindowContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitWhen_then_clause(ctx *When_then_clauseContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitSql_expr_list(ctx *Sql_expr_listContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitNormal_call_sql(ctx *Normal_call_sqlContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitFunction_call_action_expr(ctx *Function_call_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitLiteral_action_expr(ctx *Literal_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitField_access_action_expr(ctx *Field_access_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitIs_action_expr(ctx *Is_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitVariable_action_expr(ctx *Variable_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitMake_array_action_expr(ctx *Make_array_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitComparison_action_expr(ctx *Comparison_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitAction_expr_arithmetic(ctx *Action_expr_arithmeticContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitArray_access_action_expr(ctx *Array_access_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitLogical_action_expr(ctx *Logical_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitParen_action_expr(ctx *Paren_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitUnary_action_expr(ctx *Unary_action_exprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitAction_expr_list(ctx *Action_expr_listContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStmt_variable_declaration(ctx *Stmt_variable_declarationContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStmt_action_call(ctx *Stmt_action_callContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStmt_variable_assignment(ctx *Stmt_variable_assignmentContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStmt_for_loop(ctx *Stmt_for_loopContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStmt_if(ctx *Stmt_ifContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStmt_sql(ctx *Stmt_sqlContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStmt_loop_control(ctx *Stmt_loop_controlContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStmt_return(ctx *Stmt_returnContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitStmt_return_next(ctx *Stmt_return_nextContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitVariable_or_underscore(ctx *Variable_or_underscoreContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitNormal_call_action(ctx *Normal_call_actionContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitIf_then_block(ctx *If_then_blockContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseKuneiformParserVisitor) VisitRange(ctx *RangeContext) interface{} {
	return v.VisitChildren(ctx)
}
