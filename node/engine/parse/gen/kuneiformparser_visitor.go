// Code generated from KuneiformParser.g4 by ANTLR 4.13.1. DO NOT EDIT.

package gen // KuneiformParser
import "github.com/antlr4-go/antlr/v4"

// A complete Visitor for a parse tree produced by KuneiformParser.
type KuneiformParserVisitor interface {
	antlr.ParseTreeVisitor

	// Visit a parse tree produced by KuneiformParser#entry.
	VisitEntry(ctx *EntryContext) interface{}

	// Visit a parse tree produced by KuneiformParser#statement.
	VisitStatement(ctx *StatementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#string_literal.
	VisitString_literal(ctx *String_literalContext) interface{}

	// Visit a parse tree produced by KuneiformParser#integer_literal.
	VisitInteger_literal(ctx *Integer_literalContext) interface{}

	// Visit a parse tree produced by KuneiformParser#decimal_literal.
	VisitDecimal_literal(ctx *Decimal_literalContext) interface{}

	// Visit a parse tree produced by KuneiformParser#boolean_literal.
	VisitBoolean_literal(ctx *Boolean_literalContext) interface{}

	// Visit a parse tree produced by KuneiformParser#null_literal.
	VisitNull_literal(ctx *Null_literalContext) interface{}

	// Visit a parse tree produced by KuneiformParser#binary_literal.
	VisitBinary_literal(ctx *Binary_literalContext) interface{}

	// Visit a parse tree produced by KuneiformParser#identifier.
	VisitIdentifier(ctx *IdentifierContext) interface{}

	// Visit a parse tree produced by KuneiformParser#allowed_identifier.
	VisitAllowed_identifier(ctx *Allowed_identifierContext) interface{}

	// Visit a parse tree produced by KuneiformParser#identifier_list.
	VisitIdentifier_list(ctx *Identifier_listContext) interface{}

	// Visit a parse tree produced by KuneiformParser#type.
	VisitType(ctx *TypeContext) interface{}

	// Visit a parse tree produced by KuneiformParser#type_cast.
	VisitType_cast(ctx *Type_castContext) interface{}

	// Visit a parse tree produced by KuneiformParser#variable.
	VisitVariable(ctx *VariableContext) interface{}

	// Visit a parse tree produced by KuneiformParser#table_column_def.
	VisitTable_column_def(ctx *Table_column_defContext) interface{}

	// Visit a parse tree produced by KuneiformParser#type_list.
	VisitType_list(ctx *Type_listContext) interface{}

	// Visit a parse tree produced by KuneiformParser#named_type_list.
	VisitNamed_type_list(ctx *Named_type_listContext) interface{}

	// Visit a parse tree produced by KuneiformParser#inline_constraint.
	VisitInline_constraint(ctx *Inline_constraintContext) interface{}

	// Visit a parse tree produced by KuneiformParser#fk_action.
	VisitFk_action(ctx *Fk_actionContext) interface{}

	// Visit a parse tree produced by KuneiformParser#fk_constraint.
	VisitFk_constraint(ctx *Fk_constraintContext) interface{}

	// Visit a parse tree produced by KuneiformParser#action_return.
	VisitAction_return(ctx *Action_returnContext) interface{}

	// Visit a parse tree produced by KuneiformParser#sql_statement.
	VisitSql_statement(ctx *Sql_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#common_table_expression.
	VisitCommon_table_expression(ctx *Common_table_expressionContext) interface{}

	// Visit a parse tree produced by KuneiformParser#create_table_statement.
	VisitCreate_table_statement(ctx *Create_table_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#table_constraint_def.
	VisitTable_constraint_def(ctx *Table_constraint_defContext) interface{}

	// Visit a parse tree produced by KuneiformParser#opt_drop_behavior.
	VisitOpt_drop_behavior(ctx *Opt_drop_behaviorContext) interface{}

	// Visit a parse tree produced by KuneiformParser#drop_table_statement.
	VisitDrop_table_statement(ctx *Drop_table_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#alter_table_statement.
	VisitAlter_table_statement(ctx *Alter_table_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#add_column_constraint.
	VisitAdd_column_constraint(ctx *Add_column_constraintContext) interface{}

	// Visit a parse tree produced by KuneiformParser#drop_column_constraint.
	VisitDrop_column_constraint(ctx *Drop_column_constraintContext) interface{}

	// Visit a parse tree produced by KuneiformParser#add_column.
	VisitAdd_column(ctx *Add_columnContext) interface{}

	// Visit a parse tree produced by KuneiformParser#drop_column.
	VisitDrop_column(ctx *Drop_columnContext) interface{}

	// Visit a parse tree produced by KuneiformParser#rename_column.
	VisitRename_column(ctx *Rename_columnContext) interface{}

	// Visit a parse tree produced by KuneiformParser#rename_table.
	VisitRename_table(ctx *Rename_tableContext) interface{}

	// Visit a parse tree produced by KuneiformParser#add_table_constraint.
	VisitAdd_table_constraint(ctx *Add_table_constraintContext) interface{}

	// Visit a parse tree produced by KuneiformParser#drop_table_constraint.
	VisitDrop_table_constraint(ctx *Drop_table_constraintContext) interface{}

	// Visit a parse tree produced by KuneiformParser#create_index_statement.
	VisitCreate_index_statement(ctx *Create_index_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#drop_index_statement.
	VisitDrop_index_statement(ctx *Drop_index_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#create_role_statement.
	VisitCreate_role_statement(ctx *Create_role_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#drop_role_statement.
	VisitDrop_role_statement(ctx *Drop_role_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#grant_statement.
	VisitGrant_statement(ctx *Grant_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#revoke_statement.
	VisitRevoke_statement(ctx *Revoke_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#transfer_ownership_statement.
	VisitTransfer_ownership_statement(ctx *Transfer_ownership_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#privilege_list.
	VisitPrivilege_list(ctx *Privilege_listContext) interface{}

	// Visit a parse tree produced by KuneiformParser#privilege.
	VisitPrivilege(ctx *PrivilegeContext) interface{}

	// Visit a parse tree produced by KuneiformParser#create_action_statement.
	VisitCreate_action_statement(ctx *Create_action_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#drop_action_statement.
	VisitDrop_action_statement(ctx *Drop_action_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#action_parameter.
	VisitAction_parameter(ctx *Action_parameterContext) interface{}

	// Visit a parse tree produced by KuneiformParser#use_extension_statement.
	VisitUse_extension_statement(ctx *Use_extension_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#unuse_extension_statement.
	VisitUnuse_extension_statement(ctx *Unuse_extension_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#create_namespace_statement.
	VisitCreate_namespace_statement(ctx *Create_namespace_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#drop_namespace_statement.
	VisitDrop_namespace_statement(ctx *Drop_namespace_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#set_current_namespace_statement.
	VisitSet_current_namespace_statement(ctx *Set_current_namespace_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#select_statement.
	VisitSelect_statement(ctx *Select_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#compound_operator.
	VisitCompound_operator(ctx *Compound_operatorContext) interface{}

	// Visit a parse tree produced by KuneiformParser#ordering_term.
	VisitOrdering_term(ctx *Ordering_termContext) interface{}

	// Visit a parse tree produced by KuneiformParser#select_core.
	VisitSelect_core(ctx *Select_coreContext) interface{}

	// Visit a parse tree produced by KuneiformParser#table_relation.
	VisitTable_relation(ctx *Table_relationContext) interface{}

	// Visit a parse tree produced by KuneiformParser#subquery_relation.
	VisitSubquery_relation(ctx *Subquery_relationContext) interface{}

	// Visit a parse tree produced by KuneiformParser#table_function_relation.
	VisitTable_function_relation(ctx *Table_function_relationContext) interface{}

	// Visit a parse tree produced by KuneiformParser#join.
	VisitJoin(ctx *JoinContext) interface{}

	// Visit a parse tree produced by KuneiformParser#expression_result_column.
	VisitExpression_result_column(ctx *Expression_result_columnContext) interface{}

	// Visit a parse tree produced by KuneiformParser#wildcard_result_column.
	VisitWildcard_result_column(ctx *Wildcard_result_columnContext) interface{}

	// Visit a parse tree produced by KuneiformParser#update_statement.
	VisitUpdate_statement(ctx *Update_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#update_set_clause.
	VisitUpdate_set_clause(ctx *Update_set_clauseContext) interface{}

	// Visit a parse tree produced by KuneiformParser#insert_statement.
	VisitInsert_statement(ctx *Insert_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#upsert_clause.
	VisitUpsert_clause(ctx *Upsert_clauseContext) interface{}

	// Visit a parse tree produced by KuneiformParser#delete_statement.
	VisitDelete_statement(ctx *Delete_statementContext) interface{}

	// Visit a parse tree produced by KuneiformParser#column_sql_expr.
	VisitColumn_sql_expr(ctx *Column_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#logical_sql_expr.
	VisitLogical_sql_expr(ctx *Logical_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#field_access_sql_expr.
	VisitField_access_sql_expr(ctx *Field_access_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#array_access_sql_expr.
	VisitArray_access_sql_expr(ctx *Array_access_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#comparison_sql_expr.
	VisitComparison_sql_expr(ctx *Comparison_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#literal_sql_expr.
	VisitLiteral_sql_expr(ctx *Literal_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#between_sql_expr.
	VisitBetween_sql_expr(ctx *Between_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#function_call_sql_expr.
	VisitFunction_call_sql_expr(ctx *Function_call_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#paren_sql_expr.
	VisitParen_sql_expr(ctx *Paren_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#collate_sql_expr.
	VisitCollate_sql_expr(ctx *Collate_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#make_array_sql_expr.
	VisitMake_array_sql_expr(ctx *Make_array_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#variable_sql_expr.
	VisitVariable_sql_expr(ctx *Variable_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#window_function_call_sql_expr.
	VisitWindow_function_call_sql_expr(ctx *Window_function_call_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#is_sql_expr.
	VisitIs_sql_expr(ctx *Is_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#arithmetic_sql_expr.
	VisitArithmetic_sql_expr(ctx *Arithmetic_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#like_sql_expr.
	VisitLike_sql_expr(ctx *Like_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#subquery_sql_expr.
	VisitSubquery_sql_expr(ctx *Subquery_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#unary_sql_expr.
	VisitUnary_sql_expr(ctx *Unary_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#case_expr.
	VisitCase_expr(ctx *Case_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#in_sql_expr.
	VisitIn_sql_expr(ctx *In_sql_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#window.
	VisitWindow(ctx *WindowContext) interface{}

	// Visit a parse tree produced by KuneiformParser#when_then_clause.
	VisitWhen_then_clause(ctx *When_then_clauseContext) interface{}

	// Visit a parse tree produced by KuneiformParser#sql_expr_list.
	VisitSql_expr_list(ctx *Sql_expr_listContext) interface{}

	// Visit a parse tree produced by KuneiformParser#normal_call_sql.
	VisitNormal_call_sql(ctx *Normal_call_sqlContext) interface{}

	// Visit a parse tree produced by KuneiformParser#function_call_action_expr.
	VisitFunction_call_action_expr(ctx *Function_call_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#literal_action_expr.
	VisitLiteral_action_expr(ctx *Literal_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#field_access_action_expr.
	VisitField_access_action_expr(ctx *Field_access_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#is_action_expr.
	VisitIs_action_expr(ctx *Is_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#variable_action_expr.
	VisitVariable_action_expr(ctx *Variable_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#make_array_action_expr.
	VisitMake_array_action_expr(ctx *Make_array_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#comparison_action_expr.
	VisitComparison_action_expr(ctx *Comparison_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#action_expr_arithmetic.
	VisitAction_expr_arithmetic(ctx *Action_expr_arithmeticContext) interface{}

	// Visit a parse tree produced by KuneiformParser#array_access_action_expr.
	VisitArray_access_action_expr(ctx *Array_access_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#logical_action_expr.
	VisitLogical_action_expr(ctx *Logical_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#paren_action_expr.
	VisitParen_action_expr(ctx *Paren_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#unary_action_expr.
	VisitUnary_action_expr(ctx *Unary_action_exprContext) interface{}

	// Visit a parse tree produced by KuneiformParser#action_expr_list.
	VisitAction_expr_list(ctx *Action_expr_listContext) interface{}

	// Visit a parse tree produced by KuneiformParser#stmt_variable_declaration.
	VisitStmt_variable_declaration(ctx *Stmt_variable_declarationContext) interface{}

	// Visit a parse tree produced by KuneiformParser#stmt_action_call.
	VisitStmt_action_call(ctx *Stmt_action_callContext) interface{}

	// Visit a parse tree produced by KuneiformParser#stmt_variable_assignment.
	VisitStmt_variable_assignment(ctx *Stmt_variable_assignmentContext) interface{}

	// Visit a parse tree produced by KuneiformParser#stmt_for_loop.
	VisitStmt_for_loop(ctx *Stmt_for_loopContext) interface{}

	// Visit a parse tree produced by KuneiformParser#stmt_if.
	VisitStmt_if(ctx *Stmt_ifContext) interface{}

	// Visit a parse tree produced by KuneiformParser#stmt_sql.
	VisitStmt_sql(ctx *Stmt_sqlContext) interface{}

	// Visit a parse tree produced by KuneiformParser#stmt_loop_control.
	VisitStmt_loop_control(ctx *Stmt_loop_controlContext) interface{}

	// Visit a parse tree produced by KuneiformParser#stmt_return.
	VisitStmt_return(ctx *Stmt_returnContext) interface{}

	// Visit a parse tree produced by KuneiformParser#stmt_return_next.
	VisitStmt_return_next(ctx *Stmt_return_nextContext) interface{}

	// Visit a parse tree produced by KuneiformParser#variable_or_underscore.
	VisitVariable_or_underscore(ctx *Variable_or_underscoreContext) interface{}

	// Visit a parse tree produced by KuneiformParser#normal_call_action.
	VisitNormal_call_action(ctx *Normal_call_actionContext) interface{}

	// Visit a parse tree produced by KuneiformParser#if_then_block.
	VisitIf_then_block(ctx *If_then_blockContext) interface{}

	// Visit a parse tree produced by KuneiformParser#range.
	VisitRange(ctx *RangeContext) interface{}
}
