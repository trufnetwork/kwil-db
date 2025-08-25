/*
 * A ANTLR4 grammar for Kuneiform.
 * Developed by the Kwil team.
*/
parser grammar KuneiformParser;

options {
    tokenVocab = KuneiformLexer;
}

// entry point for the parser
entry:
 // optional semicolons, but required if there are multiple statements to delimit them
    statement (SCOL statement)* SCOL? EOF
;

statement:
    (LBRACE namespace=identifier RBRACE)?
    (
        sql_statement
        | create_table_statement
        | alter_table_statement
        | drop_table_statement
        | create_index_statement
        | drop_index_statement
        | create_role_statement
        | drop_role_statement
        | grant_statement
        | revoke_statement
        | transfer_ownership_statement
        | create_action_statement
        | drop_action_statement
        | use_extension_statement
        | unuse_extension_statement
        | create_namespace_statement
        | drop_namespace_statement
        | set_current_namespace_statement
    )
;

/*
    The following section includes the parser rules that are commonly
    used among all sections of the grammar. These include literals,
*/

literal:
    STRING_                                     # string_literal
    | (PLUS | MINUS)? DIGITS_                   # integer_literal
    | (PLUS | MINUS)? DIGITS_ PERIOD DIGITS_    # decimal_literal
    | (TRUE | FALSE)                            # boolean_literal
    | NULL                                      # null_literal
    | BINARY_                                   # binary_literal
;

// identifier is used for table / column names
identifier:
    (DOUBLE_QUOTE allowed_identifier DOUBLE_QUOTE) | allowed_identifier
;

// allowed_identifier allows us to use reserved keywords as identifiers
allowed_identifier:
    IDENTIFIER
    // we include a lot of tokens here to allow them to be used as identifiers.
    // Some tokens, such as NOT, IS, etc., are not included since it causes parsing issues.
    | CREATE
    | ALTER
    | ADD
    | DROP
    | RENAME
    | CHECK
    | FOREIGN
    | PRIMARY
    | KEY
    | UNIQUE
    | RESTRICT
    | INDEX
    | RETURNS
    | FOR
    | IF
    | ELSEIF
    | ELSE
    | BREAK
    | CONTINUE
    | RETURN
    | GRANT
    | GRANTED
    | REVOKE
    | ROLE
    | REPLACE
    | NAMESPACE
    | ROLES
    | CALL
    | USE
    | UNUSE
    | DEFAULT
    | ACTION
    | TRANSFER
    | OWNERSHIP
    | CURRENT
;

identifier_list:
    identifier (COMMA identifier)*
;

type:
    identifier (LPAREN precision=DIGITS_ (COMMA scale=DIGITS_)? RPAREN)? (LBRACKET RBRACKET)? // Handles arrays of any type, including nested arrays
;

type_cast:
    TYPE_CAST type
;

variable:
    VARIABLE | CONTEXTUAL_VARIABLE
;

/*
    The following section includes parser rules for top-level Kuneiform.
    These are the rules that parse the schema / DDL, and are used pre-consensus.
*/

table_column_def:
    name=identifier type inline_constraint*
;

type_list:
    type (COMMA type)*
;

named_type_list:
    identifier type (COMMA identifier type)*
;

inline_constraint:
    PRIMARY KEY
    | UNIQUE
    | NOT NULL
    | DEFAULT action_expr
    | fk_constraint
    | CHECK (LPAREN sql_expr RPAREN)
;

fk_action:
    ON (UPDATE|DELETE)
    (SET NULL | SET DEFAULT | RESTRICT | NO ACTION | CASCADE)
;

fk_constraint:
    REFERENCES (namespace=identifier PERIOD)? table=identifier LPAREN identifier_list RPAREN (fk_action (fk_action)?)? // can be up to 0-2 actions
;

action_return:
    RETURNS (TABLE? LPAREN return_columns=named_type_list RPAREN
    | LPAREN unnamed_return_types=type_list RPAREN)
;

/*
    The following section includes parser rules for SQL.
*/

sql_statement: // NOTE: This is only DDL. We should combine ddl and dml into sql_stmt in the future.
    (WITH RECURSIVE? common_table_expression (COMMA common_table_expression)*)?
    (select_statement | update_statement | insert_statement | delete_statement)
;

common_table_expression:
    identifier (LPAREN (identifier (COMMA identifier)*)? RPAREN)? AS LPAREN select_statement RPAREN
;

create_table_statement:
    CREATE TABLE (IF NOT EXISTS)? name=identifier
    LPAREN
    (table_column_def | table_constraint_def)
    (COMMA  (table_column_def | table_constraint_def))*
    RPAREN
;

table_constraint_def:
    (CONSTRAINT name=identifier)?
    (
    UNIQUE LPAREN identifier_list RPAREN
     | CHECK LPAREN sql_expr RPAREN
     | FOREIGN KEY LPAREN identifier_list RPAREN fk_constraint
     | PRIMARY KEY LPAREN identifier_list RPAREN
     )
;

opt_drop_behavior:
    CASCADE
    | RESTRICT
;

drop_table_statement:
    DROP TABLE (IF EXISTS)? tables=identifier_list opt_drop_behavior?
;

alter_table_statement:
    ALTER TABLE table=identifier
    alter_table_action (COMMA alter_table_action)*
;

alter_table_action:
      ALTER COLUMN column=identifier SET (NOT NULL | DEFAULT action_expr)   # add_column_constraint
    | ALTER COLUMN column=identifier DROP (NOT NULL | DEFAULT)          # drop_column_constraint
    | ADD COLUMN (IF NOT EXISTS)? column=identifier type                                 # add_column
    | DROP COLUMN (IF EXISTS)? column=identifier                                     # drop_column
    | RENAME COLUMN old_column=identifier TO new_column=identifier      # rename_column
    | RENAME TO new_table=identifier                                    # rename_table
    | ADD table_constraint_def                                          # add_table_constraint
    | DROP CONSTRAINT (IF EXISTS)? identifier                                        # drop_table_constraint
;

create_index_statement:
    CREATE UNIQUE? INDEX (IF NOT EXISTS)? name=identifier?
    ON table=identifier LPAREN  columns=identifier_list RPAREN
;

drop_index_statement:
    DROP INDEX (IF EXISTS)? name=identifier
;

create_role_statement:
    CREATE ROLE (IF NOT EXISTS)? identifier
;

drop_role_statement:
    DROP ROLE (IF EXISTS)? identifier
;

grant_statement:
    GRANT (IF NOT GRANTED)? (privilege_list|grant_role=identifier) (ON namespace=identifier)? TO (role=identifier|user=STRING_|user_var=action_expr)
;

revoke_statement:
    REVOKE (IF GRANTED)? (privilege_list|grant_role=identifier) (ON namespace=identifier)? FROM (role=identifier|user=STRING_|user_var=action_expr)
;

transfer_ownership_statement:
    TRANSFER OWNERSHIP TO (user=STRING_|user_var=action_expr)
;

privilege_list:
    privilege (COMMA privilege)*
;

privilege:
    SELECT | INSERT | UPDATE | DELETE | CREATE | DROP | ALTER | ROLES | CALL | USE
;

create_action_statement:
    CREATE (OR REPLACE)? ACTION (IF NOT EXISTS)? identifier
    LPAREN (action_parameter (COMMA action_parameter)*)? RPAREN
    identifier*
    action_return?
    LBRACE action_statement* RBRACE
;

drop_action_statement:
    DROP ACTION (IF EXISTS)? identifier
;

action_parameter:
    VARIABLE type (DEFAULT literal)?
;

use_extension_statement:
    USE (IF NOT EXISTS)? extension_name=identifier 
    (LBRACE (identifier COL action_expr (COMMA identifier COL action_expr)*)? RBRACE)?
    AS alias=identifier
;

unuse_extension_statement:
    UNUSE alias=identifier (IF EXISTS)?
;

create_namespace_statement:
    CREATE NAMESPACE (IF NOT EXISTS)? identifier
;

drop_namespace_statement:
    DROP NAMESPACE (IF EXISTS)? identifier
;

set_current_namespace_statement:
    SET CURRENT NAMESPACE TO identifier
;

select_statement:
    select_core
    (compound_operator select_core)*
    (ORDER BY ordering_term (COMMA ordering_term)*)?
    (LIMIT limit=sql_expr)?
    (OFFSET offset=sql_expr)?
;

compound_operator:
    UNION ALL? | INTERSECT | EXCEPT
;

ordering_term:
    sql_expr (ASC | DESC)? (NULLS (FIRST | LAST))?
;

select_core:
    SELECT DISTINCT?
    result_column (COMMA result_column)*
    (FROM relation join*)?
    (WHERE where=sql_expr)?
    (
        GROUP BY group_by=sql_expr_list
        (HAVING having=sql_expr)?
    )?
    (WINDOW identifier AS window (COMMA identifier AS window)*)?
;

relation:
    (namespace=identifier PERIOD)? table_name=identifier (AS? alias=identifier)?   # table_relation
    // aliases are technically required in Kuneiform for subquery and function calls,
    // but we allow it to pass here since it is standard SQL to not require it, and
    // we can throw a better error message after parsing.
    | LPAREN select_statement RPAREN (AS? alias=identifier)?    # subquery_relation
    | (identifier | UNNEST) LPAREN sql_expr (COMMA sql_expr)* RPAREN 
      (AS? alias=identifier (LPAREN column_aliases=identifier_list RPAREN)?)?    # table_function_relation
;

join:
    (INNER| LEFT | RIGHT | FULL)? JOIN
    relation ON sql_expr
;

result_column:
    sql_expr (AS? identifier)?              # expression_result_column
    | (table_name=identifier PERIOD)? STAR  # wildcard_result_column
;

update_statement:
    UPDATE table_name=identifier (AS? alias=identifier)?
    SET update_set_clause (COMMA update_set_clause)*
    (FROM relation join*)?
    (WHERE where=sql_expr)?
;

update_set_clause:
   column=identifier EQUALS sql_expr
;

insert_statement:
    INSERT INTO table_name=identifier (AS? alias=identifier)?
    (LPAREN target_columns=identifier_list RPAREN)?
    (
        (VALUES LPAREN sql_expr_list RPAREN (COMMA LPAREN sql_expr_list RPAREN)*)
        | (select_statement)
    )
    upsert_clause?
;

upsert_clause:
    ON CONFLICT
    (LPAREN conflict_columns=identifier_list RPAREN (WHERE conflict_where=sql_expr)?)?
    DO (
        NOTHING
        | UPDATE SET update_set_clause (COMMA update_set_clause)*
        (WHERE update_where=sql_expr)?
    )
;

delete_statement:
    DELETE FROM table_name=identifier (AS? alias=identifier)?
    // (USING relation join*)?
    (WHERE where=sql_expr)?
;

// https://docs.kwil.com/docs/kuneiform/operators
sql_expr:
    // highest precedence:
    LPAREN sql_expr RPAREN type_cast?                                                       # paren_sql_expr
    | sql_expr PERIOD identifier type_cast?                                                 # field_access_sql_expr
    | array_element=sql_expr LBRACKET (
        // can be arr[1], arr[1:2], arr[1:], arr[:2], arr[:]
            single=sql_expr
            | (left=sql_expr? COL right=sql_expr?)
        ) RBRACKET type_cast?                                                               # array_access_sql_expr
    | <assoc=right> (PLUS|MINUS) sql_expr                                                   # unary_sql_expr
    | sql_expr COLLATE identifier                                                           # collate_sql_expr
    | left=sql_expr EXP right=sql_expr                                                      # arithmetic_sql_expr
    | left=sql_expr (STAR | DIV | MOD) right=sql_expr                                       # arithmetic_sql_expr
    | left=sql_expr (PLUS | MINUS) right=sql_expr                                           # arithmetic_sql_expr

    // any unspecified operator:
    | literal type_cast?                                                                    # literal_sql_expr
    // direct function calls can have a type cast, but window functions cannot
    | sql_function_call (FILTER LPAREN WHERE sql_expr RPAREN)? OVER (window|identifier)     # window_function_call_sql_expr
    | sql_function_call type_cast?                                                          # function_call_sql_expr
    | variable type_cast?                                                                   # variable_sql_expr
    | ARRAY LBRACKET (sql_expr_list)? RBRACKET type_cast?                                   # make_array_sql_expr
    | (table=identifier PERIOD)? column=identifier type_cast?                               # column_sql_expr
    | CASE case_clause=sql_expr?
        (when_then_clause)+
        (ELSE else_clause=sql_expr)? END                                                    # case_expr
    | (NOT? EXISTS)? LPAREN select_statement RPAREN type_cast?                              # subquery_sql_expr
    // setting precedence for arithmetic operations:
    | left=sql_expr CONCAT right=sql_expr                                                   # arithmetic_sql_expr

    // the rest:
    | sql_expr NOT? IN LPAREN (sql_expr_list|select_statement) RPAREN                       # in_sql_expr
    | left=sql_expr NOT? (LIKE|ILIKE) right=sql_expr                                        # like_sql_expr
    | element=sql_expr (NOT)? BETWEEN lower=sql_expr AND upper=sql_expr                     # between_sql_expr
    | left=sql_expr (EQUALS | EQUATE | NEQ | LT | LTE | GT | GTE) right=sql_expr            # comparison_sql_expr
    | left=sql_expr IS NOT? ((DISTINCT FROM right=sql_expr) | NULL | TRUE | FALSE)          # is_sql_expr
    | <assoc=right> (NOT) sql_expr                                                          # unary_sql_expr
    | left=sql_expr AND right=sql_expr                                                      # logical_sql_expr
    | left=sql_expr OR right=sql_expr                                                       # logical_sql_expr
;

window:
    LPAREN
        (PARTITION BY partition=sql_expr_list)?
        (ORDER BY ordering_term (COMMA ordering_term)*)?
    RPAREN
;


when_then_clause:
    WHEN when_condition=sql_expr THEN then=sql_expr
;

sql_expr_list:
    sql_expr (COMMA sql_expr)*
;

sql_function_call:
    identifier LPAREN (DISTINCT? sql_expr_list|STAR)? RPAREN                                                #normal_call_sql
;

/*
    The following section includes parser rules for action blocks.
*/

/*
    This section includes parser rules for actions
*/

// https://docs.kwil.com/docs/kuneiform/operators
action_expr:
    // highest precedence:
    LPAREN action_expr RPAREN type_cast?                                                     # paren_action_expr
    | action_expr PERIOD identifier type_cast?                                               # field_access_action_expr
    | array_element=action_expr LBRACKET (
            // can be arr[1], arr[1:2], arr[1:], arr[:2], arr[:]
            single=action_expr
            | (left=action_expr? COL right=action_expr?)
        ) RBRACKET type_cast?                                                                   # array_access_action_expr
    | <assoc=right> (PLUS|MINUS|EXCL) action_expr                                            # unary_action_expr
    | action_expr EXP action_expr                                                            # action_expr_arithmetic
    | action_expr (STAR | DIV | MOD) action_expr                                          # action_expr_arithmetic
    | action_expr (PLUS | MINUS) action_expr                                              # action_expr_arithmetic

    // any unspecified operator:
    | literal type_cast?                                                                        # literal_action_expr
    | action_function_call type_cast?                                                        # function_call_action_expr
    | variable type_cast?                                                                       # variable_action_expr
    | ARRAY? LBRACKET (action_expr_list)? RBRACKET type_cast?                                       # make_array_action_expr // array is optional for backwards compatibility
    | action_expr CONCAT action_expr                                                      # action_expr_arithmetic

    // the rest:
    | action_expr (EQUALS | EQUATE | NEQ | LT | LTE | GT | GTE) action_expr               # comparison_action_expr
    | left=action_expr IS NOT? ((DISTINCT FROM right=action_expr) | NULL | TRUE | FALSE)  # is_action_expr
    | <assoc=right> (NOT) action_expr                                                        # unary_action_expr
    | action_expr AND action_expr                                                         # logical_action_expr
    | action_expr OR action_expr                                                          # logical_action_expr
;

action_expr_list:
    action_expr (COMMA action_expr)*
;

// some of the action_statements have optional semicolons. This is for backwards compatibility.
action_statement:
    VARIABLE type SCOL                                                                                  # stmt_variable_declaration
    // stmt_action_call must go above stmt_variable_assignment due to lexer ambiguity
    | ((variable_or_underscore) (COMMA (variable_or_underscore))* (ASSIGN | EQUALS))? action_function_call SCOL # stmt_action_call
    | action_expr type? (ASSIGN | EQUALS) action_expr SCOL                                                         # stmt_variable_assignment
    | FOR receiver=VARIABLE IN (range|sql_statement|ARRAY? action_expr) LBRACE action_statement* RBRACE SCOL?  # stmt_for_loop
    | IF if_then_block ((ELSEIF| ELSE IF) if_then_block)* (ELSE LBRACE action_statement* RBRACE)? SCOL?                        # stmt_if
    | sql_statement SCOL                                                                                # stmt_sql
    | (BREAK|CONTINUE) SCOL                                                                                        # stmt_loop_control
    | RETURN (action_expr_list|sql_statement)? SCOL                                                   # stmt_return
    | RETURN NEXT action_expr_list SCOL                                                              # stmt_return_next
;

variable_or_underscore:
    VARIABLE | UNDERSCORE
;

action_function_call:
    (namespace=identifier PERIOD)? function=identifier LPAREN (action_expr_list)? RPAREN                                #normal_call_action
;

if_then_block:
    action_expr LBRACE action_statement* RBRACE
;

// range used for for loops
range:
    action_expr RANGE action_expr
;