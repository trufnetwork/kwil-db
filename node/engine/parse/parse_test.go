package parse

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
)

// assertPositionsAreSet asserts that all positions in the ast are set.
func assertPositionsAreSet(t *testing.T, v any) {
	RecursivelyVisitPositions(v, func(gp GetPositioner) {
		pos := gp.GetPosition()
		// if not set, this will tell us the struct
		assert.True(t, pos.isSet, "position is not set. struct type: %T", gp)
	})
}

// exprVar makes an ExpressionVariable.
func exprVar(n string) *ExpressionVariable {
	if n[0] != '$' && n[0] != '@' {
		panic("TEST ERROR: variable name must start with $ or @")
	}

	return &ExpressionVariable{
		Name:   n,
		Prefix: VariablePrefix(n[0]),
	}
}

// exprLitCast makes an expression based on the type of v.
// If cast is true, it will add a typecast to the expression.
// Legacy Kwil (<=v0.9) auto-cast certain values. v0.10 leaves this
// to another layer.
func exprLitCast(v any, cast bool) Expression {
	switch t := v.(type) {
	case int:
		isNeg := t < 0
		if isNeg {
			t *= -1
		}

		liter := &ExpressionLiteral{
			Type:  types.IntType,
			Value: int64(t),
		}
		if cast {
			liter.Typecastable = Typecastable{
				TypeCast: types.IntType,
			}
		}

		if isNeg {
			return &ExpressionUnary{
				Operator:   UnaryOperatorNeg,
				Expression: liter,
			}
		}

		return liter
	case int64:
		isNeg := t < 0
		if isNeg {
			t *= -1
		}

		liter := &ExpressionLiteral{
			Type:  types.IntType,
			Value: t,
		}
		if cast {
			liter.Typecastable = Typecastable{
				TypeCast: types.IntType,
			}
		}

		if isNeg {
			return &ExpressionUnary{
				Operator:   UnaryOperatorNeg,
				Expression: liter,
			}
		}

		return liter
	case string:
		ee := &ExpressionLiteral{
			Type:  types.TextType,
			Value: t,
		}
		if cast {
			ee.Typecastable = Typecastable{
				TypeCast: types.TextType,
			}
		}
		return ee
	case bool:
		ee := &ExpressionLiteral{
			Type:  types.BoolType,
			Value: t,
		}
		if cast {
			ee.Typecastable = Typecastable{
				TypeCast: types.BoolType,
			}
		}
		return ee
	default:
		panic("TEST ERROR: invalid type for literal")
	}
}

// exprLit makes an ExpressionLiteral.
// it can only make strings and ints.
// It will automatically add a typecast to the expression.
// This is legacy behavior from Kwil <=v0.9
func exprLit(v any) Expression {
	return exprLitCast(v, false)
}

func exprFunctionCall(name string, args ...Expression) *ExpressionFunctionCall {
	return &ExpressionFunctionCall{
		Name: name,
		Args: args,
	}
}

func Test_DDL(t *testing.T) {
	type testCase struct {
		name string
		sql  string
		want TopLevelStatement
		err  error
	}

	tests := []testCase{
		// non-sensical foreign key but its just to test
		{
			name: "create table",
			sql: `CREATE TABLE users (
		id int PRIMARY KEY,
		name text CHECK(LENGTH(name) > 10),
		address text NOT NULL DEFAULT 'usa',
		email text NOT NULL UNIQUE ,
		city_id int,
		group_id int REFERENCES groups(id) ON UPDATE RESTRICT ON DELETE CASCADE,
		CONSTRAINT city_fk FOREIGN KEY (city_id, address) REFERENCES cities(id, address) ON UPDATE NO ACTION ON DELETE SET NULL,
		CHECK(LENGTH(email) > 1),
		UNIQUE (city_id, address)
		);`,
			want: &CreateTableStatement{
				Name: "users",
				Columns: []*Column{
					{
						Name: "id",
						Type: types.IntType,
						Constraints: []InlineConstraint{
							&PrimaryKeyInlineConstraint{},
						},
					},
					{
						Name: "name",
						Type: types.TextType,
						Constraints: []InlineConstraint{
							&CheckConstraint{
								Expression: &ExpressionComparison{
									Left:     exprFunctionCall("length", exprColumn("", "name")),
									Right:    exprLitCast(10, false),
									Operator: ComparisonOperatorGreaterThan,
								},
							},
						},
					},
					{
						Name: "address",
						Type: types.TextType,
						Constraints: []InlineConstraint{
							&NotNullConstraint{},
							&DefaultConstraint{
								Value: &ExpressionLiteral{
									Type:  types.TextType,
									Value: "usa",
								},
							},
						},
					},
					{
						Name: "email",
						Type: types.TextType,
						Constraints: []InlineConstraint{
							&NotNullConstraint{},
							&UniqueInlineConstraint{},
						},
					},
					{
						Name: "city_id",
						Type: types.IntType,
					},
					{
						Name: "group_id",
						Type: types.IntType,
						Constraints: []InlineConstraint{
							&ForeignKeyReferences{
								RefTable:   "groups",
								RefColumns: []string{"id"},
								Actions: []*ForeignKeyAction{
									{
										On: ON_UPDATE,
										Do: DO_RESTRICT,
									},
									{
										On: ON_DELETE,
										Do: DO_CASCADE,
									},
								},
							},
						},
					},
				},
				Constraints: []*OutOfLineConstraint{
					{
						Name: "city_fk",
						Constraint: &ForeignKeyOutOfLineConstraint{
							Columns: []string{"city_id", "address"},
							References: &ForeignKeyReferences{
								RefTable:   "cities",
								RefColumns: []string{"id", "address"},
								Actions: []*ForeignKeyAction{
									{
										On: ON_UPDATE,
										Do: DO_NO_ACTION,
									},
									{
										On: ON_DELETE,
										Do: DO_SET_NULL,
									},
								},
							},
						},
					},
					{
						Constraint: &CheckConstraint{
							Expression: &ExpressionComparison{
								Left:     exprFunctionCall("length", exprColumn("", "email")),
								Right:    exprLitCast(1, false),
								Operator: ComparisonOperatorGreaterThan,
							},
						},
					},
					{
						Constraint: &UniqueOutOfLineConstraint{
							Columns: []string{
								"city_id",
								"address",
							},
						},
					},
				},
			},
		},
		{
			name: "create table if not exists",
			sql:  `CREATE TABLE IF NOT EXISTS users (id int primary key)`,
			want: &CreateTableStatement{
				Name:        "users",
				IfNotExists: true,
				Columns: []*Column{
					{
						Name: "id",
						Type: types.IntType,
						Constraints: []InlineConstraint{
							&PrimaryKeyInlineConstraint{},
						},
					},
				},
			},
		},
		{
			name: "alter table add column constraint NOT NULL",
			sql:  `ALTER TABLE user ALTER COLUMN name SET NOT NULL;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&AlterColumnSet{
						Column: "name",
						Type:   ConstraintTypeNotNull,
					},
				},
			},
		},
		{
			name: "alter table add column constraint DEFAULT",
			sql:  `ALTER TABLE user ALTER COLUMN name SET DEFAULT 10;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&AlterColumnSet{
						Column: "name",
						Type:   ConstraintTypeDefault,
						Value: &ExpressionLiteral{
							Type:  types.IntType,
							Value: int64(10),
						},
					},
				},
			},
		},
		{
			name: "alter table drop column constraint NOT NULL",
			sql:  `ALTER TABLE user ALTER COLUMN name DROP NOT NULL;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&AlterColumnDrop{
						Column: "name",
						Type:   ConstraintTypeNotNull,
					},
				},
			},
		},
		{
			name: "alter table drop column constraint DEFAULT",
			sql:  `ALTER TABLE user ALTER COLUMN name DROP DEFAULT;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&AlterColumnDrop{
						Column: "name",
						Type:   ConstraintTypeDefault,
					},
				},
			},
		},
		{
			name: "alter table add column",
			sql:  `ALTER TABLE user ADD COLUMN abc int;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&AddColumn{
						Name: "abc",
						Type: types.IntType,
					},
				},
			},
		},
		{
			name: "alter table drop column",
			sql:  `ALTER TABLE user DROP COLUMN abc;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&DropColumn{
						Name: "abc",
					},
				},
			},
		},
		{
			name: "alter table rename column",
			sql:  `ALTER TABLE user RENAME COLUMN abc TO def;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&RenameColumn{
						OldName: "abc",
						NewName: "def",
					},
				},
			},
		},
		{
			name: "alter table rename table",
			sql:  `ALTER TABLE user RENAME TO account;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&RenameTable{
						Name: "account",
					},
				},
			},
		},
		{
			name: "alter table add constraint fk",
			sql:  `ALTER TABLE user ADD constraint new_fk FOREIGN KEY (city_id) REFERENCES cities(id) ON DELETE CASCADE;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&AddTableConstraint{
						Constraint: &OutOfLineConstraint{
							Name: "new_fk",
							Constraint: &ForeignKeyOutOfLineConstraint{
								Columns: []string{"city_id"},
								References: &ForeignKeyReferences{
									RefTable:   "cities",
									RefColumns: []string{"id"},
									Actions: []*ForeignKeyAction{
										{
											On: ON_DELETE,
											Do: DO_CASCADE,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "alter table drop constraint",
			sql:  `ALTER TABLE user DROP CONSTRAINT abc;`,
			want: &AlterTableStatement{
				Table: "user",
				Actions: []AlterTableAction{
					&DropTableConstraint{
						Name: "abc",
					},
				},
			},
		},
		{
			name: "drop table",
			sql:  `DROP TABLE users, posts;`,
			want: &DropTableStatement{
				Tables:   []string{"users", "posts"},
				Behavior: DropBehaviorDefault,
			},
		},
		{
			name: "drop table single table",
			sql:  `DROP TABLE users;`,
			want: &DropTableStatement{
				Tables:   []string{"users"},
				Behavior: DropBehaviorDefault,
			},
		},
		{
			name: "drop table if exists",
			sql:  `DROP TABLE IF EXISTS users, posts;`,
			want: &DropTableStatement{
				Tables:   []string{"users", "posts"},
				IfExists: true,
			},
		},
		{
			name: "drop table CASCADE",
			sql:  `DROP TABLE IF EXISTS users, posts CASCADE;`,
			want: &DropTableStatement{
				Tables:   []string{"users", "posts"},
				Behavior: DropBehaviorCascade,
				IfExists: true,
			},
		},
		{
			name: "drop table RESTRICT ",
			sql:  `DROP TABLE users, posts RESTRICT;`,
			want: &DropTableStatement{
				Tables:   []string{"users", "posts"},
				Behavior: DropBehaviorRestrict,
			},
		},
		{
			name: "create index",
			sql:  `CREATE INDEX abc ON user(name);`,
			want: &CreateIndexStatement{
				Name:    "abc",
				On:      "user",
				Columns: []string{"name"},
				Type:    IndexTypeBTree,
			},
		},
		{
			name: "create unique index",
			sql:  `CREATE UNIQUE INDEX abc ON user(name);`,
			want: &CreateIndexStatement{
				Name:    "abc",
				On:      "user",
				Columns: []string{"name"},
				Type:    IndexTypeUnique,
			},
		},
		{
			name: "create index with no name",
			sql:  `CREATE INDEX ON user(name);`,
			want: &CreateIndexStatement{
				On:      "user",
				Columns: []string{"name"},
				Type:    IndexTypeBTree,
			},
		},
		{
			name: "create index if not exist",
			sql:  `CREATE INDEX IF NOT EXISTS abc ON user(name);`,
			want: &CreateIndexStatement{
				IfNotExists: true,
				Name:        "abc",
				On:          "user",
				Columns:     []string{"name"},
				Type:        IndexTypeBTree,
			},
		},
		{
			name: "drop index",
			sql:  `DROP INDEX abc;`,
			want: &DropIndexStatement{
				Name: "abc",
			},
		},

		{
			name: "drop index check exist",
			sql:  `DROP INDEX IF EXISTS abc;`,
			want: &DropIndexStatement{
				Name:       "abc",
				CheckExist: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ParseWithErrListener(tt.sql)
			require.NoError(t, err)

			if res.ParseErrs.Err() != nil {
				if tt.err == nil {
					t.Errorf("unexpected error: %v", res.ParseErrs.Err())
				} else {
					require.ErrorIs(t, res.ParseErrs.Err(), tt.err)
				}

				return
			}
			if tt.err != nil {
				t.Errorf("expected error but got none")
				return
			}

			require.Len(t, res.Statements, 1)

			assertPositionsAreSet(t, res.Statements[0])

			if !deepCompare(tt.want, res.Statements[0]) {
				t.Errorf("unexpected AST:%s", diff(tt.want, res.Statements[0]))
			}
		})
	}
}

func Test_SQL(t *testing.T) {
	type testCase struct {
		name string
		sql  string
		want *SQLStatement
		err  error
	}

	tests := []testCase{
		{
			name: "simple select",
			sql:  "select *, id i, length(username) as name_len from users u where u.id = 1;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
								&ResultColumnExpression{
									Expression: exprColumn("", "id"),
									Alias:      "i",
								},
								&ResultColumnExpression{
									Expression: &ExpressionFunctionCall{
										Name: "length",
										Args: []Expression{
											exprColumn("", "username"),
										},
									},
									Alias: "name_len",
								},
							},
							From: &RelationTable{
								Table: "users",
								Alias: "u",
							},
							Where: &ExpressionComparison{
								Left:     exprColumn("u", "id"),
								Operator: ComparisonOperatorEqual,
								Right:    exprLitCast(1, false),
							},
						},
					},
				},
			},
		},
		{
			name: "insert",
			sql: `insert into posts (id, author_id) values (1, 1),
			(2, (SELECT id from users where username = 'user2' LIMIT 1));`,
			want: &SQLStatement{
				SQL: &InsertStatement{
					Table:   "posts",
					Columns: []string{"id", "author_id"},
					Values: [][]Expression{
						{
							exprLit(1),
							exprLit(1),
						},
						{
							exprLit(2),
							&ExpressionSubquery{
								Subquery: &SelectStatement{
									SelectCores: []*SelectCore{
										{
											Columns: []ResultColumn{
												&ResultColumnExpression{
													Expression: exprColumn("", "id"),
												},
											},
											From: &RelationTable{
												Table: "users",
											},
											Where: &ExpressionComparison{
												Left:     exprColumn("", "username"),
												Operator: ComparisonOperatorEqual,
												Right:    exprLit("user2"),
											},
										},
									},
									Limit: exprLit(1),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "select join",
			sql: `SELECT p.id as id, u.username as author FROM posts AS p
			INNER JOIN users AS u ON p.author_id = u.id
			WHERE u.username = 'satoshi' order by u.username DESC NULLS LAST;`,
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: exprColumn("p", "id"),
									Alias:      "id",
								},
								&ResultColumnExpression{
									Expression: exprColumn("u", "username"),
									Alias:      "author",
								},
							},
							From: &RelationTable{
								Table: "posts",
								Alias: "p",
							},
							Joins: []*Join{
								{
									Type: JoinTypeInner,
									Relation: &RelationTable{
										Table: "users",
										Alias: "u",
									},
									On: &ExpressionComparison{
										Left:     exprColumn("p", "author_id"),
										Operator: ComparisonOperatorEqual,
										Right:    exprColumn("u", "id"),
									},
								},
							},
							Where: &ExpressionComparison{
								Left:     exprColumn("u", "username"),
								Operator: ComparisonOperatorEqual,
								Right:    exprLit("satoshi"),
							},
						},
					},

					Ordering: []*OrderingTerm{
						{
							Expression: exprColumn("u", "username"),
							Order:      OrderTypeDesc,
							Nulls:      NullOrderLast,
						},
					},
				},
			},
		},
		{
			name: "delete",
			sql:  "delete from users where id = 1;",
			want: &SQLStatement{
				SQL: &DeleteStatement{
					Table: "users",
					Where: &ExpressionComparison{
						Left:     exprColumn("", "id"),
						Operator: ComparisonOperatorEqual,
						Right:    exprLit(1),
					},
				},
			},
		},
		{
			name: "upsert with conflict - success",
			sql:  `INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = users.id + excluded.id;`,
			want: &SQLStatement{
				SQL: &InsertStatement{
					Table:   "users",
					Columns: []string{"id"},
					Values: [][]Expression{
						{
							exprLit(1),
						},
					},
					OnConflict: &OnConflict{
						ConflictColumns: []string{"id"},
						DoUpdate: []*UpdateSetClause{
							{
								Column: "id",
								Value: &ExpressionArithmetic{
									Left:     exprColumn("users", "id"),
									Operator: ArithmeticOperatorAdd,
									Right:    exprColumn("excluded", "id"),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "compound select",
			sql:  `SELECT * FROM users union SELECT * FROM users;`,
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
					CompoundOperators: []CompoundOperator{
						CompoundOperatorUnion,
					},
				},
			},
		},
		{
			name: "compound selecting 1 column",
			sql:  `SELECT username FROM users union SELECT username FROM users;`,
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: exprColumn("", "username"),
								},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: exprColumn("", "username"),
								},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
					CompoundOperators: []CompoundOperator{CompoundOperatorUnion},
				},
			},
		},
		{
			name: "group by",
			sql:  `SELECT u.username, count(u.id) FROM users as u GROUP BY u.username HAVING count(u.id) > 1;`,
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: exprColumn("u", "username"),
								},
								&ResultColumnExpression{
									Expression: &ExpressionFunctionCall{
										Name: "count",
										Args: []Expression{
											exprColumn("u", "id"),
										},
									},
								},
							},
							From: &RelationTable{
								Table: "users",
								Alias: "u",
							},
							GroupBy: []Expression{
								exprColumn("u", "username"),
							},
							Having: &ExpressionComparison{
								Left: &ExpressionFunctionCall{
									Name: "count",
									Args: []Expression{
										exprColumn("u", "id"),
									},
								},
								Operator: ComparisonOperatorGreaterThan,
								Right:    exprLit(1),
							},
						},
					},
				},
			},
		},
		{
			name: "group by with having, having is in group by clause",
			// there's a much easier way to write this query, but this is just to test the parser
			sql: `SELECT username FROM users GROUP BY username HAVING length(username) > 1;`,
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: exprColumn("", "username"),
								},
							},
							From: &RelationTable{
								Table: "users",
							},
							GroupBy: []Expression{
								exprColumn("", "username"),
							},
							Having: &ExpressionComparison{
								Left: &ExpressionFunctionCall{
									Name: "length",
									Args: []Expression{
										exprColumn("", "username"),
									},
								},
								Operator: ComparisonOperatorGreaterThan,
								Right:    exprLit(1),
							},
						},
					},
				},
			},
		},
		{
			name: "aggregate with no group by returns one column",
			sql:  `SELECT count(*) FROM users;`,
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionFunctionCall{
										Name: "count",
										Star: true,
									},
								},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
				},
			},
		},
		{
			name: "ordering for subqueries",
			sql:  `SELECT u.username, p.id FROM (SELECT * FROM users) as u inner join (SELECT * FROM posts) as p on u.id = p.author_id;`,
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: exprColumn("u", "username"),
								},
								&ResultColumnExpression{
									Expression: exprColumn("p", "id"),
								},
							},
							From: &RelationSubquery{
								Subquery: &SelectStatement{
									SelectCores: []*SelectCore{
										{
											Columns: []ResultColumn{
												&ResultColumnWildcard{},
											},
											From: &RelationTable{
												Table: "users",
											},
										},
									},
								},
								Alias: "u",
							},
							Joins: []*Join{
								{
									Type: JoinTypeInner,
									Relation: &RelationSubquery{
										Subquery: &SelectStatement{
											SelectCores: []*SelectCore{
												{
													Columns: []ResultColumn{
														&ResultColumnWildcard{},
													},
													From: &RelationTable{
														Table: "posts",
													},
												},
											},
										},
										Alias: "p",
									},
									On: &ExpressionComparison{
										Left:     exprColumn("u", "id"),
										Operator: ComparisonOperatorEqual,
										Right:    exprColumn("p", "author_id"),
									},
								},
							},
						},
					},
				},
			},
		},
		{name: "non utf-8", sql: "\xbd\xb2\x3d\xbc\x20\xe2\x8c\x98;", err: ErrSyntax},
		{
			// this select doesn't make much sense, however
			// it is a regression test for a previously known bug
			// https://github.com/trufnetwork/kwil-db/pull/810
			name: "offset and limit",
			sql:  `SELECT * FROM users LIMIT id OFFSET id;`,
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
					Offset: exprColumn("", "id"),
					Limit:  exprColumn("", "id"),
				},
			},
		},
		{
			// this is a regression test for a previous bug.
			// when parsing just SQL, we can have unknown variables
			name: "unknown variable is ok",
			sql:  `SELECT $id;`,
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: exprVar("$id"),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "select JOIN, with no specified INNER/OUTER",
			sql: `SELECT u.* FROM users as u
			JOIN posts as p ON u.id = p.author_id;`, // default is INNER
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{
									Table: "u",
								},
							},
							From: &RelationTable{
								Table: "users",
								Alias: "u",
							},
							Joins: []*Join{
								{
									Type: JoinTypeInner,
									Relation: &RelationTable{
										Table: "posts",
										Alias: "p",
									},
									On: &ExpressionComparison{
										Left:     exprColumn("u", "id"),
										Operator: ComparisonOperatorEqual,
										Right:    exprColumn("p", "author_id"),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			// regression tests for a previous bug, where whitespace after
			// the semicolon would cause the parser to add an extra semicolon
			name: "whitespace after semicolon",
			sql:  "SELECT 1;     ",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: exprLit(1),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "cte",
			sql:  `WITH cte AS (SELECT id FROM users) SELECT * FROM cte;`,
			want: &SQLStatement{
				CTEs: []*CommonTableExpression{
					{
						Name: "cte",
						Query: &SelectStatement{
							SelectCores: []*SelectCore{
								{
									Columns: []ResultColumn{
										&ResultColumnExpression{
											Expression: exprColumn("", "id"),
										},
									},
									From: &RelationTable{
										Table: "users",
									},
								},
							},
						},
					},
				},
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "cte",
							},
						},
					},
				},
			},
		},
		{
			name: "cte with columns",
			sql:  `WITH cte (id2) AS (SELECT id FROM users) SELECT * FROM cte;`,
			want: &SQLStatement{
				CTEs: []*CommonTableExpression{
					{
						Name:    "cte",
						Columns: []string{"id2"},
						Query: &SelectStatement{
							SelectCores: []*SelectCore{
								{
									Columns: []ResultColumn{
										&ResultColumnExpression{
											Expression: exprColumn("", "id"),
										},
									},
									From: &RelationTable{
										Table: "users",
									},
								},
							},
						},
					},
				},
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "cte",
							},
						},
					},
				},
			},
		},
		{
			name: "namespacing",
			sql:  `{test}SELECT * FROM users;`,
			want: &SQLStatement{
				Namespacing: Namespacing{
					NamespacePrefix: "test",
				},
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
				},
			},
		},
		{
			name: "array access - single index",
			sql:  "SELECT users[1] FROM arrays;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionArrayAccess{
										Array: exprColumn("", "users"),
										Index: exprLit(1),
									},
								},
							},
							From: &RelationTable{
								Table: "arrays",
							},
						},
					},
				},
			},
		},
		{
			name: "array access - range",
			sql:  "SELECT users[1:5] FROM arrays;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionArrayAccess{
										Array: exprColumn("", "users"),
										FromTo: &[2]Expression{
											exprLit(1),
											exprLit(5),
										},
									},
								},
							},
							From: &RelationTable{
								Table: "arrays",
							},
						},
					},
				},
			},
		},
		{
			name: "array access - left range",
			sql:  "SELECT users[1:] FROM arrays;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionArrayAccess{
										Array: exprColumn("", "users"),
										FromTo: &[2]Expression{
											exprLit(1),
											nil,
										},
									},
								},
							},
							From: &RelationTable{
								Table: "arrays",
							},
						},
					},
				},
			},
		},
		{
			name: "array access - right range",
			sql:  "SELECT users[:5] FROM arrays;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionArrayAccess{
										Array: exprColumn("", "users"),
										FromTo: &[2]Expression{
											nil,
											exprLit(5),
										},
									},
								},
							},
							From: &RelationTable{
								Table: "arrays",
							},
						},
					},
				},
			},
		},
		{
			name: "array access - full range",
			sql:  "SELECT users[:] FROM arrays;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionArrayAccess{
										Array: exprColumn("", "users"),
										FromTo: &[2]Expression{
											nil,
											nil,
										},
									},
								},
							},
							From: &RelationTable{
								Table: "arrays",
							},
						},
					},
				},
			},
		},
		{
			name: "between expression",
			sql:  "SELECT * FROM users WHERE id BETWEEN 1 AND 10;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionBetween{
								Expression: exprColumn("", "id"),
								Lower:      exprLit(1),
								Upper:      exprLit(10),
							},
						},
					},
				},
			},
		},
		{
			name: "not between expression",
			sql:  "SELECT * FROM users WHERE id NOT BETWEEN 1 AND 10;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionBetween{
								Expression: exprColumn("", "id"),
								Lower:      exprLit(1),
								Upper:      exprLit(10),
								Not:        true,
							},
						},
					},
				},
			},
		},
		{
			name: "logical operators with between",
			sql:  "SELECT * FROM users WHERE (id BETWEEN 1 AND 10) AND username = 'test';",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionLogical{
								Left: &ExpressionParenthesized{
									Inner: &ExpressionBetween{
										Expression: exprColumn("", "id"),
										Lower:      exprLit(1),
										Upper:      exprLit(10),
									},
								},
								Operator: LogicalOperatorAnd,
								Right: &ExpressionComparison{
									Left:     exprColumn("", "username"),
									Operator: ComparisonOperatorEqual,
									Right:    exprLit("test"),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "logical operators",
			sql:  "SELECT * FROM users WHERE username = 'test' AND id > 5 OR active = true;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionLogical{
								Left: &ExpressionLogical{
									Left: &ExpressionComparison{
										Left:     exprColumn("", "username"),
										Operator: ComparisonOperatorEqual,
										Right:    exprLit("test"),
									},
									Operator: LogicalOperatorAnd,
									Right: &ExpressionComparison{
										Left:     exprColumn("", "id"),
										Operator: ComparisonOperatorGreaterThan,
										Right:    exprLit(5),
									},
								},
								Operator: LogicalOperatorOr,
								Right: &ExpressionComparison{
									Left:     exprColumn("", "active"),
									Operator: ComparisonOperatorEqual,
									Right:    exprLit(true),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "window function with named window",
			sql:  "SELECT row_number() OVER win FROM users WINDOW win AS (PARTITION BY username ORDER BY id);",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionWindowFunctionCall{
										FunctionCall: &ExpressionFunctionCall{
											Name: "row_number",
										},
										Window: &WindowReference{
											Name: "win",
										},
									},
								},
							},
							From: &RelationTable{
								Table: "users",
							},
							Windows: []*struct {
								Name   string
								Window *WindowImpl
							}{
								{
									Name: "win",
									Window: &WindowImpl{
										PartitionBy: []Expression{
											exprColumn("", "username"),
										},
										OrderBy: []*OrderingTerm{
											{
												Expression: exprColumn("", "id"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "window function with inline window and filter",
			sql:  "SELECT count(*) FILTER (WHERE active = true) OVER (PARTITION BY dept ORDER BY salary) FROM employees;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionWindowFunctionCall{
										FunctionCall: &ExpressionFunctionCall{
											Name: "count",
											Star: true,
										},
										Filter: &ExpressionComparison{
											Left:     exprColumn("", "active"),
											Operator: ComparisonOperatorEqual,
											Right:    exprLit(true),
										},
										Window: &WindowImpl{
											PartitionBy: []Expression{
												exprColumn("", "dept"),
											},
											OrderBy: []*OrderingTerm{
												{
													Expression: exprColumn("", "salary"),
												},
											},
										},
									},
								},
							},
							From: &RelationTable{
								Table: "employees",
							},
						},
					},
				},
			},
		},
		{
			name: "collate expression",
			sql:  "SELECT name FROM users ORDER BY name COLLATE NOCASE;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: exprColumn("", "name"),
								},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
					Ordering: []*OrderingTerm{
						{
							Expression: &ExpressionCollate{
								Expression: exprColumn("", "name"),
								Collation:  "nocase",
							},
						},
					},
				},
			},
		},
		{
			name: "is null expression",
			sql:  "SELECT * FROM users WHERE last_login IS NULL;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIs{
								Left: exprColumn("", "last_login"),
								Right: &ExpressionLiteral{
									Type: types.NullType,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "is not null expression",
			sql:  "SELECT * FROM users WHERE last_login IS NOT NULL;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIs{
								Left: exprColumn("", "last_login"),
								Not:  true,
								Right: &ExpressionLiteral{
									Type: types.NullType,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "is true expression",
			sql:  "SELECT * FROM users WHERE active IS TRUE;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIs{
								Left: exprColumn("", "active"),
								Right: &ExpressionLiteral{
									Type:  types.BoolType,
									Value: true,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "is not false expression",
			sql:  "SELECT * FROM users WHERE active IS NOT FALSE;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIs{
								Left: exprColumn("", "active"),
								Not:  true,
								Right: &ExpressionLiteral{
									Type:  types.BoolType,
									Value: false,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "is distinct from expression",
			sql:  "SELECT * FROM users WHERE username IS DISTINCT FROM email;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIs{
								Left:     exprColumn("", "username"),
								Distinct: true,
								Right:    exprColumn("", "email"),
							},
						},
					},
				},
			},
		},
		{
			name: "is not distinct from expression",
			sql:  "SELECT * FROM users WHERE username IS NOT DISTINCT FROM email;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIs{
								Left:     exprColumn("", "username"),
								Not:      true,
								Distinct: true,
								Right:    exprColumn("", "email"),
							},
						},
					},
				},
			},
		},
		{
			name: "like expression",
			sql:  "SELECT * FROM users WHERE username LIKE '%admin%';",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionStringComparison{
								Left:     exprColumn("", "username"),
								Operator: StringComparisonOperatorLike,
								Right:    exprLit("%admin%"),
							},
						},
					},
				},
			},
		},
		{
			name: "not like expression",
			sql:  "SELECT * FROM users WHERE username NOT LIKE '%admin%';",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionStringComparison{
								Left:     exprColumn("", "username"),
								Operator: StringComparisonOperatorLike,
								Not:      true,
								Right:    exprLit("%admin%"),
							},
						},
					},
				},
			},
		},
		{
			name: "ilike expression",
			sql:  "SELECT * FROM users WHERE username ILIKE '%ADMIN%';",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionStringComparison{
								Left:     exprColumn("", "username"),
								Operator: StringComparisonOperatorILike,
								Right:    exprLit("%ADMIN%"),
							},
						},
					},
				},
			},
		},
		{
			name: "not ilike expression",
			sql:  "SELECT * FROM users WHERE username NOT ILIKE '%ADMIN%';",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionStringComparison{
								Left:     exprColumn("", "username"),
								Operator: StringComparisonOperatorILike,
								Not:      true,
								Right:    exprLit("%ADMIN%"),
							},
						},
					},
				},
			},
		},
		{
			name: "unary not expression",
			sql:  "SELECT * FROM users WHERE NOT active;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionUnary{
								Operator:   UnaryOperatorNot,
								Expression: exprColumn("", "active"),
							},
						},
					},
				},
			},
		},
		{
			name: "unary negation expression",
			sql:  "SELECT -count(*) FROM users;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionUnary{
										Operator: UnaryOperatorNeg,
										Expression: &ExpressionFunctionCall{
											Name: "count",
											Star: true,
										},
									},
								},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
				},
			},
		},
		{
			name: "unary positive expression",
			sql:  "SELECT +id FROM users;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionUnary{
										Operator:   UnaryOperatorPos,
										Expression: exprColumn("", "id"),
									},
								},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
				},
			},
		},
		{
			name: "make array expression",
			sql:  "SELECT array[1, 2, 3] FROM dual;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionMakeArray{
										Values: []Expression{
											exprLit(1),
											exprLit(2),
											exprLit(3),
										},
									},
								},
							},
							From: &RelationTable{
								Table: "dual",
							},
						},
					},
				},
			},
		},
		{
			name: "empty array expression",
			sql:  "SELECT array[] FROM dual;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionMakeArray{
										Values: nil,
									},
								},
							},
							From: &RelationTable{
								Table: "dual",
							},
						},
					},
				},
			},
		},
		{
			name: "array expression with type cast",
			sql:  "SELECT array[1, 2, 3]::int[] FROM dual;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionMakeArray{
										Values: []Expression{
											exprLit(1),
											exprLit(2),
											exprLit(3),
										},
										Typecastable: Typecastable{
											types.IntArrayType,
										},
									},
								},
							},
							From: &RelationTable{
								Table: "dual",
							},
						},
					},
				},
			},
		},
		{
			name: "simple case expression",
			sql:  "SELECT CASE status WHEN 'active' THEN 1 WHEN 'inactive' THEN 0 ELSE -1 END FROM users;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionCase{
										Case: exprColumn("", "status"),
										WhenThen: [][2]Expression{
											{
												exprLit("active"),
												exprLit(1),
											},
											{
												exprLit("inactive"),
												exprLit(0),
											},
										},
										Else: exprLit(-1),
									},
								},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
				},
			},
		},
		{
			name: "searched case expression",
			sql:  "SELECT CASE WHEN id < 10 THEN 'low' WHEN id < 100 THEN 'medium' ELSE 'high' END FROM users;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionCase{
										WhenThen: [][2]Expression{
											{
												&ExpressionComparison{
													Left:     exprColumn("", "id"),
													Operator: ComparisonOperatorLessThan,
													Right:    exprLit(10),
												},
												exprLit("low"),
											},
											{
												&ExpressionComparison{
													Left:     exprColumn("", "id"),
													Operator: ComparisonOperatorLessThan,
													Right:    exprLit(100),
												},
												exprLit("medium"),
											},
										},
										Else: exprLit("high"),
									},
								},
							},
							From: &RelationTable{
								Table: "users",
							},
						},
					},
				},
			},
		},
		{
			name: "case expression without else",
			sql:  "SELECT CASE WHEN score > 90 THEN 'A' WHEN score > 80 THEN 'B' END FROM grades;",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnExpression{
									Expression: &ExpressionCase{
										WhenThen: [][2]Expression{
											{
												&ExpressionComparison{
													Left:     exprColumn("", "score"),
													Operator: ComparisonOperatorGreaterThan,
													Right:    exprLit(90),
												},
												exprLit("A"),
											},
											{
												&ExpressionComparison{
													Left:     exprColumn("", "score"),
													Operator: ComparisonOperatorGreaterThan,
													Right:    exprLit(80),
												},
												exprLit("B"),
											},
										},
									},
								},
							},
							From: &RelationTable{
								Table: "grades",
							},
						},
					},
				},
			},
		},
		{
			name: "in expression with list",
			sql:  "SELECT * FROM users WHERE status IN ('active', 'pending', 'suspended');",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIn{
								Expression: exprColumn("", "status"),
								List: []Expression{
									exprLit("active"),
									exprLit("pending"),
									exprLit("suspended"),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "not in expression with list",
			sql:  "SELECT * FROM users WHERE status NOT IN ('deleted', 'banned');",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIn{
								Expression: exprColumn("", "status"),
								Not:        true,
								List: []Expression{
									exprLit("deleted"),
									exprLit("banned"),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "in expression with subquery",
			sql:  "SELECT * FROM users WHERE id IN (SELECT user_id FROM admins);",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIn{
								Expression: exprColumn("", "id"),
								Subquery: &SelectStatement{
									SelectCores: []*SelectCore{
										{
											Columns: []ResultColumn{
												&ResultColumnExpression{
													Expression: exprColumn("", "user_id"),
												},
											},
											From: &RelationTable{
												Table: "admins",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "not in expression with subquery",
			sql:  "SELECT * FROM users WHERE id NOT IN (SELECT user_id FROM banned_users);",
			want: &SQLStatement{
				SQL: &SelectStatement{
					SelectCores: []*SelectCore{
						{
							Columns: []ResultColumn{
								&ResultColumnWildcard{},
							},
							From: &RelationTable{
								Table: "users",
							},
							Where: &ExpressionIn{
								Expression: exprColumn("", "id"),
								Not:        true,
								Subquery: &SelectStatement{
									SelectCores: []*SelectCore{
										{
											Columns: []ResultColumn{
												&ResultColumnExpression{
													Expression: exprColumn("", "user_id"),
												},
											},
											From: &RelationTable{
												Table: "banned_users",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ParseWithErrListener(tt.sql)
			require.NoError(t, err)

			if res.ParseErrs.Err() != nil {
				if tt.err == nil {
					t.Errorf("unexpected error: %v", res.ParseErrs.Err())
				} else {
					require.ErrorIs(t, res.ParseErrs.Err(), tt.err)
				}

				return
			}
			if tt.err != nil {
				t.Errorf("expected %v but got none", tt.err)
				return
			}

			assertPositionsAreSet(t, res.Statements[0])
			res.Statements[0].(*SQLStatement).raw = nil
			RecursivelyVisitPositions(res.Statements[0], func(gp GetPositioner) {
				gp.Clear()
			})
			if !deepCompare(tt.want, res.Statements[0]) {
				assert.EqualValues(t, tt.want, res.Statements[0])
			}
		})
	}
}

func exprColumn(t, c string) *ExpressionColumn {
	return &ExpressionColumn{
		Table:  t,
		Column: c,
	}
}

// deepCompare deep compares the values of two nodes.
// It ignores the parseTypes.Node field.
func deepCompare(node1, node2 any) bool {
	// we return true for the parseTypes.Node field,
	// we also need to ignore the unexported "schema" fields
	return cmp.Equal(node1, node2, cmpOpts()...)
}

// diff returns the diff between two nodes.
func diff(node1, node2 any) string {
	return cmp.Diff(node1, node2, cmpOpts()...)
}

func cmpOpts() []cmp.Option {
	return []cmp.Option{
		cmp.AllowUnexported(
			ExpressionLiteral{},
			ExpressionFunctionCall{},
			ExpressionVariable{},
			ExpressionArrayAccess{},
			ExpressionMakeArray{},
			ExpressionFieldAccess{},
			ExpressionParenthesized{},
			ExpressionColumn{},
			ExpressionSubquery{},
			ActionStmtDeclaration{},
			ActionStmtAssign{},
			ActionStmtCall{},
			ActionStmtForLoop{},
			ActionStmtIf{},
			ActionStmtSQL{},
			ActionStmtLoopControl{},
			ActionStmtReturn{},
			ActionStmtReturnNext{},
			LoopTermRange{},
			LoopTermSQL{},
			LoopTermExpression{},
			ActionStmtSQL{},
			SQLStatement{},
		),
		cmp.Comparer(func(x, y Position) bool {
			return true
		}),
		cmp.Comparer(func(x, y *SQLStatement) bool {
			if x == nil && y == nil {
				return true
			}
			if x == nil || y == nil {
				return false
			}

			x.raw = nil
			y.raw = nil

			eq := cmp.Equal(x.CTEs, y.CTEs, cmpOpts()...)
			if !eq {
				return false
			}

			if x.Recursive != y.Recursive {
				return false
			}

			if x.Namespacing != y.Namespacing {
				return false
			}

			return cmp.Equal(x.SQL, y.SQL, cmpOpts()...)
		}),
	}
}

func TestCreateActionStatements(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect *CreateActionStatement
		err    error
	}{
		{
			name:  "Basic create action with no params and no returns",
			input: "CREATE ACTION my_action() PUBLIC {};",
			expect: &CreateActionStatement{
				Name:        "my_action",
				Modifiers:   []string{"public"},
				Parameters:  nil,
				Returns:     nil,
				IfNotExists: false,
				OrReplace:   false,
			},
		},
		{
			name:  "Create action with parameters",
			input: "CREATE ACTION my_action($param1 int, $param2 text) private {};",
			expect: &CreateActionStatement{
				Name:      "my_action",
				Modifiers: []string{"private"},
				Parameters: []*engine.NamedType{
					{Name: "$param1", Type: types.IntType},
					{Name: "$param2", Type: &types.DataType{Name: "text"}},
				},
				Returns: nil,
			},
		},
		{
			name: "Create action with owner and view modifiers",
			input: `CREATE ACTION my_complex_action($user_id int) PUBLIC OWNER VIEW {
		        // body
		    };`,
			expect: &CreateActionStatement{
				Name: "my_complex_action",
				Parameters: []*engine.NamedType{
					{Name: "$user_id", Type: types.IntType},
				},
				Modifiers: []string{"public", "owner", "view"},
			},
		},
		{
			name:  "Create action with IF NOT EXISTS",
			input: `CREATE ACTION IF NOT EXISTS my_action() private {};`,
			expect: &CreateActionStatement{
				IfNotExists: true,
				Name:        "my_action",
				Modifiers:   []string{"private"},
			},
		},
		{
			name:  "Create action with OR REPLACE",
			input: `CREATE OR REPLACE ACTION my_action() PUBLIC {};`,
			expect: &CreateActionStatement{
				OrReplace: true,
				Name:      "my_action",
				Modifiers: []string{"public"},
			},
		},
		{
			name:  "Create action with return table",
			input: `CREATE ACTION my_returns_action() PUBLIC RETURNS TABLE(id int, name text) {};`,
			expect: &CreateActionStatement{
				Name:      "my_returns_action",
				Modifiers: []string{"public"},
				Returns: &ActionReturn{
					IsTable: true,
					Fields: []*engine.NamedType{
						{Name: "id", Type: types.IntType},
						{Name: "name", Type: &types.DataType{Name: "text"}},
					},
				},
			},
		},
		{
			name:  "Create action with unnamed return types",
			input: `CREATE ACTION my_return_types() private RETURNS (int, text) {};`,
			expect: &CreateActionStatement{
				Name:      "my_return_types",
				Modifiers: []string{"private"},
				Returns: &ActionReturn{
					IsTable: false,
					Fields: []*engine.NamedType{
						{Name: "", Type: types.IntType},
						{Name: "", Type: &types.DataType{Name: "text"}},
					},
				},
			},
		},
		{
			name: "Create action with multiple parameters and complex body",
			input: `CREATE ACTION do_something($a int, $b int) PUBLIC VIEW RETURNS (int) {
		        $c int;
		        $c := $a + $b;
		        return $c;
		    };`,
			expect: &CreateActionStatement{
				Name: "do_something",
				Parameters: []*engine.NamedType{
					{Name: "$a", Type: types.IntType},
					{Name: "$b", Type: types.IntType},
				},
				Modifiers: []string{"public", "view"},
				Returns: &ActionReturn{
					IsTable: false,
					Fields:  []*engine.NamedType{{Name: "", Type: types.IntType}},
				},
				Statements: []ActionStmt{
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$c", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtAssign{
						Variable: &ExpressionVariable{Name: "$c", Prefix: VariablePrefixDollar},
						Value: &ExpressionArithmetic{
							Left:     &ExpressionVariable{Name: "$a", Prefix: VariablePrefixDollar},
							Operator: ArithmeticOperatorAdd,
							Right:    &ExpressionVariable{Name: "$b", Prefix: VariablePrefixDollar},
						},
					},
					&ActionStmtReturn{
						Values: []Expression{
							&ExpressionVariable{Name: "$c", Prefix: VariablePrefixDollar},
						},
					},
				},
			},
		},
		{
			name: "Create action with IF-ELSE and multiple statements",
			input: `
				CREATE ACTION conditional_action($val int) PUBLIC {
					$res int;
					if $val > 10 {
						$res := $val * 2;
					} else {
						$res := $val + 5;
					}
					return $res;
				};
			`,
			expect: &CreateActionStatement{
				Name:      "conditional_action",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$val", Type: types.IntType},
				},
				Returns: nil,
				Statements: []ActionStmt{
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$res", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtIf{
						IfThens: []*IfThen{
							{
								If: &ExpressionComparison{
									Left:     &ExpressionVariable{Name: "$val", Prefix: VariablePrefixDollar},
									Operator: ComparisonOperatorGreaterThan,
									Right:    exprLit(10),
								},
								Then: []ActionStmt{
									&ActionStmtAssign{
										Variable: &ExpressionVariable{Name: "$res", Prefix: VariablePrefixDollar},
										Value: &ExpressionArithmetic{
											Left:     &ExpressionVariable{Name: "$val", Prefix: VariablePrefixDollar},
											Operator: ArithmeticOperatorMultiply,
											Right:    exprLit(2),
										},
									},
								},
							},
						},
						Else: []ActionStmt{
							&ActionStmtAssign{
								Variable: &ExpressionVariable{Name: "$res", Prefix: VariablePrefixDollar},
								Value: &ExpressionArithmetic{
									Left:     &ExpressionVariable{Name: "$val", Prefix: VariablePrefixDollar},
									Operator: ArithmeticOperatorAdd,
									Right:    exprLit(5),
								},
							},
						},
					},
					&ActionStmtReturn{
						Values: []Expression{
							&ExpressionVariable{Name: "$res", Prefix: VariablePrefixDollar},
						},
					},
				},
			},
		},
		{
			name: "Create action with a FOR loop over a range",
			input: `
				CREATE ACTION loop_action() private {
					$i int;
					$sum int;
					$sum := 0;
					for $i in 1..5 {
						$sum := $sum + $i;
					}
					return $sum;
				};
			`,
			expect: &CreateActionStatement{
				Name:       "loop_action",
				Modifiers:  []string{"private"},
				Returns:    nil,
				Parameters: nil,
				Statements: []ActionStmt{
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$i", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$sum", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtAssign{
						Variable: &ExpressionVariable{Name: "$sum", Prefix: VariablePrefixDollar},
						Value:    exprLit(0),
					},
					&ActionStmtForLoop{
						Receiver: &ExpressionVariable{Name: "$i", Prefix: VariablePrefixDollar},
						LoopTerm: &LoopTermRange{
							Start: exprLit(1),
							End:   exprLit(5),
						},
						Body: []ActionStmt{
							&ActionStmtAssign{
								Variable: &ExpressionVariable{Name: "$sum", Prefix: VariablePrefixDollar},
								Value: &ExpressionArithmetic{
									Left:     &ExpressionVariable{Name: "$sum", Prefix: VariablePrefixDollar},
									Operator: ArithmeticOperatorAdd,
									Right:    &ExpressionVariable{Name: "$i", Prefix: VariablePrefixDollar},
								},
							},
						},
					},
					&ActionStmtReturn{
						Values: []Expression{
							&ExpressionVariable{Name: "$sum", Prefix: VariablePrefixDollar},
						},
					},
				},
			},
		},
		{
			name: "Create action with RETURN NEXT and multiple RETURNs",
			input: `
				CREATE ACTION return_next_action($arr int) PUBLIC RETURNS (int) {
					// Assume $arr is an array of ints.
					$el int;
					for $el in array $arr {
						return next $el;
					}
					// If loop finishes, return a default value
					return 0;
				};
			`,
			expect: &CreateActionStatement{
				Name:      "return_next_action",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$arr", Type: types.IntType},
				},
				Returns: &ActionReturn{
					IsTable: false,
					Fields: []*engine.NamedType{
						{Name: "", Type: types.IntType},
					},
				},
				Statements: []ActionStmt{
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$el", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtForLoop{
						Receiver: &ExpressionVariable{Name: "$el", Prefix: VariablePrefixDollar},
						LoopTerm: &LoopTermExpression{
							Array:      true,
							Expression: &ExpressionVariable{Name: "$arr", Prefix: VariablePrefixDollar},
						},
						Body: []ActionStmt{
							&ActionStmtReturnNext{
								Values: []Expression{
									&ExpressionVariable{Name: "$el", Prefix: VariablePrefixDollar},
								},
							},
						},
					},
					&ActionStmtReturn{
						Values: []Expression{
							exprLit(0),
						},
					},
				},
			},
		},
		{
			name: "Create action with nested action calls",
			input: `
				CREATE ACTION call_other_actions($x int) private {
					$y int;
					$y := $x + 10;
					$z := my_other_action($y);
					return $z;
				};
			`,
			expect: &CreateActionStatement{
				Name:      "call_other_actions",
				Modifiers: []string{"private"},
				Parameters: []*engine.NamedType{
					{Name: "$x", Type: types.IntType},
				},
				Statements: []ActionStmt{
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$y", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtAssign{
						Variable: &ExpressionVariable{Name: "$y", Prefix: VariablePrefixDollar},
						Value: &ExpressionArithmetic{
							Left:     &ExpressionVariable{Name: "$x", Prefix: VariablePrefixDollar},
							Operator: ArithmeticOperatorAdd,
							Right:    exprLit(10),
						},
					},
					&ActionStmtCall{
						Receivers: []*ExpressionVariable{
							{Name: "$z", Prefix: VariablePrefixDollar},
						},
						Call: &ExpressionFunctionCall{
							Name: "my_other_action",
							Args: []Expression{
								&ExpressionVariable{Name: "$y", Prefix: VariablePrefixDollar},
							},
						},
					},
					&ActionStmtReturn{
						Values: []Expression{
							&ExpressionVariable{Name: "$z", Prefix: VariablePrefixDollar},
						},
					},
				},
			},
		},
		{
			name: "Create action with IF, ELSEIF, ELSE conditions",
			input: `
				CREATE ACTION complex_conditions($score int) PUBLIC RETURNS (text) {
					// Score analysis
					if $score > 90 {
						return 'A';
					} elseif $score > 80 {
						return 'B';
					} else {
						return 'C';
					}
				};
			`,
			expect: &CreateActionStatement{
				Name:      "complex_conditions",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$score", Type: types.IntType},
				},
				Returns: &ActionReturn{
					IsTable: false,
					Fields: []*engine.NamedType{
						{Name: "", Type: &types.DataType{Name: "text"}},
					},
				},
				Statements: []ActionStmt{
					&ActionStmtIf{
						IfThens: []*IfThen{
							{
								If: &ExpressionComparison{
									Left:     &ExpressionVariable{Name: "$score", Prefix: VariablePrefixDollar},
									Operator: ComparisonOperatorGreaterThan,
									Right:    exprLit(90),
								},
								Then: []ActionStmt{
									&ActionStmtReturn{
										Values: []Expression{
											exprLit("A"),
										},
									},
								},
							},
							{
								If: &ExpressionComparison{
									Left:     &ExpressionVariable{Name: "$score", Prefix: VariablePrefixDollar},
									Operator: ComparisonOperatorGreaterThan,
									Right:    exprLit(80),
								},
								Then: []ActionStmt{
									&ActionStmtReturn{
										Values: []Expression{
											exprLit("B"),
										},
									},
								},
							},
						},
						Else: []ActionStmt{
							&ActionStmtReturn{
								Values: []Expression{
									exprLit("C"),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Create action with array parameters and array return",
			input: `CREATE ACTION array_manipulation($arr int[]) private RETURNS (int[]) {
				// Just return the input array
				return $arr;
			};`,
			expect: &CreateActionStatement{
				Name:       "array_manipulation",
				Modifiers:  []string{"private"},
				Parameters: []*engine.NamedType{{Name: "$arr", Type: &types.DataType{Name: "int8", IsArray: true}}},
				Returns: &ActionReturn{
					IsTable: false,
					Fields:  []*engine.NamedType{{Name: "", Type: &types.DataType{Name: "int8", IsArray: true}}},
				},
				Statements: []ActionStmt{
					&ActionStmtReturn{
						Values: []Expression{
							&ExpressionVariable{Name: "$arr", Prefix: VariablePrefixDollar},
						},
					},
				},
			},
		},
		{
			name: "Create action calling a function with distinct arguments",
			input: `CREATE ACTION calc_distinct($vals int[]) PUBLIC {
				$total int;
				for $row in SELECT count(distinct $vals) as total {
					$total := $row.total;
				};
				return $total;
			};`,
			expect: &CreateActionStatement{
				Name:      "calc_distinct",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$vals", Type: &types.DataType{Name: "int8", IsArray: true}},
				},
				Statements: []ActionStmt{
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$total", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtForLoop{
						Receiver: &ExpressionVariable{Name: "$row", Prefix: VariablePrefixDollar},
						LoopTerm: &LoopTermSQL{
							Statement: &SQLStatement{
								SQL: &SelectStatement{
									SelectCores: []*SelectCore{
										{
											Columns: []ResultColumn{
												&ResultColumnExpression{
													Expression: &ExpressionFunctionCall{
														Name:     "count",
														Distinct: true,
														Args: []Expression{
															&ExpressionVariable{Name: "$vals", Prefix: VariablePrefixDollar},
														},
													},
													Alias: "total",
												},
											},
										},
									},
								},
							},
						},
						Body: []ActionStmt{
							&ActionStmtAssign{
								Variable: &ExpressionVariable{Name: "$total", Prefix: VariablePrefixDollar},
								Value: &ExpressionFieldAccess{
									Record: &ExpressionVariable{Name: "$row", Prefix: VariablePrefixDollar},
									Field:  "total",
								},
							},
						},
					},
					&ActionStmtReturn{
						Values: []Expression{
							&ExpressionVariable{Name: "$total", Prefix: VariablePrefixDollar},
						},
					},
				},
			},
		},
		{
			name: "Create action performing an UPDATE inside action",
			input: `CREATE ACTION update_something($id int, $name text) PUBLIC {
				update my_table set name = $name where id = $id;
				return;
			};`,
			expect: &CreateActionStatement{
				Name:      "update_something",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$id", Type: types.IntType},
					{Name: "$name", Type: &types.DataType{Name: "text"}},
				},
				Statements: []ActionStmt{
					&ActionStmtSQL{
						SQL: &SQLStatement{
							SQL: &UpdateStatement{
								Table: "my_table",
								SetClause: []*UpdateSetClause{
									{
										Column: "name",
										Value:  &ExpressionVariable{Name: "$name", Prefix: VariablePrefixDollar},
									},
								},
								Where: &ExpressionComparison{
									Left:     &ExpressionColumn{Column: "id"},
									Operator: ComparisonOperatorEqual,
									Right:    &ExpressionVariable{Name: "$id", Prefix: VariablePrefixDollar},
								},
							},
						},
					},
					&ActionStmtReturn{},
				},
			},
		},
		{
			name: "Create action with array indexing",
			input: `CREATE ACTION array_access($arr int[]) PUBLIC RETURNS (int) {
				$val int;
				$val := $arr[2];
				return $val;
			};`,
			expect: &CreateActionStatement{
				Name:      "array_access",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$arr", Type: &types.DataType{Name: "int8", IsArray: true}},
				},
				Returns: &ActionReturn{
					IsTable: false,
					Fields: []*engine.NamedType{
						{Name: "", Type: types.IntType},
					},
				},
				Statements: []ActionStmt{
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$val", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtAssign{
						Variable: &ExpressionVariable{Name: "$val", Prefix: VariablePrefixDollar},
						Value: &ExpressionArrayAccess{
							Array: &ExpressionVariable{Name: "$arr", Prefix: VariablePrefixDollar},
							Index: exprLit(int64(2)),
						},
					},
					&ActionStmtReturn{
						Values: []Expression{
							&ExpressionVariable{Name: "$val", Prefix: VariablePrefixDollar},
						},
					},
				},
			},
		},
		{
			name: "Create action with casting inside the body",
			input: `CREATE ACTION cast_stuff($val text) private {
				$int_val int;
				$int_val := ($val)::int;
				return $int_val;
			};`,
			expect: &CreateActionStatement{
				Name:      "cast_stuff",
				Modifiers: []string{"private"},
				Parameters: []*engine.NamedType{
					{Name: "$val", Type: &types.DataType{Name: "text"}},
				},
				Statements: []ActionStmt{
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$int_val", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtAssign{
						Variable: &ExpressionVariable{Name: "$int_val", Prefix: VariablePrefixDollar},
						Value: &ExpressionParenthesized{
							Inner: &ExpressionVariable{Name: "$val", Prefix: VariablePrefixDollar},
							Typecastable: Typecastable{
								TypeCast: types.IntType,
							},
						},
					},
					&ActionStmtReturn{
						Values: []Expression{
							&ExpressionVariable{Name: "$int_val", Prefix: VariablePrefixDollar},
						},
					},
				},
			},
		},
		{
			name: "Create action with a FOR loop and BREAK",
			input: `CREATE ACTION break_loop_example() PUBLIC {
				$i int;
				for $i in 1..10 {
					if $i = 5 {
						break;
					}
				}
				return $i;
			};`,
			expect: &CreateActionStatement{
				Name:      "break_loop_example",
				Modifiers: []string{"public"},
				Statements: []ActionStmt{
					&ActionStmtDeclaration{
						Variable: &ExpressionVariable{Name: "$i", Prefix: VariablePrefixDollar},
						Type:     types.IntType,
					},
					&ActionStmtForLoop{
						Receiver: &ExpressionVariable{Name: "$i", Prefix: VariablePrefixDollar},
						LoopTerm: &LoopTermRange{
							Start: exprLit(int64(1)),
							End:   exprLit(int64(10)),
						},
						Body: []ActionStmt{
							&ActionStmtIf{
								IfThens: []*IfThen{
									{
										If: &ExpressionComparison{
											Left:     &ExpressionVariable{Name: "$i", Prefix: VariablePrefixDollar},
											Operator: ComparisonOperatorEqual,
											Right:    exprLit(int64(5)),
										},
										Then: []ActionStmt{
											&ActionStmtLoopControl{
												Type: LoopControlTypeBreak,
											},
										},
									},
								},
							},
						},
					},
					&ActionStmtReturn{
						Values: []Expression{
							&ExpressionVariable{Name: "$i", Prefix: VariablePrefixDollar},
						},
					},
				},
			},
		},
		{
			name: "Create action with just a SELECT statement in the body",
			input: `CREATE ACTION just_select() PUBLIC {
				select * from my_table;
				return;
			};`,
			expect: &CreateActionStatement{
				Name:      "just_select",
				Modifiers: []string{"public"},
				Statements: []ActionStmt{
					&ActionStmtSQL{
						SQL: &SQLStatement{
							SQL: &SelectStatement{
								SelectCores: []*SelectCore{
									{
										Columns: []ResultColumn{
											&ResultColumnWildcard{},
										},
										From: &RelationTable{Table: "my_table"},
									},
								},
							},
						},
					},
					&ActionStmtReturn{},
				},
			},
		},
		{
			name:  "create action with duplicate parameters",
			input: `CREATE ACTION duplicate_params($a int, $a text) PUBLIC {};`,
			err:   ErrDuplicateParameterName,
		},
		{
			name:  "create action with duplicate return names",
			input: `CREATE ACTION duplicate_returns() PUBLIC RETURNS (id int, id text) {};`,
			err:   ErrDuplicateResultColumnName,
		},
		{
			name:  "Create action with default parameter (boolean)",
			input: "CREATE ACTION my_action($param1 int, $use_cache bool DEFAULT false) public {};",
			expect: &CreateActionStatement{
				Name:      "my_action",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$param1", Type: types.IntType},
					{Name: "$use_cache", Type: types.BoolType, DefaultValue: &DefaultValue{
						LiteralValue: false,
					}},
				},
				Returns: nil,
			},
		},
		{
			name:  "Create action with default parameter (null)",
			input: "CREATE ACTION my_action($param1 int, $param2 text DEFAULT null) public {};",
			expect: &CreateActionStatement{
				Name:      "my_action",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$param1", Type: types.IntType},
					{Name: "$param2", Type: &types.DataType{Name: "text"}, DefaultValue: &DefaultValue{
						LiteralValue: nil,
					}},
				},
				Returns: nil,
			},
		},
		{
			name:  "Create action with default parameter (integer)",
			input: "CREATE ACTION my_action($param1 text, $timeout int DEFAULT 30) public {};",
			expect: &CreateActionStatement{
				Name:      "my_action",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$param1", Type: &types.DataType{Name: "text"}},
					{Name: "$timeout", Type: types.IntType, DefaultValue: &DefaultValue{
						LiteralValue: int64(30),
					}},
				},
				Returns: nil,
			},
		},
		{
			name:  "Create action with multiple default parameters",
			input: "CREATE ACTION my_action($param1 text, $use_cache bool DEFAULT false, $timeout int DEFAULT 30) public {};",
			expect: &CreateActionStatement{
				Name:      "my_action",
				Modifiers: []string{"public"},
				Parameters: []*engine.NamedType{
					{Name: "$param1", Type: &types.DataType{Name: "text"}},
					{Name: "$use_cache", Type: types.BoolType, DefaultValue: &DefaultValue{
						LiteralValue: false,
					}},
					{Name: "$timeout", Type: types.IntType, DefaultValue: &DefaultValue{
						LiteralValue: int64(30),
					}},
				},
				Returns: nil,
			},
		},
		{
			name:  "Create action with expression default should fail",
			input: "CREATE ACTION my_action($param1 text, $computed int DEFAULT 10 + 20) public {};",
			err:   ErrSyntax, // Should fail parsing due to grammar restriction
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Parse(tt.input)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)

			require.Len(t, res, 1)

			tt.expect.Raw = res[0].(*CreateActionStatement).Raw

			assertPositionsAreSet(t, res[0])

			if !deepCompare(tt.expect, res[0]) {
				t.Errorf("unexpected AST:%s", diff(tt.expect, res[0]))
			}
		})
	}
}

// TestCreateActionStatementsWithOptionalParams tests default value storage in Phase 2
func TestCreateActionStatementsWithOptionalParams(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expected    []struct {
			name         string
			hasDefault   bool
			literalValue any
			isLiteral    bool
		}
	}{
		{
			name:  "Boolean default parameter",
			input: "CREATE ACTION test($param bool DEFAULT false) public {};",
			expected: []struct {
				name         string
				hasDefault   bool
				literalValue any
				isLiteral    bool
			}{
				{name: "$param", hasDefault: true, literalValue: false, isLiteral: true},
			},
		},
		{
			name:  "Null default parameter",
			input: "CREATE ACTION test($param text DEFAULT null) public {};",
			expected: []struct {
				name         string
				hasDefault   bool
				literalValue any
				isLiteral    bool
			}{
				{name: "$param", hasDefault: true, literalValue: nil, isLiteral: true},
			},
		},
		{
			name:  "Integer default parameter",
			input: "CREATE ACTION test($param int DEFAULT 42) public {};",
			expected: []struct {
				name         string
				hasDefault   bool
				literalValue any
				isLiteral    bool
			}{
				{name: "$param", hasDefault: true, literalValue: int64(42), isLiteral: true},
			},
		},
		{
			name:  "Mixed parameters with and without defaults",
			input: "CREATE ACTION test($required text, $optional bool DEFAULT true, $timeout int DEFAULT 30) public {};",
			expected: []struct {
				name         string
				hasDefault   bool
				literalValue any
				isLiteral    bool
			}{
				{name: "$required", hasDefault: false},
				{name: "$optional", hasDefault: true, literalValue: true, isLiteral: true},
				{name: "$timeout", hasDefault: true, literalValue: int64(30), isLiteral: true},
			},
		},
		{
			name:  "Expression default should fail",
			input: "CREATE ACTION test($param int DEFAULT 10 + 20) public {};",
			expected: []struct {
				name         string
				hasDefault   bool
				literalValue any
				isLiteral    bool
			}{
				// This test should fail parsing, so no expected results
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Parse(tt.input)

			if tt.expectError {
				require.Error(t, err, "Expected parsing to fail")
				return
			}

			require.NoError(t, err)
			require.Len(t, res, 1)

			stmt := res[0].(*CreateActionStatement)
			require.Len(t, stmt.Parameters, len(tt.expected))

			for i, expected := range tt.expected {
				param := stmt.Parameters[i]
				require.Equal(t, expected.name, param.Name)

				if expected.hasDefault {
					require.NotNil(t, param.DefaultValue, "Parameter %s should have default value", expected.name)
					defaultVal := param.DefaultValue.(*DefaultValue)
					require.Equal(t, expected.literalValue, defaultVal.LiteralValue, "Literal value mismatch for %s", expected.name)
				} else {
					require.Nil(t, param.DefaultValue, "Parameter %s should not have default value", expected.name)
				}
			}
		})
	}
}

// TestJSONSerialization tests JSON serialization of default values
func TestJSONSerialization(t *testing.T) {
	input := "CREATE ACTION test($required text, $optional bool DEFAULT true) public {};"
	res, err := Parse(input)
	require.NoError(t, err)
	require.Len(t, res, 1)

	stmt := res[0].(*CreateActionStatement)

	// Test JSON marshaling
	jsonData, err := json.Marshal(stmt) //nolint:musttag
	require.NoError(t, err)

	// Test JSON unmarshaling
	var unmarshaled CreateActionStatement
	err = json.Unmarshal(jsonData, &unmarshaled) //nolint:musttag
	require.NoError(t, err)

	// Verify the unmarshaled structure
	require.Equal(t, stmt.Name, unmarshaled.Name)
	require.Len(t, unmarshaled.Parameters, 2)

	// Check required parameter (no default)
	require.Equal(t, "$required", unmarshaled.Parameters[0].Name)
	require.Nil(t, unmarshaled.Parameters[0].DefaultValue)

	// Check optional parameter (has default)
	require.Equal(t, "$optional", unmarshaled.Parameters[1].Name)
	require.NotNil(t, unmarshaled.Parameters[1].DefaultValue)
}
