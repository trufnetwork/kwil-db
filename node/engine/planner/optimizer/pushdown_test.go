package optimizer

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
	"github.com/trufnetwork/kwil-db/node/engine/planner/logical"
)

func Test_Pushdown(t *testing.T) {
	type testcase struct {
		name string
		sql  string
		wt   string // expected logical plan, uses name "wt" for formatting
		err  error
	}

	tests := []testcase{
		{
			name: "simple pushdown",
			sql:  "select * from users where name = 'foo'",
			wt: "Return: id [uuid], name [text], age [int8]\n" +
				"└─Project: users.id; users.name; users.age\n" +
				"  └─Scan Table: users [physical] filter=[users.name = 'foo']\n",
		},
		{
			name: "push down join",
			sql:  "select u.* from users u inner join posts p on u.id = p.owner_id where u.name = p.content",
			wt: "Return: id [uuid], name [text], age [int8]\n" +
				"└─Project: u.id; u.name; u.age\n" +
				"  └─Join [inner]: u.id = p.owner_id AND u.name = p.content\n" +
				"    ├─Scan Table [alias=\"u\"]: users [physical]\n" +
				"    └─Scan Table [alias=\"p\"]: posts [physical]\n",
		},
		{
			name: "pushdown through join",
			sql:  "select u.* from users u inner join posts p on u.id = p.owner_id where u.name = 'foo'",
			wt: "Return: id [uuid], name [text], age [int8]\n" +
				"└─Project: u.id; u.name; u.age\n" +
				"  └─Join [inner]: u.id = p.owner_id\n" +
				"    ├─Scan Table [alias=\"u\"]: users [physical] filter=[u.name = 'foo']\n" +
				"    └─Scan Table [alias=\"p\"]: posts [physical]\n",
		},
		{
			name: "doesn't pushdown through join if not all columns are from one side",
			sql:  "select u.id from users u inner join posts p on u.id = p.owner_id inner join users u2 on u2.id = p.owner_id where u.age + u2.age = length(p.content)",
			wt: "Return: id [uuid]\n" +
				"└─Project: u.id\n" +
				"  └─Join [inner]: u2.id = p.owner_id AND u.age + u2.age = length(p.content)\n" +
				"    ├─Join [inner]: u.id = p.owner_id\n" +
				"    │ ├─Scan Table [alias=\"u\"]: users [physical]\n" +
				"    │ └─Scan Table [alias=\"p\"]: posts [physical]\n" +
				"    └─Scan Table [alias=\"u2\"]: users [physical]\n",
		},
		{
			name: "split and pushdown AND",
			sql:  "select u.id from users u inner join posts p on u.id = p.owner_id where u.age = 10 and p.created_at = 100",
			wt: "Return: id [uuid]\n" +
				"└─Project: u.id\n" +
				"  └─Join [inner]: u.id = p.owner_id\n" +
				"    ├─Scan Table [alias=\"u\"]: users [physical] filter=[u.age = 10]\n" +
				"    └─Scan Table [alias=\"p\"]: posts [physical] filter=[p.created_at = 100]\n",
		},
		{
			// shouldn't do anything, just checking that aggregates work as expected.
			// Since the planner uses a reference system for any aggregate results,
			// there is no need to push down any aggregate function.
			name: "aggregate having",
			sql:  "select u.id, count(p.id) from users u inner join posts p on u.id = p.owner_id group by u.id having count(p.id) > 10",
			wt: "Return: id [uuid], count [int8]\n" +
				"└─Project: {#ref(A)}; {#ref(B)}\n" +
				"  └─Filter: {#ref(B)} > 10\n" +
				"    └─Aggregate [{#ref(A) = u.id}]: {#ref(B) = count(p.id)}\n" +
				"      └─Join [inner]: u.id = p.owner_id\n" +
				"        ├─Scan Table [alias=\"u\"]: users [physical]\n" +
				"        └─Scan Table [alias=\"p\"]: posts [physical]\n",
		},
		{
			name: "update with a basic FROM clause",
			sql:  "update users set name = 'foo' from posts where users.id = posts.owner_id",
			wt: "Update [users]: name = 'foo'\n" +
				"└─Join [inner]: users.id = posts.owner_id\n" +
				"  ├─Scan Table: users [physical]\n" +
				"  └─Scan Table: posts [physical]\n",
		},
		{
			name: "more complex update with a FROM clause",
			sql:  "update users set name = posts.content from posts inner join users u on u.id = posts.owner_id where users.id = u.id",
			wt: "Update [users]: name = posts.content\n" +
				"└─Join [inner]: users.id = u.id\n" +
				"  ├─Scan Table: users [physical]\n" +
				"  └─Join [inner]: u.id = posts.owner_id\n" +
				"    ├─Scan Table: posts [physical]\n" +
				"    └─Scan Table [alias=\"u\"]: users [physical]\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			parsedSql, err := parse.Parse(test.sql)
			require.NoError(t, err)

			plan, err := logical.CreateLogicalPlan(parsedSql[0].(*parse.SQLStatement),
				func(namespace, tableName string) (table *engine.Table, err error) {
					t, found := testTables[tableName]
					if !found {
						return nil, fmt.Errorf("table %s not found", tableName)
					}
					return t, nil
				},
				func(varName string) (dataType *types.DataType, err error) { return nil, engine.ErrUnknownVariable },
				func(objName string) (obj map[string]*types.DataType, err error) {
					return nil, engine.ErrUnknownVariable
				},
				func(s string) bool { return false },
				false, "")
			require.NoError(t, err)

			newPlan, err := PushdownPredicates(plan.Plan)
			plan.Plan = newPlan
			if test.err != nil {
				require.Error(t, err)

				// special case for testing
				if errors.Is(test.err, errAny) {
					return
				}

				require.ErrorIs(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.wt, plan.Format())
			}
		})
	}
}

// special error for testing that will match any error
var errAny = errors.New("any error")

var testTables = map[string]*engine.Table{
	"users": {
		Name: "users",
		Columns: []*engine.Column{
			{
				Name:         "id",
				DataType:     types.UUIDType,
				IsPrimaryKey: true,
			},
			{
				Name:     "name",
				DataType: types.TextType,
			},
			{
				Name:     "age",
				DataType: types.IntType,
			},
		},
		Indexes: []*engine.Index{
			{
				Name: "name_idx",
				Type: engine.UNIQUE_BTREE,
				Columns: []string{
					"name",
				},
			},
		},
	},
	"posts": {
		Name: "posts",
		Columns: []*engine.Column{
			{
				Name:         "id",
				DataType:     types.UUIDType,
				IsPrimaryKey: true,
			},
			{
				Name:     "owner_id",
				DataType: types.UUIDType,
			},
			{
				Name:     "content",
				DataType: types.TextType,
			},
			{
				Name:     "created_at",
				DataType: types.IntType,
			},
		},
		Constraints: map[string]*engine.Constraint{
			"content_unique": {
				Type: engine.ConstraintUnique,
				Columns: []string{
					"content",
				},
			},
			"owner_created_idx": {
				Type: engine.ConstraintUnique,
				Columns: []string{
					"owner_id",
					"created_at",
				},
			},
		},
	},
}
