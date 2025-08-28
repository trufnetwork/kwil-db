package logical_test

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

func Test_Planner(t *testing.T) {
	type testcase struct {
		name            string
		sql             string
		wt              string                                // want, abbreviated for formatting test cases
		vars            map[string]*types.DataType            // variables that can be accessed, can be nil
		objects         map[string]map[string]*types.DataType // objects that can be referenced, can be nil
		actions         map[string]struct{}                   // actions that exist, can be nil
		defaultOrdering bool                                  // whether to use default ordering
		err             error                                 // can be nil if no error is expected
	}

	tests := []testcase{
		{
			name: "basic select",
			sql:  "select 1",
			wt: "Return: ?column? [int8]\n" +
				"└─Project: 1\n" +
				"  └─Empty Scan\n",
		},
		{
			name: "array_agg with order by",
			sql:  "select array_agg(name order by id) from users",
			wt: "Return: array_agg [text[]]\n" +
				"└─Project: {#ref(A)}\n" +
				"  └─Aggregate: {#ref(A) = array_agg(users.name ORDER BY users.id asc nulls last)}\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "array_agg with multiple order by terms",
			sql:  "select array_agg(name order by age desc, name asc) from users",
			wt: "Return: array_agg [text[]]\n" +
				"└─Project: {#ref(A)}\n" +
				"  └─Aggregate: {#ref(A) = array_agg(users.name ORDER BY users.age desc nulls last, users.name asc nulls last)}\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "array and object",
			sql:  "select $a.b, $c as c1",
			vars: map[string]*types.DataType{
				"$c": types.ArrayType(types.IntType),
			},
			objects: map[string]map[string]*types.DataType{
				"$a": {"b": types.IntType},
			},
			wt: "Return: ?column? [int8], c1 [int8[]]\n" +
				"└─Project: $a.b; $c AS c1\n" +
				"  └─Empty Scan\n",
		},
		{
			name: "select array",
			sql:  "select ARRAY[1, 2, 3]",
			wt: "Return: ?column? [int8[]]\n" +
				"└─Project: [1, 2, 3]\n" +
				"  └─Empty Scan\n",
		},
		{
			name: "select with filter",
			sql:  "select id, name from users where age > 18",
			wt: "Return: id [uuid], name [text]\n" +
				"└─Project: users.id; users.name\n" +
				"  └─Filter: users.age > 18\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "subquery join",
			sql:  "select name from users u inner join (select owner_id from posts) p on u.id = p.owner_id",
			wt: "Return: name [text]\n" +
				"└─Project: u.name\n" +
				"  └─Join [inner]: u.id = p.owner_id\n" +
				"    ├─Scan Table [alias=\"u\"]: users [physical]\n" +
				"    └─Scan Subquery [alias=\"p\"]: [subplan_id=0] (uncorrelated)\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: posts.owner_id\n" +
				"  └─Scan Table: posts [physical]\n",
		},
		{
			name: "correlated joined subquery",
			sql:  "select name from users u where id = (select owner_id from posts inner join (select age from users where id = u.id) as u2 on u2.age=length(posts.content))",
			wt: "Return: name [text]\n" +
				"└─Project: u.name\n" +
				"  └─Filter: u.id = [subquery (scalar) (subplan_id=1) (correlated: u.id)]\n" +
				"    └─Scan Table [alias=\"u\"]: users [physical]\n" +
				"Subplan [subquery] [id=1]\n" +
				"└─Project: posts.owner_id\n" +
				"  └─Join [inner]: u2.age = length(posts.content)\n" +
				"    ├─Scan Table: posts [physical]\n" +
				"    └─Scan Subquery [alias=\"u2\"]: [subplan_id=0] (correlated: u.id)\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: users.age\n" +
				"  └─Filter: users.id = u.id\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "scalar subquery in where clause",
			sql:  "select name from users where id = (select id from posts where content = 'hello')",
			wt: "Return: name [text]\n" +
				"└─Project: users.name\n" +
				"  └─Filter: users.id = [subquery (scalar) (subplan_id=0) (uncorrelated)]\n" +
				"    └─Scan Table: users [physical]\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: posts.id\n" +
				"  └─Filter: posts.content = 'hello'\n" +
				"    └─Scan Table: posts [physical]\n",
		},
		{
			name: "correlated subquery in where clause",
			sql:  "select name from users u where exists (select 1 from posts p where p.owner_id = u.id)",
			wt: "Return: name [text]\n" +
				"└─Project: u.name\n" +
				"  └─Filter: [subquery (exists) (subplan_id=0) (correlated: u.id)]\n" +
				"    └─Scan Table [alias=\"u\"]: users [physical]\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: 1\n" +
				"  └─Filter: p.owner_id = u.id\n" +
				"    └─Scan Table [alias=\"p\"]: posts [physical]\n",
		},
		{
			name: "subquery in result",
			sql:  "select (select * from (select id from posts where owner_id = users.id) as p limit 1) from users",
			wt: "Return: id [uuid]\n" +
				"└─Project: [subquery (scalar) (subplan_id=1) (correlated: users.id)]\n" +
				"  └─Scan Table: users [physical]\n" +
				"Subplan [subquery] [id=1]\n" +
				"└─Project: p.id\n" +
				"  └─Limit: 1\n" +
				"    └─Scan Subquery [alias=\"p\"]: [subplan_id=0] (correlated: users.id)\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: posts.id\n" +
				"  └─Filter: posts.owner_id = users.id\n" +
				"    └─Scan Table: posts [physical]\n",
		},
		{
			name: "subquery exists",
			sql:  "select name from users where exists (select 1 from posts where owner_id = users.id)",
			wt: "Return: name [text]\n" +
				"└─Project: users.name\n" +
				"  └─Filter: [subquery (exists) (subplan_id=0) (correlated: users.id)]\n" +
				"    └─Scan Table: users [physical]\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: 1\n" +
				"  └─Filter: posts.owner_id = users.id\n" +
				"    └─Scan Table: posts [physical]\n",
		},
		{
			// tests that correlation is propagated across multiple subqueries
			name: "double nested correlated subquery",
			sql:  "select name from users u where exists (select 1 from posts p where exists (select 1 from posts p2 where p2.owner_id = u.id))",
			wt: "Return: name [text]\n" +
				"└─Project: u.name\n" +
				"  └─Filter: [subquery (exists) (subplan_id=1) (correlated: u.id)]\n" +
				"    └─Scan Table [alias=\"u\"]: users [physical]\n" +
				"Subplan [subquery] [id=1]\n" +
				"└─Project: 1\n" +
				"  └─Filter: [subquery (exists) (subplan_id=0) (correlated: u.id)]\n" +
				"    └─Scan Table [alias=\"p\"]: posts [physical]\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: 1\n" +
				"  └─Filter: p2.owner_id = u.id\n" +
				"    └─Scan Table [alias=\"p2\"]: posts [physical]\n",
		},
		{
			name: "aggregate without group by",
			sql:  "select sum(age) from users",
			wt: "Return: sum [numeric(1000,0)]\n" +
				"└─Project: {#ref(A)}\n" +
				"  └─Aggregate: {#ref(A) = sum(users.age)}\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "aggregate with group by",
			sql:  "select name, sum(age) from users where name = 'a' group by name having sum(age)::int8 > 100",
			wt: "Return: name [text], sum [numeric(1000,0)]\n" +
				"└─Project: {#ref(A)}; {#ref(B)}\n" +
				"  └─Filter: {#ref(B)}::int8 > 100\n" +
				"    └─Aggregate [{#ref(A) = users.name}]: {#ref(B) = sum(users.age)}\n" +
				"      └─Filter: users.name = 'a'\n" +
				"        └─Scan Table: users [physical]\n",
		},
		{
			name: "complex group by and aggregate",
			sql:  "select sum(u.age)::int/(p.created_at/100) as res from users u inner join posts p on u.id=p.owner_id group by (p.created_at/100) having (p.created_at/100)>10",
			wt: "Return: res [int8]\n" +
				"└─Project: {#ref(B)}::int8 / {#ref(A)} AS res\n" +
				"  └─Filter: {#ref(A)} > 10\n" +
				"    └─Aggregate [{#ref(A) = p.created_at / 100}]: {#ref(B) = sum(u.age)}\n" +
				"      └─Join [inner]: u.id = p.owner_id\n" +
				"        ├─Scan Table [alias=\"u\"]: users [physical]\n" +
				"        └─Scan Table [alias=\"p\"]: posts [physical]\n",
		},
		{
			name: "invalid group by column",
			sql:  "select age from users group by age/2",
			err:  logical.ErrIllegalAggregate,
		},
		{
			name: "aggregate in group by",
			sql:  "select sum(age) from users group by sum(age)",
			err:  logical.ErrIllegalAggregate,
		},
		{
			name: "aggregate in where clause",
			sql:  "select sum(age) from users where sum(age)::int8 > 100",
			err:  logical.ErrIllegalAggregate,
		},
		{
			name: "complex group by",
			sql:  "select age/2, age*3 from users group by age/2, age*3",
			wt: "Return: ?column? [int8], ?column? [int8]\n" +
				"└─Project: {#ref(A)}; {#ref(B)}\n" +
				"  └─Aggregate [{#ref(A) = users.age / 2}] [{#ref(B) = users.age * 3}]\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "select * with group by",
			sql:  "select * from users group by name, age, id",
			wt: "Return: id [uuid], name [text], age [int8]\n" +
				"└─Project: {#ref(C)}; {#ref(A)}; {#ref(B)}\n" +
				"  └─Aggregate [{#ref(A) = users.name}] [{#ref(B) = users.age}] [{#ref(C) = users.id}]\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "select * with group by (not enough group by columns)",
			sql:  "select * from users group by name",
			err:  logical.ErrIllegalAggregate,
		},
		{
			name: "complex having",
			sql:  "select name, sum(age/2)+sum(age*10) from users group by name having sum(age)::int8 > 100 or sum(age/2)::int8 > 10",
			wt: "Return: name [text], ?column? [numeric(1000,0)]\n" +
				"└─Project: {#ref(A)}; {#ref(C)} + {#ref(D)}\n" +
				"  └─Filter: {#ref(B)}::int8 > 100 OR {#ref(C)}::int8 > 10\n" +
				"    └─Aggregate [{#ref(A) = users.name}]: {#ref(B) = sum(users.age)}; {#ref(C) = sum(users.age / 2)}; {#ref(D) = sum(users.age * 10)}\n" +
				"      └─Scan Table: users [physical]\n",
		},
		{
			name: "duplicate group by columns",
			sql:  "select name, age from users group by name, name, age",
			wt: "Return: name [text], age [int8]\n" +
				"└─Project: {#ref(A)}; {#ref(B)}\n" +
				"  └─Aggregate [{#ref(A) = users.name}] [{#ref(B) = users.age}]\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "group by with alias",
			sql:  "select name from users group by users.name",
			wt: "Return: name [text]\n" +
				"└─Project: {#ref(A)}\n" +
				"  └─Aggregate [{#ref(A) = users.name}]\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "every type of join",
			vars: map[string]*types.DataType{
				"$id":   types.IntType,
				"$name": types.TextType,
			},
			sql: `select u.name, u2.id, count(p.id) from users u
					inner join posts p on u.id = p.owner_id
					full join (select id from users where age > 18) u2 on u2.id = u.id
					group by u.name, u2.id;`,
			wt: "Return: name [text], id [uuid], count [int8]\n" +
				"└─Project: {#ref(A)}; {#ref(B)}; {#ref(C)}\n" +
				"  └─Aggregate [{#ref(A) = u.name}] [{#ref(B) = u2.id}]: {#ref(C) = count(p.id)}\n" +
				"    └─Join [outer]: u2.id = u.id\n" +
				"      ├─Join [inner]: u.id = p.owner_id\n" +
				"      │ ├─Scan Table [alias=\"u\"]: users [physical]\n" +
				"      │ └─Scan Table [alias=\"p\"]: posts [physical]\n" +
				"      └─Scan Subquery [alias=\"u2\"]: [subplan_id=0] (uncorrelated)\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: users.id\n" +
				"  └─Filter: users.age > 18\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "basic inline window",
			sql:  "select name, sum(age) over (partition by name) from users",
			wt: "Return: name [text], sum [numeric(1000,0)]\n" +
				"└─Project: users.name; {#ref(A)}\n" +
				"  └─Window [partition_by=users.name]: {#ref(A) = sum(users.age)}\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "named window used several times",
			sql:  "select name, sum(age) over w1, array_agg(name) over w1 from users window w1 as (partition by name order by age)",
			wt: "Return: name [text], sum [numeric(1000,0)], array_agg [text[]]\n" +
				"└─Project: users.name; {#ref(A)}; {#ref(B)}\n" +
				"  └─Window [partition_by=users.name] [order_by=users.age asc nulls last]: {#ref(A) = sum(users.age)}; {#ref(B) = array_agg(users.name)}\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "window ordering",
			sql:  "select name, sum(age) over (partition by name order by age desc) from users",
			wt: "Return: name [text], sum [numeric(1000,0)]\n" +
				"└─Project: users.name; {#ref(A)}\n" +
				"  └─Sort: 1 asc nulls last; 2 asc nulls last\n" +
				"    └─Window [partition_by=users.name] [order_by=users.age desc nulls last]: {#ref(A) = sum(users.age)}\n" +
				"      └─Scan Table: users [physical]\n",
			defaultOrdering: true,
		},
		{
			name: "common table expressions",
			sql: `with a (id2, name2) as (select id, name from users),
					b as (select * from a)
					select * from b;`,
			wt: "Return: id2 [uuid], name2 [text]\n" +
				"└─Project: b.id2; b.name2\n" +
				"  └─Scan Table: b [cte]\n" +
				"Subplan [cte] [id=b] [a.id2 -> id2] [a.name2 -> name2]\n" +
				"└─Project: a.id2; a.name2\n" +
				"  └─Scan Table: a [cte]\n" +
				"Subplan [cte] [id=a] [users.id -> id2] [users.name -> name2]\n" +
				"└─Project: users.id; users.name\n" +
				"  └─Scan Table: users [physical]\n",
		},
		{
			name: "set operations",
			sql: `select id, name from users
					union
					select id, name from users
					union all
					select id, name from users
					intersect
					select id, name from users
					except
					select id, name from users;`,
			wt: "Return: id [uuid], name [text]\n" +
				"└─Set: except\n" +
				"  ├─Set: intersect\n" +
				"  │ ├─Set: union all\n" +
				"  │ │ ├─Set: union\n" +
				"  │ │ │ ├─Project: users.id; users.name\n" +
				"  │ │ │ │ └─Scan Table: users [physical]\n" +
				"  │ │ │ └─Project: users.id; users.name\n" +
				"  │ │ │   └─Scan Table: users [physical]\n" +
				"  │ │ └─Project: users.id; users.name\n" +
				"  │ │   └─Scan Table: users [physical]\n" +
				"  │ └─Project: users.id; users.name\n" +
				"  │   └─Scan Table: users [physical]\n" +
				"  └─Project: users.id; users.name\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "incompatible set schema types",
			sql: `select id, name from users
					union
					select id, owner_id from posts;`,
			err: logical.ErrSetIncompatibleSchemas,
		},
		{
			name: "incompatible set schema lengths",
			sql: `select id, name from users
					union
					select 1;`,
			err: logical.ErrSetIncompatibleSchemas,
		},
		{
			name: "set operations with order by and limit",
			sql: `select id, name from users
					union
					select id, content from posts
					order by name desc;`,
			wt: "Return: id [uuid], name [text]\n" +
				"└─Sort: name desc nulls last\n" +
				"  └─Set: union\n" +
				"    ├─Project: users.id; users.name\n" +
				"    │ └─Scan Table: users [physical]\n" +
				"    └─Project: posts.id; posts.content\n" +
				"      └─Scan Table: posts [physical]\n",
		},
		{
			name: "sort",
			sql:  "select name, age from users order by name desc nulls last, id asc",
			wt: "Return: name [text], age [int8]\n" +
				"└─Project: users.name; users.age\n" +
				"  └─Sort: users.name desc nulls last; users.id asc nulls last\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "sort with group by",
			sql:  "select name, sum(age) from users group by name order by name, sum(age)",
			wt: "Return: name [text], sum [numeric(1000,0)]\n" +
				"└─Project: {#ref(A)}; {#ref(B)}\n" +
				"  └─Sort: {#ref(A)} asc nulls last; {#ref(B)} asc nulls last\n" +
				"    └─Aggregate [{#ref(A) = users.name}]: {#ref(B) = sum(users.age)}\n" +
				"      └─Scan Table: users [physical]\n",
		},
		{
			// unlike the above, this tests that we can make new aggregate references from the ORDER BY clause
			name: "sort with aggregate",
			sql:  "select name from users group by name order by sum(age)",
			wt: "Return: name [text]\n" +
				"└─Project: {#ref(A)}\n" +
				"  └─Sort: {#ref(B)} asc nulls last\n" +
				"    └─Aggregate [{#ref(A) = users.name}]: {#ref(B) = sum(users.age)}\n" +
				"      └─Scan Table: users [physical]\n",
		},
		{
			name: "sort invalid column",
			sql:  "select name, age from users order by wallet",
			err:  logical.ErrColumnNotFound,
		},
		{
			name: "limit and offset",
			sql:  "select name, age from users limit 10 offset 5",
			wt: "Return: name [text], age [int8]\n" +
				"└─Project: users.name; users.age\n" +
				"  └─Limit [offset=5]: 10\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "distinct",
			sql:  "select distinct name, age from users",
			wt: "Return: name [text], age [int8]\n" +
				"└─Distinct\n" +
				"  └─Project: users.name; users.age\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "distinct aggregate",
			sql:  "select count(distinct name), sum(age) from users",
			wt: "Return: count [int8], sum [numeric(1000,0)]\n" +
				"└─Project: {#ref(A)}; {#ref(B)}\n" +
				"  └─Aggregate: {#ref(A) = count(distinct users.name)}; {#ref(B) = sum(users.age)}\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "unary and alias",
			sql:  "select age as pos_age, -age from users",
			wt: "Return: pos_age [int8], ?column? [int8]\n" +
				"└─Project: users.age AS pos_age; -users.age\n" +
				"  └─Scan Table: users [physical]\n",
		},
		{
			name: "order by alias",
			sql:  "select age as pos_age from users order by pos_age",
			wt: "Return: pos_age [int8]\n" +
				"└─Project: users.age AS pos_age\n" +
				"  └─Sort: pos_age asc nulls last\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "collate",
			sql:  "select name collate nocase from users where name = 'SATOSHI' collate nocase",
			wt: "Return: name [text]\n" +
				"└─Project: users.name COLLATE nocase\n" +
				"  └─Filter: users.name = 'SATOSHI' COLLATE nocase\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "in",
			sql:  "select name from users where name not in ('satoshi', 'wendys_drive_through_lady')",
			wt: "Return: name [text]\n" +
				"└─Project: users.name\n" +
				// planner rewrites NOT IN to a unary NOT(IN) for simplicity, since it's equivalent
				"  └─Filter: NOT users.name IN ('satoshi', 'wendys_drive_through_lady')\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "like and ilike",
			// planner rewrites NOT LIKE/ILIKE to unary NOT(LIKE/ILIKE) for simplicity
			sql: "select name from users where name like 's%' or name not ilike 'w_Nd%'",
			wt: "Return: name [text]\n" +
				"└─Project: users.name\n" +
				"  └─Filter: users.name LIKE 's%' OR NOT users.name ILIKE 'w_Nd%'\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "case",
			sql:  `select name from users where case age when 20 then true else false end`,
			wt: "Return: name [text]\n" +
				"└─Project: users.name\n" +
				"  └─Filter: CASE [users.age] WHEN [20] THEN [true] ELSE [false] END\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "case (no expression)",
			sql:  `select name from users where case when age = 20 then true else false end`,
			wt: "Return: name [text]\n" +
				"└─Project: users.name\n" +
				"  └─Filter: CASE WHEN [users.age = 20] THEN [true] ELSE [false] END\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			name: "basic update",
			sql:  "update users set name = 'satoshi' where age = 1",
			wt: "Update [users]: name = 'satoshi'\n" +
				"└─Filter: users.age = 1\n" +
				"  └─Scan Table: users [physical]\n",
		},
		{
			name: "update from with join",
			sql: `update users set name = pu.content from posts p inner join (
				select p.content from posts p
			inner join users u on p.owner_id = u.id
			where u.name = 'satoshi'
			) pu on p.content = pu.content where p.owner_id = users.id`,
			// will be unoptimized, so it will use a cartesian product
			// optimization could re-write the filter to a join, as well as
			// add projections.
			wt: "Update [users]: name = pu.content\n" +
				"└─Filter: p.owner_id = users.id\n" +
				"  └─Cartesian Product\n" +
				"    ├─Scan Table: users [physical]\n" +
				"    └─Join [inner]: p.content = pu.content\n" +
				"      ├─Scan Table [alias=\"p\"]: posts [physical]\n" +
				"      └─Scan Subquery [alias=\"pu\"]: [subplan_id=0] (uncorrelated)\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: p.content\n" +
				"  └─Filter: u.name = 'satoshi'\n" +
				"    └─Join [inner]: p.owner_id = u.id\n" +
				"      ├─Scan Table [alias=\"p\"]: posts [physical]\n" +
				"      └─Scan Table [alias=\"u\"]: users [physical]\n",
		},
		{
			name: "update with from without where",
			sql:  "update users set name = pu.content from posts pu",
			err:  logical.ErrUpdateOrDeleteWithoutWhere,
		},
		{
			name: "basic delete",
			sql:  "delete from users where age = 1",
			wt: "Delete [users]\n" +
				"└─Filter: users.age = 1\n" +
				"  └─Scan Table: users [physical]\n",
		},
		{
			name: "insert",
			sql:  "insert into users values ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1), ('123e4567-e89b-12d3-a456-426614174001'::uuid, 'satoshi2', 2)",
			wt: "Insert [users]: id [uuid], name [text], age [int8]\n" +
				"└─Values: ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1); ('123e4567-e89b-12d3-a456-426614174001'::uuid, 'satoshi2', 2)\n",
		},
		{
			name: "insert with null",
			sql:  "insert into users (id, name) values ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi')",
			wt: "Insert [users]: id [uuid], name [text], age [int8]\n" +
				"└─Values: ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', NULL)\n",
		},
		{
			name: "insert null in non-nullable column",
			sql:  "insert into users (name) values ('satoshi')",
			err:  logical.ErrNotNullableColumn,
		},
		{
			name: "on conflict do nothing",
			sql:  "insert into users values ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1) on conflict do nothing",
			wt: "Insert [users]: id [uuid], name [text], age [int8]\n" +
				"├─Values: ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1)\n" +
				"└─Conflict [nothing]\n",
		},
		{
			name: "on conflict do update (arbiter index primary key)",
			sql:  "insert into users values ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1) on conflict (id) do update set name = 'satoshi'",
			wt: "Insert [users]: id [uuid], name [text], age [int8]\n" +
				"├─Values: ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1)\n" +
				"└─Conflict [update] [arbiter=users.id (primary key)]: [name = 'satoshi']\n",
		},
		{
			name: "on conflict do update (arbiter unique constraint)",
			sql:  "insert into posts values ('123e4567-e89b-12d3-a456-426614174000'::uuid, '123e4567-e89b-12d3-a456-426614174001'::uuid, 'hello', 1) on conflict (content) do update set owner_id = '123e4567-e89b-12d3-a456-426614174001'::uuid",
			wt: "Insert [posts]: id [uuid], owner_id [uuid], content [text], created_at [int8]\n" +
				"├─Values: ('123e4567-e89b-12d3-a456-426614174000'::uuid, '123e4567-e89b-12d3-a456-426614174001'::uuid, 'hello', 1)\n" +
				"└─Conflict [update] [arbiter=posts.content (unique)]: [owner_id = '123e4567-e89b-12d3-a456-426614174001'::uuid]\n",
		},
		{
			name: "on conflict do update (arbiter index non-primary key)",
			sql:  "insert into users values ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1) on conflict (name) do update set name = 'satoshi' WHERE users.age = 1",
			wt: "Insert [users]: id [uuid], name [text], age [int8]\n" +
				"├─Values: ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1)\n" +
				"└─Conflict [update] [arbiter=name_idx (index)]: [name = 'satoshi'] where [users.age = 1]\n",
		},
		{
			name: "on conflict with non-arbiter column",
			sql:  "insert into users values ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1) on conflict (age) do update set name = 'satoshi'",
			err:  logical.ErrIllegalConflictArbiter,
		},
		{
			name: "on conflict with half of a composite index",
			sql:  "insert into posts values ('123e4567-e89b-12d3-a456-426614174000'::uuid, '123e4567-e89b-12d3-a456-426614174001'::uuid, 'hello', 1) on conflict (owner_id) do update set content = 'hello'",
			err:  logical.ErrIllegalConflictArbiter,
		},
		{
			name: "on conflict with non-unique index",
			sql:  "insert into users values ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1) on conflict (age) do update set name = 'satoshi'",
			err:  logical.ErrIllegalConflictArbiter,
		},
		{
			name: "conflict on composite unique index",
			sql:  "insert into posts values ('123e4567-e89b-12d3-a456-426614174000'::uuid, '123e4567-e89b-12d3-a456-426614174001'::uuid, 'hello', 1) on conflict (owner_id, created_at) do update set content = 'hello'",
			wt: "Insert [posts]: id [uuid], owner_id [uuid], content [text], created_at [int8]\n" +
				"├─Values: ('123e4567-e89b-12d3-a456-426614174000'::uuid, '123e4567-e89b-12d3-a456-426614174001'::uuid, 'hello', 1)\n" +
				"└─Conflict [update] [arbiter=owner_created_idx (index)]: [content = 'hello']\n",
		},
		{
			name: "excluded clause",
			sql:  "insert into users (id, name) values ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi') on conflict (id) do update set name = excluded.name where (excluded.age/2) = 0",
			wt: "Insert [users]: id [uuid], name [text], age [int8]\n" +
				"├─Values: ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', NULL)\n" +
				"└─Conflict [update] [arbiter=users.id (primary key)]: [name = excluded.name] where [excluded.age / 2 = 0]\n",
		},
		{
			// surprisingly, this mirrors Postgres's behavior
			name: "ambiguous column due to excluded",
			sql:  "insert into users values ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', 1) on conflict (name) do update set name = 'satoshi' WHERE age = 1",
			err:  logical.ErrAmbiguousColumn,
		},
		{
			name: "insert with select",
			sql:  "insert into users select * from users",
			wt: "Insert [users]: id [uuid], name [text], age [int8]\n" +
				"└─Project: users.id; users.name; users.age\n" +
				"  └─Scan Table: users [physical]\n",
		},
		{
			name: "recursive CTE",
			sql: `with recursive r as (
					select 1 as n
					union all
					select n+1 from r where n < 10
				)
				select * from r;`,
			wt: "Return: n [int8]\n" +
				"└─Project: r.n\n" +
				"  └─Scan Table: r [cte]\n" +
				"Subplan [recursive cte] [id=r] [r.n -> n]\n" +
				"└─Set: union all\n" +
				"  ├─Project: 1 AS n\n" +
				"  │ └─Empty Scan\n" +
				"  └─Project: r.n + 1\n" +
				"    └─Filter: r.n < 10\n" +
				"      └─Scan Table: r [cte]\n",
		},
		{
			// this caused a nil pointer dereference.
			// It is an illegal query, but it should not crash the planner.
			name: "inserting a cte",
			sql: `with a as (select 1)
				INSERT INTO users VALUES ('123e4567-e89b-12d3-a456-426614174000'::uuid, 'satoshi', a)`,
			err: logical.ErrColumnNotFound,
		},
		{
			// this is a regression test for a previous uncaught type case
			name: "subquery type cast",
			sql:  `select * from users where age = (select sum(age) from users)::int8`,
			wt: "Return: id [uuid], name [text], age [int8]\n" +
				"└─Project: users.id; users.name; users.age\n" +
				"  └─Filter: users.age = [subquery (scalar) (subplan_id=0) (uncorrelated)]::int8\n" +
				"    └─Scan Table: users [physical]\n" +
				"Subplan [subquery] [id=0]\n" +
				"└─Project: {#ref(A)}\n" +
				"  └─Aggregate: {#ref(A) = sum(users.age)}\n" +
				"    └─Scan Table: users [physical]\n",
		},
		{
			// regression test for a previous case where an update
			// without a FROM and WHERE panicked because it did not
			// use the target table as a reference-able source table.
			name: "update without where",
			sql:  "update users set age = age + 1",
			wt: "Update [users]: age = users.age + 1\n" +
				"└─Scan Table: users [physical]\n",
		},
		{
			name: "on conflict to composite primary key, but one referenced column does not exist",
			sql:  "insert into follows values ('123e4567-e89b-12d3-a456-426614174000'::uuid, '123e4567-e89b-12d3-a456-426614174001'::uuid) on conflict (follower_id, id) do nothing",
			err:  logical.ErrColumnNotFound,
		},
		{
			name: "use action in query",
			sql:  "select my_act()",
			actions: map[string]struct{}{
				"my_act": {},
			},
			err: logical.ErrActionInSQLStmt,
		},
		{
			name: "select empty array",
			sql:  "select array[]",
			err:  logical.ErrUntypedEmptyArray,
		},
		{
			name: "select empty array with type",
			sql:  "select array[]::int[]",
			wt: "Return: ?column? [int8[]]\n" +
				"└─Project: []::int8\n" +
				"  └─Empty Scan\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsedSql, err := parse.Parse(test.sql)
			require.NoError(t, err)
			require.Len(t, parsedSql, 1)

			sqlPlan, ok := parsedSql[0].(*parse.SQLStatement)
			require.True(t, ok)

			plan, err := logical.CreateLogicalPlan(sqlPlan,
				func(namespace, tableName string) (table *engine.Table, err error) {
					table, found := testTables[tableName]

					if !found {
						return nil, fmt.Errorf("table %s not found", tableName)
					}

					return table, nil
				},
				func(varName string) (dataType *types.DataType, err error) {
					dataType, found := test.vars[varName]
					if !found {
						return nil, engine.ErrUnknownVariable
					}

					return dataType, nil
				},
				func(objName string) (obj map[string]*types.DataType, err error) {
					obj, ok := test.objects[objName]
					if !ok {
						return nil, engine.ErrUnknownVariable
					}

					return obj, nil
				},
				func(fn string) bool {
					if test.actions == nil {
						return false
					}
					_, ok := test.actions[fn]
					return ok
				},
				test.defaultOrdering, "")
			if test.err != nil {
				require.Error(t, err)

				// special case for testing
				if errors.Is(test.err, errAny) {
					return
				}

				require.ErrorIs(t, err, test.err)
			} else {
				require.NoError(t, err)

				if plan.Format() != test.wt {
					fmt.Println(test.name)
					fmt.Println("Expected:")
					fmt.Println(test.wt)
					fmt.Println("----")
					fmt.Println("Received:")
					fmt.Println(plan.Format())
				}

				require.Equal(t, test.wt, plan.Format())

				// check that Relation() works
				plan.Plan.Relation()

				for _, cte := range plan.CTEs {
					cte.Relation()
				}

				// make sure nothing changed
				require.Equal(t, test.wt, plan.Format())
			}
		})
	}
}

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
	"follows": {
		Name: "follows",
		Columns: []*engine.Column{
			{
				Name:         "follower_id",
				DataType:     types.UUIDType,
				IsPrimaryKey: true,
			},
			{
				Name:         "followee_id",
				DataType:     types.UUIDType,
				IsPrimaryKey: true,
			},
		},
	},
}

// special error for testing that will match any error
var errAny = errors.New("any error")
