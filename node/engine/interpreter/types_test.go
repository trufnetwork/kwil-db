//go:build pglive

package interpreter

import (
	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

// mustParse is a helper function to parse an action and panic on error.
func mustParse(s string) *action {
	res, err := parse.Parse(s)
	if err != nil {
		panic(err)
	}

	act := action{}
	err = act.FromAST(res[0].(*parse.CreateActionStatement))
	if err != nil {
		panic(err)
	}

	return &act
}

// actions
var (
	all_test_actions = []*action{
		action_create_user,
		action_list_users,
		action_get_user_by_name,
	}
	action_create_user = mustParse(`CREATE ACTION create_user ($name TEXT, $age INT) public {
			INSERT INTO users (id, name, age)
			VALUES (
				uuid_generate_v5('c7b6a54c-392c-48f9-803d-31cb97e76052'::uuid, @txid),
				$name,
				$age
			);
		};`)

	action_list_users = mustParse(`CREATE ACTION list_users () public view owner {
			RETURN SELECT id, name, age
			FROM users;
		};`)

	action_get_user_by_name = mustParse(`CREATE ACTION get_user_by_name ($name TEXT) public view {
			FOR $row IN SELECT id, age
			FROM users
			WHERE name = $name {
				RETURN $row.id, $row.age;
			}
		};`)
)
