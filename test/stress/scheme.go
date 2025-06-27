package main

// This embeds the toy schema required by the test harness.

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/trufnetwork/kwil-db/core/types"
)

//go:embed users_template.sql
var testSchemaTemplate string

// These are the actions currently used by the harness.
const (
	actGetPost           = "get_thread"           // get_thread($post_id UUID, $max_depth int) public view returns table(post_id UUID, content TEXT, created_at INT, author TEXT, likes INT, children UUID[], depth INT)
	actCreatePost        = "create_post"          // create_post($username TEXT, $content TEXT, $parent_id UUID) public returns (UUID)
	actCreateUser        = "create_profile"       // create_profile($username TEXT, $age INT, $bio TEXT) public
	actGetMyProfileID    = "get_my_profile_id"    // get_ny_profile_id($username TEXT) public view returns (UUID)
	actGetMyUsernames    = "get_my_usernames"     // get_my_usernames() public view returns table(username TEXT)
	actGetUserPosts      = "get_posts"            // get_posts($username TEXT) public view returns table(post_id UUID, content TEXT, created_at INT, likes INT)
	actGetLatestUserPost = "get_latest_user_post" // get_latest_user_post($username TEXT) public view returns table(post_id UUID, content TEXT, created_at INT)
	// actListUsers      = "list_users"

	actAuthnOnly = "authn_only" // matters with KGW
)

// makeTestSchemaSQL creates a test schema from the template, using the provided namespace.
func makeTestSchemaSQL(namespace string) string {
	schema := strings.ReplaceAll(testSchemaTemplate, "{NAMESPACE}", "{"+namespace+"}")
	return `CREATE NAMESPACE IF NOT EXISTS ` + namespace + ";\n" + schema
}

func init() {
	// Consistency check the embedded schema
	_ = makeTestSchemaSQL("a")
	// would have to use engine interpreter...
	// haveActions := make(map[string]bool, len(schema.Actions))
	// for _, act := range schema.Actions {
	// 	haveActions[act.Name] = true
	// }
	// for _, expected := range []string{actGetPost, actCreatePost, actCreateUser,
	// 	actListUsers, actGetUserPosts, actAuthnOnly} {
	// 	if !haveActions[expected] {
	// 		panic(fmt.Sprintf("missing action %v", expected))
	// 	}
	// }
	// testSchema = schema
}

type actSchemaClient struct {
	h         *harness
	username  string
	namespace string
	schemaSQL string
}

func newActSchemaClient(h *harness, namespace string) *actSchemaClient {
	schemaSQL := makeTestSchemaSQL(namespace)
	return &actSchemaClient{
		h: h,
		// username:  username,
		namespace: namespace,
		schemaSQL: schemaSQL,
	}
}

func (asc *actSchemaClient) deployDB(ctx context.Context) error {
	return asc.h.deployDB(ctx, asc.schemaSQL)
}

// func (asc *actSchemaClient) deployDBAsync(ctx context.Context) (<-chan asyncResp, error) {
// 	return asc.h.deployDBAsync(ctx, asc.schemaSQL)
// }

func (asc *actSchemaClient) getOrCreateUserProfile(ctx context.Context, namespace string) error {
	const molAge int = 42

	h := asc.h

	if asc.username == "" { // try to find an existing user name of ours
		res, err := h.Call(ctx, namespace, actGetMyUsernames, nil)
		if err != nil {
			return fmt.Errorf("%s: %w", actGetMyUsernames, err)
		}
		for _, row := range res.QueryResult.Values {
			if len(row) == 0 {
				continue
			}
			username := row[0].(string)
			if username != "" {
				asc.username = username
				h.printf("Found me in list_users: %v", asc.username)
				return nil
			}
		}
		// boo, we didn't have a user name
		asc.username = fmt.Sprintf("user_%v", rand.Intn(10000000))
	}

	err := h.execute(ctx, namespace, actCreateUser, [][]any{{asc.username, molAge, "just a kwil user"}})
	if err != nil {
		return fmt.Errorf("%s: %w", actCreateUser, err)
	}
	res, err := h.Call(ctx, namespace, actGetMyProfileID, []any{asc.username})
	if err != nil {
		return fmt.Errorf("%s: %w", actGetMyProfileID, err)
	}
	vals := res.QueryResult.Values
	if len(vals) == 0 || len(vals[0]) == 0 {
		return fmt.Errorf("no user UUID returned")
	}
	userUUID, err := types.ParseUUID(vals[0][0].(string))
	if err != nil {
		return fmt.Errorf("failed to parse UUID: %w", err)
	}
	h.printf("Added me to users table: %v / %v", userUUID, asc.username)

	return nil
}

func (asc *actSchemaClient) lastPostID(ctx context.Context, namespace string) (*types.UUID, error) {
	h := asc.h
	res, err := h.Call(ctx, namespace, actGetLatestUserPost, []any{asc.username})
	// res, err := h.Call(ctx, namespace, actGetUserPosts, []any{user}) // tuples for the Schema.Actions[i].Inputs
	if err != nil {
		return nil, fmt.Errorf("get_user_posts_by_userid: %w", err)
	}
	h.printRecs(res.QueryResult)

	if len(res.QueryResult.Values) == 0 {
		return nil, nil
		// return nil, fmt.Errorf("no posts found for user %s", user)
	}

	str, ok := res.QueryResult.Values[0][0].(string)
	if !ok {
		return nil, fmt.Errorf("unexpected type for post ID: %T", res.QueryResult.Values[0][0])
	}

	return types.ParseUUID(str)
}

var ErrExpected = errors.New("expected")

func (asc *actSchemaClient) createPostAsync(ctx context.Context, namespace string, content string) (<-chan asyncResp, error) {
	h := asc.h
	args := [][]any{{asc.username, content, nil}}
	// Randomly fail execution. TODO: make frequency flag, like execFailRate,
	// but we really don't need it to succeed, only be mined. The failures
	// ensure expected nonce and balance updates regardless.
	var expectFail bool
	if !noErrActs && rand.Intn(6) == 0 {
		if rand.Intn(2) == 0 {
			// kwild.abci: "msg":"failed to execute transaction","error":"ERROR: invalid input syntax for type bigint: \"not integer\" (SQLSTATE 22P02)"
			args = [][]any{{2, content, "not UUID"}} // id not integer (SQL exec error)
		} else {
			// kwild.abci: "msg":"failed to execute transaction","error":"incorrect number of arguments: procedure \"create_post\" requires 3 arguments, but 2 were provided"
			args = [][]any{{asc.username, content}} // too few args (engine procedure call error)
		}
	}
	txHash, err := h.executeAsync(ctx, namespace, actCreatePost, args)
	if err != nil {
		if expectFail {
			err = errors.Join(err, ErrExpected)
		}
		return nil, err
	}

	promise := make(chan asyncResp, 1)
	go func() {
		t0 := time.Now()
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		resp, err := h.WaitTx(ctx, txHash, txPollInterval)
		if err != nil {
			err = errors.Join(err, h.recoverNonce(ctx))
			promise <- asyncResp{err: err}
			return
		}

		h.printf("Created post (len %d), log = %q, waited %v", len(content), resp.Result.Log, time.Since(t0))
		promise <- asyncResp{res: resp.Result, expectFail: expectFail}
	}()
	return promise, nil
}
