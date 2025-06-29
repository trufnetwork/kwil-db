package acceptance

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	ctypes "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/test"
	"github.com/trufnetwork/kwil-db/test/setup"
)

// TODO:
// - log / "notice()" tests

var dev = flag.Bool("dev", false, "run for development purpose (no tests)")
var withKGW = flag.Bool("kgw", false, "test with kgw")

func TestLocalDevSetup(t *testing.T) {
	if !*dev {
		t.Skip("skipping local dev setup")
	}

	// running forever for local development
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		t.Log("interrupt received, shutting down")
		cancel()
	}()

	client := setupSingleNodeClient(t, ctx, setup.Go, *withKGW)
	ci, err := client.ChainInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ci)

	// deploy a schema for convenience
	tx, err := client.ExecuteSQL(ctx, usersSchema, nil, opts)
	require.NoError(t, err)
	test.ExpectTxSuccess(t, client, ctx, tx)

	<-ctx.Done()
}

var (
	//go:embed users.sql
	usersSchema  string
	UserPrivkey1 = func() *crypto.Secp256k1PrivateKey {
		privk, err := crypto.Secp256k1PrivateKeyFromHex("f1aa5a7966c3863ccde3047f6a1e266cdc0c76b399e256b8fede92b1c69e4f4e")
		if err != nil {
			panic(err)
		}
		return privk
	}()

	kgwSvc = &setup.CustomService{
		ServiceName:  "kgw",
		DockerImage:  "kgw:latest",
		Command:      `--log-level debug --log-outputs stdout --cors-allow-origins * --backends node0:8484 node1:8484 --domain http://localhost:8090 --statement 'Trust me ok?' --session-secret 'kgwtest' --chain-id kwil-testnet --allow-adhoc-query --devmode`,
		ExposedPort:  "8090",
		InternalPort: "8090",
		ServiceProto: "http",
		WaitMsg:      "KGW Server started",
		DependsOn:    "node0",
	}
)

// setupSingleNodeClient creates a single node network for testing, and returns the client.
// If useKGW=true, a KGW node will be created, the returned client will talk to KGW instead of the kwild node.
func setupSingleNodeClient(t *testing.T, ctx context.Context, d setup.ClientDriver, useKGW bool) setup.JSONRPCClient {
	t.Helper()

	signer := auth.GetUserSigner(UserPrivkey1)
	ident, err := auth.EthSecp256k1Authenticator{}.Identifier(signer.CompactID())
	require.NoError(t, err)

	var extraServices []*setup.CustomService

	if useKGW {
		extraServices = append(extraServices, kgwSvc)
	}

	testnet := setup.SetupTests(t, &setup.TestConfig{
		ClientDriver: d,
		Network: &setup.NetworkConfig{
			DBOwner: ident,
			Nodes: []*setup.NodeConfig{
				setup.DefaultNodeConfig(),
			},
			ExtraServices: extraServices,
		},
	})

	opts := &setup.ClientOptions{
		PrivateKey: UserPrivkey1,
	}

	kgwNode, ok := testnet.SearchExtraNode("kgw")
	if ok {
		opts.UsingKGW = true
		opts.Endpoint = kgwNode.ExposedChainRPC
	}

	return testnet.Nodes[0].JSONRPCClient(t, ctx, opts)
}

func Test_Transfer(t *testing.T) {
	ctx := context.Background()

	for _, driver := range setup.AllDrivers {
		t.Run("transfer_"+driver.String(), func(t *testing.T) {
			userPrivateKey, _, err := crypto.GenerateSecp256k1Key(nil)
			require.NoError(t, err)

			// helper function for getting the address of a private key
			address := func(p crypto.PrivateKey) types.HexBytes {
				secp, ok := p.(*crypto.Secp256k1PrivateKey)
				require.True(t, ok)

				return crypto.EthereumAddressFromPubKey(secp.Public().(*crypto.Secp256k1PublicKey))
			}

			stringAddress := func(p crypto.PrivateKey) string {
				addr := address(p)
				val, err := auth.EthSecp256k1Authenticator{}.Identifier(addr)
				require.NoError(t, err)
				return val
			}

			var extraServices []*setup.CustomService
			if *withKGW {
				extraServices = append(extraServices, kgwSvc)
			}

			testnet := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					ConfigureGenesis: func(gc *config.GenesisConfig) {
						gc.DisabledGasCosts = false

						// giving gas to the user
						gc.Allocs = append(gc.Allocs, config.GenesisAlloc{
							ID:      config.KeyHexBytes{HexBytes: address(userPrivateKey)},
							KeyType: crypto.KeyTypeSecp256k1.String(),
							Amount:  big.NewInt(1000000000000000000),
						})
					},
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(),
					},
					DBOwner:       stringAddress(userPrivateKey),
					ExtraServices: extraServices,
				},
			})

			cltOpts := &setup.ClientOptions{
				PrivateKey: userPrivateKey,
			}

			kgwNode, ok := testnet.SearchExtraNode("kgw")
			if ok {
				cltOpts.UsingKGW = true
				cltOpts.Endpoint = kgwNode.ExposedChainRPC
			}

			// user 1 will send funds to user 2. User 2 will check that they received the funds
			user1 := testnet.Nodes[0].JSONRPCClient(t, ctx, cltOpts)

			// user 1 creates an action, which user 2 will call to test they have funds
			tx, err := user1.ExecuteSQL(ctx, "CREATE ACTION do_something() public {}", nil, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, user1, ctx, tx)

			// auto-generate the private key for user 2
			user2 := testnet.Nodes[0].JSONRPCClient(t, ctx, nil)

			// user 2 tries to execute, gets rejected from mempool because no gas
			_, err = user2.Execute(ctx, "", "do_something", nil, opts)
			require.Error(t, err)
			require.Contains(t, err.Error(), "insufficient balance")

			tx, err = user1.Transfer(ctx, &types.AccountID{
				Identifier: address(user2.PrivateKey()),
				KeyType:    crypto.KeyTypeSecp256k1,
			}, big.NewInt(100000000000000000), opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, user1, ctx, tx)

			// user 2 tries to execute, works because they have gas
			tx, err = user2.Execute(ctx, "", "do_something", nil, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, user2, ctx, tx)
		})
	}
}

// In case we need "sync" broadcast for testing:
var opts = func(*ctypes.TxOptions) {} // ctypes.WithSyncBroadcast(true)

func Test_Engine(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run("engine_"+driver.String(), func(t *testing.T) {
			ctx := context.Background()
			client := setupSingleNodeClient(t, ctx, driver, *withKGW)

			// deploy the schema
			tx, err := client.ExecuteSQL(ctx, usersSchema, nil, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, client, ctx, tx)

			// create two profiles: satoshi and megatron
			tx, err = client.Execute(ctx, "", "create_profile", [][]any{
				{"satoshi", 32, "father of $btc"},
				{"megatron", 1000000, "leader of the decepticons"},
			}, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, client, ctx, tx)

			// create three posts, all responding to each other
			tx, err = client.Execute(ctx, "", "create_post", [][]any{
				{"satoshi", "hello world", nil},
			}, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, client, ctx, tx)

			satoshiPostUUID, err := getLatestPostID(ctx, client, "satoshi")
			require.NoError(t, err)

			tx, err = client.Execute(ctx, "", "create_post", [][]any{
				{"megatron", "hello satoshi", satoshiPostUUID},
			}, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, client, ctx, tx)

			megatronPostUUID, err := getLatestPostID(ctx, client, "megatron")
			require.NoError(t, err)

			tx, err = client.Execute(ctx, "", "create_post", [][]any{
				{"satoshi", "go back to cybertron", megatronPostUUID},
			}, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, client, ctx, tx)

			// testing recursive CTEs by getting the post chain
			res, err := client.Call(ctx, "", "get_thread", []any{satoshiPostUUID, 5})
			require.NoError(t, err)

			// 3 posts in the chain, and get_thread does not include the root post
			require.Len(t, res.QueryResult.Values, 2)

			assert.Equal(t, "hello satoshi", res.QueryResult.Values[0][1])
			assert.Equal(t, "go back to cybertron", res.QueryResult.Values[1][1])
		})
	}
}

// Test_Roundtrip tests roundtripping types through the database for both
// actions and regular SQL
func Test_Roundtrip(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run("roundtrip_"+driver.String(), func(t *testing.T) {
			ctx := context.Background()
			client := setupSingleNodeClient(t, ctx, driver, *withKGW)

			// a table that stores all data types
			tx, err := client.ExecuteSQL(ctx, `
			CREATE TABLE data_types (
				id int PRIMARY KEY,
				-- text
				text_col TEXT,
				text_arr TEXT[],
				-- numbers
				int_col INT8,
				int_arr INT8[],
				num_col NUMERIC(100,50),
				num_arr NUMERIC(100,50)[],
				-- booleans
				bool_col BOOLEAN,
				bool_arr BOOLEAN[],
				-- bytes
				bytes_col BYTEA,
				bytes_arr BYTEA[],
				-- uuid
				uuid_col UUID,
				uuid_arr UUID[]
			);

			CREATE ACTION insert_data_types(
				$id int,
				$text_col TEXT,
				$text_arr TEXT[],
				$int_col INT8,
				$int_arr INT8[],
				$num_col NUMERIC(100,50),
				$num_arr NUMERIC(100,50)[],
				$bool_col BOOLEAN,
				$bool_arr BOOLEAN[],
				$bytes_col BYTEA,
				$bytes_arr BYTEA[],
				$uuid_col UUID,
				$uuid_arr UUID[]
			) public {
				INSERT INTO data_types (
					id, text_col, text_arr, int_col, int_arr, num_col, num_arr, bool_col, bool_arr, bytes_col, bytes_arr, uuid_col, uuid_arr
				) VALUES (
				 	$id, $text_col, $text_arr, $int_col, $int_arr, $num_col, $num_arr, $bool_col, $bool_arr, $bytes_col, $bytes_arr, $uuid_col, $uuid_arr
				);
			};
			`, nil, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, client, ctx, tx)

			textVal := "hello world"
			textArrVal := []*string{p("hello"), p("world"), nil}
			intVal := int64(math.MaxInt64)
			intArrVal := []*int64{p(intVal), p(intVal + 1), nil}
			boolVal := true
			boolArrVal := []*bool{p(boolVal), p(!boolVal), nil}
			bytesVal := []byte{0x01, 0x02, 0x03}
			bytesArrVal := []*[]byte{&bytesVal, nil}
			uuidVal := *types.NewUUIDV5([]byte{0x01, 0x02, 0x03})
			uuidArrVal := []*types.UUID{&uuidVal, nil}
			numeric := *types.MustParseDecimalExplicit("100.5", 100, 50)
			numericArr := []*types.Decimal{&numeric, nil}

			// assureEqual assures that the given id rows are equal to the expected values
			assureEqual := func(t *testing.T, id int) {
				var outID int
				var outText string
				var outTextArr []*string
				var outInt int64
				var outIntArr []*int64
				var outNum types.Decimal
				var outNumArr []*types.Decimal
				var outBool bool
				var outBoolArr []*bool
				var outBytes []byte
				var outBytesArr []*[]byte
				var outUUID types.UUID
				var outUUIDArr []*types.UUID

				res, err := client.Query(ctx, `SELECT * FROM data_types WHERE id = $id`, map[string]any{
					"id": id,
				}, true)
				require.NoError(t, err)
				err = res.Scan(func() error { return nil }, &outID, &outText, &outTextArr, &outInt, &outIntArr, &outNum, &outNumArr, &outBool, &outBoolArr, &outBytes, &outBytesArr, &outUUID, &outUUIDArr)
				require.NoError(t, err)

				// since json does not fully preserve precision and scale info for decimals, we need to enforce it and then compare manually
				err = outNum.SetPrecisionAndScale(100, 50)
				require.NoError(t, err)
				decimalsAreEqual(t, &numeric, &outNum)

				// types.DecimalCmp()

				for i, num := range outNumArr {
					if num == nil {
						assert.Nil(t, numericArr[i])
						continue
					}
					err = num.SetPrecisionAndScale(100, 50)
					require.NoError(t, err)

					decimalsAreEqual(t, numericArr[i], num)
				}

				assert.EqualValues(t, id, outID)
				assert.EqualValues(t, textVal, outText)
				assert.EqualValues(t, textArrVal, outTextArr)
				assert.EqualValues(t, intVal, outInt)
				assert.EqualValues(t, intArrVal, outIntArr)
				assert.EqualValues(t, boolVal, outBool)
				assert.EqualValues(t, boolArrVal, outBoolArr)
				assert.EqualValues(t, bytesVal, outBytes)
				assert.EqualValues(t, bytesArrVal, outBytesArr)
				assert.EqualValues(t, uuidVal, outUUID)
				assert.EqualValues(t, uuidArrVal, outUUIDArr)
			}

			// insert using INSERT
			tx, err = client.ExecuteSQL(ctx, `
			INSERT INTO data_types (
				id, text_col, text_arr, int_col, int_arr, num_col, num_arr, bool_col, bool_arr, bytes_col, bytes_arr, uuid_col, uuid_arr
			) VALUES (
			 	$id, $text_col, $text_arr, $int_col, $int_arr, $num_col, $num_arr, $bool_col, $bool_arr, $bytes_col, $bytes_arr, $uuid_col, $uuid_arr
			);
			`, map[string]any{
				"id":        1,
				"text_col":  textVal,
				"text_arr":  textArrVal,
				"int_col":   intVal,
				"int_arr":   intArrVal,
				"num_col":   numeric,
				"num_arr":   numericArr,
				"bool_col":  boolVal,
				"bool_arr":  boolArrVal,
				"bytes_col": bytesVal,
				"bytes_arr": bytesArrVal,
				"uuid_col":  uuidVal,
				"uuid_arr":  uuidArrVal,
			}, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, client, ctx, tx)
			assureEqual(t, 1)

			// insert using action
			tx, err = client.Execute(ctx, "", "insert_data_types", [][]any{
				{2, textVal, textArrVal, intVal, intArrVal, numeric, numericArr, boolVal, boolArrVal, bytesVal, bytesArrVal, uuidVal, uuidArrVal},
			}, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, client, ctx, tx)

			assureEqual(t, 2)
		})
	}
}

// Test_Notice tests that Kwil properly handles NOTICE messages
func Test_Notice(t *testing.T) {
	expectedErrMsg := `custom error`
	expectedCallLogs := `1. hello world`
	// the tx execution result adds any error encountered as the final log.
	// Call split them.
	expectedTxLogs := expectedCallLogs + "\nERROR: " + expectedErrMsg

	for _, driver := range setup.AllDrivers {
		t.Run("notice_"+driver.String(), func(t *testing.T) {
			ctx := context.Background()
			client := setupSingleNodeClient(t, ctx, driver, *withKGW)

			tx, err := client.ExecuteSQL(ctx, `
			CREATE ACTION notice_test() public view {
				NOTICE('hello world');
				ERROR('custom error');
			}
			`, nil, opts)
			require.NoError(t, err)
			test.ExpectTxSuccess(t, client, ctx, tx)

			// we will both execute it against consensus and call

			// first, execute it against consensus
			tx, err = client.Execute(ctx, "", "notice_test", nil, opts)
			require.NoError(t, err)
			test.ExpectTxError(t, client, ctx, tx, "custom error")

			txRes, err := client.TxQuery(ctx, tx)
			require.NoError(t, err)

			require.Equal(t, expectedTxLogs, txRes.Result.Log)

			// then, call it
			res, err := client.Call(ctx, "", "notice_test", nil)
			require.NoError(t, err)
			require.NotNil(t, res.Error)
			require.Equal(t, expectedErrMsg, *res.Error)
			require.Equal(t, expectedCallLogs, res.Logs)
		})
	}
}

// p makes a pointer to a value
func p[T any](v T) *T {
	return &v
}

// getLatestPostID returns the latest post from a user
func getLatestPostID(ctx context.Context, client setup.JSONRPCClient, user string) (id *types.UUID, err error) {
	res, err := client.Call(ctx, "", "get_posts", []any{user})
	if err != nil {
		return nil, err
	}

	if len(res.QueryResult.Values) == 0 {
		return nil, fmt.Errorf("no posts found for user %s", user)
	}

	str, ok := res.QueryResult.Values[0][0].(string)
	if !ok {
		return nil, fmt.Errorf("unexpected type for post ID: %T", res.QueryResult.Values[0][0])
	}

	return types.ParseUUID(str)
}

func decimalsAreEqual(t *testing.T, a, b *types.Decimal) {
	if a == nil && b == nil {
		return
	}
	if a == nil || b == nil {
		assert.Fail(t, "one of the decimals is nil")
	}
	require.NotNil(t, a)
	require.NotNil(t, b)

	c, err := types.DecimalCmp(a, b)
	require.NoError(t, err)

	assert.Equal(t, int64(0), c)
}
