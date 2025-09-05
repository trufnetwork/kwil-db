package acceptance

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/rpc/client/user/jsonrpc"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/test/setup"
)

// Test client private key - matches the DB owner setup
var testPrivkey1 = func() *crypto.Secp256k1PrivateKey {
	privk, err := crypto.Secp256k1PrivateKeyFromHex("f1aa5a7966c3863ccde3047f6a1e266cdc0c76b399e256b8fede92b1c69e4f4e")
	if err != nil {
		panic(err)
	}
	return privk
}()

// leaderCompactIDForAuthTest is a copy of the internal function for testing
func leaderCompactIDForAuthTest(proposer crypto.PublicKey, authType string) ([]byte, error) {
	if proposer == nil {
		return nil, nil
	}
	switch strings.ToLower(authType) {
	case "ed25519":
		// tx signer is an ed25519 pubkey (32B) → proposer must be ed25519
		if proposer.Type() != crypto.KeyTypeEd25519 {
			// cannot represent leader in this scheme
			return nil, nil
		}
		return proposer.Bytes(), nil
	case "secp256k1":
		// tx signer is a compressed secp256k1 pubkey (33B)
		if proposer.Type() != crypto.KeyTypeSecp256k1 {
			return nil, nil
		}
		return proposer.Bytes(), nil // compressed
	case "secp256k1_ep":
		// tx signer is a 20B Ethereum address derived from secp256k1 pubkey
		if proposer.Type() != crypto.KeyTypeSecp256k1 {
			return nil, nil
		}
		// For Ethereum address derivation, we need the concrete Secp256k1PublicKey type
		pk, ok := proposer.(*crypto.Secp256k1PublicKey)
		if !ok {
			return nil, nil
		}
		// Use the same derivation as the Eth authenticator: Keccak(uncompressed pubkey)[12:]
		return crypto.EthereumAddressFromPubKey(pk), nil
	default:
		return nil, fmt.Errorf("unsupported authenticator: %s", authType)
	}
}

// Test_LeaderSenderLogic tests the @leader_sender logic directly without full network setup
// This validates our understanding of the leader_sender behavior before running full acceptance tests
func Test_LeaderSenderLogic(t *testing.T) {
	// Test the leaderCompactIDForAuth function directly
	secpPriv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	secpPub := secpPriv.Public().(*crypto.Secp256k1PublicKey)

	edPriv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	edPub := edPriv.Public().(*crypto.Ed25519PublicKey)

	tests := []struct {
		name        string
		proposer    crypto.PublicKey
		authType    string
		expectNull  bool
		expectBytes []byte
	}{
		{
			name:        "secp proposer + eth personal auth",
			proposer:    secpPub,
			authType:    "secp256k1_ep",
			expectNull:  false,
			expectBytes: crypto.EthereumAddressFromPubKey(secpPub),
		},
		{
			name:        "secp proposer + secp256k1 auth",
			proposer:    secpPub,
			authType:    "secp256k1",
			expectNull:  false,
			expectBytes: secpPub.Bytes(),
		},
		{
			name:       "secp proposer + ed25519 auth",
			proposer:   secpPub,
			authType:   "ed25519",
			expectNull: true,
		},
		{
			name:        "ed25519 proposer + ed25519 auth",
			proposer:    edPub,
			authType:    "ed25519",
			expectNull:  false,
			expectBytes: edPub.Bytes(),
		},
		{
			name:       "ed25519 proposer + eth personal auth",
			proposer:   edPub,
			authType:   "secp256k1_ep",
			expectNull: true,
		},
		{
			name:       "ed25519 proposer + secp256k1 auth",
			proposer:   edPub,
			authType:   "secp256k1",
			expectNull: true,
		},
		{
			name:       "nil proposer",
			proposer:   nil,
			authType:   "secp256k1_ep",
			expectNull: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := leaderCompactIDForAuthTest(tt.proposer, tt.authType)
			require.NoError(t, err)

			if tt.expectNull {
				require.Nil(t, result, "expected nil result for %s", tt.name)
			} else {
				require.NotNil(t, result, "expected non-nil result for %s", tt.name)
				require.Equal(t, tt.expectBytes, result, "expected bytes mismatch for %s", tt.name)
			}
		})
	}
}

// This acceptance test validates @leader_sender behavior against the transaction signer
// for different authenticator types, closely mirroring the unit tests in interpreter/context_test.go.
//
// NOTE: Currently these tests FAIL because BlockContext creation differs between execution paths:
//  1. SELECT queries create incomplete BlockContext (Height: -1, no Proposer) - returns NULL
//  2. Actions should use proper BlockContext from block processor, but consensus engine
//     leader reassignment corrupts the proposer value during updateValidatorSetAndRole().
//
// This is a LOGIC BUG in BlockContext consistency and leader isolation, not test infrastructure.
//
// Network: single validator (secp256k1). The block proposer equals the validator's pubkey.
// Cases:
//   - EthPersonalSign (secp256k1 address): @leader_sender equals tx signer (validator key) -> SHOULD succeed
//   - Secp256k1Auth (raw pubkey bytes): @leader_sender equals tx signer (validator key) -> SHOULD succeed
//   - Ed25519Auth (caller with ed25519 key): proposer is secp256k1, not representable -> @leader_sender IS NULL -> SHOULD succeed
func Test_LeaderSenderVsSigner(t *testing.T) {
	ctx := context.Background()

	for _, driver := range setup.AllDrivers {
		t.Run("leader_sender_vs_signer_"+driver.String(), func(t *testing.T) {
			// Use a custom node config with our test private key as the validator
			nodeCfg := setup.CustomNodeConfig(func(cfg *setup.NodeConfig) {
				cfg.PrivateKey = testPrivkey1
			})

			// Set up DB owner with our test private key
			signer := auth.GetUserSigner(testPrivkey1)
			ident, err := auth.EthSecp256k1Authenticator{}.Identifier(signer.CompactID())
			require.NoError(t, err)

			// Stand up single-node network with our test client as DB owner and validator
			net := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					DBOwner: ident,
					Nodes: []*setup.NodeConfig{
						nodeCfg,
					},
				},
			})

			// Create client with our test private key
			clientOpts := &setup.ClientOptions{
				PrivateKey: testPrivkey1,
			}
			client := net.Nodes[0].JSONRPCClient(t, ctx, clientOpts)

			// Minimal actions for assertions - strict expectations with debug output
			hash, err := client.ExecuteSQL(ctx, `
			CREATE ACTION debug_leader_sender() public {
				-- Debug: simple log
				NOTICE('DEBUG: debug_leader_sender executed');
			};

			CREATE ACTION debug_context() public {
				-- Debug: always succeed, just log
				NOTICE('DEBUG: debug_context action executed');
			};

			CREATE ACTION test_leader_sender_logic() public {
				-- Debug: log authenticator and values
				NOTICE('test action executed');

				-- When proposer and auth key types match, leader_sender must equal signer
				if @signer is null { ERROR('signer is null'); }
				if @leader_sender is null { ERROR('leader_sender is null'); }
				if @leader_sender != @signer { ERROR('leader_sender != signer'); }
				NOTICE('secp256k1 leader_sender equals signer');
			};

			CREATE ACTION test_ed25519_mismatch() public {
				-- Debug: log authenticator and values
				NOTICE('test action executed');

				-- For ed25519 caller against secp256k1 proposer, leader_sender must be NULL
				if @signer is null { ERROR('signer is null'); }
				if @leader_sender is not null { ERROR('leader_sender should be null for ed25519'); }
				NOTICE('leader_sender correctly null for mismatch');
			};
			`, nil, opts)
			require.NoError(t, err)

			// Wait for schema transaction to commit
			result, err := client.WaitTx(ctx, hash, 100*time.Millisecond)
			require.NoError(t, err)
			require.Equal(t, uint32(types.CodeOk), result.Result.Code, "Schema creation should succeed, log=%q", result.Result.Log)

			// Give the network time to produce a block after schema deployment
			time.Sleep(2 * time.Second)

			// Build direct JSON-RPC client for custom-signed txs
			exposed, _, err := net.Nodes[0].JSONRPCEndpoint(t, ctx)
			require.NoError(t, err)
			u, err := url.Parse(exposed)
			require.NoError(t, err)
			jr := jsonrpc.NewClient(u)

			// Helper to exec an action with a specific signer and expect success or failure
			exec := func(t *testing.T, signer auth.Signer, action string, expectOK bool) {
				acctID, err := types.GetSignerAccount(signer)
				require.NoError(t, err)
				acct, err := jr.GetAccount(ctx, acctID, types.AccountStatusLatest)
				var nonce uint64
				if err != nil {
					nonce = 1
				} else {
					nonce = uint64(acct.Nonce + 1)
				}

				payload := &types.ActionExecution{
					Namespace: "",
					Action:    action,
				}
				tx, err := types.CreateTransaction(payload, "", nonce)
				require.NoError(t, err)
				require.NoError(t, tx.Sign(signer))

				h, err := jr.Broadcast(ctx, tx, rpcclient.BroadcastWaitCommit)
				require.NoError(t, err)

				// Wait for commit result and assert code
				res, err := jr.TxQuery(ctx, h)
				require.NoError(t, err)

				// Debug: query contextual variables to ensure proposer/auth are as expected
				// auth type used
				authRes, authErr := client.ExecuteSQL(ctx, `SELECT @authenticator;`, nil, opts)
				if authErr == nil {
					authResult, _ := client.WaitTx(ctx, authRes, 50*time.Millisecond)
					t.Logf("DEBUG: @authenticator query result: %v", authResult)
				} else {
					t.Logf("DEBUG: @authenticator query failed: %v", authErr)
				}
				// leader_sender value
				lsRes, lsErr := client.ExecuteSQL(ctx, `SELECT @leader_sender;`, nil, opts)
				if lsErr == nil {
					lsResult, _ := client.WaitTx(ctx, lsRes, 50*time.Millisecond)
					t.Logf("DEBUG: @leader_sender query result: %v", lsResult)
				} else {
					t.Logf("DEBUG: @leader_sender query failed: %v", lsErr)
				}
				if expectOK {
					require.Equal(t, uint32(types.CodeOk), res.Result.Code, "tx expected to succeed, log=%q", res.Result.Log)
				} else {
					require.NotEqual(t, uint32(types.CodeOk), res.Result.Code, "tx expected to fail")
				}
			}

			// Create signers - validator key (testPrivkey1) is the same as client key
			ethPersonalSigner := auth.GetUserSigner(testPrivkey1) // EthPersonalSign
			secpSigner := auth.GetNodeSigner(testPrivkey1)        // Secp256k1Auth

			// Ed25519 user signer (mismatch with secp256k1 proposer → leader_sender NULL)
			edPriv, _, err := crypto.GenerateEd25519Key(rand.Reader)
			require.NoError(t, err)
			edSigner := auth.GetUserSigner(edPriv)

			// First, debug: check what values we get
			t.Log("=== DEBUG: Checking leader_sender values ===")
			exec(t, ethPersonalSigner, "debug_context", true)       // Check BlockContext
			exec(t, ethPersonalSigner, "debug_leader_sender", true) // Debug action should succeed (just logs values)

			// 1) EthPersonalSign: secp256k1 proposer + secp256k1 auth → leader_sender should equal signer
			exec(t, ethPersonalSigner, "test_leader_sender_logic", true) // SHOULD succeed

			// 2) Secp256k1Auth: secp256k1 proposer + secp256k1 auth → leader_sender should equal signer
			exec(t, secpSigner, "test_leader_sender_logic", true) // SHOULD succeed

			// 3) Ed25519Auth: secp256k1 proposer + ed25519 auth → leader_sender should be NULL
			exec(t, edSigner, "test_ed25519_mismatch", true) // SHOULD succeed
		})
	}
}

// Test_LeaderSenderEd25519Validator tests @leader_sender behavior with an Ed25519 validator.
// This tests the scenario where the proposer is an Ed25519 key, so @leader_sender should
// be available and match the signer for compatible authenticator types.
//
// NOTE: Currently these tests FAIL because BlockContext creation differs between execution paths:
//  1. SELECT queries create incomplete BlockContext (Height: -1, no Proposer) - returns NULL
//  2. Actions should use proper BlockContext from block processor, but consensus engine
//     leader reassignment corrupts the proposer value during updateValidatorSetAndRole().
//
// This is a LOGIC BUG in BlockContext consistency and leader isolation, not test infrastructure.
func Test_LeaderSenderEd25519Validator(t *testing.T) {
	ctx := context.Background()

	for _, driver := range setup.AllDrivers {
		if driver == setup.CLI {
			// CLI driver doesn't support Ed25519 keys yet
			continue
		}

		t.Run("leader_sender_ed25519_validator_"+driver.String(), func(t *testing.T) {
			// Use a custom node config with an Ed25519 private key as the validator
			nodeCfg := setup.CustomEd25519NodeConfig(func(cfg *setup.NodeConfig) {
				// Keep default settings
			})

			// Set up DB owner with the Ed25519 validator key
			ident, err := auth.GetUserIdentifier(nodeCfg.PrivateKey.Public())
			require.NoError(t, err)

			// Stand up single-node network with Ed25519 validator as DB owner
			net := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					DBOwner: ident,
					Nodes: []*setup.NodeConfig{
						nodeCfg,
					},
				},
			})

			// Create client with the Ed25519 validator private key
			clientOpts := &setup.ClientOptions{
				PrivateKey: nodeCfg.PrivateKey,
			}
			client := net.Nodes[0].JSONRPCClient(t, ctx, clientOpts)

			// Minimal actions for assertions - strict expectations with debug output
			hash, err := client.ExecuteSQL(ctx, `
			CREATE ACTION debug_leader_sender() public {
				-- Debug: simple log
				NOTICE('DEBUG: debug_leader_sender executed');
			};

			CREATE ACTION debug_context() public {
				-- Debug: check if BlockContext exists and has proposer
				NOTICE('DEBUG: Ed25519 BlockContext proposer exists check');
			};

			CREATE ACTION test_ed25519_leader_logic() public {
				-- Debug: log authenticator and values
				NOTICE('test action executed');

				-- With Ed25519 proposer and Ed25519 auth, leader_sender must equal signer
				if @signer is null { ERROR('signer is null'); }
				if @leader_sender is null { ERROR('leader_sender is null'); }
				if @leader_sender != @signer { ERROR('leader_sender != signer'); }
				NOTICE('Ed25519 leader_sender equals signer');
			};

			CREATE ACTION test_secp_mismatch() public {
				-- Debug: log authenticator and values
				NOTICE('test action executed');

				-- For secp256k1 caller against Ed25519 proposer, leader_sender must be NULL
				if @signer is null { ERROR('signer is null'); }
				if @leader_sender is not null { ERROR('leader_sender should be null for secp256k1 vs Ed25519'); }
				NOTICE('leader_sender correctly null for mismatch');
			};
			`, nil, opts)
			require.NoError(t, err)

			// Wait for schema transaction to commit
			result, err := client.WaitTx(ctx, hash, 100*time.Millisecond)
			require.NoError(t, err)
			require.Equal(t, uint32(types.CodeOk), result.Result.Code, "Schema creation should succeed, log=%q", result.Result.Log)

			// Build direct JSON-RPC client for custom-signed txs
			exposed, _, err := net.Nodes[0].JSONRPCEndpoint(t, ctx)
			require.NoError(t, err)
			u, err := url.Parse(exposed)
			require.NoError(t, err)
			jr := jsonrpc.NewClient(u)

			// Helper to exec an action with a specific signer and expect success or failure
			exec := func(t *testing.T, signer auth.Signer, action string, expectOK bool) {
				acctID, err := types.GetSignerAccount(signer)
				require.NoError(t, err)
				acct, err := jr.GetAccount(ctx, acctID, types.AccountStatusLatest)
				var nonce uint64
				if err != nil {
					nonce = 1
				} else {
					nonce = uint64(acct.Nonce + 1)
				}

				payload := &types.ActionExecution{
					Namespace: "",
					Action:    action,
				}
				tx, err := types.CreateTransaction(payload, "", nonce)
				require.NoError(t, err)
				require.NoError(t, tx.Sign(signer))

				h, err := jr.Broadcast(ctx, tx, rpcclient.BroadcastWaitCommit)
				require.NoError(t, err)

				// Wait for commit result and assert code
				res, err := jr.TxQuery(ctx, h)
				require.NoError(t, err)
				if expectOK {
					require.Equal(t, uint32(types.CodeOk), res.Result.Code, "tx expected to succeed, log=%q", res.Result.Log)
				} else {
					require.NotEqual(t, uint32(types.CodeOk), res.Result.Code, "tx expected to fail")
				}
			}

			// Test Ed25519 signer (matches the Ed25519 validator/leader)
			edSigner := auth.GetUserSigner(nodeCfg.PrivateKey)

			// Test secp256k1 signer (mismatch with Ed25519 validator/leader)
			secpPriv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
			require.NoError(t, err)
			secpSigner := auth.GetUserSigner(secpPriv)

			// First, debug: check what values we get
			t.Log("=== DEBUG: Checking Ed25519 validator leader_sender values ===")
			exec(t, edSigner, "debug_context", true)       // Check BlockContext
			exec(t, edSigner, "debug_leader_sender", true) // Debug action should succeed (just logs values)

			// 1) Ed25519 signer with Ed25519 leader: leader_sender should equal signer
			exec(t, edSigner, "test_ed25519_leader_logic", true)

			// 2) Secp256k1 signer with Ed25519 leader: leader_sender should be NULL
			exec(t, secpSigner, "test_secp_mismatch", true)
		})
	}
}
