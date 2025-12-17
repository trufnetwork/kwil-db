//go:build kwiltest

package usersvc

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine/interpreter"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/erc20"
	bridgeUtils "github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
	"github.com/trufnetwork/kwil-db/node/pg"
)

var (
	testDB         *pg.DB
	dbInitOnce     sync.Once
	schemaInitOnce sync.Once
	dbInitErr      error
	schemaInitErr  error
)

// NOTE: These tests require manual cleanup between runs due to extension singleton state.
// Run this before executing tests:
//   PGPASSWORD=kwild psql -h localhost -p 5432 -U kwild -d kwil_test_db -c "DELETE FROM kwil_erc20_meta.epoch_votes; DELETE FROM kwil_erc20_meta.epoch_rewards; DELETE FROM kwil_erc20_meta.epochs; DELETE FROM kwil_erc20_meta.reward_instances;"
//
// Or run tests individually:
//   go test -tags=kwiltest -run "^TestGetWithdrawalProof_ValidRequest$" -v

// resetTestSingletons resets all global singleton state used by the extensions.
// This must be called at the beginning of each test AFTER the schema is created.
func resetTestSingletons() {
	// Reset the ordered-sync singleton
	orderedsync.ForTestingReset()
	// Reset the ERC20 extension singleton
	erc20.ForTestingResetSingleton()
}

// getTestDB returns a shared database connection for all tests.
func getTestDB(t *testing.T) *pg.DB {
	t.Helper()

	dbInitOnce.Do(func() {
		// Create the test database connection
		cfg := &pg.DBConfig{
			PoolConfig: pg.PoolConfig{
				ConnConfig: pg.ConnConfig{
					Host:   "127.0.0.1",
					Port:   "5432",
					User:   "kwild",
					Pass:   "kwild",
					DBName: "kwil_test_db",
				},
				MaxConns: 11,
			},
		}

		var err error
		testDB, err = pg.NewDB(context.Background(), cfg)
		if err != nil {
			dbInitErr = err
			return
		}
	})

	require.NoError(t, dbInitErr)
	require.NotNil(t, testDB)
	return testDB
}

// initSchemaOnce ensures the ERC20 schema is created exactly once before all tests.
// This is safe to call multiple times - it will only execute once.
func initSchemaOnce(t *testing.T) {
	t.Helper()

	schemaInitOnce.Do(func() {
		db := getTestDB(t)
		ctx := context.Background()

		// Create a temporary transaction just for schema initialization
		tx, err := db.BeginTx(ctx)
		if err != nil {
			schemaInitErr = err
			return
		}

		engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
		if err != nil {
			tx.Rollback(ctx)
			schemaInitErr = err
			return
		}

		app := &common.App{
			DB:     tx,
			Engine: engine,
			Service: &common.Service{
				Logger: log.New(),
			},
		}

		// Check if schema already exists
		testErr := app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
			{kwil_erc20_meta}SELECT COUNT(*) FROM reward_instances WHERE 1=0
		`, nil, func(row *common.Row) error {
			return nil
		})

		// If namespace not found, create the schema
		if testErr != nil && strings.Contains(testErr.Error(), "namespace not found") {
			// Transfer ownership
			err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, "TRANSFER OWNERSHIP TO $user", map[string]any{
				"user": "test_owner",
			}, nil)
			if err != nil {
				tx.Rollback(ctx)
				schemaInitErr = err
				return
			}

			// Deploy the schema (this will initialize the singleton)
			err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, "USE kwil_erc20_meta AS kwil_erc20_meta", nil, nil)
			if err != nil {
				tx.Rollback(ctx)
				schemaInitErr = err
				return
			}

			// Commit the schema creation
			err = tx.Commit(ctx)
			if err != nil {
				schemaInitErr = err
				return
			}
		} else {
			tx.Rollback(ctx)
		}
	})

	require.NoError(t, schemaInitErr)
}

// setupTestEpochData creates test data in the database for withdrawal proof tests.
// It creates a confirmed epoch with rewards and validator signatures.
// suffix should be unique for each test to avoid conflicts.
func setupTestEpochData(t *testing.T, ctx context.Context, app *common.App, suffix string) (
	epochID *types.UUID,
	recipients []ethcommon.Address,
	amounts []*big.Int,
	blockHash [32]byte,
	merkleRoot []byte,
) {
	t.Helper()

	epochID = types.NewUUIDV5([]byte("test-epoch-" + suffix))
	instanceID := types.NewUUIDV5([]byte("test-instance-" + suffix))

	recipients = []ethcommon.Address{
		ethcommon.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb4"),
		ethcommon.HexToAddress("0x1234567890123456789012345678901234567890"),
		ethcommon.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
	}

	amounts = []*big.Int{
		big.NewInt(1000000000000000000), // 1 token
		big.NewInt(2000000000000000000), // 2 tokens
		big.NewInt(500000000000000000),  // 0.5 tokens
	}

	// Generate merkle tree
	userAddrs := make([]string, len(recipients))
	for i, addr := range recipients {
		userAddrs[i] = addr.Hex()
	}

	escrowAddr := "0x2d4f435867066737ba1617ef024e073413909ad2"
	blockHash = [32]byte{0x01, 0x02, 0x03}
	jsonTree, root, err := bridgeUtils.GenRewardMerkleTree(userAddrs, amounts, escrowAddr, blockHash)
	require.NoError(t, err)
	merkleRoot = root

	// Insert reward instance
	// Use big.Int and convert to Decimal(78,0) for ERC20 amounts
	balanceBig := big.NewInt(3500000000000000000) // 3.5 tokens
	balance, err := types.NewDecimalFromBigInt(balanceBig, 0)
	require.NoError(t, err)
	err = balance.SetPrecisionAndScale(78, 0)
	require.NoError(t, err)

	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO reward_instances (id, chain_id, escrow_address, distribution_period, synced, active, erc20_address, erc20_decimals, synced_at, balance)
		VALUES ($id, $chain_id, $escrow, $period, true, true, $erc20, 18, 100, $balance)
	`, map[string]any{
		"id":       instanceID,
		"chain_id": "11155111",
		"escrow":   ethcommon.HexToAddress(escrowAddr).Bytes(),
		"period":   int64(86400),
		"erc20":    ethcommon.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
		"balance":  balance,
	}, nil)
	require.NoError(t, err)

	// Insert epoch
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epochs (id, instance_id, reward_root, block_hash, confirmed, created_at_block, created_at_unix, ended_at)
		VALUES ($id, $instance_id, $root, $hash, true, 100, 1000000, 200)
	`, map[string]any{
		"id":          epochID,
		"instance_id": instanceID,
		"root":        merkleRoot,
		"hash":        blockHash[:],
	}, nil)
	require.NoError(t, err)

	// Insert epoch rewards
	for i, recipient := range recipients {
		// Convert to Decimal(78,0) for ERC20 amounts
		decimalAmt, err := types.NewDecimalFromBigInt(amounts[i], 0)
		require.NoError(t, err)
		err = decimalAmt.SetPrecisionAndScale(78, 0)
		require.NoError(t, err)

		err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
			{kwil_erc20_meta}INSERT INTO epoch_rewards (epoch_id, recipient, amount)
			VALUES ($epoch_id, $recipient, $amount)
		`, map[string]any{
			"epoch_id":  epochID,
			"recipient": recipient.Bytes(),
			"amount":    decimalAmt,
		}, nil)
		require.NoError(t, err)
	}

	// Insert validator signatures (3 signatures)
	validators := []ethcommon.Address{
		ethcommon.HexToAddress("0xValidator1000000000000000000000000000001"),
		ethcommon.HexToAddress("0xValidator2000000000000000000000000000002"),
		ethcommon.HexToAddress("0xValidator3000000000000000000000000000003"),
	}

	for i, validator := range validators {
		// Create mock signature (65 bytes: R || S || V)
		sig := make([]byte, 65)
		copy(sig[0:32], []byte(fmt.Sprintf("R%d", i)))  // R component
		copy(sig[32:64], []byte(fmt.Sprintf("S%d", i))) // S component
		sig[64] = byte(27 + (i % 2))                    // V component (27 or 28)

		err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
			{kwil_erc20_meta}INSERT INTO epoch_votes (epoch_id, voter, nonce, signature)
			VALUES ($epoch_id, $voter, $nonce, $signature)
		`, map[string]any{
			"epoch_id":  epochID,
			"voter":     validator.Bytes(),
			"nonce":     int64(i),
			"signature": sig,
		}, nil)
		require.NoError(t, err)
	}

	// Verify merkle tree structure
	require.Equal(t, root, merkleRoot)
	require.NotNil(t, jsonTree)

	return epochID, recipients, amounts, blockHash, merkleRoot
}

func setupTestService(t *testing.T, db *pg.DB, engine EngineReader) *Service {
	t.Helper()

	return &Service{
		engine:        engine,
		log:           log.New(),
		db:            db,
		readTxTimeout: 30 * time.Second, // Longer timeout for tests
	}
}

func TestGetWithdrawalProof_ValidRequest(t *testing.T) {
	// Initialize schema once (safe to call multiple times)
	initSchemaOnce(t)

	// Reset singleton state before each test to ensure isolation
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)

	// Begin transaction for setup
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	// Setup engine (interpreter) and initialize ERC20 bridge schema
	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: engine,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	// Setup test data with unique suffix to avoid conflicts
	testSuffix := "valid-request"
	epochID, recipients, amounts, _, _ := setupTestEpochData(t, ctx, app, testSuffix)

	// Commit the transaction so the service can see the data
	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Create service
	svc := setupTestService(t, db, engine)

	// Test: Get withdrawal proof for first recipient
	req := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipients[0].Hex(),
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, jsonErr, "expected no JSON-RPC error")
	require.NotNil(t, resp)

	// Verify response
	withdrawalResp := resp
	require.Equal(t, recipients[0].Hex(), withdrawalResp.Recipient)
	require.Equal(t, amounts[0].String(), withdrawalResp.Amount)
	require.Equal(t, "ready", withdrawalResp.Status)
	require.NotEmpty(t, withdrawalResp.MerkleProof)
	require.NotEmpty(t, withdrawalResp.ValidatorSignatures)
	require.Len(t, withdrawalResp.ValidatorSignatures, 3)
	require.Equal(t, int64(11155111), withdrawalResp.ChainID)

	// Verify signature format
	for _, sig := range withdrawalResp.ValidatorSignatures {
		require.NotEmpty(t, sig.R)
		require.NotEmpty(t, sig.S)
		require.True(t, sig.V == 27 || sig.V == 28, "V must be 27 or 28")
	}
}

func TestGetWithdrawalProof_InvalidEpochID(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	// Commit empty transaction (no test data needed for validation tests)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	req := &userjson.WithdrawalProofRequest{
		EpochID:   "not-a-uuid",
		Recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb4",
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, resp)
	require.NotNil(t, jsonErr)
	require.Equal(t, jsonrpc.ErrorInvalidParams, jsonErr.Code)
}

func TestGetWithdrawalProof_InvalidRecipientFormat(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	// Commit empty transaction (no test data needed for validation tests)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	testCases := []struct {
		name      string
		recipient string
	}{
		{"no 0x prefix", "742d35Cc6634C0532925a3b844Bc9e7595f0bEb4"},
		{"too short", "0x742d35"},
		{"invalid hex", "0xZZZZ35Cc6634C0532925a3b844Bc9e7595f0bEb4"},
		{"empty", ""},
	}

	epochID := types.NewUUIDV5([]byte("test"))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &userjson.WithdrawalProofRequest{
				EpochID:   epochID.String(),
				Recipient: tc.recipient,
			}

			resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
			require.Nil(t, resp)
			require.NotNil(t, jsonErr)
			require.Equal(t, jsonrpc.ErrorInvalidParams, jsonErr.Code)
		})
	}
}

func TestGetWithdrawalProof_EpochNotFound(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	// Commit empty transaction (no test data needed)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	nonExistentEpoch := types.NewUUIDV5([]byte("non-existent"))

	req := &userjson.WithdrawalProofRequest{
		EpochID:   nonExistentEpoch.String(),
		Recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb4",
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, resp)
	require.NotNil(t, jsonErr)
	require.Equal(t, jsonrpc.ErrorInvalidParams, jsonErr.Code)
}

func TestGetWithdrawalProof_RecipientNotInEpoch(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: engine,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	testSuffix := "recipient-not-in-epoch"
	epochID, _, _, _, _ := setupTestEpochData(t, ctx, app, testSuffix)

	// Commit transaction so service can see the data
	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	// Use an address that's not in the epoch
	notInEpoch := "0x9999999999999999999999999999999999999999"

	req := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: notInEpoch,
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, resp)
	require.NotNil(t, jsonErr)
	require.Equal(t, jsonrpc.ErrorInvalidParams, jsonErr.Code)
}

func TestGetWithdrawalProof_PendingEpoch_NotEnded(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: engine,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	// Create pending epoch (not ended)
	testSuffix := "pending-not-ended"
	epochID := types.NewUUIDV5([]byte("test-epoch-" + testSuffix))
	instanceID := types.NewUUIDV5([]byte("test-instance-" + testSuffix))
	recipient := ethcommon.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb4")

	// Insert reward instance
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO reward_instances (id, chain_id, escrow_address, distribution_period, synced, active, erc20_address, erc20_decimals, synced_at, balance)
		VALUES ($id, $chain_id, $escrow, $period, true, true, $erc20, 18, 100, $balance)
	`, map[string]any{
		"id":       instanceID,
		"chain_id": "11155111",
		"escrow":   ethcommon.HexToAddress("0x2d4f435867066737ba1617ef024e073413909ad2").Bytes(),
		"period":   int64(86400),
		"erc20":    ethcommon.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
		"balance": func() *types.Decimal {
			d, _ := types.NewDecimalFromBigInt(big.NewInt(1000000000000000000), 0)
			_ = d.SetPrecisionAndScale(78, 0)
			return d
		}(),
	}, nil)
	require.NoError(t, err)

	// Insert pending epoch (ended_at is NULL)
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epochs (id, instance_id, reward_root, block_hash, confirmed, created_at_block, created_at_unix, ended_at)
		VALUES ($id, $instance_id, NULL, NULL, false, 100, 1000000, NULL)
	`, map[string]any{
		"id":          epochID,
		"instance_id": instanceID,
	}, nil)
	require.NoError(t, err)

	// Insert reward for recipient
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epoch_rewards (epoch_id, recipient, amount)
		VALUES ($epoch_id, $recipient, $amount)
	`, map[string]any{
		"epoch_id":  epochID,
		"recipient": recipient.Bytes(),
		"amount": func() *types.Decimal {
			d, _ := types.NewDecimalFromBigInt(big.NewInt(1000000000000000000), 0)
			_ = d.SetPrecisionAndScale(78, 0)
			return d
		}(),
	}, nil)
	require.NoError(t, err)

	// Commit transaction so service can see the data
	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	req := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipient.Hex(),
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, jsonErr)
	require.NotNil(t, resp)

	withdrawalResp := resp
	require.Equal(t, "pending", withdrawalResp.Status)
	require.NotNil(t, withdrawalResp.EstimatedReadyAt)
	require.Equal(t, int64(1000000+86400), *withdrawalResp.EstimatedReadyAt) // created_at + distribution_period
}

func TestGetWithdrawalProof_PendingEpoch_NotConfirmed(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: engine,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	// Create ended but not confirmed epoch
	testSuffix := "pending-not-confirmed"
	epochID := types.NewUUIDV5([]byte("test-epoch-" + testSuffix))
	instanceID := types.NewUUIDV5([]byte("test-instance-" + testSuffix))
	recipient := ethcommon.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb4")

	// Insert reward instance
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO reward_instances (id, chain_id, escrow_address, distribution_period, synced, active, erc20_address, erc20_decimals, synced_at, balance)
		VALUES ($id, $chain_id, $escrow, $period, true, true, $erc20, 18, 100, $balance)
	`, map[string]any{
		"id":       instanceID,
		"chain_id": "11155111",
		"escrow":   ethcommon.HexToAddress("0x2d4f435867066737ba1617ef024e073413909ad2").Bytes(),
		"period":   int64(86400),
		"erc20":    ethcommon.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
		"balance": func() *types.Decimal {
			d, _ := types.NewDecimalFromBigInt(big.NewInt(1000000000000000000), 0)
			_ = d.SetPrecisionAndScale(78, 0)
			return d
		}(),
	}, nil)
	require.NoError(t, err)

	// Insert ended but not confirmed epoch
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epochs (id, instance_id, reward_root, block_hash, confirmed, created_at_block, created_at_unix, ended_at)
		VALUES ($id, $instance_id, $root, $hash, false, 100, 1000000, 200)
	`, map[string]any{
		"id":          epochID,
		"instance_id": instanceID,
		"root":        []byte{0x01, 0x02},
		"hash":        []byte{0x03, 0x04},
	}, nil)
	require.NoError(t, err)

	// Insert reward for recipient
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epoch_rewards (epoch_id, recipient, amount)
		VALUES ($epoch_id, $recipient, $amount)
	`, map[string]any{
		"epoch_id":  epochID,
		"recipient": recipient.Bytes(),
		"amount": func() *types.Decimal {
			d, _ := types.NewDecimalFromBigInt(big.NewInt(1000000000000000000), 0)
			_ = d.SetPrecisionAndScale(78, 0)
			return d
		}(),
	}, nil)
	require.NoError(t, err)

	// Commit transaction so service can see the data
	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	req := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipient.Hex(),
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, jsonErr)
	require.NotNil(t, resp)

	withdrawalResp := resp
	require.Equal(t, "pending", withdrawalResp.Status)
	require.Nil(t, withdrawalResp.EstimatedReadyAt) // No estimate when ended but not confirmed
}

// setupTestEpochDataWithWithdrawal creates test data including a withdrawal record.
// This is a helper for withdrawal status tracking tests.
func setupTestEpochDataWithWithdrawal(t *testing.T, ctx context.Context, app *common.App, suffix string, withdrawalStatus string, includeTxHash bool) (
	epochID *types.UUID,
	recipient ethcommon.Address,
	amount *big.Int,
) {
	t.Helper()

	epochID = types.NewUUIDV5([]byte("test-epoch-" + suffix))
	instanceID := types.NewUUIDV5([]byte("test-instance-" + suffix))

	recipient = ethcommon.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb4")
	amount = big.NewInt(1000000000000000000) // 1 token

	// Generate merkle tree
	userAddrs := []string{recipient.Hex()}
	amounts := []*big.Int{amount}
	escrowAddr := "0x2d4f435867066737ba1617ef024e073413909ad2"
	blockHash := [32]byte{0x01, 0x02, 0x03}
	_, root, err := bridgeUtils.GenRewardMerkleTree(userAddrs, amounts, escrowAddr, blockHash)
	require.NoError(t, err)

	// Insert reward instance
	balanceBig := big.NewInt(1000000000000000000)
	balance, err := types.NewDecimalFromBigInt(balanceBig, 0)
	require.NoError(t, err)
	err = balance.SetPrecisionAndScale(78, 0)
	require.NoError(t, err)

	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO reward_instances (id, chain_id, escrow_address, distribution_period, synced, active, erc20_address, erc20_decimals, synced_at, balance)
		VALUES ($id, $chain_id, $escrow, $period, true, true, $erc20, 18, 100, $balance)
	`, map[string]any{
		"id":       instanceID,
		"chain_id": "11155111",
		"escrow":   ethcommon.HexToAddress(escrowAddr).Bytes(),
		"period":   int64(86400),
		"erc20":    ethcommon.HexToAddress("0x1234567890123456789012345678901234567890").Bytes(),
		"balance":  balance,
	}, nil)
	require.NoError(t, err)

	// Insert epoch
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epochs (id, instance_id, reward_root, block_hash, confirmed, created_at_block, created_at_unix, ended_at)
		VALUES ($id, $instance_id, $root, $hash, true, 100, 1000000, 200)
	`, map[string]any{
		"id":          epochID,
		"instance_id": instanceID,
		"root":        root,
		"hash":        blockHash[:],
	}, nil)
	require.NoError(t, err)

	// Insert epoch reward
	decimalAmt, err := types.NewDecimalFromBigInt(amount, 0)
	require.NoError(t, err)
	err = decimalAmt.SetPrecisionAndScale(78, 0)
	require.NoError(t, err)

	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epoch_rewards (epoch_id, recipient, amount)
		VALUES ($epoch_id, $recipient, $amount)
	`, map[string]any{
		"epoch_id":  epochID,
		"recipient": recipient.Bytes(),
		"amount":    decimalAmt,
	}, nil)
	require.NoError(t, err)

	// Insert validator signatures
	validator := ethcommon.HexToAddress("0xValidator1000000000000000000000000000001")
	sig := make([]byte, 65)
	copy(sig[0:32], []byte("R1"))
	copy(sig[32:64], []byte("S1"))
	sig[64] = 27

	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epoch_votes (epoch_id, voter, nonce, signature)
		VALUES ($epoch_id, $voter, $nonce, $signature)
	`, map[string]any{
		"epoch_id":  epochID,
		"voter":     validator.Bytes(),
		"nonce":     int64(0),
		"signature": sig,
	}, nil)
	require.NoError(t, err)

	// Insert withdrawal record if status is not empty
	if withdrawalStatus != "" {
		if includeTxHash {
			txHashBytes := ethcommon.HexToHash("0xabc123def456abc123def456abc123def456abc123def456abc123def456abc1").Bytes()
			err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
				{kwil_erc20_meta}INSERT INTO withdrawals (epoch_id, recipient, status, tx_hash, block_number, created_at, claimed_at, updated_at)
				VALUES ($epoch_id, $recipient, $status, $tx_hash, 12345678, 1000, 2000, 2000)
			`, map[string]any{
				"epoch_id":  epochID,
				"recipient": recipient.Bytes(),
				"status":    withdrawalStatus,
				"tx_hash":   txHashBytes,
			}, nil)
		} else {
			err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
				{kwil_erc20_meta}INSERT INTO withdrawals (epoch_id, recipient, status, created_at, updated_at)
				VALUES ($epoch_id, $recipient, $status, 1000, 1000)
			`, map[string]any{
				"epoch_id":  epochID,
				"recipient": recipient.Bytes(),
				"status":    withdrawalStatus,
			}, nil)
		}
		require.NoError(t, err)
	}

	return epochID, recipient, amount
}

// cleanupTestData removes all test data from the database.
// This should be called with defer to ensure cleanup happens even if test fails.
func cleanupTestData(t *testing.T, db *pg.DB) {
	t.Helper()
	ctx := context.Background()

	tx, err := db.BeginTx(ctx)
	if err != nil {
		t.Logf("Warning: failed to begin cleanup transaction: %v", err)
		return
	}
	defer tx.Rollback(ctx)

	// Delete in order respecting foreign keys
	queries := []string{
		"DELETE FROM kwil_erc20_meta.withdrawals",
		"DELETE FROM kwil_erc20_meta.epoch_votes",
		"DELETE FROM kwil_erc20_meta.epoch_rewards",
		"DELETE FROM kwil_erc20_meta.epochs",
		"DELETE FROM kwil_erc20_meta.reward_instances",
	}

	for _, query := range queries {
		_, err := tx.Execute(ctx, query)
		if err != nil {
			t.Logf("Warning: cleanup query failed: %s - %v", query, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		t.Logf("Warning: failed to commit cleanup: %v", err)
	}
}

// TestGetWithdrawalProof_StatusTracking_DefaultReady tests that when no withdrawal
// tracking record exists, the status defaults to "ready" and eth_tx_hash is nil.
func TestGetWithdrawalProof_StatusTracking_DefaultReady(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	defer cleanupTestData(t, db)

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: engine,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	// Setup test data WITHOUT withdrawal record
	epochID, recipient, amount := setupTestEpochDataWithWithdrawal(t, ctx, app, "status-default-ready", "", false)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	req := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipient.Hex(),
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, jsonErr)
	require.NotNil(t, resp)

	// Verify response - should have default "ready" status with no tx hash
	require.Equal(t, recipient.Hex(), resp.Recipient)
	require.Equal(t, amount.String(), resp.Amount)
	require.Equal(t, "ready", resp.Status, "status should default to 'ready' when no tracking record exists")
	require.Nil(t, resp.EthTxHash, "eth_tx_hash should be nil when no tracking record exists")
}

// TestGetWithdrawalProof_StatusTracking_Ready tests that when a withdrawal
// tracking record exists with status='ready', it is returned correctly.
func TestGetWithdrawalProof_StatusTracking_Ready(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	defer cleanupTestData(t, db)

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: engine,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	// Setup test data WITH withdrawal record (status='ready', no tx_hash)
	epochID, recipient, amount := setupTestEpochDataWithWithdrawal(t, ctx, app, "status-ready", "ready", false)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	req := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipient.Hex(),
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, jsonErr)
	require.NotNil(t, resp)

	// Verify response - should have 'ready' status with no tx hash
	require.Equal(t, recipient.Hex(), resp.Recipient)
	require.Equal(t, amount.String(), resp.Amount)
	require.Equal(t, "ready", resp.Status, "status should be 'ready' from tracking record")
	require.Nil(t, resp.EthTxHash, "eth_tx_hash should be nil when status is 'ready'")
}

// TestGetWithdrawalProof_StatusTracking_Claimed tests that when a withdrawal
// tracking record exists with status='claimed' and a tx_hash, both are returned correctly.
func TestGetWithdrawalProof_StatusTracking_Claimed(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	defer cleanupTestData(t, db)

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: engine,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	// Setup test data WITH withdrawal record (status='claimed', with tx_hash)
	epochID, recipient, amount := setupTestEpochDataWithWithdrawal(t, ctx, app, "status-claimed", "claimed", true)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	req := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipient.Hex(),
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, jsonErr)
	require.NotNil(t, resp)

	expectedTxHash := "0xabc123def456abc123def456abc123def456abc123def456abc123def456abc1"

	// Verify response - should have 'claimed' status with tx hash
	require.Equal(t, recipient.Hex(), resp.Recipient)
	require.Equal(t, amount.String(), resp.Amount)
	require.Equal(t, "claimed", resp.Status, "status should be 'claimed' from tracking record")
	require.NotNil(t, resp.EthTxHash, "eth_tx_hash should not be nil when status is 'claimed'")
	require.Equal(t, expectedTxHash, *resp.EthTxHash, "eth_tx_hash should match the stored value")
}

// TestGetWithdrawalProof_StatusTracking_Pending tests that withdrawal records
// can have 'pending' status (validates the CHECK constraint).
func TestGetWithdrawalProof_StatusTracking_Pending(t *testing.T) {
	initSchemaOnce(t)
	resetTestSingletons()

	ctx := context.Background()
	db := getTestDB(t)
	defer cleanupTestData(t, db)

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	engine, err := interpreter.NewInterpreter(ctx, tx, &common.Service{Logger: log.New()}, nil, nil, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: engine,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	// Setup test data WITH withdrawal record (status='pending')
	epochID, recipient, amount := setupTestEpochDataWithWithdrawal(t, ctx, app, "status-pending", "pending", false)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	svc := setupTestService(t, db, engine)

	req := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipient.Hex(),
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, jsonErr)
	require.NotNil(t, resp)

	// Verify response - should have 'pending' status with no tx hash
	require.Equal(t, recipient.Hex(), resp.Recipient)
	require.Equal(t, amount.String(), resp.Amount)
	require.Equal(t, "pending", resp.Status, "status should be 'pending' from tracking record")
	require.Nil(t, resp.EthTxHash, "eth_tx_hash should be nil when status is 'pending'")
}
