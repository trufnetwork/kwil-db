//go:build kwiltest

package erc20

import (
	"context"
	"math/big"
	"strings"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine/interpreter"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

func newTestDB() (*pg.DB, error) {
	cfg := &pg.DBConfig{
		PoolConfig: pg.PoolConfig{
			ConnConfig: pg.ConnConfig{
				Host:   "127.0.0.1",
				Port:   "5432",
				User:   "kwild",
				Pass:   "kwild", // would be ignored if pg_hba.conf set with trust
				DBName: "kwil_test_db",
			},
			MaxConns: 11,
		},
	}

	ctx := context.Background()

	return pg.NewDB(ctx, cfg)
}

const defaultCaller = "owner"

func setup(t *testing.T, tx sql.DB) *common.App {
	interp, err := interpreter.NewInterpreter(context.Background(), tx, &common.Service{}, nil, nil, nil)
	require.NoError(t, err)

	err = interp.ExecuteWithoutEngineCtx(context.Background(), tx, "TRANSFER OWNERSHIP TO $user", map[string]any{
		"user": defaultCaller,
	}, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: interp,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	// Check if schema already exists before trying to USE it
	testErr := app.Engine.ExecuteWithoutEngineCtx(context.Background(), app.DB, `
		{kwil_erc20_meta}SELECT COUNT(*) FROM reward_instances WHERE 1=0
	`, nil, func(row *common.Row) error {
		return nil
	})

	// Only initialize the extension if the namespace is not found
	if testErr != nil && strings.Contains(testErr.Error(), "namespace not found") {
		err = genesisExec(context.Background(), app)
		require.NoError(t, err)
	}

	return app
}

var lastID = types.NewUUIDV5([]byte("first"))

func newUUID() *types.UUID {
	id := types.NewUUIDV5WithNamespace(*lastID, []byte("next"))
	lastID = &id
	return &id
}

// TestCreateNewRewardInstance tests the createNewRewardInstance function.
func TestCreateNewRewardInstance(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	app := setup(t, tx)

	id := newUUID()
	// Create a userProvidedData object
	chainInfo, _ := chains.GetChainInfoByID("1") // or whichever chain ID you want
	testReward := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      zeroHex,
		DistributionPeriod: 3600,
	}

	err = createNewRewardInstance(ctx, app, testReward)
	require.NoError(t, err)

	pending := &PendingEpoch{
		ID:          newUUID(),
		StartHeight: 10,
		StartTime:   100,
	}
	err = createEpoch(ctx, app, pending, id)
	require.NoError(t, err)

	rewards, err := getStoredRewardInstances(ctx, app)
	require.NoError(t, err)
	require.Len(t, rewards, 1)
	require.Equal(t, testReward.ID, rewards[0].ID)
	require.False(t, rewards[0].synced)
	require.Equal(t, int64(3600), rewards[0].DistributionPeriod)
	require.Equal(t, zeroHex, rewards[0].EscrowAddress)
	require.Equal(t, chainInfo, *rewards[0].ChainInfo)
	require.Equal(t, pending.ID, rewards[0].currentEpoch.ID)
	require.Equal(t, pending.StartHeight, rewards[0].currentEpoch.StartHeight)
	require.Equal(t, pending.StartTime, rewards[0].currentEpoch.StartTime)

	// set synced to true, active to false
	err = setRewardSynced(ctx, app, testReward.ID, 102, &syncedRewardData{
		Erc20Address:  zeroHex,
		Erc20Decimals: 18,
	})
	require.NoError(t, err)
	err = setActiveStatus(ctx, app, testReward.ID, false)
	require.NoError(t, err)

	rewards, err = getStoredRewardInstances(ctx, app)
	require.NoError(t, err)

	require.Len(t, rewards, 1)
	// we will only check the new values
	require.True(t, rewards[0].synced)
	require.False(t, rewards[0].active)
	require.Equal(t, int64(102), rewards[0].syncedAt)
	require.Equal(t, zeroHex, rewards[0].syncedRewardData.Erc20Address)
	require.Equal(t, int64(18), rewards[0].syncedRewardData.Erc20Decimals)

	root := []byte{0x03, 0x04}
	amt, _ := erc20ValueFromBigInt(big.NewInt(100))
	// finalize the epoch
	err = finalizeEpoch(ctx, app, pending.ID, 20, []byte{0x01, 0x02}, root, amt)
	require.NoError(t, err)

	// confirm the epoch
	err = confirmEpoch(ctx, app, root)
	require.NoError(t, err)

	// TODO: we currently do not have queries for reading full epochs.
	// These will get added when we implement the rest of the extension.
}

var zeroHex = ethcommon.HexToAddress("0x0000000000000000000000000000000000000001")

// TestWithdrawalsTableExists verifies that the withdrawals table is created by the schema
// with all expected columns, constraints, and indexes.
func TestWithdrawalsTableExists(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available - this test requires database connection")
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	_ = setup(t, tx) // setup creates the schema

	// 1. Verify table exists and is queryable
	query := `SELECT COUNT(*) FROM kwil_erc20_meta.withdrawals`
	result, err := tx.Execute(ctx, query)
	require.NoError(t, err, "withdrawals table should exist and be queryable")
	require.Len(t, result.Rows, 1, "should have one result row")
	require.Len(t, result.Rows[0], 1, "should have one column")

	// 2. Verify column presence and types
	expectedColumns := map[string]string{
		"epoch_id":     "uuid",
		"recipient":    "bytea",
		"tx_hash":      "bytea",
		"block_number": "bigint",
		"created_at":   "bigint",
		"claimed_at":   "bigint",
		"updated_at":   "bigint",
		"status":       "text",
	}

	columnsQuery := `
		SELECT column_name::text, data_type::text
		FROM information_schema.columns
		WHERE table_schema = 'kwil_erc20_meta'
		  AND table_name = 'withdrawals'
		ORDER BY column_name
	`

	result, err = tx.Execute(ctx, columnsQuery)
	require.NoError(t, err, "should query columns successfully")
	require.GreaterOrEqual(t, len(result.Rows), len(expectedColumns), "should have at least expected columns")

	foundColumns := make(map[string]string)
	for _, row := range result.Rows {
		require.Len(t, row, 2, "each row should have column_name and data_type")
		colName, ok := row[0].(string)
		require.True(t, ok, "column_name should be string")
		dataType, ok := row[1].(string)
		require.True(t, ok, "data_type should be string")
		foundColumns[colName] = dataType
	}

	for colName, expectedType := range expectedColumns {
		actualType, exists := foundColumns[colName]
		require.True(t, exists, "column %s should exist", colName)
		require.Equal(t, expectedType, actualType, "column %s should have type %s", colName, expectedType)
	}

	// 3. Verify primary key constraint on (epoch_id, recipient)
	pkQuery := `
		SELECT
			conname::text,
			pg_get_constraintdef(c.oid)::text as constraint_def
		FROM pg_constraint c
		JOIN pg_namespace n ON n.oid = c.connamespace
		JOIN pg_class cl ON cl.oid = c.conrelid
		WHERE n.nspname = 'kwil_erc20_meta'
		  AND cl.relname = 'withdrawals'
		  AND c.contype = 'p'
	`

	result, err = tx.Execute(ctx, pkQuery)
	require.NoError(t, err, "should query primary key constraint successfully")
	require.Len(t, result.Rows, 1, "should have exactly one primary key constraint")

	if len(result.Rows) > 0 && len(result.Rows[0]) >= 2 {
		constraintDef, ok := result.Rows[0][1].(string)
		require.True(t, ok, "constraint_def should be string")
		require.Contains(t, constraintDef, "epoch_id", "primary key should include epoch_id")
		require.Contains(t, constraintDef, "recipient", "primary key should include recipient")
	}

	// 4. Verify foreign key constraint to epochs table
	fkQuery := `
		SELECT
			conname::text,
			pg_get_constraintdef(c.oid)::text as constraint_def
		FROM pg_constraint c
		JOIN pg_namespace n ON n.oid = c.connamespace
		JOIN pg_class cl ON cl.oid = c.conrelid
		WHERE n.nspname = 'kwil_erc20_meta'
		  AND cl.relname = 'withdrawals'
		  AND c.contype = 'f'
	`

	result, err = tx.Execute(ctx, fkQuery)
	require.NoError(t, err, "should query foreign key constraint successfully")
	require.GreaterOrEqual(t, len(result.Rows), 1, "should have at least one foreign key constraint")

	foundEpochFK := false
	for _, row := range result.Rows {
		if len(row) >= 2 {
			constraintDef, ok := row[1].(string)
			require.True(t, ok, "constraint_def should be string")
			if containsIgnoreCase(constraintDef, "epochs") {
				foundEpochFK = true
				require.Contains(t, constraintDef, "epoch_id", "foreign key should reference epoch_id")
			}
		}
	}
	require.True(t, foundEpochFK, "should have foreign key to epochs table")

	// 5. Verify CHECK constraint on status column
	checkQuery := `
		SELECT
			conname::text,
			pg_get_constraintdef(c.oid)::text as constraint_def
		FROM pg_constraint c
		JOIN pg_namespace n ON n.oid = c.connamespace
		JOIN pg_class cl ON cl.oid = c.conrelid
		WHERE n.nspname = 'kwil_erc20_meta'
		  AND cl.relname = 'withdrawals'
		  AND c.contype = 'c'
	`

	result, err = tx.Execute(ctx, checkQuery)
	require.NoError(t, err, "should query check constraints successfully")
	require.GreaterOrEqual(t, len(result.Rows), 1, "should have at least one check constraint")

	foundStatusCheck := false
	for _, row := range result.Rows {
		if len(row) >= 2 {
			constraintDef, ok := row[1].(string)
			require.True(t, ok, "constraint_def should be string")
			if containsIgnoreCase(constraintDef, "status") {
				foundStatusCheck = true
				// Verify that the CHECK constraint includes all three allowed values
				require.Contains(t, constraintDef, "pending", "status CHECK should allow 'pending'")
				require.Contains(t, constraintDef, "ready", "status CHECK should allow 'ready'")
				require.Contains(t, constraintDef, "claimed", "status CHECK should allow 'claimed'")
			}
		}
	}
	require.True(t, foundStatusCheck, "should have CHECK constraint on status column")

	// 6. Verify indexes exist
	indexQuery := `
		SELECT indexname::text, indexdef::text
		FROM pg_indexes
		WHERE schemaname = 'kwil_erc20_meta'
		  AND tablename = 'withdrawals'
		ORDER BY indexname
	`

	result, err = tx.Execute(ctx, indexQuery)
	require.NoError(t, err, "should query indexes successfully")
	require.GreaterOrEqual(t, len(result.Rows), 3, "should have at least 3 indexes (excluding primary key)")

	expectedIndexes := []string{
		"idx_withdrawals_status",
		"idx_withdrawals_tx_hash",
		"idx_withdrawals_recipient",
	}

	foundIndexes := make(map[string]bool)
	for _, row := range result.Rows {
		if len(row) >= 1 {
			indexName, ok := row[0].(string)
			require.True(t, ok, "index name should be string")
			foundIndexes[indexName] = true
		}
	}

	for _, expectedIdx := range expectedIndexes {
		require.True(t, foundIndexes[expectedIdx], "index %s should exist", expectedIdx)
	}
}

// TestTransactionHistoryTableExists verifies that the transaction_history table is created by the schema.
func TestTransactionHistoryTableExists(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available - this test requires database connection")
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	_ = setup(t, tx) // setup creates the schema

	// 1. Verify table exists
	query := `SELECT COUNT(*) FROM kwil_erc20_meta.transaction_history`
	result, err := tx.Execute(ctx, query)
	require.NoError(t, err, "transaction_history table should exist")

	// 2. Verify column presence and types
	expectedColumns := map[string]string{
		"id":                    "uuid",
		"instance_id":           "uuid",
		"type":                  "text",
		"from_address":          "bytea",
		"to_address":            "bytea",
		"amount":                "numeric",
		"internal_tx_hash":      "bytea",
		"external_tx_hash":      "bytea",
		"status":                "text",
		"block_height":          "bigint",
		"block_timestamp":       "bigint",
		"external_block_height": "bigint",
	}

	columnsQuery := `
		SELECT column_name::text, data_type::text
		FROM information_schema.columns
		WHERE table_schema = 'kwil_erc20_meta'
		  AND table_name = 'transaction_history'
		ORDER BY column_name
	`

	result, err = tx.Execute(ctx, columnsQuery)
	require.NoError(t, err)

	foundColumns := make(map[string]string)
	for _, row := range result.Rows {
		foundColumns[row[0].(string)] = row[1].(string)
	}

	for colName, expectedType := range expectedColumns {
		actualType, exists := foundColumns[colName]
		require.True(t, exists, "column %s should exist", colName)
		require.Equal(t, expectedType, actualType, "column %s should have type %s", colName, expectedType)
	}

	// 3. Verify indexes exist
	indexQuery := `
		SELECT indexname::text
		FROM pg_indexes
		WHERE schemaname = 'kwil_erc20_meta'
		  AND tablename = 'transaction_history'
	`

	result, err = tx.Execute(ctx, indexQuery)
	require.NoError(t, err)

	expectedIndexes := []string{
		"idx_tx_history_from",
		"idx_tx_history_to",
		"idx_tx_history_inst_id",
		"idx_tx_history_type",
	}

	foundIndexes := make(map[string]bool)
	for _, row := range result.Rows {
		foundIndexes[row[0].(string)] = true
	}

	for _, expectedIdx := range expectedIndexes {
		require.True(t, foundIndexes[expectedIdx], "index %s should exist", expectedIdx)
	}
}

// containsIgnoreCase checks if a string contains a substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// TestGetWalletEpochs verifies the getWalletEpochs function correctly filters
// out claimed withdrawals and returns epochs in deterministic order.
func TestGetWalletEpochs(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available - this test requires database connection")
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	app := setup(t, tx)

	// Create a reward instance
	instanceID := newUUID()
	chainInfo, _ := chains.GetChainInfoByID("1")
	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      zeroHex,
		DistributionPeriod: 3600,
	}
	err = createNewRewardInstance(ctx, app, testReward)
	require.NoError(t, err)

	// Create test wallet
	testWallet := ethcommon.HexToAddress("0xF9820f9143699cac6F662B19a4B29E13C9393783")

	// Create 3 epochs with different created_at_block values
	epoch1 := &PendingEpoch{
		ID:          newUUID(),
		StartHeight: 100,
		StartTime:   1000,
	}
	err = createEpoch(ctx, app, epoch1, instanceID)
	require.NoError(t, err)

	epoch2 := &PendingEpoch{
		ID:          newUUID(),
		StartHeight: 200,
		StartTime:   2000,
	}
	err = createEpoch(ctx, app, epoch2, instanceID)
	require.NoError(t, err)

	epoch3 := &PendingEpoch{
		ID:          newUUID(),
		StartHeight: 300,
		StartTime:   3000,
	}
	err = createEpoch(ctx, app, epoch3, instanceID)
	require.NoError(t, err)

	// Finalize and confirm all epochs
	root1 := []byte{0x01, 0x01}
	root2 := []byte{0x02, 0x02}
	root3 := []byte{0x03, 0x03}
	amt, _ := erc20ValueFromBigInt(big.NewInt(100))

	err = finalizeEpoch(ctx, app, epoch1.ID, 110, []byte{0x01}, root1, amt)
	require.NoError(t, err)
	err = finalizeEpoch(ctx, app, epoch2.ID, 210, []byte{0x02}, root2, amt)
	require.NoError(t, err)
	err = finalizeEpoch(ctx, app, epoch3.ID, 310, []byte{0x03}, root3, amt)
	require.NoError(t, err)

	err = confirmEpoch(ctx, app, root1)
	require.NoError(t, err)
	err = confirmEpoch(ctx, app, root2)
	require.NoError(t, err)
	err = confirmEpoch(ctx, app, root3)
	require.NoError(t, err)

	// Add epoch_rewards for the test wallet for all epochs
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epoch_rewards (epoch_id, recipient, amount)
		VALUES ($epoch1, $wallet, $amount),
		       ($epoch2, $wallet, $amount),
		       ($epoch3, $wallet, $amount)
	`, map[string]any{
		"epoch1": epoch1.ID,
		"epoch2": epoch2.ID,
		"epoch3": epoch3.ID,
		"wallet": testWallet.Bytes(),
		"amount": amt,
	}, nil)
	require.NoError(t, err)

	// Test 1: Initially, all 3 epochs should be returned (no withdrawals records)
	var epochsReturned []*Epoch
	err = getWalletEpochs(ctx, app, instanceID, testWallet, false, func(e *Epoch) error {
		epochsReturned = append(epochsReturned, e)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, epochsReturned, 3, "should return all 3 unclaimed epochs")

	// Test 2: Verify deterministic ordering (newest first: epoch3, epoch2, epoch1)
	require.Equal(t, epoch3.ID.String(), epochsReturned[0].ID.String(), "first epoch should be newest (epoch3)")
	require.Equal(t, epoch2.ID.String(), epochsReturned[1].ID.String(), "second epoch should be middle (epoch2)")
	require.Equal(t, epoch1.ID.String(), epochsReturned[2].ID.String(), "third epoch should be oldest (epoch1)")

	// Test 3: Mark epoch2 as 'claimed' in withdrawals table
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO withdrawals (epoch_id, recipient, status, created_at, updated_at, claimed_at)
		VALUES ($epoch2, $wallet, 'claimed', $now, $now, $now)
	`, map[string]any{
		"epoch2": epoch2.ID,
		"wallet": testWallet.Bytes(),
		"now":    2000,
	}, nil)
	require.NoError(t, err)

	// Test 4: Now only 2 epochs should be returned (epoch3 and epoch1, excluding claimed epoch2)
	epochsReturned = nil
	err = getWalletEpochs(ctx, app, instanceID, testWallet, false, func(e *Epoch) error {
		epochsReturned = append(epochsReturned, e)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, epochsReturned, 2, "should return only 2 unclaimed epochs")
	require.Equal(t, epoch3.ID.String(), epochsReturned[0].ID.String(), "first should still be epoch3")
	require.Equal(t, epoch1.ID.String(), epochsReturned[1].ID.String(), "second should be epoch1 (epoch2 filtered out)")

	// Test 5: Mark epoch3 as 'pending' (not claimed) - should still be returned
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO withdrawals (epoch_id, recipient, status, created_at, updated_at)
		VALUES ($epoch3, $wallet, 'pending', $now, $now)
	`, map[string]any{
		"epoch3": epoch3.ID,
		"wallet": testWallet.Bytes(),
		"now":    3000,
	}, nil)
	require.NoError(t, err)

	// Test 6: Should still return 2 epochs (epoch3 with pending, epoch1 with no record)
	epochsReturned = nil
	err = getWalletEpochs(ctx, app, instanceID, testWallet, false, func(e *Epoch) error {
		epochsReturned = append(epochsReturned, e)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, epochsReturned, 2, "should return 2 epochs (pending and no-record)")

	// Test 7: Mark epoch1 as 'ready' - should still be returned
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO withdrawals (epoch_id, recipient, status, created_at, updated_at)
		VALUES ($epoch1, $wallet, 'ready', $now, $now)
	`, map[string]any{
		"epoch1": epoch1.ID,
		"wallet": testWallet.Bytes(),
		"now":    1000,
	}, nil)
	require.NoError(t, err)

	// Test 8: Should still return 2 epochs (both have non-claimed status)
	epochsReturned = nil
	err = getWalletEpochs(ctx, app, instanceID, testWallet, false, func(e *Epoch) error {
		epochsReturned = append(epochsReturned, e)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, epochsReturned, 2, "should return 2 epochs with ready/pending status")

	// Test 9: Mark all as claimed - should return 0 epochs
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE withdrawals
		SET status = 'claimed', claimed_at = $now, updated_at = $now
		WHERE recipient = $wallet
	`, map[string]any{
		"wallet": testWallet.Bytes(),
		"now":    4000,
	}, nil)
	require.NoError(t, err)

	// Test 10: Should return 0 epochs (all claimed)
	epochsReturned = nil
	err = getWalletEpochs(ctx, app, instanceID, testWallet, false, func(e *Epoch) error {
		epochsReturned = append(epochsReturned, e)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, epochsReturned, 0, "should return no epochs when all are claimed")
}
