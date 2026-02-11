//go:build kwiltest

package erc20

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/abigen"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

var (
	// Parse TrufNetworkBridge ABI once for all tests
	bridgeABI = func() abi.ABI {
		parsed, err := abi.JSON(strings.NewReader(abigen.TrufNetworkBridgeMetaData.ABI))
		if err != nil {
			panic(err)
		}
		return parsed
	}()

	// Get Withdraw event signature programmatically
	withdrawEventID = bridgeABI.Events["Withdraw"].ID
)

// TestWithdrawalListenerUniqueName tests the withdrawal listener unique name generation
func TestWithdrawalListenerUniqueName(t *testing.T) {
	id := types.MustParseUUID("12345678-1234-1234-1234-123456789012")

	uniqueName := withdrawalListenerUniqueName(*id)
	require.Equal(t, "erc20_withdrawal_listener_12345678-1234-1234-1234-123456789012", uniqueName)

	// Test round-trip
	extractedID, err := idFromWithdrawalListenerUniqueName(uniqueName)
	require.NoError(t, err)
	require.Equal(t, id, extractedID)
}

// TestIdFromWithdrawalListenerUniqueName_InvalidName tests error handling for invalid names
func TestIdFromWithdrawalListenerUniqueName_InvalidName(t *testing.T) {
	_, err := idFromWithdrawalListenerUniqueName("invalid_name")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid withdrawal listener name")
}

// TestApplyWithdrawalLog_InvalidData tests validation logic for invalid withdrawal events
func TestApplyWithdrawalLog_InvalidData(t *testing.T) {
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

	app := setup(t, tx)
	id := newUUID()

	// Helper to pad amount to 32 bytes for ABI encoding
	padAmount := func(amount *big.Int) []byte {
		var data [32]byte
		amountBytes := amount.Bytes()
		copy(data[32-len(amountBytes):], amountBytes)
		return data[:]
	}

	tests := []struct {
		name      string
		log       ethtypes.Log
		wantError string
	}{
		{
			name: "zero recipient address",
			log: ethtypes.Log{
				Topics: []ethcommon.Hash{
					withdrawEventID,  // Programmatically derived from ABI
					ethcommon.Hash{}, // zero address
					{0x01, 0x02, 0x03},
				},
				Data:        padAmount(big.NewInt(100)),
				BlockNumber: 12345,
				TxHash:      ethcommon.HexToHash("0xabcd"),
			},
			wantError: "zero recipient address",
		},
		{
			name: "empty kwilBlockHash",
			log: ethtypes.Log{
				Topics: []ethcommon.Hash{
					withdrawEventID, // Programmatically derived from ABI
					ethcommon.BytesToHash(ethcommon.HexToAddress("0xcc").Bytes()),
					{}, // empty kwilBlockHash
				},
				Data:        padAmount(big.NewInt(100)),
				BlockNumber: 12345,
				TxHash:      ethcommon.HexToHash("0xabcd"),
			},
			wantError: "empty kwilBlockHash",
		},
		{
			name: "zero block number",
			log: ethtypes.Log{
				Topics: []ethcommon.Hash{
					withdrawEventID, // Programmatically derived from ABI
					ethcommon.BytesToHash(ethcommon.HexToAddress("0xcc").Bytes()),
					{0x01, 0x02, 0x03},
				},
				Data:        padAmount(big.NewInt(100)),
				BlockNumber: 0, // zero block number
				TxHash:      ethcommon.HexToHash("0xabcd"),
			},
			wantError: "zero block number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := applyWithdrawalLog(ctx, app, id, tt.log, 250)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

// TestApplyWithdrawalLog_HappyPath tests the basic withdrawal status update flow
func TestApplyWithdrawalLog_HappyPath(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available - this test requires database connection")
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Reset singletons for test isolation
	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	app := setup(t, tx)

	// Create test instance
	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, testReward))
	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
		Erc20Decimals: 18,
	}))

	// Create epoch with a specific block_hash
	kwilBlockHash := [32]byte{0xaa, 0xbb, 0xcc}
	epochID := newUUID()

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, id))

	// Finalize the epoch with the block_hash
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE epochs
		SET ended_at = 200,
		    block_hash = $block_hash
		WHERE id = $id
	`, map[string]any{
		"id":         epochID,
		"block_hash": kwilBlockHash[:],
	}, nil)
	require.NoError(t, err)

	// Create a withdrawal record
	recipient := ethcommon.HexToAddress("0x00000000000000000000000000000000000000dd")
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO withdrawals (epoch_id, recipient, status, created_at, updated_at)
		VALUES ($epoch_id, $recipient, 'ready', 1000, 1000)
	`, map[string]any{
		"epoch_id":  epochID,
		"recipient": recipient.Bytes(),
	}, nil)
	require.NoError(t, err)

	// Create mock Withdraw event
	// Pad amount to 32 bytes for ABI encoding
	amount := big.NewInt(1_500_000_000_000_000_000)
	var amountData [32]byte
	amountBytes := amount.Bytes()
	copy(amountData[32-len(amountBytes):], amountBytes)

	withdrawLog := ethtypes.Log{
		Topics: []ethcommon.Hash{
			withdrawEventID, // Programmatically derived from ABI
			ethcommon.BytesToHash(recipient.Bytes()),
			kwilBlockHash,
		},
		Data:        amountData[:],
		BlockNumber: 12345,
		TxHash:      ethcommon.HexToHash("0xabcd1234"),
	}

	// Apply the withdrawal log
	kwilBlockHeight := int64(250)
	err = applyWithdrawalLog(ctx, app, id, withdrawLog, kwilBlockHeight)
	require.NoError(t, err)

	// Verify withdrawal status was updated to 'claimed'
	var status string
	var claimedAt *int64
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}SELECT status, claimed_at
		FROM withdrawals
		WHERE epoch_id = $epoch_id AND recipient = $recipient
	`, map[string]any{
		"epoch_id":  epochID,
		"recipient": recipient.Bytes(),
	}, func(row *common.Row) error {
		status = row.Values[0].(string)
		if row.Values[1] != nil {
			val := row.Values[1].(int64)
			claimedAt = &val
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "claimed", status)
	require.NotNil(t, claimedAt)
	require.Equal(t, kwilBlockHeight, *claimedAt)
}

// TestUpdateWithdrawalStatus_NoMatchingRow verifies idempotency when no withdrawal record matches
func TestUpdateWithdrawalStatus_NoMatchingRow(t *testing.T) {
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

	app := setup(t, tx)

	// Create test instance
	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, testReward))
	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
		Erc20Decimals: 18,
	}))

	// Call updateWithdrawalStatus with non-existent data (should not error - idempotent)
	recipient := ethcommon.HexToAddress("0x00000000000000000000000000000000000000dd")
	kwilBlockHash := [32]byte{0x01, 0x02, 0x03}
	txHash := []byte{0x11, 0x22}
	blockNumber := int64(12345)
	claimedAt := int64(2000)

	err = updateWithdrawalStatus(ctx, app, id, recipient, kwilBlockHash, txHash, blockNumber, claimedAt)
	require.NoError(t, err, "should be idempotent when no matching withdrawal")
}

// TestApplyWithdrawalLog_CreatesRecordFromScratch verifies that applyWithdrawalLog creates
// a withdrawal record when none exists (the production scenario that was previously broken)
func TestApplyWithdrawalLog_CreatesRecordFromScratch(t *testing.T) {
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

	app := setup(t, tx)

	// Create test instance
	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, testReward))
	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
		Erc20Decimals: 18,
	}))

	// Create epoch with a specific block_hash
	kwilBlockHash := [32]byte{0xaa, 0xbb, 0xcc}
	epochID := newUUID()

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, id))

	// Finalize the epoch with the block_hash
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE epochs
		SET ended_at = 200,
		    block_hash = $block_hash
		WHERE id = $id
	`, map[string]any{
		"id":         epochID,
		"block_hash": kwilBlockHash[:],
	}, nil)
	require.NoError(t, err)

	// CRITICAL: Do NOT create a withdrawal record (this is the production scenario!)
	// In production, no code creates withdrawal records - the listener should create them

	// Verify withdrawals table is empty for this epoch
	var count int64
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}SELECT COUNT(*) FROM withdrawals WHERE epoch_id = $epoch_id
	`, map[string]any{
		"epoch_id": epochID,
	}, func(row *common.Row) error {
		count = row.Values[0].(int64)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, int64(0), count, "withdrawals table should be empty initially")

	// Create mock Withdraw event
	recipient := ethcommon.HexToAddress("0x00000000000000000000000000000000000000dd")
	amount := big.NewInt(1_500_000_000_000_000_000)
	var amountData [32]byte
	amountBytes := amount.Bytes()
	copy(amountData[32-len(amountBytes):], amountBytes)

	withdrawLog := ethtypes.Log{
		Topics: []ethcommon.Hash{
			withdrawEventID,
			ethcommon.BytesToHash(recipient.Bytes()),
			kwilBlockHash,
		},
		Data:        amountData[:],
		BlockNumber: 12345,
		TxHash:      ethcommon.HexToHash("0xabcd1234"),
	}

	// Apply the withdrawal log (should CREATE the record from scratch)
	kwilBlockHeight := int64(250)
	err = applyWithdrawalLog(ctx, app, id, withdrawLog, kwilBlockHeight)
	require.NoError(t, err)

	// Verify withdrawal record was CREATED with status='claimed'
	var status string
	var claimedAt *int64
	var txHash []byte
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}SELECT status, claimed_at, tx_hash
		FROM withdrawals
		WHERE epoch_id = $epoch_id AND recipient = $recipient
	`, map[string]any{
		"epoch_id":  epochID,
		"recipient": recipient.Bytes(),
	}, func(row *common.Row) error {
		status = row.Values[0].(string)
		if row.Values[1] != nil {
			val := row.Values[1].(int64)
			claimedAt = &val
		}
		if row.Values[2] != nil {
			txHash = row.Values[2].([]byte)
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "claimed", status, "withdrawal should be created with status='claimed'")
	require.NotNil(t, claimedAt, "claimed_at should be set")
	require.Equal(t, kwilBlockHeight, *claimedAt)
	require.NotNil(t, txHash, "tx_hash should be set")
	require.Equal(t, withdrawLog.TxHash.Bytes(), txHash)
}

// TestApplyWithdrawalLog_Idempotent verifies that applying the same withdrawal log twice is safe
func TestApplyWithdrawalLog_Idempotent(t *testing.T) {
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

	app := setup(t, tx)

	// Create test instance and epoch (same as happy path)
	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, testReward))
	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
		Erc20Decimals: 18,
	}))

	kwilBlockHash := [32]byte{0xaa, 0xbb, 0xcc}
	epochID := newUUID()

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, id))

	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE epochs
		SET ended_at = 200,
		    block_hash = $block_hash
		WHERE id = $id
	`, map[string]any{
		"id":         epochID,
		"block_hash": kwilBlockHash[:],
	}, nil)
	require.NoError(t, err)

	recipient := ethcommon.HexToAddress("0x00000000000000000000000000000000000000dd")
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO withdrawals (epoch_id, recipient, status, created_at, updated_at)
		VALUES ($epoch_id, $recipient, 'ready', 1000, 1000)
	`, map[string]any{
		"epoch_id":  epochID,
		"recipient": recipient.Bytes(),
	}, nil)
	require.NoError(t, err)

	// Pad amount to 32 bytes for ABI encoding
	amount := big.NewInt(1_500_000_000_000_000_000)
	var amountData [32]byte
	amountBytes := amount.Bytes()
	copy(amountData[32-len(amountBytes):], amountBytes)

	withdrawLog := ethtypes.Log{
		Topics: []ethcommon.Hash{
			withdrawEventID, // Programmatically derived from ABI
			ethcommon.BytesToHash(recipient.Bytes()),
			kwilBlockHash,
		},
		Data:        amountData[:],
		BlockNumber: 12345,
		TxHash:      ethcommon.HexToHash("0xabcd1234"),
	}

	kwilBlockHeight := int64(250)

	// Apply the first time
	err = applyWithdrawalLog(ctx, app, id, withdrawLog, kwilBlockHeight)
	require.NoError(t, err)

	// Apply the second time (should not error - idempotent)
	err = applyWithdrawalLog(ctx, app, id, withdrawLog, kwilBlockHeight)
	require.NoError(t, err, "applying withdrawal log twice should be idempotent")

	// Verify status is still 'claimed'
	var status string
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}SELECT status
		FROM withdrawals
		WHERE epoch_id = $epoch_id AND recipient = $recipient
	`, map[string]any{
		"epoch_id":  epochID,
		"recipient": recipient.Bytes(),
	}, func(row *common.Row) error {
		status = row.Values[0].(string)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "claimed", status)
}

// ============================================================================
// Validator Signing Tests
// ============================================================================

// TestComputeEpochMessageHash tests the message hash computation for epoch signing
func TestComputeEpochMessageHash(t *testing.T) {
	merkleRoot := crypto.Keccak256([]byte("test merkle root"))
	blockHash := crypto.Keccak256([]byte("test block hash"))

	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)
	require.Len(t, messageHash, 32)

	// Verify the hash is deterministic
	messageHash2, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)
	require.Equal(t, messageHash, messageHash2)

	// Verify different inputs produce different hashes
	differentRoot := crypto.Keccak256([]byte("different root"))
	messageHash3, err := computeEpochMessageHash(differentRoot, blockHash)
	require.NoError(t, err)
	require.NotEqual(t, messageHash, messageHash3)
}

// TestSignMessage tests ECDSA signing functionality with Ethereum signed message prefix
func TestSignMessage(t *testing.T) {
	// Generate test key
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	messageHash := crypto.Keccak256([]byte("test message"))

	signature, err := signMessage(messageHash, privateKey)
	require.NoError(t, err)
	require.Len(t, signature, 65, "ECDSA signature should be 65 bytes")

	// Verify the signature (signMessage adds Ethereum signed message prefix)
	prefix := []byte(EthereumSignedMessagePrefix)
	ethSignedMessageHash := crypto.Keccak256(append(prefix, messageHash...))

	// Adjust V for recovery (standard Ethereum V=27/28 -> internal V=0/1)
	sigForRecovery := make([]byte, len(signature))
	copy(sigForRecovery, signature)
	sigForRecovery[64] -= 27

	pubKey, err := crypto.SigToPub(ethSignedMessageHash, sigForRecovery)
	require.NoError(t, err)
	require.Equal(t, privateKey.PublicKey, *pubKey)
}

// TestWithdrawalHistory verifies the full lifecycle of withdrawal logging in transaction_history
func TestWithdrawalHistory(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available")
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	app := setup(t, tx)

	// 1. Setup instance and epoch
	id := newUUID()
	chainInfo, _ := chains.GetChainInfoByID("1")

	upd := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}
	require.NoError(t, createNewRewardInstance(ctx, app, upd))
	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	}))

	epochID := newUUID()
	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, id))

	// Set the singleton's current epoch for the instance
	getSingleton().instances.Set(*id, &rewardExtensionInfo{
		userProvidedData: *upd,
		currentEpoch:     pending,
		synced:           true,
		active:           true,
	})

	// 2. Initiate withdrawal (lockAndIssueTokens)
	from := ethcommon.HexToAddress("0x0000000000000000000000000000000000000011").Hex()
	recipient := ethcommon.HexToAddress("0x0000000000000000000000000000000000000022")
	amount := types.MustParseDecimalExplicit("10.5", 78, 0)

	// Give user balance first
	require.NoError(t, creditBalance(ctx, app, id, ethcommon.HexToAddress(from), types.MustParseDecimalExplicit("100", 78, 0)))

	block := &common.BlockContext{
		Height:    500,
		Timestamp: 1600000500,
	}

	engCtx := &common.EngineContext{
		TxContext: &common.TxContext{
			Ctx:  ctx,
			TxID: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
	}

	require.NoError(t, getSingleton().lockAndIssueTokens(engCtx, app, id, from, recipient.Hex(), amount, block))

	// Verify history record created with 'pending_epoch'
	res, err := app.DB.Execute(ctx, "SELECT status, amount, epoch_id FROM kwil_erc20_meta.transaction_history WHERE instance_id = $1", id)
	require.NoError(t, err)
	require.Len(t, res.Rows, 1)
	require.Equal(t, "pending_epoch", res.Rows[0][0])
	require.Equal(t, amount.String(), res.Rows[0][1].(*types.Decimal).String())
	require.Equal(t, epochID.String(), res.Rows[0][2].(*types.UUID).String())

	// 3. Finalize epoch (simulating time passing)
	kwilBlockHash := [32]byte{0xde, 0xad, 0xbe, 0xef}
	_, err = app.DB.Execute(ctx, "UPDATE kwil_erc20_meta.epochs SET block_hash = $1, ended_at = 600 WHERE id = $2", kwilBlockHash[:], epochID)
	require.NoError(t, err)

	// 4. Claim withdrawal (applyWithdrawalLog)
	externalTxHash := ethcommon.HexToHash("0xabc")
	withdrawLog := ethtypes.Log{
		Topics: []ethcommon.Hash{
			withdrawEventID,
			ethcommon.BytesToHash(recipient.Bytes()),
			kwilBlockHash,
		},
		Data:        make([]byte, 32), // amount not used by update logic
		BlockNumber: 9999,
		TxHash:      externalTxHash,
	}

	err = applyWithdrawalLog(ctx, app, id, withdrawLog, 700)
	require.NoError(t, err)

	// Verify history record updated to 'claimed'
	res, err = app.DB.Execute(ctx, "SELECT status, external_tx_hash, external_block_height FROM kwil_erc20_meta.transaction_history WHERE instance_id = $1", id)
	require.NoError(t, err)
	require.Len(t, res.Rows, 1)
	require.Equal(t, "claimed", res.Rows[0][0])
	require.Equal(t, externalTxHash.Bytes(), res.Rows[0][1])
	require.Equal(t, int64(9999), res.Rows[0][2])
}
