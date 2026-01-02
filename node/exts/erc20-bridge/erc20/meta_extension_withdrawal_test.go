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

// TestSignMessage tests ECDSA signing functionality
func TestSignMessage(t *testing.T) {
	// Generate test key
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	messageHash := crypto.Keccak256([]byte("test message"))

	signature, err := signMessage(messageHash, privateKey)
	require.NoError(t, err)
	require.Len(t, signature, 65, "ECDSA signature should be 65 bytes")

	// Verify the signature
	pubKey, err := crypto.SigToPub(messageHash, signature)
	require.NoError(t, err)
	require.Equal(t, privateKey.PublicKey, *pubKey)
}

// TestCountEpochVotes tests counting validator signatures
func TestCountEpochVotes(t *testing.T) {
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

	// Create test instance and epoch
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

	epochID := newUUID()
	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, id))

	// Count for empty epoch
	count, err := countEpochVotes(ctx, app, epochID)
	require.NoError(t, err)
	require.Equal(t, 0, count)

	// Add validator votes using direct database inserts (storeEpochVote was removed)
	const nonCustodialNonce = 0

	// Add first validator vote
	validator1 := ethcommon.HexToAddress("0x0000000000000000000000000000000000000001")
	_, err = app.DB.Execute(ctx, `
		INSERT INTO kwil_erc20_meta.epoch_votes (epoch_id, voter, nonce, signature)
		VALUES ($1, $2, $3, $4)
	`, epochID, validator1.Bytes(), nonCustodialNonce, []byte("sig1"))
	require.NoError(t, err)

	count, err = countEpochVotes(ctx, app, epochID)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// Add second validator vote
	validator2 := ethcommon.HexToAddress("0x0000000000000000000000000000000000000002")
	_, err = app.DB.Execute(ctx, `
		INSERT INTO kwil_erc20_meta.epoch_votes (epoch_id, voter, nonce, signature)
		VALUES ($1, $2, $3, $4)
	`, epochID, validator2.Bytes(), nonCustodialNonce, []byte("sig2"))
	require.NoError(t, err)

	count, err = countEpochVotes(ctx, app, epochID)
	require.NoError(t, err)
	require.Equal(t, 2, count)

	// Add third validator vote
	validator3 := ethcommon.HexToAddress("0x0000000000000000000000000000000000000003")
	_, err = app.DB.Execute(ctx, `
		INSERT INTO kwil_erc20_meta.epoch_votes (epoch_id, voter, nonce, signature)
		VALUES ($1, $2, $3, $4)
	`, epochID, validator3.Bytes(), nonCustodialNonce, []byte("sig3"))
	require.NoError(t, err)

	count, err = countEpochVotes(ctx, app, epochID)
	require.NoError(t, err)
	require.Equal(t, 3, count)
}
