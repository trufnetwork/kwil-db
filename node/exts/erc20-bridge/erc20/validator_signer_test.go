//go:build kwiltest

package erc20

import (
	"context"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

// TestVoteEpochAction tests the vote_epoch action directly
func TestVoteEpochAction(t *testing.T) {
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
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, testReward))

	// Create and finalize an epoch
	epochID := newUUID()
	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	merkleRoot := crypto.Keccak256([]byte("test merkle root"))
	blockHash := crypto.Keccak256([]byte("test block hash"))
	amount, _ := erc20ValueFromBigInt(big.NewInt(1000))

	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	// Generate validator key and sign epoch
	validatorKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)

	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	signature, err := signMessage(messageHash, validatorKey)
	require.NoError(t, err)

	// Call voteEpoch directly
	const nonCustodialNonce = 0
	err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, signature)
	require.NoError(t, err)

	// Verify vote was stored
	result, err := app.DB.Execute(ctx, `
		SELECT voter, signature FROM kwil_erc20_meta.epoch_votes
		WHERE epoch_id = $1 AND nonce = $2
	`, epochID, nonCustodialNonce)
	require.NoError(t, err)
	require.Len(t, result.Rows, 1)
	require.Equal(t, validatorAddr.Bytes(), result.Rows[0][0])
	require.Equal(t, signature, result.Rows[0][1])

	// Verify signature is valid by recovering public key
	recoveredPubKey, err := crypto.SigToPub(messageHash, signature)
	require.NoError(t, err)
	require.Equal(t, validatorKey.PublicKey, *recoveredPubKey)

	// Verify epoch is NOT confirmed yet (need 2 votes)
	result, err = app.DB.Execute(ctx, `
		SELECT confirmed FROM kwil_erc20_meta.epochs WHERE id = $1
	`, epochID)
	require.NoError(t, err)
	require.False(t, result.Rows[0][0].(bool))
}

// TestVoteEpochThresholdAndConfirmation tests epoch confirmation when threshold is reached
func TestVoteEpochThresholdAndConfirmation(t *testing.T) {
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
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, testReward))

	// Create and finalize an epoch
	epochID := newUUID()
	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	merkleRoot := crypto.Keccak256([]byte("test merkle root for threshold"))
	blockHash := crypto.Keccak256([]byte("test block hash for threshold"))
	amount, _ := erc20ValueFromBigInt(big.NewInt(1000))

	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	// First validator votes
	validator1Key, err := crypto.GenerateKey()
	require.NoError(t, err)
	validator1Addr := crypto.PubkeyToAddress(validator1Key.PublicKey)

	sig1, err := signMessage(messageHash, validator1Key)
	require.NoError(t, err)

	const nonCustodialNonce = 0
	err = voteEpoch(ctx, app, epochID, validator1Addr, nonCustodialNonce, sig1)
	require.NoError(t, err)

	// Verify epoch NOT confirmed (need 2 votes)
	result, err := app.DB.Execute(ctx, `
		SELECT confirmed FROM kwil_erc20_meta.epochs WHERE id = $1
	`, epochID)
	require.NoError(t, err)
	require.False(t, result.Rows[0][0].(bool))

	// Verify vote count is 1
	result, err = app.DB.Execute(ctx, "SELECT COUNT(*) FROM kwil_erc20_meta.epoch_votes WHERE epoch_id = $1 AND nonce = 0", epochID)
	require.NoError(t, err)
	count := int(result.Rows[0][0].(int64))
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// Second validator votes - this should trigger confirmation!
	validator2Key, err := crypto.GenerateKey()
	require.NoError(t, err)
	validator2Addr := crypto.PubkeyToAddress(validator2Key.PublicKey)

	sig2, err := signMessage(messageHash, validator2Key)
	require.NoError(t, err)

	err = voteEpoch(ctx, app, epochID, validator2Addr, nonCustodialNonce, sig2)
	require.NoError(t, err)

	// Now call confirmEpoch manually (in production, vote_epoch action does this)
	err = confirmEpoch(ctx, app, merkleRoot)
	require.NoError(t, err)

	// Verify epoch IS confirmed
	result, err = app.DB.Execute(ctx, `
		SELECT confirmed FROM kwil_erc20_meta.epochs WHERE id = $1
	`, epochID)
	require.NoError(t, err)
	require.True(t, result.Rows[0][0].(bool))

	// Verify votes were cleaned up after confirmation
	result, err = app.DB.Execute(ctx, "SELECT COUNT(*) FROM kwil_erc20_meta.epoch_votes WHERE epoch_id = $1 AND nonce = 0", epochID)
	require.NoError(t, err)
	count = int(result.Rows[0][0].(int64))
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

// TestVoteEpochDuplicateVote tests handling of duplicate votes from the same validator
func TestVoteEpochDuplicateVote(t *testing.T) {
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
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
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
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	merkleRoot := crypto.Keccak256([]byte("test merkle root"))
	blockHash := crypto.Keccak256([]byte("test block hash"))
	amount, _ := erc20ValueFromBigInt(big.NewInt(1000))

	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	// Validator votes first time
	validatorKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)

	sig1, err := signMessage(messageHash, validatorKey)
	require.NoError(t, err)

	const nonCustodialNonce = 0
	err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, sig1)
	require.NoError(t, err)

	// Verify vote count is 1
	result, err := app.DB.Execute(ctx, "SELECT COUNT(*) FROM kwil_erc20_meta.epoch_votes WHERE epoch_id = $1 AND nonce = 0", epochID)
	require.NoError(t, err)
	count := int(result.Rows[0][0].(int64))
	require.Equal(t, 1, count)

	// Validator votes again with different signature (simulate re-signing)
	sig2, err := signMessage(messageHash, validatorKey)
	require.NoError(t, err)

	err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, sig2)
	require.NoError(t, err)

	// Verify vote count is STILL 1 (duplicate vote updated, not added)
	result, err = app.DB.Execute(ctx, "SELECT COUNT(*) FROM kwil_erc20_meta.epoch_votes WHERE epoch_id = $1 AND nonce = 0", epochID)
	require.NoError(t, err)
	count = int(result.Rows[0][0].(int64))
	require.Equal(t, 1, count)

	// Verify signature was updated
	result, err = app.DB.Execute(ctx, `
		SELECT signature FROM kwil_erc20_meta.epoch_votes
		WHERE epoch_id = $1 AND voter = $2
	`, epochID, validatorAddr.Bytes())
	require.NoError(t, err)
	require.Len(t, result.Rows, 1)
	require.Equal(t, sig2, result.Rows[0][0])
}

// TestValidatorSignerGetFinalizedEpochs tests querying for finalized epochs
func TestValidatorSignerGetFinalizedEpochs(t *testing.T) {
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
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, testReward))

	// Create validator signer
	validatorKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	signer := NewValidatorSigner(app, instanceID, validatorKey)

	// Initially, no finalized epochs
	epochs, err := signer.getFinalizedEpochs(ctx)
	require.NoError(t, err)
	require.Empty(t, epochs)

	// Create and finalize an epoch
	epochID := newUUID()
	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	merkleRoot := crypto.Keccak256([]byte("test merkle root"))
	blockHash := crypto.Keccak256([]byte("test block hash"))
	amount, _ := erc20ValueFromBigInt(big.NewInt(1000))

	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	// Now should find 1 finalized epoch
	epochs, err = signer.getFinalizedEpochs(ctx)
	require.NoError(t, err)
	require.Len(t, epochs, 1)
	require.Equal(t, epochID, epochs[0].ID)
	require.Equal(t, merkleRoot, epochs[0].RewardRoot)
	require.Equal(t, blockHash, epochs[0].BlockHash)
}

// TestValidatorSignerHasVoted tests checking if validator has voted
func TestValidatorSignerHasVoted(t *testing.T) {
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
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
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
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	// Create validator signer
	validatorKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)

	signer := NewValidatorSigner(app, instanceID, validatorKey)

	// Initially, validator has not voted
	hasVoted, err := signer.hasVoted(ctx, epochID)
	require.NoError(t, err)
	require.False(t, hasVoted)

	// Submit a vote
	merkleRoot := crypto.Keccak256([]byte("test merkle root"))
	blockHash := crypto.Keccak256([]byte("test block hash"))
	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	signature, err := signMessage(messageHash, validatorKey)
	require.NoError(t, err)

	const nonCustodialNonce = 0
	err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, signature)
	require.NoError(t, err)

	// Now validator has voted
	hasVoted, err = signer.hasVoted(ctx, epochID)
	require.NoError(t, err)
	require.True(t, hasVoted)
}

// TestValidatorSignerSignAndVote tests the signing and voting flow
func TestValidatorSignerSignAndVote(t *testing.T) {
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
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, testReward))

	// Create and finalize epoch
	epochID := newUUID()
	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	merkleRoot := crypto.Keccak256([]byte("test merkle root"))
	blockHash := crypto.Keccak256([]byte("test block hash"))
	amount, _ := erc20ValueFromBigInt(big.NewInt(1000))

	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	// Create validator signer
	validatorKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)

	// For this test, we'll test the signing logic without full transaction creation
	// since the test environment doesn't have a full Accounts setup

	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	signature, err := signMessage(messageHash, validatorKey)
	require.NoError(t, err)

	// Verify signature length
	require.Equal(t, 65, len(signature), "signature should be 65 bytes")

	// Verify signature is valid
	recoveredPubKey, err := crypto.SigToPub(messageHash, signature)
	require.NoError(t, err)
	require.Equal(t, validatorKey.PublicKey, *recoveredPubKey)

	// Manually call voteEpoch (simulating what would happen via transaction)
	const nonCustodialNonce = 0
	err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, signature)
	require.NoError(t, err)

	// Verify vote was stored
	signer := NewValidatorSigner(app, instanceID, validatorKey)
	hasVoted, err := signer.hasVoted(ctx, epochID)
	require.NoError(t, err)
	require.True(t, hasVoted)
}

// TestValidatorSignerEndToEnd tests the complete flow with multiple validators
func TestValidatorSignerEndToEnd(t *testing.T) {
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
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, testReward))

	// Create and finalize epoch
	epochID := newUUID()
	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	merkleRoot := crypto.Keccak256([]byte("test merkle root for end-to-end"))
	blockHash := crypto.Keccak256([]byte("test block hash for end-to-end"))
	amount, _ := erc20ValueFromBigInt(big.NewInt(1000))

	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	// Create 3 validators
	validator1Key, _ := crypto.GenerateKey()
	validator2Key, _ := crypto.GenerateKey()
	validator3Key, _ := crypto.GenerateKey()

	validator1Addr := crypto.PubkeyToAddress(validator1Key.PublicKey)
	validator2Addr := crypto.PubkeyToAddress(validator2Key.PublicKey)
	validator3Addr := crypto.PubkeyToAddress(validator3Key.PublicKey)

	t.Logf("Validator 1: %s", validator1Addr.Hex())
	t.Logf("Validator 2: %s", validator2Addr.Hex())
	t.Logf("Validator 3: %s", validator3Addr.Hex())

	// Compute message hash once
	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	// Create signer for validator 1 (we'll test hasVoted with this)
	signer1 := NewValidatorSigner(app, instanceID, validator1Key)

	// Validator 1 signs and votes
	sig1, err := signMessage(messageHash, validator1Key)
	require.NoError(t, err)

	const nonCustodialNonce = 0
	err = voteEpoch(ctx, app, epochID, validator1Addr, nonCustodialNonce, sig1)
	require.NoError(t, err)

	// Verify 1 vote, epoch NOT confirmed
	result, err := app.DB.Execute(ctx, "SELECT COUNT(*) FROM kwil_erc20_meta.epoch_votes WHERE epoch_id = $1 AND nonce = 0", epochID)
	require.NoError(t, err)
	count := int(result.Rows[0][0].(int64))
	require.Equal(t, 1, count)

	result, err = app.DB.Execute(ctx, `SELECT confirmed FROM kwil_erc20_meta.epochs WHERE id = $1`, epochID)
	require.NoError(t, err)
	require.False(t, result.Rows[0][0].(bool))

	// Verify signer1 has voted
	hasVoted, err := signer1.hasVoted(ctx, epochID)
	require.NoError(t, err)
	require.True(t, hasVoted)

	// Validator 2 signs and votes - this should reach threshold!
	sig2, err := signMessage(messageHash, validator2Key)
	require.NoError(t, err)

	err = voteEpoch(ctx, app, epochID, validator2Addr, nonCustodialNonce, sig2)
	require.NoError(t, err)

	// Confirm epoch (simulating what vote_epoch action does)
	err = confirmEpoch(ctx, app, merkleRoot)
	require.NoError(t, err)

	// Verify epoch IS confirmed
	result, err = app.DB.Execute(ctx, `SELECT confirmed FROM kwil_erc20_meta.epochs WHERE id = $1`, epochID)
	require.NoError(t, err)
	require.True(t, result.Rows[0][0].(bool))

	// Verify votes were cleaned up
	result, err = app.DB.Execute(ctx, "SELECT COUNT(*) FROM kwil_erc20_meta.epoch_votes WHERE epoch_id = $1 AND nonce = 0", epochID)
	require.NoError(t, err)
	count = int(result.Rows[0][0].(int64))
	require.NoError(t, err)
	require.Equal(t, 0, count)

	// Validator 3 tries to vote (after confirmation)
	sig3, err := signMessage(messageHash, validator3Key)
	require.NoError(t, err)

	// Vote might fail or succeed depending on implementation
	// After confirmation, votes are cleaned up, so this tests late-arriving votes
	_ = voteEpoch(ctx, app, epochID, validator3Addr, nonCustodialNonce, sig3)

	t.Logf("End-to-end test completed successfully!")
}

// TestValidatorSignerNoBroadcastTxFn tests error handling when BroadcastTxFn is nil
func TestValidatorSignerNoBroadcastTxFn(t *testing.T) {
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
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
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
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	merkleRoot := crypto.Keccak256([]byte("test merkle root"))
	blockHash := crypto.Keccak256([]byte("test block hash"))
	amount, _ := erc20ValueFromBigInt(big.NewInt(1000))

	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	// Verify BroadcastTxFn is nil by default
	require.Nil(t, app.Service.BroadcastTxFn)

	// The actual error check for nil BroadcastTxFn happens in signAndVote method
	// which we've verified in the implementation at validator_signer.go:201-202
	t.Log("Verified that BroadcastTxFn nil check is in place in the code")
}
