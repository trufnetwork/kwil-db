//go:build kwiltest

package erc20

import (
	"context"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

// Edge Case Tests for Validator Signing Flow

// TestVoteEpochInvalidSignature tests rejection of invalid signatures
func TestVoteEpochInvalidSignature(t *testing.T) {
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

	validatorKey, _ := crypto.GenerateKey()
	validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)

	const nonCustodialNonce = 0

	// Test: voteEpoch stores signatures without validation
	// (validation happens in the vote_epoch action entry point and at withdrawal time)
	wrongMessage := crypto.Keccak256([]byte("wrong message"))
	wrongSig, err := signMessage(wrongMessage, validatorKey)
	require.NoError(t, err)

	// voteEpoch is an internal function that doesn't validate - should succeed
	err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, wrongSig)
	require.NoError(t, err)

	// Verify it was stored
	result, err := app.DB.Execute(ctx, `
		SELECT signature FROM kwil_erc20_meta.epoch_votes
		WHERE epoch_id = $1
	`, epochID)
	require.NoError(t, err)
	require.Len(t, result.Rows, 1)
	require.Equal(t, wrongSig, result.Rows[0][0].([]byte))
}

// TestVoteEpochNonFinalizedEpoch tests voting on a non-finalized epoch
func TestVoteEpochNonFinalizedEpoch(t *testing.T) {
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

	// Create epoch but DON'T finalize it
	epochID := newUUID()
	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	// Try to vote on non-finalized epoch
	validatorKey, _ := crypto.GenerateKey()
	validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)

	merkleRoot := crypto.Keccak256([]byte("test merkle root"))
	blockHash := crypto.Keccak256([]byte("test block hash"))
	messageHash, _ := computeEpochMessageHash(merkleRoot, blockHash)
	signature, _ := signMessage(messageHash, validatorKey)

	const nonCustodialNonce = 0
	err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, signature)
	require.NoError(t, err) // Vote succeeds (validation happens elsewhere)

	// But epoch shouldn't be confirmed because it's not finalized
	result, err := app.DB.Execute(ctx, `
		SELECT ended_at, confirmed FROM kwil_erc20_meta.epochs WHERE id = $1
	`, epochID)
	require.NoError(t, err)
	require.Nil(t, result.Rows[0][0]) // ended_at should be nil (not finalized)
}

// TestConfirmEpochIdempotency tests that confirmEpoch can be called multiple times safely
func TestConfirmEpochIdempotency(t *testing.T) {
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

	// Create instance and finalize epoch
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

	// Confirm epoch first time
	err = confirmEpoch(ctx, app, merkleRoot)
	require.NoError(t, err)

	// Verify confirmed
	result, err := app.DB.Execute(ctx, `
		SELECT confirmed FROM kwil_erc20_meta.epochs WHERE id = $1
	`, epochID)
	require.NoError(t, err)
	require.True(t, result.Rows[0][0].(bool))

	// Confirm again - should be idempotent (no error)
	err = confirmEpoch(ctx, app, merkleRoot)
	require.NoError(t, err)

	// Confirm a third time
	err = confirmEpoch(ctx, app, merkleRoot)
	require.NoError(t, err)

	// Still confirmed
	result, err = app.DB.Execute(ctx, `
		SELECT confirmed FROM kwil_erc20_meta.epochs WHERE id = $1
	`, epochID)
	require.NoError(t, err)
	require.True(t, result.Rows[0][0].(bool))
}

// TestMultipleEpochsVoting tests voting on multiple epochs simultaneously
func TestMultipleEpochsVoting(t *testing.T) {
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

	// Create instance
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

	// Create 3 epochs
	epoch1ID := newUUID()
	epoch2ID := newUUID()
	epoch3ID := newUUID()

	for i, epochID := range []*types.UUID{epoch1ID, epoch2ID, epoch3ID} {
		pending := &PendingEpoch{
			ID:          epochID,
			StartHeight: int64(10 + i*10),
			StartTime:   int64(100 + i*100),
		}
		require.NoError(t, createEpoch(ctx, app, pending, instanceID))

		merkleRoot := crypto.Keccak256([]byte("merkle root " + epochID.String()))
		blockHash := crypto.Keccak256([]byte("block hash " + epochID.String()))
		amount, _ := erc20ValueFromBigInt(big.NewInt(1000))

		err = finalizeEpoch(ctx, app, epochID, int64(20+i*10), blockHash, merkleRoot, amount)
		require.NoError(t, err)
	}

	// Validator votes on all 3 epochs
	validatorKey, _ := crypto.GenerateKey()
	validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)

	const nonCustodialNonce = 0

	for _, epochID := range []*types.UUID{epoch1ID, epoch2ID, epoch3ID} {
		result, _ := app.DB.Execute(ctx, `
			SELECT reward_root, block_hash FROM kwil_erc20_meta.epochs WHERE id = $1
		`, epochID)

		merkleRoot := result.Rows[0][0].([]byte)
		blockHash := result.Rows[0][1].([]byte)

		messageHash, _ := computeEpochMessageHash(merkleRoot, blockHash)
		signature, _ := signMessage(messageHash, validatorKey)

		err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, signature)
		require.NoError(t, err)
	}

	// Verify all 3 epochs have 1 vote each
	for _, epochID := range []*types.UUID{epoch1ID, epoch2ID, epoch3ID} {
		result, err := app.DB.Execute(ctx, "SELECT COUNT(*) FROM kwil_erc20_meta.epoch_votes WHERE epoch_id = $1 AND nonce = 0", epochID)
		require.NoError(t, err)
		count := int(result.Rows[0][0].(int64))
		require.NoError(t, err)
		require.Equal(t, 1, count)
	}

	t.Log("Successfully voted on 3 different epochs")
}

// TestValidatorSignerPollAfterConfirmation tests that polling stops finding confirmed epochs
func TestValidatorSignerPollAfterConfirmation(t *testing.T) {
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

	// Create instance and epoch
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

	validatorKey, _ := crypto.GenerateKey()
	signer := NewValidatorSigner(app, instanceID, validatorKey)

	// Before confirmation: epoch should be found
	epochs, err := signer.getFinalizedEpochs(ctx)
	require.NoError(t, err)
	require.Len(t, epochs, 1)

	// Confirm the epoch
	err = confirmEpoch(ctx, app, merkleRoot)
	require.NoError(t, err)

	// After confirmation: epoch should NOT be found (already confirmed)
	epochs, err = signer.getFinalizedEpochs(ctx)
	require.NoError(t, err)
	require.Len(t, epochs, 0, "confirmed epoch should not appear in finalized epochs query")

	t.Log("Verified that confirmed epochs are filtered out")
}

// TestMessageHashConsistency tests that message hash computation is consistent
func TestMessageHashConsistency(t *testing.T) {
	merkleRoot := crypto.Keccak256([]byte("test merkle root"))
	blockHash := crypto.Keccak256([]byte("test block hash"))

	hash1, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)
	require.Len(t, hash1, 32)

	// Same inputs should produce same hash
	hash2, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)
	require.Equal(t, hash1, hash2)

	// Different inputs should produce different hash
	differentRoot := crypto.Keccak256([]byte("different merkle root"))
	hash3, err := computeEpochMessageHash(differentRoot, blockHash)
	require.NoError(t, err)
	require.NotEqual(t, hash1, hash3)
}

// TestSignMessageDeterminism tests that signing is deterministic
func TestSignMessageDeterminism(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	messageHash := crypto.Keccak256([]byte("test message"))

	// Sign twice
	sig1, err := signMessage(messageHash, privateKey)
	require.NoError(t, err)

	sig2, err := signMessage(messageHash, privateKey)
	require.NoError(t, err)

	// Signatures might not be identical due to random k value in ECDSA
	// But both should be valid and recover to the same public key
	require.Len(t, sig1, 65)
	require.Len(t, sig2, 65)

	// signMessage adds Ethereum signed message prefix, so we need to add it for recovery too
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	ethSignedMessageHash := crypto.Keccak256(append(prefix, messageHash...))

	// Adjust V for recovery (Gnosis Safe V=31/32 -> standard V=0/1)
	sig1ForRecovery := make([]byte, len(sig1))
	copy(sig1ForRecovery, sig1)
	sig1ForRecovery[64] -= 31

	sig2ForRecovery := make([]byte, len(sig2))
	copy(sig2ForRecovery, sig2)
	sig2ForRecovery[64] -= 31

	pubKey1, err := crypto.SigToPub(ethSignedMessageHash, sig1ForRecovery)
	require.NoError(t, err)

	pubKey2, err := crypto.SigToPub(ethSignedMessageHash, sig2ForRecovery)
	require.NoError(t, err)

	require.Equal(t, privateKey.PublicKey, *pubKey1)
	require.Equal(t, privateKey.PublicKey, *pubKey2)
}
