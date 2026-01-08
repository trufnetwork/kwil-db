//go:build kwiltest

package erc20

import (
	"context"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

// TestListWalletRewards tests the list_wallet_rewards precompile method
// and verifies it returns 10 columns including validator signatures
func TestListWalletRewards(t *testing.T) {
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

	// Setup: Create reward instance
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

	// Setup: Create and finalize epoch
	epochID := newUUID()
	wallet := ethcommon.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	// Load instance into singleton (after epoch creation)
	instances, err := getStoredRewardInstances(ctx, app)
	require.NoError(t, err)
	for _, instance := range instances {
		if instance.ownedBalance == nil {
			instance.ownedBalance, _ = erc20ValueFromBigInt(big.NewInt(0))
		}
		instance.synced = true
		_SINGLETON.instances.Set(*instance.ID, instance)
	}

	// Add balance to reward instance before issuing rewards
	amount, _ := erc20ValueFromBigInt(big.NewInt(1000))
	_, err = app.DB.Execute(ctx, `UPDATE kwil_erc20_meta.reward_instances SET balance = $1 WHERE id = $2`, amount, instanceID)
	require.NoError(t, err)

	// Add reward for wallet
	require.NoError(t, issueReward(ctx, app, instanceID, epochID, wallet, amount))

	// Generate actual merkle root from rewards
	blockHash := crypto.Keccak256([]byte("test block hash"))
	var blockHash32 [32]byte
	copy(blockHash32[:], blockHash)
	_, _, merkleRoot, _, err := genMerkleTreeForEpoch(ctx, app, epochID, testReward.EscrowAddress.Hex(), blockHash32)
	require.NoError(t, err)

	// Finalize epoch with correct merkle root
	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	// Add validator signature
	validatorKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)

	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	signature, err := signMessage(messageHash, validatorKey)
	require.NoError(t, err)

	const nonCustodialNonce = 0
	err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, signature)
	require.NoError(t, err)

	// Confirm epoch
	require.NoError(t, confirmEpoch(ctx, app, merkleRoot))

	// TEST: Call list_wallet_rewards via Engine.Call
	engineCtx := &common.EngineContext{TxContext: &common.TxContext{Ctx: ctx, Caller: defaultCaller}}
	var results [][]any
	_, err = app.Engine.Call(engineCtx, app.DB, RewardMetaExtensionName, "list_wallet_rewards",
		[]any{instanceID, wallet.String(), false}, // with_pending=false
		func(row *common.Row) error {
			results = append(results, row.Values)
			return nil
		},
	)
	require.NoError(t, err)

	// VERIFY: Should return 1 row with 10 columns
	require.Len(t, results, 1, "Should return 1 row for wallet with rewards")
	require.Len(t, results[0], 10, "Should return 10 columns including signatures")

	// VERIFY: Columns match expected types
	row := results[0]
	require.IsType(t, "", row[0], "chain should be TEXT")
	require.IsType(t, "", row[1], "chain_id should be TEXT")
	require.IsType(t, "", row[2], "contract should be TEXT")
	require.IsType(t, int64(0), row[3], "created_at should be INT")
	require.IsType(t, "", row[4], "param_recipient should be TEXT")
	// row[5] is uint256Numeric (complex type)
	require.IsType(t, []byte{}, row[6], "param_block_hash should be BYTEA")
	require.IsType(t, []byte{}, row[7], "param_root should be BYTEA")
	require.IsType(t, [][]byte{}, row[8], "param_proofs should be BYTEA[]")
	require.IsType(t, [][]byte{}, row[9], "param_signatures should be BYTEA[]")

	// VERIFY: Data values are correct
	require.Equal(t, chainInfo.Name.String(), row[0], "chain name should match")
	require.Equal(t, wallet.Hex(), row[4], "recipient should match wallet")
	require.Equal(t, blockHash, row[6], "block hash should match")
	require.Equal(t, merkleRoot, row[7], "merkle root should match")

	// VERIFY: Signatures are present and valid
	signatures := row[9].([][]byte)
	require.Len(t, signatures, 1, "Should have 1 validator signature")
	require.Len(t, signatures[0], 65, "Signature should be 65 bytes (r||s||v)")
	require.Equal(t, signature, signatures[0], "Signature should match stored signature")

	// VERIFY: Signature recovers to validator address
	// Note: signMessage adds Ethereum prefix and hashes again
	// We need to use the prefixed hash for recovery
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	ethSignedMessageHash := crypto.Keccak256(append(prefix, messageHash...))

	sigForRecovery := make([]byte, 65)
	copy(sigForRecovery, signatures[0])
	sigForRecovery[64] -= 27 // Convert V: 27/28 -> 0/1 for recovery

	recoveredPub, err := crypto.SigToPub(ethSignedMessageHash, sigForRecovery)
	require.NoError(t, err)
	recoveredAddr := crypto.PubkeyToAddress(*recoveredPub)
	require.Equal(t, validatorAddr, recoveredAddr, "Signature should recover to validator address")
}

// TestListWalletRewardsNoPending tests that pending epochs are filtered out
// when with_pending=false
func TestListWalletRewardsNoPending(t *testing.T) {
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

	// Setup: Create reward instance
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000dd"),
		DistributionPeriod: 3600,
	}
	require.NoError(t, createNewRewardInstance(ctx, app, testReward))

	// Setup: Create finalized but NOT confirmed epoch
	epochID := newUUID()
	wallet := ethcommon.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	// Load instance into singleton (after epoch creation)
	instances, err := getStoredRewardInstances(ctx, app)
	require.NoError(t, err)
	for _, instance := range instances {
		if instance.ownedBalance == nil {
			instance.ownedBalance, _ = erc20ValueFromBigInt(big.NewInt(0))
		}
		instance.synced = true
		_SINGLETON.instances.Set(*instance.ID, instance)
	}

	// Add balance to reward instance before issuing rewards
	amount, _ := erc20ValueFromBigInt(big.NewInt(2000))
	_, err = app.DB.Execute(ctx, `UPDATE kwil_erc20_meta.reward_instances SET balance = $1 WHERE id = $2`, amount, instanceID)
	require.NoError(t, err)

	// Add reward for wallet
	require.NoError(t, issueReward(ctx, app, instanceID, epochID, wallet, amount))

	// Generate actual merkle root from rewards
	blockHash := crypto.Keccak256([]byte("unconfirmed block hash"))
	var blockHash32 [32]byte
	copy(blockHash32[:], blockHash)
	_, _, merkleRoot, _, err := genMerkleTreeForEpoch(ctx, app, epochID, testReward.EscrowAddress.Hex(), blockHash32)
	require.NoError(t, err)

	// Finalize epoch (but don't confirm it)
	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	// TEST: Call list_wallet_rewards with with_pending=false
	engineCtx := &common.EngineContext{TxContext: &common.TxContext{Ctx: ctx, Caller: defaultCaller}}
	var results [][]any
	_, err = app.Engine.Call(engineCtx, app.DB, RewardMetaExtensionName, "list_wallet_rewards",
		[]any{instanceID, wallet.String(), false}, // with_pending=false
		func(row *common.Row) error {
			results = append(results, row.Values)
			return nil
		},
	)
	require.NoError(t, err)

	// VERIFY: Should return 0 results (epoch not confirmed)
	require.Len(t, results, 0, "Unconfirmed epochs should be filtered out when with_pending=false")

	// TEST: Call list_wallet_rewards with with_pending=true
	var resultsWithPending [][]any
	_, err = app.Engine.Call(engineCtx, app.DB, RewardMetaExtensionName, "list_wallet_rewards",
		[]any{instanceID, wallet.String(), true}, // with_pending=true
		func(row *common.Row) error {
			resultsWithPending = append(resultsWithPending, row.Values)
			return nil
		},
	)
	require.NoError(t, err)

	// VERIFY: Should return 1 result when with_pending=true
	require.Len(t, resultsWithPending, 1, "Unconfirmed epochs should be included when with_pending=true")

	// VERIFY: Signatures may be empty for unconfirmed epoch
	row := resultsWithPending[0]
	signatures := row[9].([][]byte)
	// Unconfirmed epochs may have 0 signatures (that's OK)
	t.Logf("Unconfirmed epoch has %d signatures (0 is expected)", len(signatures))
}

// TestListWalletRewardsMultipleValidators tests multiple validator signatures
// are returned in deterministic order
func TestListWalletRewardsMultipleValidators(t *testing.T) {
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

	// Setup: Create reward instance
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000ee"),
		DistributionPeriod: 3600,
	}
	require.NoError(t, createNewRewardInstance(ctx, app, testReward))

	// Setup: Create and finalize epoch
	epochID := newUUID()
	wallet := ethcommon.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	// Load instance into singleton (after epoch creation)
	instances, err := getStoredRewardInstances(ctx, app)
	require.NoError(t, err)
	for _, instance := range instances {
		if instance.ownedBalance == nil {
			instance.ownedBalance, _ = erc20ValueFromBigInt(big.NewInt(0))
		}
		instance.synced = true
		_SINGLETON.instances.Set(*instance.ID, instance)
	}

	// Add balance to reward instance before issuing rewards
	amount, _ := erc20ValueFromBigInt(big.NewInt(3000))
	_, err = app.DB.Execute(ctx, `UPDATE kwil_erc20_meta.reward_instances SET balance = $1 WHERE id = $2`, amount, instanceID)
	require.NoError(t, err)

	// Add reward for wallet
	require.NoError(t, issueReward(ctx, app, instanceID, epochID, wallet, amount))

	// Generate actual merkle root from rewards
	blockHash := crypto.Keccak256([]byte("multi validator block hash"))
	var blockHash32 [32]byte
	copy(blockHash32[:], blockHash)
	_, _, merkleRoot, _, err := genMerkleTreeForEpoch(ctx, app, epochID, testReward.EscrowAddress.Hex(), blockHash32)
	require.NoError(t, err)

	// Finalize epoch
	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	// Add 3 validator signatures
	const nonCustodialNonce = 0
	var validators []ethcommon.Address
	var signatures [][]byte

	for i := 0; i < 3; i++ {
		validatorKey, err := crypto.GenerateKey()
		require.NoError(t, err)
		validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)
		validators = append(validators, validatorAddr)

		signature, err := signMessage(messageHash, validatorKey)
		require.NoError(t, err)
		signatures = append(signatures, signature)

		err = voteEpoch(ctx, app, epochID, validatorAddr, nonCustodialNonce, signature)
		require.NoError(t, err)
	}

	// Confirm epoch
	require.NoError(t, confirmEpoch(ctx, app, merkleRoot))

	// TEST: Call list_wallet_rewards
	engineCtx := &common.EngineContext{TxContext: &common.TxContext{Ctx: ctx, Caller: defaultCaller}}
	var results [][]any
	_, err = app.Engine.Call(engineCtx, app.DB, RewardMetaExtensionName, "list_wallet_rewards",
		[]any{instanceID, wallet.String(), false}, // with_pending=false
		func(row *common.Row) error {
			results = append(results, row.Values)
			return nil
		},
	)
	require.NoError(t, err)

	// VERIFY: Should return 1 row
	require.Len(t, results, 1, "Should return 1 row")
	row := results[0]

	// VERIFY: Signatures array has 3 elements
	returnedSigs := row[9].([][]byte)
	require.Len(t, returnedSigs, 3, "Should have 3 validator signatures")

	// VERIFY: All signatures are 65 bytes
	for i, sig := range returnedSigs {
		require.Len(t, sig, 65, "Signature %d should be 65 bytes", i)
	}

	// VERIFY: Signatures are ordered deterministically (by voter address)
	// Query to get the expected order
	result, err := app.DB.Execute(ctx, `
		SELECT signature FROM kwil_erc20_meta.epoch_votes
		WHERE epoch_id = $1 AND nonce = $2
		ORDER BY voter
	`, epochID, nonCustodialNonce)
	require.NoError(t, err)
	require.Len(t, result.Rows, 3)

	// Compare returned signatures with database order
	for i := 0; i < 3; i++ {
		expectedSig := result.Rows[i][0].([]byte)
		require.Equal(t, expectedSig, returnedSigs[i], "Signature %d should match database order", i)
	}
}

// TestListWalletRewardsNoRewards tests behavior when wallet has no rewards
func TestListWalletRewardsNoRewards(t *testing.T) {
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

	// Setup: Create reward instance
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000ff"),
		DistributionPeriod: 3600,
	}
	require.NoError(t, createNewRewardInstance(ctx, app, testReward))

	// Create an epoch (required for singleton initialization)
	epochID := newUUID()
	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   100,
	}
	require.NoError(t, createEpoch(ctx, app, pending, instanceID))

	// Load instance into singleton (after epoch creation)
	instances, err := getStoredRewardInstances(ctx, app)
	require.NoError(t, err)
	for _, instance := range instances {
		if instance.ownedBalance == nil {
			instance.ownedBalance, _ = erc20ValueFromBigInt(big.NewInt(0))
		}
		instance.synced = true
		_SINGLETON.instances.Set(*instance.ID, instance)
	}

	// Wallet with no rewards
	wallet := ethcommon.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906")

	// TEST: Call list_wallet_rewards
	engineCtx := &common.EngineContext{TxContext: &common.TxContext{Ctx: ctx, Caller: defaultCaller}}
	var results [][]any
	_, err = app.Engine.Call(engineCtx, app.DB, RewardMetaExtensionName, "list_wallet_rewards",
		[]any{instanceID, wallet.String(), false}, // with_pending=false
		func(row *common.Row) error {
			results = append(results, row.Values)
			return nil
		},
	)
	require.NoError(t, err)

	// VERIFY: Should return 0 results
	require.Len(t, results, 0, "Wallet with no rewards should return empty result")
}

// TestGetEpochSignatures tests the getEpochSignatures helper function
func TestGetEpochSignatures(t *testing.T) {
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

	// Create test epoch
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
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

	// Finalize epoch
	merkleRoot := crypto.Keccak256([]byte("test signatures"))
	blockHash := crypto.Keccak256([]byte("test signatures block"))
	amount, _ := erc20ValueFromBigInt(big.NewInt(5000))
	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	// Add 2 validator signatures with known addresses
	validator1Key, err := crypto.GenerateKey()
	require.NoError(t, err)
	validator1Addr := crypto.PubkeyToAddress(validator1Key.PublicKey)

	validator2Key, err := crypto.GenerateKey()
	require.NoError(t, err)
	validator2Addr := crypto.PubkeyToAddress(validator2Key.PublicKey)

	sig1, err := signMessage(messageHash, validator1Key)
	require.NoError(t, err)

	sig2, err := signMessage(messageHash, validator2Key)
	require.NoError(t, err)

	const nonCustodialNonce = 0
	err = voteEpoch(ctx, app, epochID, validator1Addr, nonCustodialNonce, sig1)
	require.NoError(t, err)

	err = voteEpoch(ctx, app, epochID, validator2Addr, nonCustodialNonce, sig2)
	require.NoError(t, err)

	// TEST: Call getEpochSignatures
	signatures, err := getEpochSignatures(ctx, app, epochID)
	require.NoError(t, err)

	// VERIFY: Returns 2 signatures
	require.Len(t, signatures, 2, "Should return 2 signatures")

	// VERIFY: Each signature is 65 bytes
	for i, sig := range signatures {
		require.Len(t, sig, 65, "Signature %d should be 65 bytes", i)
	}

	// VERIFY: Signatures are in deterministic order (sorted by voter)
	// The order should match the ORDER BY voter clause
	result, err := app.DB.Execute(ctx, `
		SELECT signature FROM kwil_erc20_meta.epoch_votes
		WHERE epoch_id = $1 AND nonce = $2
		ORDER BY voter
	`, epochID, nonCustodialNonce)
	require.NoError(t, err)

	for i := 0; i < 2; i++ {
		expectedSig := result.Rows[i][0].([]byte)
		require.Equal(t, expectedSig, signatures[i], "Signature order should match database ORDER BY voter")
	}
}

// TestGetEpochSignaturesEmpty tests behavior with no signatures
func TestGetEpochSignaturesEmpty(t *testing.T) {
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

	// Create epoch without any signatures
	instanceID := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000bb"),
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

	// Finalize epoch but don't add any signatures
	merkleRoot := crypto.Keccak256([]byte("empty signatures"))
	blockHash := crypto.Keccak256([]byte("empty signatures block"))
	amount, _ := erc20ValueFromBigInt(big.NewInt(6000))
	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	// TEST: Call getEpochSignatures
	signatures, err := getEpochSignatures(ctx, app, epochID)
	require.NoError(t, err)

	// VERIFY: Returns empty slice (not nil, not error)
	require.NotNil(t, signatures, "Should return non-nil slice")
	require.Len(t, signatures, 0, "Should return empty slice for epoch with no signatures")
}

// TestGetEpochSignaturesNonexistentEpoch tests behavior with invalid epoch ID
func TestGetEpochSignaturesNonexistentEpoch(t *testing.T) {
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

	// Use non-existent epoch ID (create a UUID that doesn't exist in DB)
	nonexistentEpochID := newUUID()

	// TEST: Call getEpochSignatures
	signatures, err := getEpochSignatures(ctx, app, nonexistentEpochID)
	require.NoError(t, err, "Should not error for nonexistent epoch")

	// VERIFY: Returns empty slice
	require.Len(t, signatures, 0, "Should return empty slice for nonexistent epoch")
}
