//go:build kwiltest

package erc20

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

// TestDuplicateWithdrawalsSameEpoch tests that multiple withdrawals by same recipient
// in same epoch aggregate correctly (ON CONFLICT DO UPDATE)
func TestDuplicateWithdrawalsSameEpoch(t *testing.T) {
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
	instanceID := newUUID()
	epochID := newUUID()

	// Create instance and epoch
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      common.HexToAddress("0x1234"),
		DistributionPeriod: 3600,
	}
	err = createNewRewardInstance(ctx, app, testReward)
	require.NoError(t, err)

	err = setRewardSynced(ctx, app, instanceID, 1, &syncedRewardData{
		Erc20Address:  common.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	})
	require.NoError(t, err)

	// Set initial balance for testing (1 billion tokens)
	testBalance, err := erc20ValueFromBigInt(big.NewInt(1000000000))
	require.NoError(t, err)
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE reward_instances
		SET balance = $balance
		WHERE id = $instance_id
	`, map[string]any{
		"instance_id": instanceID,
		"balance":     testBalance,
	}, nil)
	require.NoError(t, err)

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   1000,
	}
	err = createEpoch(ctx, app, pending, instanceID)
	require.NoError(t, err)

	recipient := common.HexToAddress("0xABCD")
	rewardID := instanceID

	// First withdrawal: 100 tokens
	amount1, err := erc20ValueFromBigInt(big.NewInt(100))
	require.NoError(t, err)
	err = issueReward(ctx, app, rewardID, epochID, recipient, amount1)
	require.NoError(t, err)

	// Second withdrawal by SAME recipient: 50 tokens
	amount2, err := erc20ValueFromBigInt(big.NewInt(50))
	require.NoError(t, err)
	err = issueReward(ctx, app, rewardID, epochID, recipient, amount2)
	require.NoError(t, err)

	// Third withdrawal: 25 tokens
	amount3, err := erc20ValueFromBigInt(big.NewInt(25))
	require.NoError(t, err)
	err = issueReward(ctx, app, rewardID, epochID, recipient, amount3)
	require.NoError(t, err)

	// Query rewards
	var rewards []*EpochReward
	err = getRewardsForEpoch(ctx, app, epochID, func(reward *EpochReward) error {
		rewards = append(rewards, reward)
		return nil
	})
	require.NoError(t, err)

	// VERIFY: Only ONE row exists (not three)
	require.Len(t, rewards, 1, "Should have exactly 1 aggregated reward, not 3 separate rows")

	// VERIFY: Amount is sum of all withdrawals (100 + 50 + 25 = 175)
	expectedAmount, err := erc20ValueFromBigInt(big.NewInt(175))
	require.NoError(t, err)
	require.Equal(t, recipient.Bytes(), rewards[0].Recipient.Bytes())
	cmp, err := rewards[0].Amount.Cmp(expectedAmount)
	require.NoError(t, err)
	require.Equal(t, 0, cmp, "Amount should be 175 (100+50+25)")
}

// TestMerkleTreeDeterminismWithShuffledRewards tests that Merkle tree
// produces same root regardless of reward insertion order
func TestMerkleTreeDeterminismWithShuffledRewards(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available")
	}
	defer db.Close()

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	// Test data: 5 different recipients with different amounts
	type withdrawal struct {
		recipient common.Address
		amount    string
	}

	testWithdrawals := []withdrawal{
		{common.HexToAddress("0x1111111111111111111111111111111111111111"), "1000"},
		{common.HexToAddress("0x2222222222222222222222222222222222222222"), "5000"},
		{common.HexToAddress("0x3333333333333333333333333333333333333333"), "250"},
		{common.HexToAddress("0x4444444444444444444444444444444444444444"), "7500"},
		{common.HexToAddress("0x5555555555555555555555555555555555555555"), "100"},
	}

	escrowAddr := "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
	var blockHash [32]byte
	copy(blockHash[:], crypto.Keccak256([]byte("test-block")))

	// Test 10 different random orderings
	merkleRoots := make(map[string]int)

	for iteration := 0; iteration < 10; iteration++ {
		// Create fresh transaction for each iteration
		tx, err := db.BeginTx(ctx)
		require.NoError(t, err)

		app := setup(t, tx)
		instanceID := newUUID()
		epochID := newUUID()

		// Create instance and epoch
		chainInfo, ok := chains.GetChainInfoByID("1")
		require.True(t, ok)

		testReward := &userProvidedData{
			ID:                 instanceID,
			ChainInfo:          &chainInfo,
			EscrowAddress:      common.HexToAddress("0x1234"),
			DistributionPeriod: 3600,
		}
		err = createNewRewardInstance(ctx, app, testReward)
		require.NoError(t, err)

		pending := &PendingEpoch{
			ID:          epochID,
			StartHeight: 10,
			StartTime:   1000,
		}
		err = createEpoch(ctx, app, pending, instanceID)
		require.NoError(t, err)

		// Shuffle withdrawal order randomly
		shuffled := make([]withdrawal, len(testWithdrawals))
		copy(shuffled, testWithdrawals)
		rand.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		// Insert in shuffled order
		for _, w := range shuffled {
			amountBig := new(big.Int)
			_, ok := amountBig.SetString(w.amount, 10)
			require.True(t, ok, "failed to parse amount")
			amount, err := erc20ValueFromBigInt(amountBig)
			require.NoError(t, err)
			err = issueReward(ctx, app, instanceID, epochID, w.recipient, amount)
			require.NoError(t, err)
		}

		// Generate Merkle tree
		leafNum, _, root, total, err := genMerkleTreeForEpoch(ctx, app, epochID, escrowAddr, blockHash)
		require.NoError(t, err)
		require.Equal(t, 5, leafNum, "Should have 5 leaves")

		// Record root (convert to hex string for map key)
		rootHex := common.Bytes2Hex(root)
		merkleRoots[rootHex]++

		// Verify total is always same
		expectedTotal := big.NewInt(13850) // 1000+5000+250+7500+100
		require.Equal(t, 0, expectedTotal.Cmp(total), "Total should always be 13850")

		tx.Rollback(ctx)
	}

	// CRITICAL VERIFICATION: All 10 iterations produced SAME Merkle root
	require.Len(t, merkleRoots, 1, "All iterations must produce identical Merkle root regardless of insertion order")

	for rootHex, count := range merkleRoots {
		t.Logf("Merkle root (all iterations): 0x%s (count: %d)", rootHex, count)
		require.Equal(t, 10, count, "All 10 iterations should produce same root")
	}
}

// TestOrderBySufficiencyForDuplicateAmounts tests that ORDER BY works correctly
// even when multiple recipients have same amount
func TestOrderBySufficiencyForDuplicateAmounts(t *testing.T) {
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
	instanceID := newUUID()
	epochID := newUUID()

	// Create instance and epoch
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      common.HexToAddress("0x1234"),
		DistributionPeriod: 3600,
	}
	err = createNewRewardInstance(ctx, app, testReward)
	require.NoError(t, err)

	err = setRewardSynced(ctx, app, instanceID, 1, &syncedRewardData{
		Erc20Address:  common.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	})
	require.NoError(t, err)

	// Set initial balance for testing (1 billion tokens)
	testBalance, err := erc20ValueFromBigInt(big.NewInt(1000000000))
	require.NoError(t, err)
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE reward_instances
		SET balance = $balance
		WHERE id = $instance_id
	`, map[string]any{
		"instance_id": instanceID,
		"balance":     testBalance,
	}, nil)
	require.NoError(t, err)

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   1000,
	}
	err = createEpoch(ctx, app, pending, instanceID)
	require.NoError(t, err)

	// Create 5 recipients with SAME amount (100 tokens each)
	// This tests if ORDER BY recipient is sufficient when amounts are equal
	recipients := []common.Address{
		common.HexToAddress("0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"),
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		common.HexToAddress("0x5555555555555555555555555555555555555555"),
		common.HexToAddress("0x9999999999999999999999999999999999999999"),
	}

	amount, err := erc20ValueFromBigInt(big.NewInt(100))
	require.NoError(t, err)

	// Insert in random order
	for _, recipient := range recipients {
		err = issueReward(ctx, app, instanceID, epochID, recipient, amount)
		require.NoError(t, err)
	}

	// Query rewards multiple times
	var firstOrdering []string
	for i := 0; i < 5; i++ {
		var rewards []*EpochReward
		err = getRewardsForEpoch(ctx, app, epochID, func(reward *EpochReward) error {
			rewards = append(rewards, reward)
			return nil
		})
		require.NoError(t, err)
		require.Len(t, rewards, 5)

		// Convert to string slice for comparison
		var ordering []string
		for _, r := range rewards {
			ordering = append(ordering, r.Recipient.Hex())
		}

		if i == 0 {
			firstOrdering = ordering
		} else {
			// VERIFY: Order is IDENTICAL across multiple queries
			require.Equal(t, firstOrdering, ordering, "ORDER BY must return consistent order across queries")
		}
	}

	// VERIFY: Order is lexicographic by recipient address (ascending)
	expectedOrder := []string{
		"0x1111111111111111111111111111111111111111",
		"0x5555555555555555555555555555555555555555",
		"0x9999999999999999999999999999999999999999",
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // lowercase in Ethereum
		"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}

	require.Equal(t, expectedOrder, firstOrdering, "Order should be lexicographic by recipient address")
}

// TestVoteOrderingDeterminism tests that getEpochSignatures returns
// signatures in consistent order
func TestVoteOrderingDeterminism(t *testing.T) {
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
	instanceID := newUUID()
	epochID := newUUID()

	// Create instance and epoch
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      common.HexToAddress("0x1234"),
		DistributionPeriod: 3600,
	}
	err = createNewRewardInstance(ctx, app, testReward)
	require.NoError(t, err)

	err = setRewardSynced(ctx, app, instanceID, 1, &syncedRewardData{
		Erc20Address:  common.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	})
	require.NoError(t, err)

	// Set initial balance for testing (1 billion tokens)
	testBalance, err := erc20ValueFromBigInt(big.NewInt(1000000000))
	require.NoError(t, err)
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE reward_instances
		SET balance = $balance
		WHERE id = $instance_id
	`, map[string]any{
		"instance_id": instanceID,
		"balance":     testBalance,
	}, nil)
	require.NoError(t, err)

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   1000,
	}
	err = createEpoch(ctx, app, pending, instanceID)
	require.NoError(t, err)

	// Finalize epoch
	merkleRoot := crypto.Keccak256([]byte("test-merkle"))
	blockHash := crypto.Keccak256([]byte("test-block"))
	amount, err := erc20ValueFromBigInt(big.NewInt(1000))
	require.NoError(t, err)
	err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
	require.NoError(t, err)

	// Create message hash for signing
	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)
	prefix := []byte(EthereumSignedMessagePrefix)
	ethSignedMessageHash := crypto.Keccak256(append(prefix, messageHash...))

	// Create 5 validators with different addresses (inserted in random order)
	type validatorVote struct {
		key       *ecdsa.PrivateKey
		address   common.Address
		signature []byte
	}

	validators := make([]validatorVote, 5)
	for i := 0; i < 5; i++ {
		key, err := crypto.GenerateKey()
		require.NoError(t, err)
		addr := crypto.PubkeyToAddress(key.PublicKey)

		sig, err := signMessage(ethSignedMessageHash, key)
		require.NoError(t, err)

		validators[i] = validatorVote{
			key:       key,
			address:   addr,
			signature: sig,
		}
	}

	// Insert votes in RANDOM order
	rand.Shuffle(len(validators), func(i, j int) {
		validators[i], validators[j] = validators[j], validators[i]
	})

	const nonCustodialNonce = 0
	for _, v := range validators {
		err = voteEpoch(ctx, app, epochID, v.address, nonCustodialNonce, v.signature)
		require.NoError(t, err)
	}

	// Query signatures multiple times
	var firstOrdering []string
	for i := 0; i < 5; i++ {
		signatures, err := getEpochSignatures(ctx, app, epochID)
		require.NoError(t, err)
		require.Len(t, signatures, 5)

		// Convert to hex strings for comparison
		var ordering []string
		for _, sig := range signatures {
			ordering = append(ordering, common.Bytes2Hex(sig))
		}

		if i == 0 {
			firstOrdering = ordering
		} else {
			// VERIFY: Order is IDENTICAL across multiple queries
			require.Equal(t, firstOrdering, ordering, "Signature order must be consistent across queries")
		}
	}
}

// TestBFTThresholdEdgeCases tests voting threshold edge cases
func TestBFTThresholdEdgeCases(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available")
	}
	defer db.Close()

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	testCases := []struct {
		name           string
		validatorPower []int64
		voterIndices   []int // which validators vote
		shouldConfirm  bool
	}{
		{
			name:           "Exactly 2/3 threshold",
			validatorPower: []int64{1, 1, 1}, // total=3, threshold=ceil(2*3/3)=2
			voterIndices:   []int{0, 1},      // power=2
			shouldConfirm:  true,
		},
		{
			name:           "Just under 2/3 threshold",
			validatorPower: []int64{1, 1, 1, 1}, // total=4, threshold=ceil(2*4/3)=3
			voterIndices:   []int{0, 1},         // power=2 < 3
			shouldConfirm:  false,
		},
		{
			name:           "Just over 2/3 threshold",
			validatorPower: []int64{1, 1, 1}, // total=3, threshold=ceil(2*3/3)=2
			voterIndices:   []int{0, 1, 2},   // power=3 > 2
			shouldConfirm:  true,
		},
		{
			name:           "Single validator network",
			validatorPower: []int64{10}, // total=10, threshold=ceil(20/3)=7
			voterIndices:   []int{0},    // power=10 >= 7
			shouldConfirm:  true,
		},
		{
			name:           "Unequal voting power - threshold met",
			validatorPower: []int64{10, 5, 3, 2}, // total=20, threshold=ceil(40/3)=14
			voterIndices:   []int{0, 1},          // power=10+5=15 >= 14
			shouldConfirm:  true,
		},
		{
			name:           "Unequal voting power - threshold not met",
			validatorPower: []int64{10, 5, 3, 2}, // total=20, threshold=ceil(40/3)=14
			voterIndices:   []int{1, 2},          // power=5+3=8 < 14
			shouldConfirm:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)

			app := setup(t, tx)
			instanceID := newUUID()
			epochID := newUUID()

			// Create instance and epoch
			chainInfo, ok := chains.GetChainInfoByID("1")
			require.True(t, ok)

			testReward := &userProvidedData{
				ID:                 instanceID,
				ChainInfo:          &chainInfo,
				EscrowAddress:      common.HexToAddress("0x1234"),
				DistributionPeriod: 3600,
			}
			err = createNewRewardInstance(ctx, app, testReward)
			require.NoError(t, err)

			pending := &PendingEpoch{
				ID:          epochID,
				StartHeight: 10,
				StartTime:   1000,
			}
			err = createEpoch(ctx, app, pending, instanceID)
			require.NoError(t, err)

			// Finalize epoch
			merkleRoot := crypto.Keccak256([]byte("test-merkle-" + tc.name))
			blockHash := crypto.Keccak256([]byte("test-block-" + tc.name))
			amount, err := erc20ValueFromBigInt(big.NewInt(1000))
			require.NoError(t, err)
			err = finalizeEpoch(ctx, app, epochID, 20, blockHash, merkleRoot, amount)
			require.NoError(t, err)

			// Mock validators with specified voting power
			// TODO: This requires injecting mock validators into app.Validators
			// For now, skip this test as it requires more infrastructure
			t.Skip("Requires mock validator injection - TODO in separate PR")
		})
	}
}

// TestEmptyEpochHandling tests that empty epochs (no rewards) are handled correctly
func TestEmptyEpochHandling(t *testing.T) {
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
	instanceID := newUUID()
	epochID := newUUID()

	// Create instance and epoch
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok)

	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      common.HexToAddress("0x1234"),
		DistributionPeriod: 3600,
	}
	err = createNewRewardInstance(ctx, app, testReward)
	require.NoError(t, err)

	err = setRewardSynced(ctx, app, instanceID, 1, &syncedRewardData{
		Erc20Address:  common.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	})
	require.NoError(t, err)

	// Set initial balance for testing (1 billion tokens)
	testBalance, err := erc20ValueFromBigInt(big.NewInt(1000000000))
	require.NoError(t, err)
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE reward_instances
		SET balance = $balance
		WHERE id = $instance_id
	`, map[string]any{
		"instance_id": instanceID,
		"balance":     testBalance,
	}, nil)
	require.NoError(t, err)

	pending := &PendingEpoch{
		ID:          epochID,
		StartHeight: 10,
		StartTime:   1000,
	}
	err = createEpoch(ctx, app, pending, instanceID)
	require.NoError(t, err)

	// DON'T add any rewards - test empty epoch

	escrowAddr := "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
	var blockHash [32]byte
	copy(blockHash[:], crypto.Keccak256([]byte("test-block")))

	// Attempt to generate Merkle tree for empty epoch
	leafNum, jsonTree, root, total, err := genMerkleTreeForEpoch(ctx, app, epochID, escrowAddr, blockHash)
	require.NoError(t, err)

	// VERIFY: Returns 0 leaves (signals epoch should not be finalized)
	require.Equal(t, 0, leafNum, "Empty epoch should return 0 leaves")
	require.Nil(t, jsonTree, "Empty epoch should return nil tree")
	require.Nil(t, root, "Empty epoch should return nil root")
	require.Nil(t, total, "Empty epoch should return nil total")
}
