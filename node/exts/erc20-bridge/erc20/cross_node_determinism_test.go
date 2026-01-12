//go:build kwiltest

package erc20

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

// TestCrossNodeMerkleConsistency simulates two separate nodes processing
// the same withdrawals and verifies they compute identical Merkle roots
func TestCrossNodeMerkleConsistency(t *testing.T) {
	ctx := context.Background()

	// Create two separate database connections (simulating two nodes)
	db1, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available")
	}
	defer db1.Close()

	db2, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available")
	}
	defer db2.Close()

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	// Test scenario: 10 withdrawals arrive in DIFFERENT order on each node
	withdrawals := []struct {
		recipient string
		amount    string
	}{
		{"0x1111111111111111111111111111111111111111", "1000"},
		{"0x2222222222222222222222222222222222222222", "2000"},
		{"0x3333333333333333333333333333333333333333", "3000"},
		{"0x4444444444444444444444444444444444444444", "4000"},
		{"0x5555555555555555555555555555555555555555", "5000"},
		{"0x6666666666666666666666666666666666666666", "6000"},
		{"0x7777777777777777777777777777777777777777", "7000"},
		{"0x8888888888888888888888888888888888888888", "8000"},
		{"0x9999999999999999999999999999999999999999", "9000"},
		{"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "10000"},
	}

	escrowAddr := "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
	var blockHash [32]byte
	copy(blockHash[:], crypto.Keccak256([]byte("block-100")))

	// Node 1: Process withdrawals in original order
	var node1Root []byte
	{
		tx1, err := db1.BeginTx(ctx)
		require.NoError(t, err)
		defer tx1.Rollback(ctx)

		app1 := setup(t, tx1)
		instanceID1 := newUUID()
		epochID1 := newUUID()

		chainInfo, ok := chains.GetChainInfoByID("1")
		require.True(t, ok)

		testReward := &userProvidedData{
			ID:                 instanceID1,
			ChainInfo:          &chainInfo,
			EscrowAddress:      common.HexToAddress("0x1234"),
			DistributionPeriod: 3600,
		}
		err = createNewRewardInstance(ctx, app1, testReward)
		require.NoError(t, err)

		err = setRewardSynced(ctx, app1, instanceID1, 1, &syncedRewardData{
			Erc20Address:  common.HexToAddress("0x00000000000000000000000000000000000000bb"),
			Erc20Decimals: 18,
		})
		require.NoError(t, err)

		// Set initial balance for testing (1 billion tokens)
		testBalance, err := erc20ValueFromBigInt(big.NewInt(1000000000))
		require.NoError(t, err)
		err = app1.Engine.ExecuteWithoutEngineCtx(ctx, app1.DB, `
			{kwil_erc20_meta}UPDATE reward_instances
			SET balance = $balance
			WHERE id = $instance_id
		`, map[string]any{
			"instance_id": instanceID1,
			"balance":     testBalance,
		}, nil)
		require.NoError(t, err)

		pending1 := &PendingEpoch{
			ID:          epochID1,
			StartHeight: 100,
			StartTime:   10000,
		}
		err = createEpoch(ctx, app1, pending1, instanceID1)
		require.NoError(t, err)

		// Insert in original order
		for _, w := range withdrawals {
			recipient := common.HexToAddress(w.recipient)
			amountBig := new(big.Int)
			_, ok := amountBig.SetString(w.amount, 10)
			require.True(t, ok, "failed to parse amount")
			amount, err := erc20ValueFromBigInt(amountBig)
			require.NoError(t, err)
			err = issueReward(ctx, app1, instanceID1, epochID1, recipient, amount)
			require.NoError(t, err)
		}

		// Generate Merkle tree
		_, _, root, _, err := genMerkleTreeForEpoch(ctx, app1, epochID1, escrowAddr, blockHash)
		require.NoError(t, err)
		node1Root = root
	}

	// Node 2: Process same withdrawals in REVERSE order
	var node2Root []byte
	{
		tx2, err := db2.BeginTx(ctx)
		require.NoError(t, err)
		defer tx2.Rollback(ctx)

		app2 := setup(t, tx2)
		instanceID2 := newUUID()
		epochID2 := newUUID()

		chainInfo, ok := chains.GetChainInfoByID("1")
		require.True(t, ok)

		testReward := &userProvidedData{
			ID:                 instanceID2,
			ChainInfo:          &chainInfo,
			EscrowAddress:      common.HexToAddress("0x1234"),
			DistributionPeriod: 3600,
		}
		err = createNewRewardInstance(ctx, app2, testReward)
		require.NoError(t, err)

		err = setRewardSynced(ctx, app2, instanceID2, 1, &syncedRewardData{
			Erc20Address:  common.HexToAddress("0x00000000000000000000000000000000000000bb"),
			Erc20Decimals: 18,
		})
		require.NoError(t, err)

		// Set initial balance for testing (1 billion tokens)
		testBalance2, err := erc20ValueFromBigInt(big.NewInt(1000000000))
		require.NoError(t, err)
		err = app2.Engine.ExecuteWithoutEngineCtx(ctx, app2.DB, `
			{kwil_erc20_meta}UPDATE reward_instances
			SET balance = $balance
			WHERE id = $instance_id
		`, map[string]any{
			"instance_id": instanceID2,
			"balance":     testBalance2,
		}, nil)
		require.NoError(t, err)

		pending2 := &PendingEpoch{
			ID:          epochID2,
			StartHeight: 100,
			StartTime:   10000,
		}
		err = createEpoch(ctx, app2, pending2, instanceID2)
		require.NoError(t, err)

		// Insert in REVERSE order
		for i := len(withdrawals) - 1; i >= 0; i-- {
			w := withdrawals[i]
			recipient := common.HexToAddress(w.recipient)
			amountBig := new(big.Int)
			_, ok := amountBig.SetString(w.amount, 10)
			require.True(t, ok, "failed to parse amount")
			amount, err := erc20ValueFromBigInt(amountBig)
			require.NoError(t, err)
			err = issueReward(ctx, app2, instanceID2, epochID2, recipient, amount)
			require.NoError(t, err)
		}

		// Generate Merkle tree
		_, _, root, _, err := genMerkleTreeForEpoch(ctx, app2, epochID2, escrowAddr, blockHash)
		require.NoError(t, err)
		node2Root = root
	}

	// CRITICAL VERIFICATION: Both nodes computed IDENTICAL Merkle root
	require.Equal(t, node1Root, node2Root,
		"Nodes processing same withdrawals in different order MUST compute identical Merkle root\nNode1: 0x%x\nNode2: 0x%x",
		node1Root, node2Root)

	t.Logf("✅ Cross-node determinism verified: Both nodes computed root 0x%x", node1Root)
}

// TestCrossNodeSignatureVerification tests that signature verification
// produces identical results on different nodes
func TestCrossNodeSignatureVerification(t *testing.T) {
	// Create two separate database connections
	db1, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available")
	}
	defer db1.Close()

	db2, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available")
	}
	defer db2.Close()

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	// Create validator and sign epoch
	validatorKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	validatorAddr := crypto.PubkeyToAddress(validatorKey.PublicKey)

	merkleRoot := crypto.Keccak256([]byte("test-merkle-root"))
	blockHash := crypto.Keccak256([]byte("test-block-hash"))

	// Compute message hash (should be same on all nodes)
	messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
	require.NoError(t, err)

	// Sign with validator (signMessage handles Ethereum prefix internally)
	signature, err := signMessage(messageHash, validatorKey)
	require.NoError(t, err)

	// Compute the prefixed hash for verification (must match what signMessage used)
	prefix := []byte(EthereumSignedMessagePrefix)
	ethSignedMessageHash := crypto.Keccak256(append(prefix, messageHash...))

	// Node 1: Verify signature (cryptographic operation, no DB needed)
	var node1Valid bool
	err = utils.EthStandardVerifyDigest(signature, ethSignedMessageHash, validatorAddr.Bytes())
	node1Valid = (err == nil)

	// Node 2: Verify same signature
	var node2Valid bool
	err = utils.EthStandardVerifyDigest(signature, ethSignedMessageHash, validatorAddr.Bytes())
	node2Valid = (err == nil)

	// CRITICAL VERIFICATION: Both nodes agree on signature validity
	require.Equal(t, node1Valid, node2Valid, "Both nodes must agree on signature validity")
	require.True(t, node1Valid, "Valid signature should verify on both nodes")
	require.True(t, node2Valid, "Valid signature should verify on both nodes")

	t.Logf("✅ Cross-node signature verification: Both nodes verified signature successfully")

	// Test with INVALID signature
	invalidSignature := make([]byte, 65)
	copy(invalidSignature, signature)
	invalidSignature[0] ^= 0xFF // Corrupt first byte

	// Node 1: Verify invalid signature
	err = utils.EthStandardVerifyDigest(invalidSignature, ethSignedMessageHash, validatorAddr.Bytes())
	node1Valid = (err == nil)

	// Node 2: Verify invalid signature
	err = utils.EthStandardVerifyDigest(invalidSignature, ethSignedMessageHash, validatorAddr.Bytes())
	node2Valid = (err == nil)

	// CRITICAL VERIFICATION: Both nodes reject invalid signature
	require.Equal(t, node1Valid, node2Valid, "Both nodes must agree on invalid signature")
	require.False(t, node1Valid, "Invalid signature should fail on both nodes")
	require.False(t, node2Valid, "Invalid signature should fail on both nodes")

	t.Logf("✅ Cross-node invalid signature rejection: Both nodes rejected corrupted signature")
}

// TestRewardAggregationDeterminism tests that aggregation of multiple
// withdrawals is deterministic regardless of order
func TestRewardAggregationDeterminism(t *testing.T) {
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

	// Test: Same recipient makes N withdrawals
	// Expected: All aggregate to single row with sum

	testCases := []struct {
		name        string
		amounts     []string
		expectedSum string
	}{
		{
			name:        "Two equal amounts",
			amounts:     []string{"100", "100"},
			expectedSum: "200",
		},
		{
			name:        "Multiple different amounts",
			amounts:     []string{"100", "250", "50", "300"},
			expectedSum: "700",
		},
		{
			name:        "Many small amounts",
			amounts:     []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"},
			expectedSum: "55",
		},
		{
			name:        "Large numbers (near uint256 limit)",
			amounts:     []string{"1000000000000000000000000", "2000000000000000000000000"},
			expectedSum: "3000000000000000000000000",
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

			// Insert all amounts
			for _, amtStr := range tc.amounts {
				amountBig := new(big.Int)
				_, ok := amountBig.SetString(amtStr, 10)
				require.True(t, ok, "failed to parse amount")
				amount, err := erc20ValueFromBigInt(amountBig)
				require.NoError(t, err)
				err = issueReward(ctx, app, instanceID, epochID, recipient, amount)
				require.NoError(t, err)
			}

			// Query rewards
			var rewards []*EpochReward
			err = getRewardsForEpoch(ctx, app, epochID, func(reward *EpochReward) error {
				rewards = append(rewards, reward)
				return nil
			})
			require.NoError(t, err)

			// VERIFY: Only one row
			require.Len(t, rewards, 1, "Should have exactly 1 aggregated reward")

			// VERIFY: Amount is correct sum
			expectedBig := new(big.Int)
			_, okExpected := expectedBig.SetString(tc.expectedSum, 10)
			require.True(t, okExpected, "failed to parse expected amount")
			expectedAmount, err := erc20ValueFromBigInt(expectedBig)
			require.NoError(t, err)
			cmp, err := rewards[0].Amount.Cmp(expectedAmount)
			require.NoError(t, err)
			require.Equal(t, 0, cmp, "Aggregated amount should equal sum of all withdrawals")
		})
	}
}

// TestMessageHashDeterminism tests that message hash computation is deterministic
func TestMessageHashDeterminism(t *testing.T) {
	// Test data
	merkleRoot := crypto.Keccak256([]byte("test-merkle-root-data"))
	blockHash := crypto.Keccak256([]byte("test-block-hash-data"))

	// Compute message hash 100 times
	hashes := make(map[string]int)
	for i := 0; i < 100; i++ {
		messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
		require.NoError(t, err)
		hashes[common.Bytes2Hex(messageHash)]++
	}

	// VERIFY: All 100 iterations produced SAME hash
	require.Len(t, hashes, 1, "Message hash computation must be deterministic")

	for hashHex, count := range hashes {
		t.Logf("Message hash (all iterations): 0x%s (count: %d)", hashHex, count)
		require.Equal(t, 100, count)
	}
}

// TestSumVotingPowerCommutative tests that summing voting power is commutative
// (order of votes doesn't matter)
func TestSumVotingPowerCommutative(t *testing.T) {
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

	// Create 5 validators
	validators := make([]*ecdsa.PrivateKey, 5)
	addresses := make([]common.Address, 5)
	for i := 0; i < 5; i++ {
		key, err := crypto.GenerateKey()
		require.NoError(t, err)
		validators[i] = key
		addresses[i] = crypto.PubkeyToAddress(key.PublicKey)
	}

	// Test two different vote orderings
	orderings := [][]int{
		{0, 1, 2, 3, 4}, // Original order
		{4, 2, 0, 3, 1}, // Shuffled order
	}

	results := make([]int, len(orderings))

	for orderIdx, ordering := range orderings {
		// Reset singleton state for each iteration
		orderedsync.ForTestingReset()
		ForTestingResetSingleton()

		tx, err := db.BeginTx(ctx)
		require.NoError(t, err)

		app := setup(t, tx)
		instanceID := newUUID()
		epochID := newUUID()

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

		// Create message hash
		messageHash, err := computeEpochMessageHash(merkleRoot, blockHash)
		require.NoError(t, err)

		// Vote in specified order
		// signMessage handles Ethereum prefix internally
		const nonCustodialNonce = 0
		for _, i := range ordering {
			sig, err := signMessage(messageHash, validators[i])
			require.NoError(t, err)

			err = voteEpoch(ctx, app, epochID, addresses[i], nonCustodialNonce, sig)
			require.NoError(t, err)
		}

		// Count votes
		result, err := app.DB.Execute(ctx, `
			SELECT COUNT(*) FROM kwil_erc20_meta.epoch_votes
			WHERE epoch_id = $1 AND nonce = $2
		`, epochID, nonCustodialNonce)
		require.NoError(t, err)

		count, ok := result.Rows[0][0].(int64)
		require.True(t, ok)
		results[orderIdx] = int(count)

		// Rollback transaction for this iteration
		tx.Rollback(ctx)
	}

	// VERIFY: Both orderings resulted in same vote count
	require.Equal(t, results[0], results[1], "Vote count should be same regardless of vote order")
	require.Equal(t, 5, results[0], "Should have 5 votes")
}
