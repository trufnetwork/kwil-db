//go:build kwiltest

package usersvc

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/log"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine/interpreter"
	bridgeUtils "github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
)

// TestWithdrawalProof_E2E_FullFlow tests the complete end-to-end withdrawal flow:
// 1. Create reward instance
// 2. Create epoch with rewards
// 3. Finalize epoch (set merkle root and block hash)
// 4. Validators sign the epoch
// 5. Confirm epoch (mark as confirmed)
// 6. Retrieve withdrawal proof via RPC
// 7. Verify all components (merkle proof, signatures, status)
func TestWithdrawalProof_E2E_FullFlow(t *testing.T) {
	initSchemaOnce(t)
	setupTest(t)

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

	// --- STEP 1: Create reward instance ---
	instanceID := types.NewUUIDV5([]byte("e2e-test-instance"))
	escrowAddr := "0x2d4f435867066737ba1617ef024e073413909ad2"
	chainID := "11155111"              // Sepolia
	distributionPeriod := int64(86400) // 1 day

	balance, _ := new(big.Int).SetString("10000000000000000000", 10) // 10 tokens
	balanceDecimal, err := types.NewDecimalFromBigInt(balance, 0)
	require.NoError(t, err)
	err = balanceDecimal.SetPrecisionAndScale(78, 0)
	require.NoError(t, err)

	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO reward_instances (id, chain_id, escrow_address, distribution_period, synced, active, balance)
		VALUES ($id, $chain_id, $escrow_address, $distribution_period, true, true, $balance)
	`, map[string]any{
		"id":                  instanceID,
		"chain_id":            chainID,
		"escrow_address":      ethcommon.HexToAddress(escrowAddr).Bytes(),
		"distribution_period": distributionPeriod,
		"balance":             balanceDecimal,
	}, nil)
	require.NoError(t, err, "failed to create reward instance")

	// --- STEP 2: Create epoch ---
	epochID := types.NewUUIDV5([]byte("e2e-test-epoch"))
	createdAtBlock := int64(1000)
	createdAtUnix := int64(1000000)

	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}INSERT INTO epochs (id, created_at_block, created_at_unix, instance_id, confirmed)
		VALUES ($id, $created_at_block, $created_at_unix, $instance_id, false)
	`, map[string]any{
		"id":               epochID,
		"created_at_block": createdAtBlock,
		"created_at_unix":  createdAtUnix,
		"instance_id":      instanceID,
	}, nil)
	require.NoError(t, err, "failed to create epoch")

	// --- STEP 3: Add rewards to epoch ---
	recipients := []ethcommon.Address{
		ethcommon.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb4"),
		ethcommon.HexToAddress("0x1234567890123456789012345678901234567890"),
		ethcommon.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
	}

	amounts := []*big.Int{
		big.NewInt(1000000000000000000), // 1 token
		big.NewInt(2000000000000000000), // 2 tokens
		big.NewInt(3000000000000000000), // 3 tokens
	}

	for i, recipient := range recipients {
		amt := amounts[i]
		decimalAmt, err := types.NewDecimalFromBigInt(amt, 0)
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
		require.NoError(t, err, "failed to add reward for recipient %d", i)
	}

	// --- STEP 4: Finalize epoch (compute merkle root) ---
	userAddrs := make([]string, len(recipients))
	for i, addr := range recipients {
		userAddrs[i] = addr.Hex()
	}

	blockHash := [32]byte{0x01, 0x02, 0x03, 0x04, 0x05}
	_, merkleRoot, err := bridgeUtils.GenRewardMerkleTree(userAddrs, amounts, escrowAddr, blockHash)
	require.NoError(t, err, "failed to generate merkle tree")

	totalAmount := big.NewInt(0)
	for _, amt := range amounts {
		totalAmount.Add(totalAmount, amt)
	}
	totalDecimal, err := types.NewDecimalFromBigInt(totalAmount, 0)
	require.NoError(t, err)
	err = totalDecimal.SetPrecisionAndScale(78, 0)
	require.NoError(t, err)

	endedAtBlock := createdAtBlock + 100
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE epochs
		SET ended_at = $ended_at, block_hash = $block_hash, reward_root = $reward_root, reward_amount = $reward_amount
		WHERE id = $epoch_id
	`, map[string]any{
		"epoch_id":      epochID,
		"ended_at":      endedAtBlock,
		"block_hash":    blockHash[:],
		"reward_root":   merkleRoot,
		"reward_amount": totalDecimal,
	}, nil)
	require.NoError(t, err, "failed to finalize epoch")

	// --- STEP 5: Validators sign the epoch ---
	// Create 3 validator private keys
	validatorKeys := make([]*ecdsa.PrivateKey, 3)
	validatorAddrs := make([]ethcommon.Address, 3)
	for i := 0; i < 3; i++ {
		key, err := ethcrypto.GenerateKey()
		require.NoError(t, err)
		validatorKeys[i] = key
		validatorAddrs[i] = ethcrypto.PubkeyToAddress(key.PublicKey)
	}

	// Sign the epoch (keccak256(abi.encode(merkleRoot, blockHash)))
	for i, key := range validatorKeys {
		// Compute message hash
		messageHash, err := computeEpochMessageHash(merkleRoot, blockHash[:])
		require.NoError(t, err)

		// Sign message
		signature, err := ethcrypto.Sign(messageHash, key)
		require.NoError(t, err)
		require.Len(t, signature, 65, "signature should be 65 bytes")

		// Store vote
		err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
			{kwil_erc20_meta}INSERT INTO epoch_votes (epoch_id, voter, nonce, signature)
			VALUES ($epoch_id, $voter, $nonce, $signature)
		`, map[string]any{
			"epoch_id":  epochID,
			"voter":     validatorAddrs[i].Bytes(),
			"nonce":     int64(i),
			"signature": signature,
		}, nil)
		require.NoError(t, err, "failed to store validator %d signature", i)
	}

	// --- STEP 6: Confirm epoch ---
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		{kwil_erc20_meta}UPDATE epochs SET confirmed = true WHERE id = $epoch_id
	`, map[string]any{
		"epoch_id": epochID,
	}, nil)
	require.NoError(t, err, "failed to confirm epoch")

	// Commit all setup
	err = tx.Commit(ctx)
	require.NoError(t, err)

	// --- STEP 7: Test RPC method - Get withdrawal proof ---
	svc := setupTestService(t, db, engine)

	// Test for first recipient
	req := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipients[0].Hex(),
	}

	resp, jsonErr := svc.GetWithdrawalProof(ctx, req)
	require.Nil(t, jsonErr, "RPC method should not return error")
	require.NotNil(t, resp, "response should not be nil")

	// --- STEP 8: Verify complete response ---
	t.Logf("Withdrawal proof response: %+v", resp)

	// Verify recipient and amount
	require.Equal(t, recipients[0].Hex(), resp.Recipient, "recipient address should match")
	require.Equal(t, amounts[0].String(), resp.Amount, "amount should match")

	// Verify blockchain metadata
	require.Equal(t, "0x"+fmt.Sprintf("%x", blockHash[:]), resp.KwilBlockHash, "kwil block hash should match")
	require.Equal(t, "0x"+fmt.Sprintf("%x", merkleRoot), resp.MerkleRoot, "merkle root should match")
	require.Equal(t, escrowAddr, resp.ContractAddress, "contract address should match")
	require.Equal(t, int64(11155111), resp.ChainID, "chain ID should be Sepolia")

	// Verify merkle proof
	require.NotEmpty(t, resp.MerkleProof, "merkle proof should not be empty")
	t.Logf("Merkle proof has %d elements", len(resp.MerkleProof))
	for i, proof := range resp.MerkleProof {
		require.True(t, len(proof) > 2 && proof[:2] == "0x", "proof element %d should be hex with 0x prefix", i)
	}

	// Verify validator signatures
	require.Len(t, resp.ValidatorSignatures, 3, "should have 3 validator signatures")
	for i, sig := range resp.ValidatorSignatures {
		require.NotEmpty(t, sig.R, "signature %d R component should not be empty", i)
		require.NotEmpty(t, sig.S, "signature %d S component should not be empty", i)
		// V can be 0-1 (from ethcrypto.Sign) or 27-32 (Ethereum/Gnosis format)
		require.True(t, sig.V <= 32, "signature %d V component should be <= 32, got %d", i, sig.V)
		require.True(t, len(sig.R) == 66 && sig.R[:2] == "0x", "R should be 0x-prefixed 32-byte hex")
		require.True(t, len(sig.S) == 66 && sig.S[:2] == "0x", "S should be 0x-prefixed 32-byte hex")
	}

	// Verify status
	require.Equal(t, "ready", resp.Status, "status should be 'ready' for confirmed epoch")
	require.Nil(t, resp.EthTxHash, "eth_tx_hash should be nil when not claimed")
	require.Nil(t, resp.EstimatedReadyAt, "estimated_ready_at should be nil when ready")

	// --- STEP 9: Test for second recipient to verify merkle proof uniqueness ---
	req2 := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipients[1].Hex(),
	}

	resp2, jsonErr2 := svc.GetWithdrawalProof(ctx, req2)
	require.Nil(t, jsonErr2)
	require.NotNil(t, resp2)
	require.Equal(t, recipients[1].Hex(), resp2.Recipient)
	require.Equal(t, amounts[1].String(), resp2.Amount)
	require.NotEqual(t, resp.MerkleProof, resp2.MerkleProof, "different recipients should have different merkle proofs")

	// --- STEP 10: Test for third recipient ---
	req3 := &userjson.WithdrawalProofRequest{
		EpochID:   epochID.String(),
		Recipient: recipients[2].Hex(),
	}

	resp3, jsonErr3 := svc.GetWithdrawalProof(ctx, req3)
	require.Nil(t, jsonErr3)
	require.NotNil(t, resp3)
	require.Equal(t, recipients[2].Hex(), resp3.Recipient)
	require.Equal(t, amounts[2].String(), resp3.Amount)

	t.Log("✅ End-to-end withdrawal proof flow completed successfully")
}

// computeEpochMessageHash computes keccak256(abi.encode(merkleRoot, blockHash))
func computeEpochMessageHash(merkleRoot []byte, blockHash []byte) ([]byte, error) {
	if len(merkleRoot) != 32 {
		return nil, fmt.Errorf("merkle root must be 32 bytes, got %d", len(merkleRoot))
	}
	if len(blockHash) != 32 {
		return nil, fmt.Errorf("block hash must be 32 bytes, got %d", len(blockHash))
	}

	// ABI encode two bytes32 values
	encoded := make([]byte, 64)
	copy(encoded[0:32], merkleRoot)
	copy(encoded[32:64], blockHash)

	// Keccak256 hash
	hash := ethcrypto.Keccak256(encoded)
	return hash, nil
}
