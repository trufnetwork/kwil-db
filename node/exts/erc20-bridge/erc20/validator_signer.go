package erc20

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ValidatorSigner is a background service that monitors for finalized epochs
// and automatically submits validator signatures via transactions.
//
// This runs outside the consensus path to avoid determinism issues.
// Signatures are submitted as transactions that call the vote_epoch action.
type ValidatorSigner struct {
	app        *common.App
	instanceID *types.UUID
	privateKey *ecdsa.PrivateKey
	address    ethcommon.Address
	logger     log.Logger

	// Track voted epochs and nonce to avoid duplicate work and nonce conflicts
	mu          sync.Mutex
	votedEpochs map[string]bool // epochID -> voted
	localNonce  uint64          // Local nonce counter for transaction creation
}

// NewValidatorSigner creates a new validator signer service.
func NewValidatorSigner(app *common.App, instanceID *types.UUID, privateKey *ecdsa.PrivateKey) *ValidatorSigner {
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	return &ValidatorSigner{
		app:         app,
		instanceID:  instanceID,
		privateKey:  privateKey,
		address:     address,
		logger:      app.Service.Logger,
		votedEpochs: make(map[string]bool),
	}
}

// Start begins the background polling loop.
// This goroutine runs for the lifetime of the node.
func (v *ValidatorSigner) Start(ctx context.Context) {
	v.logger.Infof("starting validator signer for instance %s (address: %s)", v.instanceID, v.address.Hex())

	ticker := time.NewTicker(30 * time.Second) // Poll every 30 seconds
	defer ticker.Stop()

	// Run immediately on startup
	v.pollAndSign(ctx)

	for {
		select {
		case <-ctx.Done():
			v.logger.Info("validator signer shutting down")
			return
		case <-ticker.C:
			v.pollAndSign(ctx)
		}
	}
}

// pollAndSign checks for finalized epochs and submits votes.
func (v *ValidatorSigner) pollAndSign(ctx context.Context) {
	// Query for finalized but unconfirmed epochs
	epochs, err := v.getFinalizedEpochs(ctx)
	if err != nil {
		v.logger.Warnf("failed to query finalized epochs: %v", err)
		return
	}

	for _, epoch := range epochs {
		// Check if already voted
		v.mu.Lock()
		alreadyVoted := v.votedEpochs[epoch.ID.String()]
		v.mu.Unlock()

		if alreadyVoted {
			continue
		}

		// Check if already voted in database
		hasVoted, err := v.hasVoted(ctx, epoch.ID)
		if err != nil {
			v.logger.Warnf("failed to check vote status for epoch %s: %v", epoch.ID, err)
			continue
		}
		if hasVoted {
			v.mu.Lock()
			v.votedEpochs[epoch.ID.String()] = true
			v.mu.Unlock()
			continue
		}

		// Sign and submit vote
		err = v.signAndVote(ctx, epoch)
		if err != nil {
			v.logger.Warnf("failed to sign and vote for epoch %s: %v", epoch.ID, err)
			continue
		}

		v.logger.Infof("submitted vote for epoch %s", epoch.ID)

		// Mark as voted in memory
		v.mu.Lock()
		v.votedEpochs[epoch.ID.String()] = true
		v.mu.Unlock()
	}
}

// FinalizedEpoch represents a finalized but unconfirmed epoch.
type FinalizedEpoch struct {
	ID         *types.UUID
	RewardRoot []byte
	BlockHash  []byte
}

// getFinalizedEpochs queries for epochs that are finalized but not yet confirmed.
func (v *ValidatorSigner) getFinalizedEpochs(ctx context.Context) ([]*FinalizedEpoch, error) {
	result, err := v.app.DB.Execute(ctx, `
		SELECT id, reward_root, block_hash
		FROM kwil_erc20_meta.epochs
		WHERE instance_id = $1
		  AND ended_at IS NOT NULL
		  AND confirmed = false
		ORDER BY created_at_block DESC
		LIMIT 10
	`, v.instanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to query epochs: %w", err)
	}

	var epochs []*FinalizedEpoch
	for _, row := range result.Rows {
		// Safely extract ID with nil check
		if row[0] == nil {
			v.logger.Warn("skipping epoch with nil ID")
			continue
		}
		epochID, ok := row[0].(*types.UUID)
		if !ok {
			v.logger.Warnf("skipping epoch with invalid ID type: %T", row[0])
			continue
		}

		// Safely extract reward_root with nil check
		var rewardRoot []byte
		if row[1] != nil {
			rewardRoot, ok = row[1].([]byte)
			if !ok {
				v.logger.Warnf("skipping epoch %s with invalid reward_root type: %T", epochID, row[1])
				continue
			}
		}

		// Safely extract block_hash with nil check
		var blockHash []byte
		if row[2] != nil {
			blockHash, ok = row[2].([]byte)
			if !ok {
				v.logger.Warnf("skipping epoch %s with invalid block_hash type: %T", epochID, row[2])
				continue
			}
		}

		epoch := &FinalizedEpoch{
			ID:         epochID,
			RewardRoot: rewardRoot,
			BlockHash:  blockHash,
		}
		epochs = append(epochs, epoch)
	}

	return epochs, nil
}

// hasVoted checks if this validator has already voted for an epoch.
func (v *ValidatorSigner) hasVoted(ctx context.Context, epochID *types.UUID) (bool, error) {
	const nonCustodialNonce = 0

	result, err := v.app.DB.Execute(ctx, `
		SELECT COUNT(*) as count
		FROM kwil_erc20_meta.epoch_votes
		WHERE epoch_id = $1
		  AND voter = $2
		  AND nonce = $3
	`, epochID, v.address.Bytes(), nonCustodialNonce)
	if err != nil {
		return false, fmt.Errorf("failed to check vote: %w", err)
	}

	if len(result.Rows) == 0 {
		return false, nil
	}

	count := result.Rows[0][0].(int64)
	return count > 0, nil
}

// signAndVote signs an epoch and submits a vote transaction.
func (v *ValidatorSigner) signAndVote(ctx context.Context, epoch *FinalizedEpoch) error {
	// 1. Compute message hash
	messageHash, err := computeEpochMessageHash(epoch.RewardRoot, epoch.BlockHash)
	if err != nil {
		return fmt.Errorf("failed to compute message hash: %w", err)
	}

	// 2. Sign the message
	signature, err := signMessage(messageHash, v.privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	// Validate signature
	if len(signature) != 65 {
		return fmt.Errorf("invalid signature length: %d", len(signature))
	}

	// 3. Submit vote transaction
	// CRITICAL: BroadcastTxFn must be available for proper consensus
	if v.app.Service.BroadcastTxFn == nil {
		return fmt.Errorf("BroadcastTxFn not available - cannot submit validator vote (check node initialization)")
	}

	// Create transaction calling vote_epoch action
	tx, err := v.createVoteTransaction(ctx, epoch.ID, signature)
	if err != nil {
		return fmt.Errorf("failed to create vote transaction: %w", err)
	}

	// Broadcast transaction to mempool
	txHash, err := v.app.Service.BroadcastTxFn(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to broadcast vote transaction: %w", err)
	}

	v.logger.Infof("broadcast vote transaction for epoch %s (tx: %s)", epoch.ID, txHash)

	// NOTE: Threshold checking and epoch confirmation happen in the vote_epoch handler
	// during block execution, ensuring deterministic consensus. See meta_extension.go:1193-1229

	return nil
}

// createVoteTransaction creates a signed transaction that calls the vote_epoch action.
func (v *ValidatorSigner) createVoteTransaction(ctx context.Context, epochID *types.UUID, signature []byte) (*types.Transaction, error) {
	// Convert *ecdsa.PrivateKey to crypto.Secp256k1PrivateKey
	privKeyBytes := crypto.FromECDSA(v.privateKey)
	kwilPrivKey, err := kwilcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %w", err)
	}

	// Create ECDSA signer
	signer := &auth.EthPersonalSigner{Key: *kwilPrivKey}

	// Get current account nonce with concurrency-safe local counter
	v.mu.Lock()
	defer v.mu.Unlock()

	// Initialize local nonce if needed
	if v.localNonce == 0 {
		accountID := &types.AccountID{
			Identifier: v.address.Bytes(),
			KeyType:    kwilcrypto.KeyTypeSecp256k1,
		}
		account, err := v.app.Accounts.GetAccount(ctx, v.app.DB, accountID)
		if err != nil {
			return nil, fmt.Errorf("failed to get account nonce: %w", err)
		}
		v.localNonce = uint64(account.Nonce)
	}

	// Use and increment local nonce
	nonce := v.localNonce
	v.localNonce++

	// Create action execution payload
	// The vote_epoch action expects: (instance_id, epoch_id, nonce, signature)

	// Encode values (handle errors)
	instanceIDVal, err := types.EncodeValue(v.instanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to encode instanceID: %w", err)
	}
	epochIDVal, err := types.EncodeValue(epochID)
	if err != nil {
		return nil, fmt.Errorf("failed to encode epochID: %w", err)
	}
	nonceVal, err := types.EncodeValue(int64(0))
	if err != nil {
		return nil, fmt.Errorf("failed to encode nonce: %w", err)
	}
	sigVal, err := types.EncodeValue(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	actionExec := &types.ActionExecution{
		Namespace: RewardMetaExtensionName, // The extension name
		Action:    "vote_epoch",
		Arguments: [][]*types.EncodedValue{{
			instanceIDVal,
			epochIDVal,
			nonceVal,
			sigVal,
		}},
	}

	// Marshal action execution
	payload, err := actionExec.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal action execution: %w", err)
	}

	// Get ChainID from genesis config
	chainID := ""
	if v.app.Service.GenesisConfig != nil {
		chainID = v.app.Service.GenesisConfig.ChainID
	}

	// Create transaction
	tx := &types.Transaction{
		Body: &types.TransactionBody{
			Description: "Validator vote for epoch " + epochID.String(),
			Payload:     payload,
			PayloadType: types.PayloadTypeExecute,
			Fee:         big.NewInt(0), // No fee for validator votes
			Nonce:       nonce,
			ChainID:     chainID, // Set chain ID to prevent replay attacks
		},
		Serialization: types.SignedMsgConcat,
	}

	// Sign transaction
	err = tx.Sign(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	return tx, nil
}
