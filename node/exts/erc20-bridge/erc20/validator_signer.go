package erc20

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// signerPollingInterval is how often the validator signer checks for new finalized epochs
	signerPollingInterval = 30 * time.Second

	// votedEpochsCleanupThreshold is the number of entries in votedEpochs map that triggers cleanup
	votedEpochsCleanupThreshold = 100
)

// ValidatorSigner is a background service that monitors for finalized epochs
// and automatically submits validator signatures via transactions.
//
// This runs outside the consensus path to avoid determinism issues.
// Signatures are submitted as transactions that call the vote_epoch action.
//
// ARCHITECTURAL FIX APPLIED: This service now uses app.Service.DBPool (database pool)
// instead of app.DB (transaction-scoped reference). This prevents "tx is closed" errors
// when the background goroutine tries to query the database.
// Pattern follows /node/exts/erc20-bridge/signersvc/kwil.go.
type ValidatorSigner struct {
	app             *common.App            // For Engine, Accounts, Service access
	dbPool          sql.DelayedReadTxMaker // Database pool for fresh transactions
	instanceID      *types.UUID
	validatorSigner common.ValidatorSigner // Interface for controlled key access
	address         ethcommon.Address
	logger          log.Logger

	// Track voted epochs and nonce to avoid duplicate work and nonce conflicts
	mu          sync.Mutex
	votedEpochs map[string]bool // epochID -> voted
	localNonce  uint64          // Local nonce counter for transaction creation
}

// NewValidatorSignerFromInterface creates a new validator signer service using the ValidatorSigner interface.
// This prevents direct access to the validator's private key.
func NewValidatorSignerFromInterface(app *common.App, instanceID *types.UUID, valSigner common.ValidatorSigner, addressBytes []byte) *ValidatorSigner {
	address := ethcommon.BytesToAddress(addressBytes)

	logger := app.Service.Logger
	logger.Infof("[VALIDATOR_SIGNER_DEBUG] Creating validator signer for instance %s", instanceID)
	logger.Infof("[VALIDATOR_SIGNER_DEBUG] app.Service.DBPool type: %T", app.Service.DBPool)

	// Get database pool from Service for background queries
	dbPool := app.Service.DBPool
	if dbPool == nil {
		logger.Warnf("DBPool is nil - validator signer will not function properly!")
	}

	return &ValidatorSigner{
		app:             app,
		dbPool:          dbPool,
		instanceID:      instanceID,
		validatorSigner: valSigner,
		address:         address,
		logger:          logger,
		votedEpochs:     make(map[string]bool),
	}
}

// beginReadTx creates a fresh read transaction from the database pool.
// Returns an error if dbPool is nil to prevent panics.
func (v *ValidatorSigner) beginReadTx() (sql.OuterReadTx, error) {
	if v.dbPool == nil {
		return nil, fmt.Errorf("database pool not available")
	}
	return v.dbPool.BeginDelayedReadTx(), nil
}

// Start begins the background polling loop.
// This goroutine runs for the lifetime of the node.
func (v *ValidatorSigner) Start(ctx context.Context) {
	v.logger.Infof("starting validator signer for instance %s (address: %s)", v.instanceID, v.address.Hex())
	v.logger.Infof("[VALIDATOR_SIGNER_DEBUG] Start() called, app.DB type: %T", v.app.DB)

	ticker := time.NewTicker(signerPollingInterval)
	defer ticker.Stop()

	// Add instance-specific delay to prevent simultaneous startup queries
	// This prevents "conn busy" errors when multiple instances start together
	// Using deterministic jitter based on UUID ensures each instance has a unique delay
	jitter := 0
	if v.instanceID != nil {
		// Sum UUID bytes for deterministic instance-specific jitter (0-9 * 100ms)
		sum := 0
		idBytes := v.instanceID[:]
		for _, b := range idBytes {
			sum += int(b)
		}
		jitter = sum % 10
	}
	time.Sleep(time.Duration(jitter) * 100 * time.Millisecond)

	// Run after delay
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
	v.logger.Debugf("[VALIDATOR_SIGNER_DEBUG] pollAndSign() called for instance %s", v.instanceID)

	// Query for finalized but unconfirmed epochs
	epochs, err := v.getFinalizedEpochs(ctx)
	if err != nil {
		v.logger.Warnf("failed to query finalized epochs: %v", err)
		return
	}

	// Periodically clean up confirmed epochs from memory to prevent unbounded growth
	v.mu.Lock()
	if len(v.votedEpochs) > votedEpochsCleanupThreshold {
		v.mu.Unlock()
		v.cleanupConfirmedEpochs(ctx)
	} else {
		v.mu.Unlock()
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

		// Check if BroadcastTxFn is available before trying to vote
		// If not available yet (during startup), skip this epoch and retry on next poll
		if v.app.Service.BroadcastTxFn == nil {
			v.logger.Debugf("BroadcastTxFn not yet available for epoch %s, will retry on next poll", epoch.ID)
			continue // Skip without marking as voted, so we retry next time
		}

		// Sign and submit vote
		err = v.signAndVote(ctx, epoch)
		if err != nil {
			v.logger.Warnf("failed to sign and vote for epoch %s: %v", epoch.ID, err)
			// Resync nonce from chain on invalid nonce so the next poll uses the correct nonce
			if errors.Is(err, types.ErrInvalidNonce) {
				v.resyncNonceFromChain(ctx)
			}
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
	// DEBUG: Log when we're trying to access the database
	v.logger.Debugf("[VALIDATOR_SIGNER_DEBUG] Attempting to query finalized epochs for instance %s", v.instanceID)
	v.logger.Debugf("[VALIDATOR_SIGNER_DEBUG] dbPool type: %T", v.dbPool)

	// Create a fresh read transaction from the database pool
	readTx, err := v.beginReadTx()
	if err != nil {
		return nil, fmt.Errorf("failed to begin read transaction: %w", err)
	}
	defer readTx.Rollback(ctx)

	v.logger.Debugf("[VALIDATOR_SIGNER_DEBUG] Successfully created delayed read transaction, type: %T", readTx)

	result, err := readTx.Execute(ctx, `
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

	v.logger.Debugf("[VALIDATOR_SIGNER_DEBUG] Checking if voted for epoch %s", epochID)

	// Create a fresh read transaction from the database pool
	readTx, err := v.beginReadTx()
	if err != nil {
		return false, fmt.Errorf("failed to begin read transaction: %w", err)
	}
	defer readTx.Rollback(ctx)

	result, err := readTx.Execute(ctx, `
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

	count, ok := result.Rows[0][0].(int64)
	if !ok {
		return false, fmt.Errorf("unexpected type for count: %T", result.Rows[0][0])
	}
	return count > 0, nil
}

// signAndVote signs an epoch and submits a vote transaction.
func (v *ValidatorSigner) signAndVote(ctx context.Context, epoch *FinalizedEpoch) error {
	// 1. Compute message hash
	messageHash, err := computeEpochMessageHash(epoch.RewardRoot, epoch.BlockHash)
	if err != nil {
		return fmt.Errorf("failed to compute message hash: %w", err)
	}

	// 2. Add Ethereum signed message prefix to match contract expectation
	// This matches OpenZeppelin's MessageHashUtils.toEthSignedMessageHash()
	prefix := []byte(EthereumSignedMessagePrefix)
	ethSignedMessageHash := crypto.Keccak256(append(prefix, messageHash...))

	// 3. Sign the prefixed message using the validator signer interface
	signature, err := v.validatorSigner.Sign(ctx, ethSignedMessageHash, common.PurposeEpochVoting)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	// Validate signature
	if len(signature) != 65 {
		return fmt.Errorf("invalid signature length: %d", len(signature))
	}

	// 4. Submit vote transaction
	// NOTE: BroadcastTxFn availability is checked in pollAndSign before calling this function

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

// resyncNonceFromChain fetches the account nonce from chain state and sets localNonce
// so the next vote transaction uses the correct nonce. Call this after an invalid-nonce
// error so the next attempt succeeds without waiting for another poll.
func (v *ValidatorSigner) resyncNonceFromChain(ctx context.Context) {
	readTx, err := v.beginReadTx()
	if err != nil {
		v.logger.Warnf("failed to resync nonce: %v", err)
		return
	}
	defer readTx.Rollback(ctx)

	accountID := &types.AccountID{
		Identifier: v.address.Bytes(),
		KeyType:    kwilcrypto.KeyTypeSecp256k1,
	}
	account, err := v.app.Accounts.GetAccount(ctx, readTx, accountID)
	if err != nil {
		v.logger.Warnf("failed to get account for nonce resync: %v", err)
		return
	}

	v.mu.Lock()
	old := v.localNonce
	newNonce := uint64(account.Nonce)
	v.localNonce = newNonce
	v.mu.Unlock()
	v.logger.Infof("resynced vote nonce from chain: %d -> %d", old, newNonce)
}

// createVoteTransaction creates a signed transaction that calls the vote_epoch action.
func (v *ValidatorSigner) createVoteTransaction(ctx context.Context, epochID *types.UUID, signature []byte) (*types.Transaction, error) {
	// Get transaction signer from validator signer interface
	signer, err := v.validatorSigner.CreateSecp256k1Signer()
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction signer: %w", err)
	}

	// Get current account nonce with concurrency-safe local counter
	// Use double-check pattern to avoid holding mutex during GetAccount call
	v.mu.Lock()
	needsInit := v.localNonce == 0
	v.mu.Unlock()

	if needsInit {
		// Fetch account nonce outside mutex to avoid blocking
		// Create fresh read transaction from database pool
		readTx, err := v.beginReadTx()
		if err != nil {
			return nil, fmt.Errorf("failed to begin read transaction: %w", err)
		}
		defer readTx.Rollback(ctx)

		accountID := &types.AccountID{
			Identifier: v.address.Bytes(),
			KeyType:    kwilcrypto.KeyTypeSecp256k1,
		}
		account, err := v.app.Accounts.GetAccount(ctx, readTx, accountID)
		if err != nil {
			return nil, fmt.Errorf("failed to get account nonce: %w", err)
		}
		initialNonce := uint64(account.Nonce)

		// Double-check pattern: only set if still zero
		v.mu.Lock()
		if v.localNonce == 0 {
			v.localNonce = initialNonce
		}
		v.mu.Unlock()
	}

	// Use and increment local nonce
	v.mu.Lock()
	nonce := v.localNonce
	v.localNonce++
	v.mu.Unlock()

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

// cleanupConfirmedEpochs removes confirmed epochs from the in-memory votedEpochs map
// to prevent unbounded memory growth over time.
func (v *ValidatorSigner) cleanupConfirmedEpochs(ctx context.Context) {
	// Create a fresh read transaction from the database pool
	readTx, err := v.beginReadTx()
	if err != nil {
		v.logger.Warnf("failed to begin read transaction for cleanup: %v", err)
		return
	}
	defer readTx.Rollback(ctx)

	// Query all confirmed epochs for this instance
	result, err := readTx.Execute(ctx, `
		SELECT id FROM kwil_erc20_meta.epochs
		WHERE instance_id = $1 AND confirmed = true
	`, v.instanceID)
	if err != nil {
		v.logger.Warnf("failed to query confirmed epochs for cleanup: %v", err)
		return
	}

	// Build set of confirmed epoch IDs
	confirmedEpochs := make(map[string]bool)
	for _, row := range result.Rows {
		if row[0] == nil {
			continue
		}
		if epochID, ok := row[0].(*types.UUID); ok {
			confirmedEpochs[epochID.String()] = true
		}
	}

	// Remove confirmed epochs from votedEpochs map
	v.mu.Lock()
	defer v.mu.Unlock()

	removedCount := 0
	for epochID := range v.votedEpochs {
		if confirmedEpochs[epochID] {
			delete(v.votedEpochs, epochID)
			removedCount++
		}
	}

	if removedCount > 0 {
		v.logger.Debugf("cleaned up %d confirmed epochs from memory (votedEpochs map now has %d entries)", removedCount, len(v.votedEpochs))
	}
}
