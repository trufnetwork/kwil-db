package consensus

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

func (ce *ConsensusEngine) validateBlock(blk *ktypes.Block) error {
	// Validate if this is the correct block proposal to be processed.
	if blk.Header.Version != ktypes.BlockVersion {
		return fmt.Errorf("block version mismatch, expected %d, got %d", ktypes.BlockVersion, blk.Header.Version)
	}

	if ce.state.lc.height+1 != blk.Header.Height {
		return fmt.Errorf("block proposal for height %d does not follow %d", blk.Header.Height, ce.state.lc.height)
	}

	if ce.state.lc.blkHash != blk.Header.PrevHash {
		return fmt.Errorf("prevBlockHash mismatch, expected %v, got %v", blk.Header.PrevHash, ce.state.lc.blkHash)
	}

	if blk.Header.PrevAppHash != ce.state.lc.appHash {
		return fmt.Errorf("apphash mismatch, expected %v, got %v", ce.state.lc.appHash, blk.Header.PrevAppHash)
	}

	if blk.Header.NumTxns != uint32(len(blk.Txns)) {
		return fmt.Errorf("transaction count mismatch, expected %d, got %d", blk.Header.NumTxns, len(blk.Txns))
	}

	// Verify the merkle root of the block transactions
	merkleRoot := blk.CalcMerkleRoot() // NOTE: this expects CalcMerkleRoot to use tx.HashCache() to prepare the Transaction's internal hash cache
	if merkleRoot != blk.Header.MerkleRoot {
		return fmt.Errorf("merkleroot mismatch, expected %v, got %v", merkleRoot, blk.Header.MerkleRoot)
	}

	// Verify the current validator set for the block
	valSetHash := ce.validatorSetHash()
	if valSetHash != blk.Header.ValidatorSetHash {
		return fmt.Errorf("validator set hash mismatch, expected %s, got %s", valSetHash.String(), blk.Header.ValidatorSetHash.String())
	}

	// network params hash
	if blk.Header.NetworkParamsHash != ce.blockProcessor.ConsensusParams().Hash() {
		return fmt.Errorf("network params hash mismatch, expected %s, got %s", ce.blockProcessor.ConsensusParams().Hash().String(), blk.Header.NetworkParamsHash.String())
	}

	// Ensure that if any leader update is present, it is valid
	if blk.Header.NewLeader != nil {
		candidate := hex.EncodeToString(blk.Header.NewLeader.Bytes())
		if _, ok := ce.validatorSet[candidate]; !ok {
			return fmt.Errorf("leader update candidate %s is not a validator", candidate)
		}
	}

	maxBlockSize := ce.ConsensusParams().MaxBlockSize
	if blockTxnsSize := blk.TxnsSize(); blockTxnsSize > maxBlockSize {
		return fmt.Errorf("block size %d exceeds max block size %d", blockTxnsSize, maxBlockSize)
	}

	// Ensure that the number of event and resolution IDs within validator vote transactions votes
	// per transaction does not exceed the max consensus limit.
	maxVotesPerTx := ce.ConsensusParams().MaxVotesPerTx
	for _, txn := range blk.Txns {
		if txn.Body.PayloadType == ktypes.PayloadTypeValidatorVoteBodies {
			// unmarshal the payload
			vote := &ktypes.ValidatorVoteBodies{}
			err := vote.UnmarshalBinary(txn.Body.Payload)
			if err != nil {
				return fmt.Errorf("failed to unmarshal validator vote body: %v", err)
			}

			if int64(len(vote.Events)) > maxVotesPerTx {
				return fmt.Errorf("max votes exceeded in tx of type %s : %d > %d", txn.Body.PayloadType, len(vote.Events), maxVotesPerTx)
			}

		} else if txn.Body.PayloadType == ktypes.PayloadTypeValidatorVoteIDs {
			// unmarshal the payload
			vote := &ktypes.ValidatorVoteIDs{}
			err := vote.UnmarshalBinary(txn.Body.Payload)
			if err != nil {
				return fmt.Errorf("failed to unmarshal validator vote id: %v", err)
			}

			if int64(len(vote.ResolutionIDs)) > maxVotesPerTx {
				return fmt.Errorf("max votes exceeded in tx of type %s : %d > %d", txn.Body.PayloadType, len(vote.ResolutionIDs), maxVotesPerTx)
			}
		}
	}

	return nil
}

// lastBlock returns the height, hash, and timestamp of the last committed
// block. This is safe for concurrent access, and access from external callers
// such via QueueTx.
func (ce *ConsensusEngine) lastBlock() (int64, types.Hash, time.Time) {
	ce.stateInfo.mtx.RLock()
	defer ce.stateInfo.mtx.RUnlock()

	var timestamp time.Time
	var hash types.Hash
	if lc := ce.stateInfo.lastCommit; lc.blk != nil {
		timestamp = lc.blk.Header.Timestamp
		hash = lc.blkHash
	}

	return ce.stateInfo.height, hash, timestamp
}

// QueueTx attempts to add a transaction to the mempool.
// It is an error if the transaction is already in the mempool.
// It is an error if the transaction fails CheckTx.
// This method holds the mempool lock for the duration of the call.
func (ce *ConsensusEngine) QueueTx(ctx context.Context, tx *types.Tx) error {
	height, _, timestamp := ce.lastBlock()

	// contention on mempoolMtx is high, between here and commit().
	// We do not want to delay commit() under any circumstances... so...

	// commit can claim priority any time, while QueueTx must sit in a queue
	// unless commit is not already running.

	ce.mempoolMtx.Lock()
	defer ce.mempoolMtx.Unlock()

	err := ce.mempool.Store(tx)
	if err != nil {
		return err
	}

	const recheck = false
	err = ce.blockProcessor.CheckTx(ctx, tx, height, timestamp, recheck)
	if err != nil {
		ce.mempool.Remove(tx.Hash())
		return err
	}

	// if the node is a leader, see if mempool has enough txs to fill the block
	// and send a trigger to the CE if it's in the waiting state to start the new round.
	if ce.role.Load() == types.RoleLeader {
		ce.stateInfo.mtx.RLock()
		// we do not defer r.Unlock because we dont want to hold a read
		// lock through the cs.mempoolReadyChan <- struct{}{} call
		if ce.stateInfo.status != Committed {
			ce.stateInfo.mtx.RUnlock() // unlock before returning
			// send the mempoolReady trigger only during the
			// newRound and waiting for blkProposal Timeout to elapse.
			return nil
		}
		ce.stateInfo.mtx.RUnlock() // unlock before waiting on other goroutines

		sz, _ := ce.mempool.Size()
		if int64(sz) >= ce.ConsensusParams().MaxBlockSize {
			full := ce.mempoolReady.Swap(true)
			if !full {
				ce.log.Debug("Mempool has enough txs to fill the block, sending trigger to the CE", "txsSize", sz)
				// only signal leader's CE once when the mempool has enough txs to fill the block
				ce.mempoolReadyChan <- struct{}{}
			}
		}
	}

	return nil
}

// lastBlockInternal is like lastBlock but but uses ce.state.lc instead of
// ce.stateInfo.lastCommit. This does NOT lock the ce.state.mtx.
func (ce *ConsensusEngine) lastBlockInternal() (int64, time.Time) {
	var timestamp time.Time
	// var hash types.Hash
	if lc := ce.state.lc; lc.blk != nil {
		timestamp = lc.blk.Header.Timestamp
		// hash = lc.blkHash
	}

	return ce.state.lc.height, timestamp
}

// BroadcastTx checks the transaction with the mempool and if the verification
// is successful, broadcasts it to the network. The TxResult will be nil unless
// sync is set to 1, in which case the BroadcastTx returns only after it is
// successfully executed in a committed block. This method is effectively
// [QueueTx] followed, by P2P broadcast of the transaction, followed by
// optionally waiting for the transaction to be mined.
func (ce *ConsensusEngine) BroadcastTx(ctx context.Context, tx *types.Tx, sync uint8) (types.Hash, *ktypes.TxResult, error) {
	// check and store the transaction in the mempool
	if err := ce.QueueTx(ctx, tx); err != nil {
		return types.Hash{}, nil, err
	}

	txHash := tx.Hash()

	// Announce the transaction to the network only if not previously announced
	if ce.txAnnouncer != nil {
		// We can't use parent context 'cause it's canceled in the caller, which
		// could be the RPC request. handler.  This shouldn't be CE's problem...
		ce.txAnnouncer(context.Background(), txHash)
	}

	// If sync is set to 1, wait for the transaction to be committed in a block.
	if sync == 1 { // Blocking code
		subChan, err := ce.SubscribeTx(txHash)
		if err != nil {
			return txHash, nil, err
		}
		defer ce.UnsubscribeTx(txHash) // Unsubscribe tx if BroadcastTx returns

		select {
		case txRes := <-subChan:
			return txHash, &txRes, nil
		case <-ctx.Done():
			return types.Hash{}, nil, ctx.Err()
		case <-time.After(ce.broadcastTxTimeout):
			return types.Hash{}, nil, ktypes.ErrTxTimeout
		}
	}

	return txHash, nil, nil
}

func (ce *ConsensusEngine) ConsensusParams() *ktypes.NetworkParameters {
	return ce.blockProcessor.ConsensusParams()
}

// executeBlock uses the block processor to execute the block and stores the
// results in the state field.
func (ce *ConsensusEngine) executeBlock(ctx context.Context, blkProp *blockProposal, syncing bool) error {
	t0 := time.Now()
	defer func() {
		ce.stateInfo.mtx.Lock()
		ce.stateInfo.status = Executed
		ce.stateInfo.mtx.Unlock()
	}()

	req := &ktypes.BlockExecRequest{
		Block:    blkProp.blk,
		Height:   blkProp.height,
		BlockID:  blkProp.blkHash,
		Proposer: ce.leader,
	}

	now := time.Now()
	results, err := ce.blockProcessor.ExecuteBlock(ctx, req, syncing)
	if err != nil {
		return err
	}

	ce.state.tExecuted = time.Now()
	mets.RecordExecuted(ctx, ce.state.tExecuted.Sub(t0), blkProp.blk.Header.Height, int64(blkProp.blk.Header.NumTxns))

	ce.state.blockRes = &blockResult{
		ack:       true,
		appHash:   results.AppHash,
		txResults: results.TxResults,
		// vote is set in processBlockProposal
		paramUpdates: results.ParamUpdates,
	}

	// reset the catchup timer as we have successfully processed a new block proposal
	ce.catchupTicker.Reset(ce.catchupTimeout)

	if !syncing { // ignore these logs during syncing
		ce.log.Info("Executed block", "height", blkProp.height, "blockID", blkProp.blkHash, "appHash", results.AppHash.String(), "numTxs", blkProp.blk.Header.NumTxns, "duration", time.Since(now))
	}
	return nil
}

// Commit method commits the block to the blockstore and postgres database.
// It also updates the txIndexer and mempool with the transactions in the block.
func (ce *ConsensusEngine) commit(ctx context.Context, syncing bool) (err error) {
	ce.mempoolMtx.PriorityLock()
	defer ce.mempoolMtx.Unlock()

	if ce.state.blockRes == nil {
		return errors.New("no block results to commit")
	}

	blkProp := ce.state.blkProp
	height, appHash := ce.state.blkProp.height, ce.state.blockRes.appHash

	var clearIntent bool
	if ce.commitLog != nil {
		if err := ce.commitLog.Record(height, blkProp.blkHash); err != nil {
			return err
		}
		defer func() {
			if !clearIntent {
				return
			}
			if clearErr := ce.commitLog.Clear(); clearErr != nil {
				ce.log.Warn("Failed to clear commit intent", "error", clearErr)
			}
		}()
	}

	if err = ce.blockStore.Store(blkProp.blk, ce.state.commitInfo); err != nil {
		return err
	}

	if err = ce.blockStore.StoreResults(blkProp.blkHash, ce.state.blockRes.txResults); err != nil {
		return err
	}

	invokeCommitHook("after-blockstore")

	req := &ktypes.CommitRequest{
		Height:  height,
		AppHash: appHash,
		// To indicate if the node is syncing, used by the blockprocessor to decide if it should create snapshots.
		Syncing: ce.inSync.Load(),
	}
	if err = ce.blockProcessor.Commit(ctx, req); err != nil { // clears the mempool cache
		return err
	}
	invokeCommitHook("after-postgres")
	clearIntent = true

	// remove transactions from the mempool
	for idx, txn := range blkProp.blk.Txns {
		txHash := txn.HashCache()
		ce.mempool.Remove(txHash)

		txRes := ce.state.blockRes.txResults[idx]

		ce.subMtx.Lock()
		subChan, ok := ce.txSubscribers[txHash]
		if ok { // Notify the subscribers about the transaction result
			subChan <- txRes
		}
		ce.subMtx.Unlock()
	}

	mets.RecordCommit(ctx, time.Since(ce.state.tExecuted), height) // keep this before nextState()

	maxBlockSize := ce.ConsensusParams().MaxBlockSize
	// update the max block size in the mempool
	// This can result in the eviction of previously accepted transactions
	// to be rejected if the are larger than the new max block size.
	ce.mempool.CapMaxTxSize(maxBlockSize)

	// recheck the transactions in the mempool
	lh, time := ce.lastBlockInternal()
	ce.blockProcessor.RecheckTxs(ctx, lh, time)

	// should there be smaller limit to accommodate for the block serialization?
	sz, _ := ce.mempool.Size()
	if int64(sz) >= maxBlockSize {
		// mempool has enough txs to fill the block
		ce.mempoolReady.Store(true)
	}

	if !syncing {
		ce.log.Info("Committed Block", "height", height, "hash", blkProp.blkHash.String(),
			"appHash", appHash.String(), "numTxs", blkProp.blk.Header.NumTxns)
	}

	// update and reset the state fields
	ce.nextState()

	// update the role of the node based on the final validator set at the end of the commit.
	ce.updateValidatorSetAndRole()

	// reset the catchup timer as we have successfully processed a new block proposal
	ce.catchupTicker.Reset(ce.catchupTimeout)

	return ctx.Err()
}

// nextState sets the lastCommit in state.lc from the current block proposal
// execution and commit results, resets the other state fields such as block
// proposal, block result, etc., and updates the status (stateInfo) to reflect
// the block that was just committed.
func (ce *ConsensusEngine) nextState() {
	ce.state.lc = &lastCommit{
		height:     ce.state.blkProp.height,
		blkHash:    ce.state.blkProp.blkHash,
		appHash:    ce.state.blockRes.appHash,
		blk:        ce.state.blkProp.blk,
		commitInfo: ce.state.commitInfo,
	}

	ce.resetState()
}

func (ce *ConsensusEngine) rollbackState(ctx context.Context) error {
	// Revert back any state changes occurred due to the current block
	if err := ce.blockProcessor.Rollback(ctx, ce.state.lc.height, ce.state.lc.appHash); err != nil {
		return err
	}

	ce.resetState()
	ce.stateInfo.hasBlock.Store(ce.state.lc.height)

	return nil
}

func (ce *ConsensusEngine) resetState() {
	ce.state.blkProp = nil
	ce.state.blockRes = nil
	ce.state.votes = make(map[string]*ktypes.VoteInfo)
	ce.state.commitInfo = nil
	if ce.state.leaderUpdate != nil {
		ce.state.leaderUpdate = nil
		ce.storeLeaderUpdates(nil) // clear the leader update once applied.
	}

	// update the stateInfo
	ce.stateInfo.mtx.Lock()
	ce.stateInfo.status = Committed
	ce.stateInfo.blkProp = nil
	ce.stateInfo.height = ce.state.lc.height
	ce.stateInfo.lastCommit = *ce.state.lc
	ce.stateInfo.mtx.Unlock()

	ce.stateInfo.hasBlock.Store(ce.state.lc.height)

	ce.cancelFnMtx.Lock()
	ce.blkExecCancelFn = nil
	ce.longRunningTxs = make([]ktypes.Hash, 0)
	ce.cancelFnMtx.Unlock()
}
