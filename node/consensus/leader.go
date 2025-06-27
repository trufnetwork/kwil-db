package consensus

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

// The Leader is responsible for proposing blocks and managing the consensus process:
// 1. Prepare Phase:
//   - Create a block proposal
//   - Broadcast the block proposal
//   - Process the block and generate the appHash
//   - Wait for votes from validators
//   - Enter the commit phase if the majority of validators approve the block
//
// 2. Commit Phase:
//   - Commit the block and initiate the next prepare phase
//   - This phase includes committing the block to the block store, clearing the mempool,
//     updating the chain state, creating snapshots, committing the pg db state, etc.
//
// The Leader can also issue ResetState messages using "kwild block reset <reset-block-height> <longrunning-tx-list>"
// When a leader receives a ResetState request, it will broadcast the ResetState message to the network to
// halt the current block execution if the current block height equals reset-block-height + 1. The leader will stop processing
// the current block, revert any state changes made, and remove the problematic transactions from the mempool before
// reproposing the block.

// Leader Election through the `replace-leader` command:
// If the leader goes offline, the network can elect the new leader using the `kwild validators replace-leader` command.
// The new leader candidate and the majority of the validators must issue the command to replace the leader.
// The new leader candidate must be online and issue the replace command for it to start proposing blocks.
// In the scenarios where the leader is online, and few of the validators agreed to replace the leader, any of the
// three below scenarios can happen:
// 1. If the majority of the validators agree to replace the leader, the new leader candidate will start proposing blocks.
//    The previous leader and the validators that did not agree to replace the leader will accept the new leader once
//    they see a new block with majority of the votes from the validator set.
// 2. If the majority of the validators do not agree to replace the leader, the previous leader candidate will continue
//    to produce blocks. The validators that agreed to replace the leader will accept the blocks from the previous leader
//    if the block is signed by the majority of the validators. They should redo the leader election process
//    at later heights and must ensure that they have majority of the validators to replace the leader successfully.
// 3. If both previous leader and new leader candidate doesn't have majority of validators, then both the nodes will be
//    proposing the blocks, but none would get majority of the votes required to commit the block. So the network will halt
//    until one of these nodes gets majority of the validators to commit the block.

func (ce *ConsensusEngine) newBlockRound(ctx context.Context) {
	ce.log.Info("Starting a new consensus round", "height", ce.lastCommitHeight()+1)

	// Leader can optimize this idle timeout of proposeTimeout duration to propose a block
	// if there are enough transactions available in the mempool to fill the block.
	// One problem with this might be is that if the validators are slow,
	// leader might end up more time waiting for the acks and flood the network with rebroadcasts.
	// but probably better than leader doing nothing???

	if ce.mempoolReady.Load() { // set by recheckTxs after commit or by the QueueTx method
		// mempool has enough transactions to fill the block, trigger the next round
		ce.log.Debug("Mempool is ready with enough transactions to fill the block, initiating block proposal without waiting for the proposeTimeout")
		ce.newBlockProposal <- struct{}{}
		return
	}

	ticker := time.NewTicker(ce.proposeTimeout)
	now := time.Now()

	// if EmptyBlockTimeout = 0, leader doesn't propose empty blocks.
	// Behavior is similar to automine feature where the blocks are produced
	// the moment transactions are available once the proposeTimeout is elapsed.
	// if EmptyBlockTimeout is not 0, leader will propose an empty block
	// if no transactions or events are available for emptyBlockTimeout duration.
	allowEmptyBlocks := ce.emptyBlockTimeout != 0

	for {
		select {
		case <-ctx.Done():
			ce.log.Info("Context cancelled, stopping the new block round")
			return
		case <-ce.mempoolReadyChan:
			// mempool has enough txs to fill the block, trigger the next round
			ce.newBlockProposal <- struct{}{}
			return
		case <-ticker.C:
			// check for the availability of transactions in the mempool or
			// if the leader has any new events to broadcast a voteID transaction
			if ce.mempool.TxsAvailable() || ce.blockProcessor.HasEvents() {
				ce.newBlockProposal <- struct{}{}
				return
			}

			// If the emptyBlockTimeout duration has elapsed, produce an empty block if
			// empty blocks are allowed
			if allowEmptyBlocks && time.Since(now) >= ce.emptyBlockTimeout {
				ce.newBlockProposal <- struct{}{}
				return
			}

			ticker.Reset(200 * time.Millisecond)
		}

		// no transactions available, wait till the next tick to recheck the mempool
	}
}

// proposeBlock used by the leader to propose a new block to the network.
// Any non-nil error should be considered fatal to the node.
func (ce *ConsensusEngine) proposeBlock(ctx context.Context) error {
	ce.state.mtx.Lock()
	defer ce.state.mtx.Unlock()

	blkProp, err := ce.createBlockProposal(ctx)
	if err != nil {
		return fmt.Errorf("error creating block proposal: %w", err)
	}

	ce.log.Info("Created block proposal", "height", blkProp.height, "hash", blkProp.blkHash)

	// Validate the block proposal before announcing it to the network
	if err := ce.validateBlock(blkProp.blk); err != nil {
		return fmt.Errorf("block proposal failed internal validation: %w", err)
	}
	ce.state.blkProp = blkProp

	// Broadcast the block proposal to the network
	go ce.proposalBroadcaster(ctx, blkProp.blk, ce.pubKey.Bytes())

	// update the stateInfo
	ce.stateInfo.mtx.Lock()
	ce.stateInfo.status = Proposed
	ce.stateInfo.blkProp = blkProp
	ce.stateInfo.mtx.Unlock()

	// execCtx is applicable only for the duration of the block execution
	// This is used to give leader the ability to cancel the block execution.
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Set the cancel function for the block execution
	var reset bool
	ce.cancelFnMtx.Lock()
	ce.blkExecCancelFn = func() {
		reset = true
		cancel()
	}
	ce.cancelFnMtx.Unlock()

	// Execute the block and generate the appHash
	if err := ce.executeBlock(execCtx, blkProp, false); err != nil {
		// check if the error is due to context cancellation
		if errors.Is(err, context.Canceled) && reset { // NOTE: if not reset, then it's parent ctx cancellation i.e. a normal shutdown
			ce.log.Warn("Block execution cancelled by the leader", "height", blkProp.height, "hash", blkProp.blkHash)
			ce.cancelFnMtx.Lock()
			// trigger a reset state message to the network
			go ce.rstStateBroadcaster(ce.state.lc.height, ce.longRunningTxs)

			// Remove the long running transactions from the mempool
			ce.log.Info("Removing long running transactions from the mempool as per leader's request", "txIDs", ce.longRunningTxs)
			for _, txID := range ce.longRunningTxs {
				ce.mempool.Remove(txID)
			}
			ce.numResets++
			ce.cancelFnMtx.Unlock()

			if err := ce.rollbackState(ctx); err != nil {
				return fmt.Errorf("error resetting the state: %w", err)
			}

			// Recheck the transactions in the mempool
			ce.mempoolMtx.PriorityLock()
			lh, t := ce.lastBlockInternal()
			ce.blockProcessor.RecheckTxs(ctx, lh, t)
			ce.mempoolMtx.Unlock()

			// signal ce to start a new round
			// ce.newRound <- struct{}{}
			// repropse a new block
			ce.newBlockProposal <- struct{}{}
			return nil
		}

		return fmt.Errorf("error executing the block: %w", err)
	}

	// Add its own vote to the votes map
	sig, err := ktypes.SignVote(blkProp.blkHash, true, &ce.state.blockRes.appHash, ce.privKey)
	if err != nil {
		return fmt.Errorf("error signing the vote: %w", err)
	}

	ce.state.votes[string(ce.pubKey.Bytes())] = &ktypes.VoteInfo{
		AppHash:   &ce.state.blockRes.appHash,
		AckStatus: ktypes.AckAgree,
		Signature: *sig,
	}

	// reset the mempool ready flag once the block is proposed
	ce.mempoolReady.Store(false)

	// We may be ready to commit if we're the only validator.
	ce.processVotes(ctx)

	if len(ce.validatorSet) > 1 { // or can check if the proposal is committed: ce.blkProp == nil
		ce.log.Info("Waiting for votes from the validators", "height", blkProp.height, "hash", blkProp.blkHash)
	}

	return nil
}

// Create Proposal creates a new block proposal for the leader
// by reaping the transactions from the mempool. This also adds the
// proposer transactions such as ValidatorVoteBodies.
// This method orders the transactions in the nonce order and also
// does basic gas and balance checks and enforces the block size limits.
func (ce *ConsensusEngine) createBlockProposal(ctx context.Context) (*blockProposal, error) {
	ce.mempoolMtx.PriorityLock()
	defer ce.mempoolMtx.Unlock()

	totalTxSizeLimit := ce.ConsensusParams().MaxBlockSize
	txns := ce.mempool.PeekN(maxNumTxnsInBlock, int(totalTxSizeLimit))

	finalTxs, invalidTxs, err := ce.blockProcessor.PrepareProposal(ctx, txns)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare proposal: %w", err)
	}

	// remove invalid transactions from the mempool
	for _, tx := range invalidTxs {
		txid := tx.Hash()
		ce.mempool.Remove(txid)
	}

	valSetHash := ce.validatorSetHash()
	paramsHash := ce.blockProcessor.ConsensusParams().Hash()
	stamp := time.Now().Truncate(time.Millisecond).UTC()
	blk := ktypes.NewBlock(ce.state.lc.height+1, ce.state.lc.blkHash, ce.state.lc.appHash, valSetHash, paramsHash, stamp, finalTxs)

	// add the leader updates to the block header if any
	if ce.state.leaderUpdate != nil {
		// blk.Header.OfflineLeaderUpdate = &ktypes.OfflineLeaderUpdate{
		// 	Candidate: ce.state.leaderUpdate.Candidate,
		// }
		blk.Header.NewLeader = ce.state.leaderUpdate.Candidate
	}

	// Sign the block
	if err := blk.Sign(ce.privKey); err != nil {
		return nil, err
	}

	return &blockProposal{
		height:  blk.Header.Height,
		blkHash: blk.Header.Hash(),
		blk:     blk,
	}, nil
}

// addVote registers the vote received from the validator if it is for the current block.
// This method will only error in scenarios where the vote is applied incorrectly to the leader's state.
// If the peers have sent an invalid vote, the leader will ignore the vote.
func (ce *ConsensusEngine) addVote(ctx context.Context, voteMsg *vote, sender string) error {
	// ce.log.Debugln("Adding vote", vote, sender)
	ce.state.mtx.Lock()
	defer ce.state.mtx.Unlock()

	if ce.state.blkProp == nil {
		ce.log.Debug("Error adding vote: not processing any block proposal at the moment")
		return nil
	}

	// check if the vote is for the current height
	vote := voteMsg.msg
	if ce.state.blkProp.height != vote.Height {
		ce.log.Debug("Error adding vote: Vote received for a different block height, ignore it", "height", vote.Height)
		return nil
	}

	// check if the vote is for the current block and from a validator
	if ce.state.blkProp.blkHash != vote.BlkHash {
		ce.log.Warn("Error adding vote: Vote received for a different block", "height", vote.Height, "blkHash", vote.BlkHash)
		return nil
	}

	// Check if the vote is from a validator
	if _, ok := ce.validatorSet[sender]; !ok {
		return fmt.Errorf("vote received from an unknown validator %s", sender)
	}

	if vote.ACK && vote.AppHash == nil {
		return errors.New("missing appHash in the vote")
	}

	if vote.Signature == nil {
		return errors.New("missing signature in the vote")
	}

	// check if the vote is a Nack vote and the leader is out of sync
	proof, ok := vote.OutOfSync()
	if ok {
		// verify the proof
		if proof.Header == nil {
			ce.log.Warnf("Invalid vote from peer %s: missing block header in the out-of-sync proof", sender)
			return nil // ignore, not a leader failure
		}
		hash := proof.Header.Hash()
		valid, err := ce.pubKey.Verify(hash[:], proof.Signature)
		if err != nil {
			ce.log.Warnf("Error verifying the out-of-sync proof: %w", err)
			return nil // ignore, not a leader failure
		}
		if !valid {
			ce.log.Warn("Invalid vote: out-of-sync proof verification failed")
			return nil // ignore, not a leader failure
		}

		// received a valid out-of-sync proof
		ce.log.Warn("Received out-of-sync proof from the validator, resetting the state and initiating the catchup mode", "from", vote.Height, "to", proof.Header.Height)

		// rollback current block execution
		if err := ce.rollbackState(ctx); err != nil {
			return fmt.Errorf("error resetting the state: %w", err)
		}

		// trigger block sync to catch up with the network till the height specified in the out-of-sync proof
		go func() {
			if err := ce.syncBlocksUntilHeight(ctx, ce.state.lc.height+1, proof.Header.Height); err != nil {
				if err != types.ErrBlkNotFound {
					haltReason := fmt.Sprintf("Error syncing blocks: %v", err)
					ce.sendHalt(haltReason)
					return
				}

				// if the block is not found, maybe retry>? or just move on to the next round
				// and let the leader propose a new block, and the validator can refute it
				// until it catches up.
			}

			if ce.role.Load() == types.RoleLeader {
				ce.newRound <- struct{}{} // signal ce to start a new round
			}
		}()

		return nil
	}

	if _, ok := ce.state.votes[sender]; !ok {
		// verify the vote signature, before accepting the vote from the validator if ack is true
		var ackStatus ktypes.AckStatus
		var appHash *types.Hash

		if vote.ACK {
			ackStatus = ktypes.AckAgree
			if *vote.AppHash != ce.state.blockRes.appHash {
				ackStatus = ktypes.AckForked
				appHash = vote.AppHash
			}
		}

		voteInfo := &ktypes.VoteInfo{
			Signature: *vote.Signature,
			AckStatus: ackStatus,
			AppHash:   appHash,
		}

		// verify signature
		if err := voteInfo.Verify(vote.BlkHash, ce.state.blockRes.appHash); err != nil {
			ce.log.Errorf("Error verifying the vote signature: %v", err)
			return fmt.Errorf("error verifying the vote signature: %w", err)
		}

		if voteInfo.AckStatus == ktypes.AckAgree {
			ce.log.Info("Adding vote", "height", vote.Height, "blkHash", vote.BlkHash, "appHash", vote.AppHash, "sender", sender)
		} else if voteInfo.AckStatus == ktypes.AckForked {
			ce.log.Warn("Adding vote with apphash mismatch", "height", vote.Height, "blkHash", vote.BlkHash, "appHash", vote.AppHash, "sender", sender)
		} else {
			ce.log.Info("Adding nack vote", "height", vote.Height, "blkHash", vote.BlkHash, "sender", sender)
		}

		ce.state.votes[sender] = voteInfo
	}

	ce.processVotes(ctx)
	return nil
}

// ProcessVotes processes the votes received from the validators.
// Depending on the votes, leader will trigger one of the following:
// 1. Commit the block
// 2. Re-announce the block proposal
// 3. Halt the network (should there be a message to halt the network?)
func (ce *ConsensusEngine) processVotes(ctx context.Context) {
	ce.log.Debug("Processing votes", "height", ce.state.lc.height+1)

	blkProp, blkRes := ce.state.blkProp, ce.state.blockRes
	if blkProp == nil || blkRes == nil {
		// Moved onto the next round or leader still processing the current block
		return
	}

	// Count the votes
	var acks, nacks int
	for _, vote := range ce.state.votes {
		if vote.AckStatus == ktypes.AckAgree {
			acks++
		} else {
			nacks++
		}
	}

	if ce.hasEnoughNacks(nacks) {
		haltReason := fmt.Sprintf("at least half the validators have rejected the block, preventing network progress. Halting the network: %d acks, %d nacks", acks, nacks)
		ce.sendHalt(haltReason)
		return
	}

	if !ce.hasMajority(acks) {
		// No majority yet, wait for more votes
		return
	}

	ce.log.Info("Majority of the validators have accepted the block, proceeding to commit the block",
		"height", blkProp.blk.Header.Height, "hash", blkProp.blkHash, "acks", acks, "nacks", nacks)

	votes := make([]*ktypes.VoteInfo, 0, len(ce.state.votes))
	for _, v := range ce.state.votes {
		votes = append(votes, v)
	}
	slices.SortFunc(votes, func(a, b *ktypes.VoteInfo) int {
		if diff := bytes.Compare(a.Signature.PubKey, b.Signature.PubKey); diff != 0 {
			return diff
		}
		return cmp.Compare(a.Signature.PubKeyType, b.Signature.PubKeyType)
	})

	// NOTE: Something to keep in mind, if there is any leader change due to some
	// offline update process, the leader update is included in the block header,
	// but as this affects the network params eventually, the same leader update is
	// included in the param updates as well. We can either keep it that way or remove
	// it from the param updates (also update the hash)

	// Set the commit info for the accepted block
	ce.state.commitInfo = &ktypes.CommitInfo{
		AppHash:          blkRes.appHash,
		Votes:            votes,
		ParamUpdates:     blkRes.paramUpdates,
		ValidatorUpdates: blkRes.valUpdates,
	}

	// Commit the block and broadcast the blockAnn message
	if err := ce.commit(ctx, false); err != nil {
		ce.sendHalt(fmt.Sprintf("Error committing block %v: %v", blkProp.blkHash, err))
		return
	}

	ce.log.Debugln("Announce committed block", blkProp.blk.Header.Height, blkProp.blkHash, blkRes.paramUpdates)

	// Broadcast the blockAnn message
	go ce.blkAnnouncer(ctx, blkProp.blk, ce.state.lc.commitInfo)

	// signal ce to start a new round if the node is still the leader
	if ce.role.Load() == types.RoleLeader {
		ce.newRound <- struct{}{}
	}
}

func (ce *ConsensusEngine) validatorSetHash() types.Hash {
	hasher := ktypes.NewHasher()

	keys := make([]string, 0, len(ce.validatorSet))
	for _, v := range ce.validatorSet {
		keys = append(keys, config.EncodePubKeyAndType(v.Identifier, v.KeyType))
	}

	// sort the keys
	slices.Sort(keys)

	for _, k := range keys {
		val := ce.validatorSet[k]
		hasher.Write(val.AccountID.Bytes())
		binary.Write(hasher, binary.BigEndian, val.Power)
	}

	return hasher.Sum(nil)
}

// CancelBlockExecution is used by the leader to manually cancel the block execution
// if it is taking too long to execute. This method takes the height of the block to
// be cancelled and the list of long transaction IDs to be evicted from the mempool.
// One concern is: what if the block finishes execution and the leader tries to cancel it,
// and the resolutions update some internal state that cannot be reverted?
func (ce *ConsensusEngine) CancelBlockExecution(height int64, txIDs []types.Hash) error {
	ce.log.Info("Block execution cancel request received", "height", height)
	// Ensure we are cancelling the block execution for the current block
	ce.stateInfo.mtx.RLock()
	defer ce.stateInfo.mtx.RUnlock()

	// Check if the height is the same as the current block height
	if height != ce.stateInfo.height+1 {
		ce.log.Warn("Cannot cancel block execution, block height does not match", "height", height, "current", ce.stateInfo.height+1)
		return fmt.Errorf("cannot cancel block execution for block height %d, currently executing %d", height, ce.stateInfo.height+1)
	}

	// Check if a block is proposed
	if ce.stateInfo.blkProp == nil {
		ce.log.Warn("Cannot cancel block execution, no block is proposed yet", "height", height)
		return fmt.Errorf("cannot cancel block execution, no block is proposed yet")
	}

	// Cannot cancel if the block is already finished executing or committed
	if ce.stateInfo.status != Proposed {
		ce.log.Warn("Cannot cancel block execution, block is already executed or committed", "height", height)
		return fmt.Errorf("cannot cancel block execution, block is already executed or committed")
	}

	// Cancel the block execution
	ce.cancelFnMtx.Lock()
	defer ce.cancelFnMtx.Unlock()

	ce.longRunningTxs = slices.Clone(txIDs)

	if ce.blkExecCancelFn != nil {
		ce.log.Info("Cancelling block execution", "height", height, "txIDs", txIDs)
		ce.blkExecCancelFn()
	} else {
		ce.log.Error("Block execution cancel function not set")
		return errors.New("block execution cancel function not set")
	}

	return nil
}
