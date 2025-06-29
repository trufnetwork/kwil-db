package consensus

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

// AcceptProposal determines if the node should download the block for the given proposal.
// This should not be processed by the leader and the sentry nodes and must return false.
// Validators should only accept the proposal if they are not currently processing
// another block and the proposal is for the next block to be processed.
// If a new proposal for the same height is received, the current proposal execution
// should be aborted and the new proposal should be processed.
// If the leader proposes a new block for already committed heights, the validator should
// send a Nack to the leader with an OutOfSyncProof, indicating the leader to
// catchup to the correct height before proposing new blocks.
func (ce *ConsensusEngine) AcceptProposal(height int64, blkID, prevBlockID types.Hash, leaderSig []byte, timestamp int64) bool {
	if ce.role.Load() != types.RoleValidator {
		return false
	}

	// check if the blkProposal is from the leader
	valid, err := ce.leader.Verify(blkID[:], leaderSig)
	if err != nil {
		ce.log.Error("Error verifying leader signature", "error", err)
		return false
	}

	if !valid {
		ce.log.Info("Invalid leader signature, ignoring the block proposal msg: ", "height", height) // log possible attack spam
		return false
	}

	ce.stateInfo.mtx.RLock()
	defer ce.stateInfo.mtx.RUnlock()

	// Check if the block is for an already committed height, but the blkID is different and newer.
	if height < ce.stateInfo.lastCommit.height {
		// proposal is for an already committed height
		bHash, blk, _, err := ce.blockStore.GetByHeight(height)
		if err != nil {
			ce.log.Error("Error fetching block from store", "height", height, "error", err)
			return false
		}

		if bHash == blkID { // already committed the proposed block, ignore the proposal
			return false
		}

		if blk.Header.Timestamp.UnixMilli() > timestamp {
			// stale proposal, ignore
			return false
		}

		// send a nack to the leader
		status := types.NackStatusOutOfSync
		sig, err := ktypes.SignVote(blkID, false, nil, ce.privKey)
		if err != nil {
			ce.log.Error("Error signing the voteInfo", "error", err)
			return false
		}

		// Get the best block for the OutOfSyncProof
		bestH, _, _, _ := ce.blockStore.Best()
		_, bestBlk, _, err := ce.blockStore.GetByHeight(bestH)
		if err != nil {
			ce.log.Error("Error fetching best block from store", "height", bestH, "error", err)
			return false
		}

		ackRes := &types.AckRes{
			ACK:        false,
			NackStatus: &status,
			BlkHash:    blkID,
			Height:     height,
			OutOfSyncProof: &types.OutOfSyncProof{
				Header:    bestBlk.Header,
				Signature: bestBlk.Signature,
			},
			Signature: sig,
		}

		ce.log.Info("leader is out of sync, sending outOfSyncNack to the leader", "leaderHeight", height, "bestHeight", bestBlk.Header.Height)
		go ce.ackBroadcaster(ackRes)
		return false
	}

	if height != ce.stateInfo.height+1 {
		ce.log.Debug("Block proposal is not for the next height", "blkPropHeight", height, "expected", ce.stateInfo.height+1)
		return false
	}

	// Check if the validator is busy processing a block.
	if ce.stateInfo.status != Committed {
		// check if we are processing a different block, if yes then reset the state.
		if ce.stateInfo.blkProp.blkHash != blkID && ce.stateInfo.blkProp.blk.Header.Timestamp.UnixMilli() < timestamp {
			ce.log.Debug("Conflicting block proposals, abort block execution and requesting the latest block: ", "height", height)
			// go ce.sendResetMsg(ce.stateInfo.height)
			return true
		}
		ce.log.Debug("Already processing the block proposal", "height", height, "blockID", blkID)
		return false
	}

	// not processing any block, accept the proposal
	return true
}

// AcceptCommit handles the blockAnnounce message from the leader.
// This should be processed only if this is the next block to be committed by the node.
// This also checks if the node should request the block from its peers. This can happen
// 1. If the node is a sentry node and doesn't have the block.
// 2. If the node is a validator and missed the block proposal message.
func (ce *ConsensusEngine) AcceptCommit(height int64, blkID types.Hash, hdr *ktypes.BlockHeader, ci *ktypes.CommitInfo, leaderSig []byte) bool {
	ce.stateInfo.mtx.RLock()
	defer ce.stateInfo.mtx.RUnlock()

	if ce.stateInfo.hasBlock.Load() == height { // ce is notified about the blkAnn message already
		// that we processed correct proposal
		if ce.stateInfo.blkProp != nil && ce.stateInfo.blkProp.blkHash == blkID {
			ce.log.Debug("Already processed the block proposal", "height", height, "blockID", blkID)
			return false
		}
	}

	// check if we already downloaded the block through the block proposal message
	if (ce.stateInfo.blkProp != nil && ce.stateInfo.blkProp.blkHash == blkID) && (ce.stateInfo.status == Proposed || ce.stateInfo.status == Executed) {
		// block is already downloaded and/being processed, accept the commit, don't request the block again
		go ce.NotifyBlockCommit(ce.stateInfo.blkProp.blk, ci, blkID, nil)
		return false
	}

	if ce.stateInfo.height+1 != height {
		return false
	}

	// Ensure that the leader update is valid, i.e the new leader is a validator.
	if hdr.NewLeader != nil {
		candidate := hdr.NewLeader
		// ensure that the Candidate is a validator
		if _, ok := ce.validatorSet[hex.EncodeToString(candidate.Bytes())]; !ok {
			ce.log.Error("Invalid leader update, candidate is not an existing validator, rejecting the block proposal", "leader with the update", hex.EncodeToString(candidate.Bytes()))
			return false
		}
	}

	// check if there are any leader updates in the block header
	updatedLeader, leaderUpdated := ci.ParamUpdates[ktypes.ParamNameLeader]
	if leaderUpdated {
		// accept this new leader only if the commitInfo votes are correctly validated
		if err := ce.verifyVotes(ci, blkID); err != nil {
			ce.log.Error("Error verifying votes", "error", err)
			return false
		}
		leader := (updatedLeader.(ktypes.PublicKey)).PublicKey

		ce.log.Infof("Received block with leader update, new leader: %s  old leader: %s", hex.EncodeToString(leader.Bytes()), hex.EncodeToString(ce.leader.Bytes()))
	}

	// Leader signature verification is not required as long as the commitInfo includes the signatures
	// from majority of the validators. There can also scenarios where the node tried to promote a new
	// leader candidate, but the candidate did not receive enough votes to be promoted as a leader.
	// In such cases, the old leader produces the block, but this node will not accept the blkAnn message
	// from the old leader, as the node has a different leader now. So accept the committed block as
	// long as the block is accepted by the majority of the validators.
	return true
}

// ProcessBlockProposal is used by the validator's consensus engine to process the new block proposal message.
// This method is used to validate the received block, execute the block and generate appHash and
// report the result back to the leader.
// Only accept the block proposals from the node that this node considers as a leader.
func (ce *ConsensusEngine) processBlockProposal(ctx context.Context, blkPropMsg *blockProposal) error {
	defer blkPropMsg.done()

	if ce.role.Load() != types.RoleValidator {
		ce.log.Warn("Only validators can process block proposals")
		return nil
	}

	ce.state.mtx.Lock()
	defer ce.state.mtx.Unlock()

	if ce.state.lc.height+1 != blkPropMsg.height {
		ce.log.Info("Block proposal is not for the current height", "blkPropHeight", blkPropMsg.height, "expected", ce.state.lc.height+1)
		return nil
	}

	if ce.state.blkProp != nil {
		if ce.state.blkProp.blkHash == blkPropMsg.blkHash {
			ce.log.Info("Already processing the block proposal", "height", blkPropMsg.height)
			return nil
		}

		if ce.state.blkProp.blk.Header.Timestamp.After(blkPropMsg.blk.Header.Timestamp) {
			ce.log.Info("Received stale block proposal, Ignore", "height", blkPropMsg.height, "blockID", blkPropMsg.blkHash)
			return nil
		}

		blkHash := ce.state.blkProp.blkHash
		ce.log.Info("Aborting execution of stale block proposal", "height", blkPropMsg.height, "blockID", blkHash)
		if err := ce.rollbackState(ctx); err != nil {
			ce.log.Error("Error aborting execution of block", "height", blkPropMsg.height, "blockID", blkHash, "error", err)
			return err
		}
	}

	if blkPropMsg.blk.Header.NewLeader != nil {
		// leader updated, ensure one more time that the node is okay with the leader change
		newLeader := hex.EncodeToString(blkPropMsg.blk.Header.NewLeader.Bytes())
		if ce.leader.Equals(blkPropMsg.blk.Header.NewLeader) {
			ce.log.Info("Node accepts the leader change", "newLeader", newLeader)
		} else {
			ce.log.Error("Node does not accept the leader change", "newLeader", newLeader)
			return nil
		}
	}

	ce.log.Debug("Processing block proposal", "height", blkPropMsg.blk.Header.Height, "blkID", blkPropMsg.blkHash, "numTxs", blkPropMsg.blk.Header.NumTxns)

	if err := ce.validateBlock(blkPropMsg.blk); err != nil {
		sig, err := ktypes.SignVote(blkPropMsg.blkHash, false, nil, ce.privKey)
		if err != nil {
			return fmt.Errorf("error signing the voteInfo: %w", err)
		}
		// go ce.ackBroadcaster(false, blkPropMsg.height, blkPropMsg.blkHash, nil, nil)
		status := types.NackStatusInvalidBlock
		go ce.ackBroadcaster(&types.AckRes{
			ACK:        false,
			NackStatus: &status,
			BlkHash:    blkPropMsg.blkHash,
			Height:     blkPropMsg.height,
			Signature:  sig,
		})

		return fmt.Errorf("error validating block: %w", err)
	}
	ce.state.blkProp = blkPropMsg
	ce.state.blockRes = nil

	// Update the stateInfo
	ce.stateInfo.mtx.Lock()
	ce.stateInfo.status = Proposed
	ce.stateInfo.blkProp = blkPropMsg
	ce.stateInfo.mtx.Unlock()

	// allow new proposals to be checked
	blkPropMsg.done()

	// execCtx is applicable only for the duration of the block execution
	// This is used to react to the leader's reset message by cancelling the block execution.
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Set the cancel function for the block execution
	ce.cancelFnMtx.Lock()
	ce.blkExecCancelFn = cancel
	ce.cancelFnMtx.Unlock()

	if err := ce.executeBlock(execCtx, blkPropMsg, false); err != nil {
		if errors.Is(err, context.Canceled) {
			ce.log.Info("Block execution cancelled", "height", blkPropMsg.height)
			return nil
		}
		return err
	}

	// Broadcast the result back to the leader
	ce.log.Info("Sending ack to the leader", "height", blkPropMsg.height,
		"hash", blkPropMsg.blkHash, "appHash", ce.state.blockRes.appHash)

	signature, err := ktypes.SignVote(blkPropMsg.blkHash, true, &ce.state.blockRes.appHash, ce.privKey)
	if err != nil {
		ce.log.Error("Error signing the voteInfo", "error", err)
		return err
	}
	voteInfo := &vote{
		msg: &types.AckRes{
			ACK:       true,
			BlkHash:   blkPropMsg.blkHash,
			Height:    blkPropMsg.height,
			AppHash:   &ce.state.blockRes.appHash,
			Signature: signature,
		},
	}
	ce.state.blockRes.vote = voteInfo

	go ce.ackBroadcaster(voteInfo.msg)

	return nil
}

// This is triggered in response to the blockAnn message from the leader.
// This method is used by the sentry and the validators nodes to commit the specified block.
// If the validator node processed a different block, it should rollback and reprocess the block.
// Validator nodes can skip the block execution and directly commit the block if they have already processed the block.
// The nodes should only commit the block if the appHash is valid, else halt the node.
func (ce *ConsensusEngine) commitBlock(ctx context.Context, blk *ktypes.Block, ci *ktypes.CommitInfo, blkID types.Hash, done func()) error {
	ce.state.mtx.Lock()
	defer ce.state.mtx.Unlock()

	defer done()

	if ce.state.lc.height+1 != blk.Header.Height { // only accept/process the block if it is for the next height
		return nil
	}

	// Three different scenarios are possible here:
	// 1. Sentry node: Execute the block, validate the appHash and commit the block.
	// 2. Validator:
	// - No blockProposal received: Execute the block, validate the appHash and commit the block.
	// - Incorrect Block received: Rollback and reprocess the block sent as part of the commit message.
	// - Incorrect AppHash: Halt the node.

	if ce.role.Load() == types.RoleSentry {
		return ce.processAndCommit(ctx, blk, ci, blkID, false)
	}

	// You are a validator
	if ce.state.blkProp == nil {
		return ce.processAndCommit(ctx, blk, ci, blkID, false)
	}

	if ce.state.blkProp.blkHash != blkID {
		ce.log.Info("Received committed block is different from the block processed, rollback and process the committed block", "height", blk.Header.Height, "blockID", blkID, "processedBlockID", ce.state.blkProp.blkHash)

		if err := ce.rollbackState(ctx); err != nil {
			ce.log.Error("error aborting execution of incorrect block proposal", "height", blk.Header.Height, "blockID", blkID, "error", err)
			// that's ok???
			return fmt.Errorf("error aborting execution of incorrect block proposal: %w", err)
		}

		return ce.processAndCommit(ctx, blk, ci, blkID, false)
	}

	// The block is already processed, just validate the appHash and commit the block if valid.
	oldH := ce.stateInfo.hasBlock.Swap(blk.Header.Height)
	if oldH != ce.state.lc.height {
		return fmt.Errorf("block %d already processed, duplicate commitBlock %s", oldH, blkID)
	}

	if !ce.state.blockRes.paramUpdates.Equals(ci.ParamUpdates) { // this is absorbed in apphash anyway, but helps diagnostics
		haltR := fmt.Sprintf("Incorrect ParamUpdates, halting the node. received: %s, computed: %s", ci.ParamUpdates, ce.state.blockRes.paramUpdates)
		ce.sendHalt(haltR)
		return nil
	}

	if ce.state.blockRes.appHash != ci.AppHash {
		haltR := fmt.Sprintf("Incorrect AppHash, halting the node. received: %s, computed: %s", ci.AppHash, ce.state.blockRes.appHash)
		ce.sendHalt(haltR)
		return nil
	}

	if err := ce.acceptCommitInfo(ci, ce.state.blkProp.blkHash); err != nil {
		ce.log.Error("Error validating commitInfo", "error", err)
		return err
	}

	// Commit the block
	if err := ce.commit(ctx, false); err != nil {
		ce.log.Errorf("Error committing block: height: %d, error: %v", blk.Header.Height, err)
		return err
	}
	return nil
}

// processAndCommit: used by the sentry nodes and slow validators to process and commit the block.
// This is used when the acks are not required to be sent back to the leader, essentially in catchup mode.
func (ce *ConsensusEngine) processAndCommit(ctx context.Context, blk *ktypes.Block, ci *ktypes.CommitInfo, blkID types.Hash, syncing bool) error {
	if ci == nil {
		return fmt.Errorf("commitInfo is nil")
	}

	if !syncing {
		ce.log.Info("Processing committed block", "height", blk.Header.Height, "blockID", blkID, "appHash", ci.AppHash)
	}

	// set the hasBlock to the height of the block
	oldH := ce.stateInfo.hasBlock.Swap(blk.Header.Height)
	if oldH != ce.state.lc.height {
		return fmt.Errorf("block %d already processed, duplicate block announcement received %s", oldH, blkID)
	}

	if err := ce.validateBlock(blk); err != nil {
		return err
	}

	// ensure that the commit info is valid
	if err := ce.acceptCommitInfo(ci, blkID); err != nil {
		return fmt.Errorf("error validating commitInfo: %w", err)
	}

	// accept the leader updates here
	if blk.Header.NewLeader != nil {
		// definitely this node is not the leader, so no role change need to be done here
		ce.leader = blk.Header.NewLeader
	}

	ce.state.blkProp = &blockProposal{
		height:  blk.Header.Height,
		blkHash: blkID,
		blk:     blk,
	}

	// Update the stateInfo
	ce.stateInfo.mtx.Lock()
	ce.stateInfo.status = Proposed
	ce.stateInfo.blkProp = ce.state.blkProp
	ce.stateInfo.mtx.Unlock()

	if err := ce.executeBlock(ctx, ce.state.blkProp, syncing); err != nil {
		return fmt.Errorf("error executing block: %w", err)
	}

	if !ce.state.blockRes.paramUpdates.Equals(ci.ParamUpdates) { // this is absorbed in apphash anyway, but helps diagnostics
		haltR := fmt.Sprintf("processAndCommit: Incorrect ParamUpdates, halting the node. received: %s, computed: %s", ci.ParamUpdates, ce.state.blockRes.paramUpdates)
		ce.sendHalt(haltR)
		return errors.New(haltR)
	}

	// Commit the block if the appHash and commitInfo is valid
	if ce.state.blockRes.appHash != ci.AppHash {
		// dump the statehashes from the block processor for debugging
		sh := ce.blockProcessor.StateHashes()
		if syncing {
			ce.log.Info("AppState updates: ",
				"prevAppHash", sh.PrevApp[:8], "changesets", sh.Changeset[:8],
				"validatorset", sh.ValUpdates[:8], "accounts", sh.Accounts[:8],
				"txResults", sh.TxResults[:8], "params", sh.ParamUpdates[:8])
		}

		haltR := fmt.Sprintf("processAndCommit: AppHash mismatch, halting the node. expected: %s, received: %s", ce.state.blockRes.appHash, ci.AppHash)
		ce.sendHalt(haltR)
		return errors.New(haltR)
	}

	if err := ce.commit(ctx, syncing); err != nil {
		return fmt.Errorf("error committing block: %w", err)
	}
	return nil
}

func (ce *ConsensusEngine) acceptCommitInfo(ci *ktypes.CommitInfo, blkID ktypes.Hash) error {
	if ci == nil {
		return fmt.Errorf("commitInfo is nil")
	}

	// Validate CommitInfo
	if err := ce.verifyVotes(ci, blkID); err != nil {
		return fmt.Errorf("error verifying votes: %w", err)
	}

	if err := ktypes.ValidateUpdates(ci.ParamUpdates); err != nil {
		return fmt.Errorf("paramUpdates failed validation: %w", err)
	}

	ce.state.commitInfo = ci

	return nil
}

func (ce *ConsensusEngine) verifyVotes(ci *ktypes.CommitInfo, blkID ktypes.Hash) error {
	// Validate CommitInfo
	var acks int
	for _, vote := range ci.Votes {
		// vote is from a validator
		_, ok := ce.validatorSet[hex.EncodeToString(vote.Signature.PubKey)]
		if !ok {
			return fmt.Errorf("vote is from a non-validator: %s", hex.EncodeToString(vote.Signature.PubKey))
		}

		err := vote.Verify(blkID, ci.AppHash)
		if err != nil {
			return fmt.Errorf("error verifying vote: %w", err)
		}

		if vote.AckStatus == ktypes.AckAgree {
			acks++
		}
	}

	if !ce.hasMajority(acks) {
		return fmt.Errorf("invalid blkAnn message, not enough acks in the commitInfo, leader misbehavior: %d", acks)
	}

	return nil
}
