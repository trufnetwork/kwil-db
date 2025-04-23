package blockprocessor

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kwilteam/kwil-db/common"
	"github.com/kwilteam/kwil-db/config"
	"github.com/kwilteam/kwil-db/core/crypto"
	"github.com/kwilteam/kwil-db/core/crypto/auth"
	"github.com/kwilteam/kwil-db/core/log"
	ktypes "github.com/kwilteam/kwil-db/core/types"
	authExt "github.com/kwilteam/kwil-db/extensions/auth"
	"github.com/kwilteam/kwil-db/node/meta"
	"github.com/kwilteam/kwil-db/node/types"
	"github.com/kwilteam/kwil-db/node/types/sql"
)

// This package will be equivalent to the ABCI application in Tendermint.
// This is responsible for processing blocks, managing consensus state, and
// handling transactions and mempool state.
// Once Consensus Engine decides on the block to be processed, it will be sent to
// Block Processor for its execution.
// Modules like Consensus Engine, RPC services rely on this package.

// shouldn't be generally concerned with the role. maybe role is needed for broadcasting eventstore events to the leader.
type BlockProcessor struct {
	// config
	genesisParams *config.GenesisConfig
	// netParams     *config.NetworkParameters // in chainCtx
	signer auth.Signer

	mtx sync.RWMutex // mutex to protect the consensus params
	// consensus params
	appHash     ktypes.Hash
	height      atomic.Int64
	chainCtx    *common.ChainContext
	stateHashes *StateHashes

	status   *blockExecStatus
	statusMu sync.RWMutex // very granular mutex to protect access to the block execution status

	// consensus TX
	consensusTx sql.PreparedTx

	// interfaces
	db          DB
	txapp       TxApp
	accounts    Accounts
	validators  ValidatorModule
	snapshotter SnapshotModule
	events      EventStore
	migrator    MigratorModule
	mempool     Mempool // only for rechecks
	log         log.Logger

	// broadcast function to send transactions to the network
	broadcastTxFn BroadcastTxFn
	// Whitelist functions for adding and removing peers
	addPeer    func(string) error
	removePeer func(string) error

	// Subscribers for the validator updates
	subChans []chan []*ktypes.Validator
	subMtx   sync.RWMutex
}

type BroadcastTxFn func(ctx context.Context, tx *ktypes.Transaction, sync uint8) (ktypes.Hash, *ktypes.TxResult, error)

func NewBlockProcessor(ctx context.Context, db DB, txapp TxApp, accounts Accounts, vs ValidatorModule,
	sp SnapshotModule, es EventStore, migrator MigratorModule, bs BlockStore, mp Mempool,
	genesisCfg *config.GenesisConfig, signer auth.Signer, logger log.Logger) (*BlockProcessor, error) {
	// get network parameters from the chain context
	bp := &BlockProcessor{
		db:          db,
		txapp:       txapp,
		accounts:    accounts,
		validators:  vs,
		snapshotter: sp,
		signer:      signer,
		events:      es,
		mempool:     mp,
		migrator:    migrator,
		log:         logger,
	}

	bp.genesisParams = genesisCfg

	tx, err := db.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin outer tx: %w", err)
	}
	defer tx.Rollback(ctx)

	height, appHash, dirty, err := meta.GetChainState(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain state: %w", err)
	}
	if dirty {
		logger.Warn("Chain state is dirty, recovering...")
		// app state is in a partially committed state, recover the chain state.
		_, _, ci, err := bs.GetByHeight(height)
		if err != nil || ci == nil {
			return nil, err
		}

		if err := meta.SetChainState(ctx, tx, height, ci.AppHash[:], false); err != nil {
			return nil, err
		}

		copy(appHash, ci.AppHash[:])

		// also update the last changeset height in the migrator
		if err := bp.migrator.PersistLastChangesetHeight(ctx, tx, height); err != nil {
			return nil, err
		}
	}

	bp.height.Store(height)
	copy(bp.appHash[:], appHash)

	var migrationParams *common.MigrationContext
	startHeight := genesisCfg.Migration.StartHeight
	endHeight := genesisCfg.Migration.EndHeight

	if startHeight != 0 && endHeight != 0 {
		migrationParams = &common.MigrationContext{
			StartHeight: startHeight,
			EndHeight:   endHeight,
		}
	}

	networkParams, err := meta.LoadParams(ctx, tx)
	if errors.Is(err, meta.ErrParamsNotFound) {
		bp.log.Debug("Network parameters not found in the database, expected if node is bootstrapping from genesis")
		networkParams = &genesisCfg.NetworkParameters // don't store, just use the genesis config for initial ChainContext until startup
	} else if err != nil {
		return nil, fmt.Errorf("failed to load the network parameters: %w", err)
	}

	bp.chainCtx = &common.ChainContext{
		ChainID:           genesisCfg.ChainID,
		NetworkParameters: networkParams,
		MigrationParams:   migrationParams,
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit the outer tx: %w", err)
	}

	return bp, nil
}

func (bp *BlockProcessor) SetCallbackFns(broadcastFn BroadcastTxFn, addPeer, removePeer func(string) error) {
	bp.broadcastTxFn = broadcastFn
	bp.addPeer = addPeer
	bp.removePeer = removePeer
}

func (bp *BlockProcessor) Close() error {
	bp.mtx.Lock()
	defer bp.mtx.Unlock()

	if bp.consensusTx != nil {
		bp.log.Info("Rolling back the consensus transaction")
		if err := bp.consensusTx.Rollback(context.Background()); err != nil {
			return fmt.Errorf("failed to rollback the consensus transaction: %w", err)
		}
	}

	return nil
}

func (bp *BlockProcessor) Rollback(ctx context.Context, height int64, appHash ktypes.Hash) error {
	bp.mtx.Lock()
	defer bp.mtx.Unlock()

	if bp.consensusTx != nil {
		bp.log.Info("Rolling back the consensus transaction")
		if err := bp.consensusTx.Rollback(context.Background()); err != nil {
			return fmt.Errorf("failed to rollback the consensus transaction: %w", err)
		}
	}

	// set the block proposer back to it's previous state
	bp.height.Store(height)
	bp.appHash = appHash

	readTx, err := bp.db.BeginReadTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin read transaction: %w", err)
	}
	defer readTx.Rollback(ctx)

	networkParams, err := bp.loadNetworkParams(ctx, readTx)
	if err != nil {
		return fmt.Errorf("failed to load the network parameters: %w", err)
	}
	bp.chainCtx.NetworkParameters = networkParams
	bp.chainCtx.NetworkUpdates = ktypes.ParamUpdates{}

	// Rollback internal state updates to the validators, accounts and mempool.
	bp.txapp.Rollback()

	return nil
}

func (bp *BlockProcessor) loadNetworkParams(ctx context.Context, readTx sql.Tx) (*ktypes.NetworkParameters, error) {
	networkParams, err := meta.LoadParams(ctx, readTx)
	if err != nil {
		return nil, fmt.Errorf("failed to load the network parameters: %w", err)
	}

	return networkParams, nil
}

func (bp *BlockProcessor) CheckTx(ctx context.Context, ntx *types.Tx, height int64, blockTime time.Time, recheck bool) error {
	readTx := bp.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	return bp.checkTx(ctx, readTx, ntx, height, blockTime, recheck)
}

func (bp *BlockProcessor) checkTx(ctx context.Context, readTx sql.Tx, ntx *types.Tx, height int64, blockTime time.Time, recheck bool) error {
	tx := ntx.Transaction
	txHash := ntx.Hash()

	// If the network is halted for migration, we reject all transactions.
	if bp.chainCtx.NetworkParameters.MigrationStatus == ktypes.MigrationCompleted {
		return ktypes.ErrMigrationComplete
	}

	bp.log.Debug("Check transaction", "Recheck", recheck, "Hash", txHash, "Sender", log.LazyHex(tx.Sender),
		"PayloadType", tx.Body.PayloadType, "Nonce", tx.Body.Nonce, "TxFee", tx.Body.Fee)

	if !recheck {
		// Verify the correct chain ID is set, if it is set.
		if protected := tx.Body.ChainID != ""; protected && tx.Body.ChainID != bp.genesisParams.ChainID {
			return fmt.Errorf("%w: %s", ktypes.ErrWrongChain, tx.Body.ChainID)
		}

		// Ensure that the transaction is valid in terms of the signature and the payload type
		if err := verifyTransaction(tx); err != nil {
			bp.log.Debug("Failed to verify the transaction", "err", err)
			return fmt.Errorf("failed to verify the transaction: %w", err)
		}
	}

	ident, err := authExt.GetIdentifier(tx.Signature.Type, tx.Sender)
	if err != nil {
		return fmt.Errorf("failed to get tx sender identifier: %w", err)
	}

	return bp.txapp.ApplyMempool(&common.TxContext{
		Ctx: ctx,
		BlockContext: &common.BlockContext{
			ChainContext: bp.chainCtx,
			Height:       height + 1,
			Timestamp:    blockTime.Unix() + 1, // eh, one second later... ?
			Proposer:     bp.chainCtx.NetworkParameters.Leader,
		},
		TxID:          hex.EncodeToString(txHash[:]),
		Signer:        tx.Sender,
		Caller:        ident,
		Authenticator: tx.Signature.Type,
	}, readTx, tx)
}

// RecheckTxs revalidates all transactions in the mempool using the checkTx function.
// It uses a reserved read transaction for DB access to avoid contention with non-consensus read requests.
func (bp *BlockProcessor) RecheckTxs(ctx context.Context, height int64, timestamp time.Time) error {
	bp.mtx.Lock()
	defer bp.mtx.Unlock()

	readTx, err := bp.db.BeginReservedReadTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start reserved read transaction for mempool rechecks: %w", err)
	}
	defer readTx.Rollback(ctx)

	bp.mempool.RecheckTxs(ctx, func(ctx context.Context, tx *types.Tx) error {
		return bp.checkTx(ctx, readTx, tx, height, timestamp, true)
	})

	return nil
}

// InitChain initializes the node with the genesis state. This included initializing the
// votestore with the genesis validators, accounts with the genesis allocations and the
// chain meta store with the genesis network parameters.
// This is called only once when the node is bootstrapping for the first time.
func (bp *BlockProcessor) InitChain(ctx context.Context) (int64, []byte, error) {
	bp.mtx.Lock()
	defer bp.mtx.Unlock()

	genesisTx, err := bp.db.BeginTx(ctx)
	if err != nil {
		return -1, nil, fmt.Errorf("failed to begin the genesis transaction: %w", err)
	}
	defer genesisTx.Rollback(ctx)

	genCfg := bp.genesisParams

	if err := bp.txapp.GenesisInit(ctx, genesisTx, genCfg, bp.chainCtx); err != nil {
		return -1, nil, err
	}

	if err := meta.SetChainState(ctx, genesisTx, genCfg.InitialHeight, genCfg.StateHash, false); err != nil {
		return -1, nil, fmt.Errorf("error storing the genesis state: %w", err)
	}

	bp.chainCtx.NetworkParameters = genCfg.NetworkParameters.Clone()
	if err := meta.StoreParams(ctx, genesisTx, bp.chainCtx.NetworkParameters); err != nil {
		return -1, nil, fmt.Errorf("error storing the genesis network parameters: %w", err)
	}

	if err := bp.txapp.Commit(); err != nil {
		return -1, nil, fmt.Errorf("txapp commit failed: %w", err)
	}

	if err := genesisTx.Commit(ctx); err != nil {
		return -1, nil, fmt.Errorf("genesis transaction commit failed: %w", err)
	}

	bp.announceValidators()

	bp.height.Store(genCfg.InitialHeight)
	if genCfg.StateHash != nil { // TODO: make it a *types.Hash
		copy(bp.appHash[:], genCfg.StateHash)
	} else {
		bp.appHash = ktypes.Hash{}
	}

	bp.log.Infof("Initialized chain: height %d, appHash: %s", genCfg.InitialHeight, hex.EncodeToString(genCfg.StateHash))

	return genCfg.InitialHeight, genCfg.StateHash, nil
}

func (bp *BlockProcessor) ExecuteBlock(ctx context.Context, req *ktypes.BlockExecRequest, syncing bool) (blkResult *ktypes.BlockExecResult, err error) {
	bp.mtx.Lock()
	defer bp.mtx.Unlock()

	// TODO: TxApp.Begin is a no-op for now, un-comment when needed
	// Begin the block execution session
	// if err = bp.txapp.Begin(ctx, req.Height); err != nil {
	// 	return nil, fmt.Errorf("failed to begin the block execution: %w", err)
	// }

	tx, err := bp.db.BeginPreparedTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin the consensus transaction: %w", err)
	}
	bp.consensusTx = tx

	var success bool
	defer func() {
		if !success {
			if err := bp.consensusTx.Rollback(context.Background()); err != nil {
				bp.log.Warn("Failed to rollback the consensus transaction", "err", err)
			}
			bp.consensusTx = nil
		}
	}()

	// Update the leader in the network parameters if the proposer is different from the current leader
	if req.Block.Header.NewLeader != nil {
		bp.chainCtx.NetworkUpdates[ktypes.ParamNameLeader] = ktypes.PublicKey{
			PublicKey: req.Block.Header.NewLeader,
		}
	}

	inMigration := bp.chainCtx.NetworkParameters.MigrationStatus == ktypes.MigrationInProgress
	haltNetwork := bp.chainCtx.NetworkParameters.MigrationStatus == ktypes.MigrationCompleted

	isLeader := bp.signer.PubKey().Equals(req.Proposer)

	blockCtx := &common.BlockContext{
		Height:       req.Height,
		Timestamp:    req.Block.Header.Timestamp.Unix(),
		ChainContext: bp.chainCtx,
		Proposer:     req.Proposer,
		Hash:         req.BlockID,
	}

	// Begin executing transactions. The chain context may be updated during the block execution.
	txResults := make([]ktypes.TxResult, len(req.Block.Txns))

	txHashes := bp.initBlockExecutionStatus(req.Block)

	for i, tx := range req.Block.Txns {
		identifier, err := authExt.GetIdentifier(tx.Signature.Type, tx.Sender)
		if err != nil {
			return nil, fmt.Errorf("failed to get identifier for the block tx: %w", err)
		}

		txHash := txHashes[i]

		txCtx := &common.TxContext{
			Ctx:           ctx,
			TxID:          txHash.String(),
			Signer:        tx.Sender,
			Authenticator: tx.Signature.Type,
			Caller:        identifier,
			BlockContext:  blockCtx,
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err() // notify the caller about the context cancellation or deadline exceeded error
		default:
			res := bp.txapp.Execute(txCtx, bp.consensusTx, tx)
			txResult := ktypes.TxResult{
				Code: uint32(res.ResponseCode),
				Gas:  res.Spend,
				Log:  res.Log,
			}

			// bookkeeping for the block execution status
			bp.updateBlockExecutionStatus(txHash)

			if res.Error != nil {
				if sql.IsFatalDBError(res.Error) {
					return nil, fmt.Errorf("fatal db error during block execution: %w", res.Error)
				}

				if txResult.Log != "" {
					txResult.Log += "\n"
				}

				// accounts for Postgres sometimes including
				// an ERROR: prefix
				resErr := res.Error.Error()
				if !strings.HasPrefix(resErr, "ERROR: ") {
					resErr = "ERROR: " + resErr
				}

				txResult.Log += resErr
				bp.log.Info("failed transaction", "tx", txHash, "err", res.Error)
			}

			txResults[i] = txResult

			if isLeader && tx.Body.PayloadType == ktypes.PayloadTypeValidatorVoteBodies {
				body := &ktypes.ValidatorVoteBodies{}
				if err := body.UnmarshalBinary(tx.Body.Payload); err != nil {
					return nil, fmt.Errorf("failed to unmarshal validator votebody tx")
				}

				numEvents := int64(len(body.Events))
				bp.events.UpdateStats(numEvents)
			}
		}
	}

	// record the end time of the block execution
	bp.recordBlockExecEndTime()

	// Broadcast any voteID events that have not been broadcasted yet
	if bp.broadcastTxFn != nil {
		if err = bp.BroadcastVoteIDTx(ctx, bp.consensusTx); err != nil {
			return nil, fmt.Errorf("failed to broadcast the voteID transactions: %w", err)
		}
	}

	// Process resolutions and end-block hooks.
	approvedJoins, expiredJoins, err := bp.txapp.Finalize(ctx, bp.consensusTx, blockCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize the block execution: %w", err)
	}

	// migrator can be updated here within notify height
	err = bp.migrator.NotifyHeight(ctx, blockCtx, bp.db, bp.consensusTx) // can modify bp.chainCtx.NetworkParameters.MigrationStatus !!!
	if err != nil {
		return nil, fmt.Errorf("failed to notify the migrator about the block height: %w", err)
	}

	// merge params here first
	newNetworkParams := bp.chainCtx.NetworkParameters.Clone()
	if err := ktypes.MergeUpdates(newNetworkParams, bp.chainCtx.NetworkUpdates); err != nil {
		return nil, err
	} // NOTE: we could store remember newNetworkParams for Commit(), or run MergeUpdates again

	// store new chain height, but with prev apphash
	if err := meta.SetChainState(ctx, bp.consensusTx, req.Height, bp.appHash[:], true); err != nil {
		return nil, fmt.Errorf("failed to set the chain state: %w", err)
	}

	if err := meta.StoreParams(ctx, bp.consensusTx, newNetworkParams); err != nil {
		return nil, fmt.Errorf("failed to store the network parameters: %w", err)
	}

	// Create a new changeset processor
	csp := newChangesetProcessor()
	// "migrator" module subscribes to the changeset processor to store changesets during the migration
	csErrChan := make(chan error, 1)
	defer close(csErrChan)

	if inMigration && !haltNetwork {
		csChanMigrator, err := csp.Subscribe(ctx, "migrator")
		if err != nil {
			return nil, fmt.Errorf("failed to subscribe to changeset processor: %w", err)
		}
		// migrator go routine will receive changesets from the changeset processor
		// give the new channel to the migrator to store changesets
		go func() {
			csErrChan <- bp.migrator.StoreChangesets(req.Height, csChanMigrator)
		}()
	}

	go csp.BroadcastChangesets(ctx)

	changesetID, err := bp.consensusTx.Precommit(ctx, csp.csChan)
	if err != nil {
		return nil, fmt.Errorf("failed to precommit the changeset: %w", err)
	}

	valUpdates := bp.validators.ValidatorUpdates()
	valUpdatesHash, valUpdatesList := validatorUpdatesHash(valUpdates)

	if len(valUpdates) > 0 {
		bp.log.Info("Validator updates", "updates", valUpdatesList)
	}

	// update the peers in the network
	bp.updatePeers(valUpdatesList, approvedJoins, expiredJoins)

	accountsHash := bp.accountsHash()
	txResultsHash := txResultsHash(txResults)

	paramUpdatesHash, err := bp.consensusUpdatesHash()
	if err != nil {
		return nil, fmt.Errorf("failed to compute the consensus updates hash: %w", err)
	}

	sh := &StateHashes{
		PrevApp:      bp.appHash,
		Changeset:    types.Hash(changesetID),
		Accounts:     accountsHash,
		ValUpdates:   valUpdatesHash,
		TxResults:    txResultsHash,
		ParamUpdates: paramUpdatesHash,
	}

	nextHash := bp.nextAppHash(sh)

	if !syncing {
		bp.log.Info("AppState updates: ",
			"prevAppHash", sh.PrevApp[:8], "changesets", sh.Changeset[:8],
			"validatorset", sh.ValUpdates[:8], "accounts", sh.Accounts[:8],
			"txResults", sh.TxResults[:8], "params", sh.ParamUpdates[:8])
	}
	bp.stateHashes = sh

	if inMigration && !haltNetwork {
		// wait for the migrator to finish storing the changesets
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-csErrChan:
			if err != nil {
				return nil, fmt.Errorf("failed to store changesets during migration: %w", err)
			}
		}
	}

	success = true

	// The CE will log the same thing, so this is a Debug message.
	bp.log.Debug("Executed Block", "height", req.Height, "blockID", req.BlockID, "appHash", nextHash, "numTxs", req.Block.Header.NumTxns)
	if len(bp.chainCtx.NetworkUpdates) != 0 {
		bp.log.Info("Consensus updates", "hash", paramUpdatesHash, "updates", bp.chainCtx.NetworkUpdates)
	}

	return &ktypes.BlockExecResult{
		TxResults:        txResults,
		AppHash:          nextHash,
		ValidatorUpdates: valUpdatesList,
		ParamUpdates:     maps.Clone(bp.chainCtx.NetworkUpdates),
	}, nil

}

func formatNodeID(identifier []byte, keyType crypto.KeyType) string {
	return fmt.Sprintf("%s#%s", hex.EncodeToString(identifier), keyType.String())
}

func (bp *BlockProcessor) updatePeers(valUpdates []*ktypes.Validator, approvedJoins, expiredJoins []*ktypes.AccountID) {
	// update the peers in the network
	localPeer := formatNodeID(bp.signer.CompactID(), bp.signer.PubKey().Type())

	for _, val := range valUpdates {
		nodeID := formatNodeID(val.Identifier, val.KeyType)
		if nodeID == localPeer {
			continue
		}

		if val.Power == 0 {
			if err := bp.removePeer(nodeID); err != nil {
				bp.log.Warn("Failed to remove peer", "nodeID", nodeID, "err", err)
			}
			bp.log.Info("Removed demoted peer from the whitelist", "nodeID", nodeID)
		} else {
			if err := bp.addPeer(nodeID); err != nil {
				bp.log.Warn("Failed to add peer from validator updates", "nodeID", nodeID, "err", err)
			}
			bp.log.Info("Added promoted peer to the whitelist", "nodeID", nodeID)
		}
	}

	for _, val := range approvedJoins {
		nodeID := formatNodeID(val.Identifier, val.KeyType)
		if nodeID == localPeer {
			continue
		}

		if err := bp.addPeer(nodeID); err != nil {
			bp.log.Warn("Failed to add peer to the whitelist", "nodeID", nodeID, "err", err)
		}
		bp.log.Info("Added peer to the whitelist", "nodeID", nodeID)
	}

	for _, val := range expiredJoins {
		nodeID := formatNodeID(val.Identifier, val.KeyType)
		if nodeID == localPeer {
			continue
		}

		if err := bp.removePeer(nodeID); err != nil {
			bp.log.Warn("Failed to remove peer", "nodeID", nodeID, "reason", "join request expired", "err", err)
		}
		bp.log.Info("Removed peer with expired join request", "nodeID", nodeID)
	}
}

// Commit method commits the block to the blockstore and postgres database.
// It also updates the txIndexer and mempool with the transactions in the block.
func (bp *BlockProcessor) Commit(ctx context.Context, req *ktypes.CommitRequest) error {
	bp.mtx.Lock()
	defer bp.mtx.Unlock()

	// Commit the Postgres Consensus transaction
	if err := bp.consensusTx.Commit(ctx); err != nil {
		// maybe attempt rollback and set nil
		return err
	}
	bp.consensusTx = nil

	// Update the active network parameters for the updates that were just committed.
	ktypes.MergeUpdates(bp.chainCtx.NetworkParameters, bp.chainCtx.NetworkUpdates) // noop if no updates
	bp.chainCtx.NetworkUpdates = ktypes.ParamUpdates{}

	// Commit pending changes to txapp state i.e. validators, accounts, mempool acct cache.
	if err := bp.txapp.Commit(); err != nil {
		return err
	}

	bp.height.Store(req.Height)
	bp.appHash = req.AppHash

	// Update the chain meta store with the new height, clearing the dirty flag.
	// We need to re-open a new transaction just to write the apphash
	// TODO: it would be great to have a way to commit the apphash without
	// opening a new transaction. This could leave us in a state where data is
	// committed but the apphash is not if there is a badly timed shutdown. This
	// is fixed upon restart in the blockProcessor constructor, where if it sees that
	// the dirty flag is set, it updates the appHash and height from the blockstore
	// restoring the state to the last committed state.
	tx, err := bp.db.BeginTx(ctx)
	if err != nil {
		return err
	}

	if err := meta.SetChainState(ctx, tx, req.Height, req.AppHash[:], false); err != nil {
		err2 := tx.Rollback(ctx)
		if err2 != nil {
			bp.log.Error("Failed to rollback the transaction", "err", err2)
			return err2
		}
		return err
	}

	if err := bp.migrator.PersistLastChangesetHeight(ctx, tx, req.Height); err != nil {
		err2 := tx.Rollback(ctx)
		if err2 != nil {
			bp.log.Error("Failed to rollback the transaction", "err", err2)
			return err2
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Snapshots:
	if err := bp.snapshotDB(ctx, req.Height); err != nil {
		bp.log.Warn("Failed to create snapshot of the database", "err", err)
	}

	bp.clearBlockExecutionStatus() // TODO: not very sure where to clear this

	// Announce final validators to subscribers
	bp.announceValidators() // can be in goroutine? no, because the modules state need to be updated by the next consensus round?

	bp.log.Debug("Committed Block", "height", req.Height, "appHash", req.AppHash.String())

	// NOTE: return ctx.Err() is NOT a normal thing to do, but there's a lot
	// going on in some of these methods that doesn't even bother with the
	// context, and all up the call stack there can be a ton of progress long
	// after the context is cancelled.
	return ctx.Err()
}

// This function enforces proper nonce ordering, validates transactions, and ensures
// that consensus limits such as the maximum block size, maxVotesPerTx are met. It also adds
// validator vote transactions for events observed by the leader. This function is
// used exclusively by the leader node to prepare the proposal block.
func (bp *BlockProcessor) PrepareProposal(ctx context.Context, txs []*types.Tx) (finalTxs []*ktypes.Transaction, invalidTxs []*ktypes.Transaction, err error) {
	// Use a reserved read transaction for any DB access, to prevent contention
	// with rpc requests and other non-consensus operations.
	readTx, err := bp.db.BeginReservedReadTx(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin reserved read transaction: %w", err)
	}

	defer readTx.Rollback(ctx)
	return bp.prepareBlockTransactions(ctx, readTx, txs)
}

var (
	statesyncSnapshotSchemas = []string{"kwild_voting", "kwild_internal", "kwild_chain", "kwild_accts", "kwild_migrations", "ds_*"}
	statsyncExcludedTables   = []string{"kwild_internal.sentry"}
)

func (bp *BlockProcessor) snapshotDB(ctx context.Context, height int64) error {
	snapshotsDue := bp.snapshotter.Enabled() &&
		(bp.snapshotter.IsSnapshotDue(uint64(height)) || len(bp.snapshotter.ListSnapshots()) == 0)
	// snapshotsDue = snapshotsDue && height > max(1, a.cfg.InitialHeight)

	if snapshotsDue {
		// we make a snapshot tx but don't directly use it. This is because under the hood,
		// we are using the pg_dump executable to create the snapshot, and we are simply
		// giving pg_dump the snapshot ID to guarantee it has an isolated view of the database.
		snapshotTx, snapshotId, err := bp.db.BeginSnapshotTx(ctx)
		if err != nil {
			return fmt.Errorf("failed to start snapshot tx: %w", err)
		}
		defer snapshotTx.Rollback(ctx) // always rollback, since this is just for view isolation

		err = bp.snapshotter.CreateSnapshot(ctx, uint64(height), snapshotId, statesyncSnapshotSchemas, statsyncExcludedTables, nil)
		if err != nil {
			return err
		} else {
			bp.log.Info("created snapshot", "height", height, "snapshot_id", snapshotId)
			return nil
		}
	}

	return nil
}

type StateHashes struct {
	PrevApp      types.Hash
	Changeset    types.Hash
	ValUpdates   types.Hash
	Accounts     types.Hash
	TxResults    types.Hash
	ParamUpdates types.Hash
}

// nextAppHash calculates the appHash that encapsulates the state changes occurred during the block execution.
// sha256(prevAppHash || changesetHash || valUpdatesHash || accountsHash || txResultsHash)
func (bp *BlockProcessor) nextAppHash(sh *StateHashes) types.Hash {
	hasher := ktypes.NewHasher()

	hasher.Write(sh.PrevApp[:])
	hasher.Write(sh.Changeset[:])
	hasher.Write(sh.ValUpdates[:])
	hasher.Write(sh.Accounts[:])
	hasher.Write(sh.TxResults[:])
	hasher.Write(sh.ParamUpdates[:])

	return hasher.Sum(nil)
}

func txResultsHash(results []ktypes.TxResult) types.Hash {
	hasher := ktypes.NewHasher()
	for _, res := range results {
		binary.Write(hasher, binary.BigEndian, res.Code)
		binary.Write(hasher, binary.BigEndian, res.Gas)
	}

	return hasher.Sum(nil)
}

func (bp *BlockProcessor) accountsHash() types.Hash {
	accounts := bp.accounts.Updates()

	slices.SortFunc(accounts, func(a, b *ktypes.Account) int {
		if idCmp := bytes.Compare(a.ID.Identifier, b.ID.Identifier); idCmp != 0 {
			return idCmp
		}
		return cmp.Compare(a.ID.KeyType, b.ID.KeyType)
	})

	hasher := ktypes.NewHasher()
	for _, acc := range accounts {
		hasher.Write(acc.ID.Bytes())
		binary.Write(hasher, binary.BigEndian, acc.Balance.Bytes())
		binary.Write(hasher, binary.BigEndian, acc.Nonce)
	}

	return hasher.Sum(nil)
}

func (bp *BlockProcessor) consensusUpdatesHash() (types.Hash, error) {
	pu := bp.chainCtx.NetworkUpdates
	bts, err := pu.MarshalBinary()
	if err != nil {
		return types.Hash{}, err
	}
	return ktypes.HashBytes(bts), nil
}

func validatorUpdatesHash(updates map[string]*ktypes.Validator) (types.Hash, []*ktypes.Validator) {
	// Go 1.23 note:
	// for _, key := range slices.Sorted(maps.Keys(m)) {}

	// sort the updates by the validator pubkey
	updatesList := make([]*ktypes.Validator, 0, len(updates))
	for _, v := range updates {
		updatesList = append(updatesList, v)
	}
	slices.SortFunc(updatesList, func(a, b *ktypes.Validator) int {
		if idCmp := bytes.Compare(a.Identifier, b.Identifier); idCmp != 0 {
			return idCmp
		}
		return cmp.Compare(a.KeyType, b.KeyType)
	})

	// hash the validator address and the validator struct
	hash := ktypes.NewHasher()
	for _, up := range updatesList {
		// hash the validator address
		hash.Write(up.Identifier)
		// hash the validator power
		binary.Write(hash, binary.BigEndian, up.Power)
	}

	return hash.Sum(nil), updatesList
}

// SubscribeValidators creates and returns a new channel on which the current
// validator set will be sent for each block Commit. The receiver will miss
// updates if they are unable to receive fast enough. This should generally
// be used after catch-up is complete, and only called once by the receiving
// goroutine rather than repeatedly in a loop, for instance. The slice should
// not be modified by the receiver.
func (bp *BlockProcessor) SubscribeValidators() <-chan []*ktypes.Validator {
	// There's only supposed to be one user of this method, and they should
	// only get one channel and listen, but play it safe and use a slice.
	bp.subMtx.Lock()
	defer bp.subMtx.Unlock()

	c := make(chan []*ktypes.Validator, 1)
	bp.subChans = append(bp.subChans, c)
	return c
}

// announceValidators sends the current validator list to subscribers from
// ReceiveValidators.
func (bp *BlockProcessor) announceValidators() {
	// dev note: this method should not be blocked by receivers. Keep a default
	// case and create buffered channels.
	bp.subMtx.RLock()
	defer bp.subMtx.RUnlock()

	if len(bp.subChans) == 0 {
		return // no subscribers, skip the slice clone
	}

	vals := bp.GetValidators()

	for _, c := range bp.subChans {
		select {
		case c <- vals:
		default: // they'll get the next one... this is just supposed to be better than polling
			bp.log.Warn("Validator update channel is blocking")
		}
	}
}

func (bp *BlockProcessor) Price(ctx context.Context, dbTx sql.DB, tx *ktypes.Transaction) (*big.Int, error) {
	return bp.txapp.Price(ctx, dbTx, tx, bp.chainCtx)
}

func (bp *BlockProcessor) AccountInfo(ctx context.Context, db sql.DB, identifier *ktypes.AccountID, pending bool) (balance *big.Int, nonce int64, err error) {
	return bp.txapp.AccountInfo(ctx, db, identifier, pending)
}

func (bp *BlockProcessor) NumAccounts(ctx context.Context, db sql.Executor) (count, height int64, err error) {
	return bp.txapp.NumAccounts(ctx, db)
}

func (bp *BlockProcessor) GetValidators() []*ktypes.Validator {
	return bp.validators.GetValidators()
}

func (bp *BlockProcessor) ConsensusParams() *ktypes.NetworkParameters {
	bp.mtx.RLock()
	defer bp.mtx.RUnlock()

	if bp.chainCtx.NetworkParameters == nil {
		return nil
	}

	return bp.chainCtx.NetworkParameters.Clone()
}

func (bp *BlockProcessor) GetMigrationMetadata(ctx context.Context) (*ktypes.MigrationMetadata, error) {
	networkParams := bp.ConsensusParams()
	if networkParams == nil {
		return nil, fmt.Errorf("network parameters not found, node is still booting up, try again later")
	}

	status := networkParams.MigrationStatus
	return bp.migrator.GetMigrationMetadata(ctx, status)
}

func (bp *BlockProcessor) StateHashes() *StateHashes {
	bp.mtx.RLock()
	defer bp.mtx.RUnlock()

	return bp.stateHashes
}
