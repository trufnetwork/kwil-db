package consensus

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	blockprocessor "github.com/trufnetwork/kwil-db/node/block_processor"
	"github.com/trufnetwork/kwil-db/node/meta"
	"github.com/trufnetwork/kwil-db/node/metrics"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types"
)

var mets metrics.ConsensusMetrics = metrics.Consensus

const (
	// maxNumTxnsInBlock is the maximum number of transactions we will put in a
	// block proposal. Currently set to a billion, which is basically no limit
	// since block size in bytes will hit first.
	maxNumTxnsInBlock = 1 << 30

	defaultProposeTimeout = 1 * time.Second
)

var zeroHash = types.Hash{}

// There are three phases in the consensus engine:
// 1. BlockProposalPhase:
//   - Depending on the role, the node is either preparing the block or waiting to receive the proposed block.
//
// 2. BlockExecutionPhase:
//   - Nodes enter this phase once they have the block to be processed. In this phase, all the transactions in the block are executed, and the appHash is generated. Leader then waits for the votes from the validators and validators respond with ack/nack.
//
// 3. BlockCommitPhase:
// - Once the leader receives the threshold acks with the same appHash as the leader, the block is committed and the leader broadcasts the blockAnn message to the network. Nodes that receive this message will enter into the commit phase where they verify the appHash and commit the block.
type ConsensusEngine struct {
	role    atomic.Value // types.Role, role can change over the lifetime of the node
	privKey crypto.PrivateKey
	pubKey  crypto.PublicKey
	log     log.Logger

	// proposeTimeout specifies the time duration to wait before proposing a new block for the next height.
	// This timeout is used by the leader to propose a block if transactions are available. Default is 1 second.
	proposeTimeout time.Duration
	// emptyBlockTimeout specifies the time duration to wait before proposing an empty block.
	// This should always be greater than the proposeTimeout. Default is 1 minute.
	emptyBlockTimeout time.Duration

	// blkProposalInterval specifies the time duration to wait before reannouncing the block proposal message.
	// This is only applicable for the leader. This timeout influences how quickly the out-of-sync nodes can
	// catchup with the consensus rounds, thereby influencing the block time. Default is 1 second.
	blkProposalInterval time.Duration

	// blkAnnReannounceTimeout specifies the time duration to wait before reannouncing the block announce message.
	blkAnnInterval time.Duration

	// broadcastTxTimeout specifies the time duration to wait for a transaction to be included in the block.
	broadcastTxTimeout time.Duration

	// checkpoint is the initial checkpoint for the leader to sync to the network.
	checkpoint checkpoint

	genesisHeight int64                       // height of the genesis block
	leader        crypto.PublicKey            // TODO: update with network param updates touching it
	validatorSet  map[string]ktypes.Validator // key: hex encoded pubkey

	// stores state machine state for the consensus engine
	state  state
	inSync atomic.Bool // set when the node is still catching up with the network during bootstrapping

	// copy of the minimal state info for the p2p layer usage.
	stateInfo StateInfo

	cancelFnMtx     sync.Mutex // protects blkExecCancelFn, longRunningTxs and numResets
	blkExecCancelFn context.CancelFunc
	// list of txs to be removed from the mempool
	// only used by the leader and protected by the cancelFnMtx
	longRunningTxs []ktypes.Hash
	numResets      int64

	// leader updates, tracks if any non-transaction based leader updates that need to be
	// applied at configured heights. These updates are to be applied before the
	// block at height is proposed or after the height-1 block is committed.
	leaderUpdates *leaderUpdate
	leaderMtx     sync.RWMutex
	leaderFile    string // file to persist the leader updates and load from on startup

	// Channels
	newBlockProposal chan struct{} // triggers block production in the leader
	// newRound triggers the start of a new round in the consensus engine.
	// leader waits for the minBlockInterval before proposing a new block if txs are available.
	// if no txs are available for the maxBlockInterval duration, the leader proposes an empty block.
	newRound     chan struct{}
	msgChan      chan consensusMessage
	haltChan     chan string        // can take a msg or reason for halting the network
	resetChan    chan *resetMsg     // to reset the state of the consensus engine
	bestHeightCh chan *discoveryMsg // to sync the leader with the network

	// interfaces
	db             DB
	mempool        Mempool
	blockStore     BlockStore
	blockProcessor BlockProcessor
	commitLog      *commitIntentLog

	// protects the mempool access. Block commit and proposal creation, and
	// QueueTx (external) take this lock to ensure that no new txs are added to
	// the mempool while the block is being committed i.e while the accounts are
	// being updated.
	mempoolMtx PriorityLockQueue
	// mempoolReady indicates consensus engine that has enough txs to propose a block
	// CE can adjust it's wait times based on this flag.
	// This flag tracks if the mempool filled enough between the commit and
	// the blkProposal Timeout and expediate leader getting into the next round.
	// Applicable only for the leader
	mempoolReady atomic.Bool // shld it be a bool or a channel?
	// queueTxs can send a trigger on this channel to notify the consensus engine that the mempool
	// has enough txs to propose a block. This is only sent once when the mempoolReady
	// flag is updated from false to true by the QueueTx method.
	// Applicable only for the leader
	mempoolReadyChan chan struct{}

	// Broadcasters
	proposalBroadcaster ProposalBroadcaster
	blkAnnouncer        BlkAnnouncer
	ackBroadcaster      AckBroadcaster
	blkRequester        BlkRequester
	rstStateBroadcaster ResetStateBroadcaster
	// discoveryReqBroadcaster DiscoveryReqBroadcaster
	txAnnouncer TxAnnouncer

	// TxSubscriber
	subMtx        sync.Mutex // protects access to txSubscribers
	txSubscribers map[ktypes.Hash]chan ktypes.TxResult

	// waitgroup to track all the consensus goroutines
	wg sync.WaitGroup

	catchupTicker  *time.Ticker
	catchupTimeout time.Duration
}

type checkpoint struct {
	height int64
	hash   types.Hash
}

type leaderUpdate struct {
	// Candidate is the new leader candidate
	Candidate crypto.PublicKey
	// Height is the height at which the leader update should be applied
	Height int64
}

// Config is the struct given to the constructor, [New].
type Config struct {
	RootDir string
	// Signer is the private key of the node.
	PrivateKey crypto.PrivateKey
	// Leader is the public key of the leader.
	Leader crypto.PublicKey
	// GenesisHeight is the initial height of the network.
	GenesisHeight int64

	// ProposeTimeout is the minimum time duration to wait before proposing a new block.
	// Leader can propose a block with transactions as soon as this timeout is reached. Default is 1 second.
	ProposeTimeout time.Duration
	// EmptyBlockTimeout is the maximum time duration to wait before proposing a new block without transactions.
	// Default is 1 minute.
	EmptyBlockTimeout time.Duration
	// BlkPropReannounceInterval is the frequency at which block proposal messages are reannounced by the Leader.
	BlockProposalInterval time.Duration
	// BlkAnnReannounceInterval is the frequency at which block commit messages are reannounced by the Leader.
	// This is also the frequency at which the validators reannounce the ack messages.
	BlockAnnInterval time.Duration
	// CatchUpInterval is the frequency at which the node attempts to catches up with the network if lagging.
	// CatchUpInterval  time.Duration
	BroadcastTxTimeout time.Duration

	// Checkpoint is the initial checkpoint for the leader to sync to.
	Checkpoint config.Checkpoint

	// Interfaces
	DB             *pg.DB
	Mempool        Mempool
	BlockStore     BlockStore
	BlockProcessor BlockProcessor
	Logger         log.Logger
}

type BroadcastFns struct {
	ProposalBroadcaster ProposalBroadcaster
	TxAnnouncer         TxAnnouncer
	BlkAnnouncer        BlkAnnouncer
	AckBroadcaster      AckBroadcaster
	BlkRequester        BlkRequester
	RstStateBroadcaster ResetStateBroadcaster
	// DiscoveryReqBroadcaster DiscoveryReqBroadcaster
	TxBroadcaster blockprocessor.BroadcastTxFn
}

type WhitelistFns struct {
	AddPeer    func(string) error
	RemovePeer func(string) error

	// List func() []string
}

// ProposalBroadcaster broadcasts the new block proposal message to the network
type ProposalBroadcaster func(ctx context.Context, blk *ktypes.Block, senderPubkey []byte)

// BlkAnnouncer broadcasts the new committed block to the network using the blockAnn message
type BlkAnnouncer func(ctx context.Context, blk *ktypes.Block, ci *ktypes.CommitInfo)

// TxAnnouncer broadcasts the new transaction to the network. The implementation
// must have access to either mempool or block store for the transaction
// contents.
type TxAnnouncer func(ctx context.Context, txID types.Hash)

// AckBroadcaster gossips the ack/nack messages to the network
// type AckBroadcaster func(ack bool, height int64, blkID types.Hash, appHash *types.Hash, Signature []byte) error
type AckBroadcaster func(msg *types.AckRes) error

// BlkRequester requests the block from the network based on the height
type BlkRequester func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error)

type ResetStateBroadcaster func(height int64, txIDs []ktypes.Hash) error

type DiscoveryReqBroadcaster func()

type Status string

const (
	Proposed  Status = "proposed"  // SM has a proposed block for the current height
	Executed  Status = "executed"  // SM has executed the proposed block
	Committed Status = "committed" // SM has committed the block
)

// StateInfo contains the state information required by the p2p layer to
// download the blocks and notify the consensus engine about the incoming blocks.
type StateInfo struct {
	// mtx protects the below fields and should be locked by the consensus engine
	// only when updating the state and the locks should be released immediately.
	mtx sync.RWMutex

	// height of the last committed block
	height int64

	// status of the consensus engine
	status Status

	// proposed block for the current height
	blkProp *blockProposal

	// hasBlock indicates that the CE has been notified about block corresponding to the height.
	// can be used by the p2p layer to avoid re-sending the same block multiple times
	// to the consensus engine.
	hasBlock atomic.Int64

	lastCommit lastCommit
}

// Consensus state that is applicable for processing the block at a specific height.
type state struct {
	mtx sync.RWMutex

	tExecuted time.Time

	blkProp  *blockProposal
	blockRes *blockResult
	lc       *lastCommit

	// Votes: Applicable only to the leader
	// These are the Acks received from the validators.
	votes map[string]*ktypes.VoteInfo

	commitInfo *ktypes.CommitInfo

	// Promoted leader uses these updates to distinguish the leader updates occurred due to
	// "replace-leader" admin command vs the leader updates due to parameter updates
	// and include the NewLeader field in the block header to notify the network about
	// this leader update. This field is applicable only to the promoted leader
	// and only on the block heights where the node became a new leader through the replace cmd.
	leaderUpdate *leaderUpdate
}

type blockResult struct {
	ack          bool
	appHash      ktypes.Hash
	txResults    []ktypes.TxResult
	vote         *vote
	paramUpdates ktypes.ParamUpdates
	valUpdates   []*ktypes.Validator
}

type lastCommit struct {
	height  int64
	blkHash types.Hash

	appHash types.Hash

	blk        *ktypes.Block // for reannounce and other status getters
	commitInfo *ktypes.CommitInfo
}

// New creates a new consensus engine.
func New(cfg *Config) (*ConsensusEngine, error) {
	logger := cfg.Logger
	if logger == nil {
		// logger = log.DiscardLogger // for prod
		logger = log.New(log.WithName("CONS"), log.WithLevel(log.LevelDebug),
			log.WithWriter(os.Stdout), log.WithFormat(log.FormatUnstructured))
	}

	// defer role assignment till the beginning of the catchup phase.
	pubKey := cfg.PrivateKey.Public()

	// rethink how this state is initialized
	var commitLog *commitIntentLog
	if cfg.RootDir != "" {
		commitLog = newCommitIntentLog(config.CommitIntentFilePath(cfg.RootDir))
	}

	ce := &ConsensusEngine{
		pubKey:              pubKey,
		privKey:             cfg.PrivateKey,
		leader:              cfg.Leader,
		proposeTimeout:      cfg.ProposeTimeout,
		emptyBlockTimeout:   cfg.EmptyBlockTimeout,
		blkProposalInterval: cfg.BlockProposalInterval,
		blkAnnInterval:      cfg.BlockAnnInterval,
		broadcastTxTimeout:  cfg.BroadcastTxTimeout,
		db:                  cfg.DB,
		leaderUpdates:       nil,
		leaderFile:          config.LeaderUpdatesFilePath(cfg.RootDir),
		state: state{
			blkProp:  nil,
			blockRes: nil,
			lc: &lastCommit{ // the zero values don't need to be specified, but for completeness...
				height:  0,
				blkHash: zeroHash,
				appHash: zeroHash,
			},
			votes: make(map[string]*ktypes.VoteInfo),
		},
		stateInfo: StateInfo{
			height:  0,
			status:  Committed,
			blkProp: nil,
		},
		genesisHeight:    cfg.GenesisHeight,
		msgChan:          make(chan consensusMessage, 1), // buffer size??
		haltChan:         make(chan string, 1),
		resetChan:        make(chan *resetMsg, 1),
		bestHeightCh:     make(chan *discoveryMsg, 1),
		newRound:         make(chan struct{}, 1),
		newBlockProposal: make(chan struct{}, 1),
		mempoolReadyChan: make(chan struct{}, 1),

		// interfaces
		mempool:        cfg.Mempool,
		blockStore:     cfg.BlockStore,
		blockProcessor: cfg.BlockProcessor,
		log:            logger,
		txSubscribers:  make(map[ktypes.Hash]chan ktypes.TxResult),
		commitLog:      commitLog,
	}

	// set it to sentry by default, will be updated in the catchup phase when the engine starts.
	// Not initializing the role here will panic the node, as a lot of RPC calls such as HealthCheck,
	// Status, etc. tries to access the role.
	ce.role.Store(types.RoleSentry)
	ce.stateInfo.hasBlock.Store(0)

	// set the node to be in the catchup mode
	ce.inSync.Store(true)

	if ce.proposeTimeout == 0 { // can't be zero
		ce.proposeTimeout = defaultProposeTimeout
	}

	ce.checkpoint.height = cfg.Checkpoint.Height
	ce.checkpoint.hash = zeroHash
	if cfg.Checkpoint.Hash != "" {
		hash, err := ktypes.NewHashFromString(cfg.Checkpoint.Hash)
		if err != nil {
			return nil, fmt.Errorf("invalid checkpoint hash: %w", err)
		}
		ce.checkpoint.hash = hash
	}

	// load the leader updates from the file if any
	if err := ce.loadLeaderUpdates(); err != nil {
		return nil, fmt.Errorf("error loading leader updates: %w", err)
	}
	return ce, nil
}

func (ce *ConsensusEngine) Start(ctx context.Context, fns BroadcastFns, peerFns WhitelistFns) error {
	ce.proposalBroadcaster = fns.ProposalBroadcaster
	ce.blkAnnouncer = fns.BlkAnnouncer
	ce.ackBroadcaster = fns.AckBroadcaster
	ce.blkRequester = fns.BlkRequester
	ce.rstStateBroadcaster = fns.RstStateBroadcaster
	// ce.discoveryReqBroadcaster = fns.DiscoveryReqBroadcaster
	ce.txAnnouncer = fns.TxAnnouncer

	ce.blockProcessor.SetCallbackFns(fns.TxBroadcaster, peerFns.AddPeer, peerFns.RemovePeer)
	// Catchup timeout should be at least greater than the emptyBlockTimeout
	ce.catchupTimeout = max(5*time.Second, ce.emptyBlockTimeout+ce.proposeTimeout)
	ce.catchupTicker = time.NewTicker(ce.catchupTimeout)

	ce.log.Info("Starting the consensus engine")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		ce.close() // Closes any consensus transactions opened either during catchup or during the regular consensus flow.
		ce.log.Info("Consensus engine stopped")
	}()

	// Fast catchup the node with the network height
	if err := ce.catchup(ctx); err != nil {
		return fmt.Errorf("error catching up: %w", err)
	}

	// apply leader updates if any before starting the consensus event loop
	ce.applyLeaderUpdates()

	// Start the mining process if the node is a leader. Validators and sentry
	// nodes are activated when they receive a block proposal or block announce msg.
	if ce.role.Load() == types.RoleLeader {
		ce.log.Infof("Starting the leader node")
		ce.newBlockProposal <- struct{}{} // recv by runConsensusEventLoop, buffered
	} else {
		ce.log.Infof("Starting the validator/sentry node")
	}

	var ceErr error

	// start the event loop
	ce.wg.Add(1)
	go func() {
		defer ce.wg.Done()
		defer cancel() // stop CE in case event loop terminated early e.g. halt

		ceErr = ce.runConsensusEventLoop(ctx)
		ce.log.Info("Consensus event loop stopped...")
	}()

	// resetChan listener
	ce.wg.Add(1)
	go func() {
		defer ce.wg.Done()

		ce.resetEventLoop(ctx)
		ce.log.Info("Reset event loop stopped...")
	}()

	ce.wg.Wait()

	return ceErr
}

func (ce *ConsensusEngine) close() {
	ce.state.mtx.Lock()
	defer ce.state.mtx.Unlock()

	if err := ce.blockProcessor.Close(); err != nil {
		ce.log.Error("Error closing the block processor", "error", err)
	}
}

func (ce *ConsensusEngine) Status() *ktypes.NodeStatus {
	params := ce.blockProcessor.ConsensusParams()
	ce.stateInfo.mtx.RLock()
	defer ce.stateInfo.mtx.RUnlock()
	lc := ce.stateInfo.lastCommit
	var hdr *ktypes.BlockHeader
	if lc.blk != nil {
		hdr = lc.blk.Header
	}
	return &ktypes.NodeStatus{
		Role:            ce.role.Load().(types.Role).String(),
		CatchingUp:      ce.inSync.Load(),
		CommittedHeader: hdr,
		CommitInfo:      lc.commitInfo,
		Params:          params,
	}
}

// runEventLoop starts the event loop for the consensus engine.
// Below are the external event triggers that nodes can receive depending on their role:
// Leader:
//   - Acks
//
// Validator:
//   - BlockProp
//   - BlockAnn
//
// Sentry:
//   - BlockAnn
//
// Apart from the above events, the node also periodically checks if it needs to
// catchup with the network and reannounce the messages.
func (ce *ConsensusEngine) runConsensusEventLoop(ctx context.Context) error {
	ce.log.Info("Starting the consensus event loop...")
	reannounceTicker := time.NewTicker(ce.blkAnnInterval)   // 3 secs (default)
	blkPropTicker := time.NewTicker(ce.blkProposalInterval) // 1 sec (default)

	// If no messages are received within the below specified duration after the last consensus message,
	// and given that the leader is expected to produce a block within the emptyBlockTimeout interval,
	// initiate catchup mode to request any missed messages.
	// The catchupticker resets with each processed consensus message that successfully advances the node's state

	for {
		select { // ignore other ready signals if we're shutting down
		case <-ctx.Done():
			ce.log.Info("Shutting down the consensus engine")
			return nil
		default:
		}

		select {
		case <-ctx.Done():
			ce.log.Info("Shutting down the consensus engine")
			return nil

		case halt := <-ce.haltChan:
			ce.log.Error("Received halt signal, stopping the consensus engine", "reason", halt)
			return errors.New(halt)

		case <-ce.newRound:
			// check if there are any leader updates to be made before starting a new round
			ce.applyLeaderUpdates()

			// if the node is not a leader, ignore the new round signal
			if ce.role.Load() != types.RoleLeader {
				continue
			}

			go ce.newBlockRound(ctx)

		case <-ce.newBlockProposal:
			params := ce.blockProcessor.ConsensusParams()
			if params.MigrationStatus == ktypes.MigrationCompleted {
				ce.log.Info("Block production halted due to migration, no more blocks will be produced")
				continue // don't die, just don't propose blocks
			}

			if ce.role.Load() != types.RoleLeader {
				continue
			}

			if err := ce.proposeBlock(ctx); err != nil {
				return fmt.Errorf("error proposing block: %w", err)
			}

		case <-ce.catchupTicker.C:
			err := ce.doCatchup(ctx)
			if err != nil {
				return fmt.Errorf("failed to do network catchup: %w", err)
			}

		case <-reannounceTicker.C:
			ce.reannounceMsgs(ctx)

		case m := <-ce.msgChan:
			ce.handleConsensusMessages(ctx, m)

		case <-blkPropTicker.C:
			ce.rebroadcastBlkProposal(ctx)
		}
	}
}

// resetEventLoop listens for the reset event and rollbacks the current block processing.
func (ce *ConsensusEngine) resetEventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			ce.log.Info("Shutting down the reset event loop")
			return
		case msg := <-ce.resetChan:
			ce.resetBlockProp(ctx, msg.height, msg.txIDs)
		}
	}
}

// handleConsensusMessages handles the consensus messages based on the message type.
func (ce *ConsensusEngine) handleConsensusMessages(ctx context.Context, msg consensusMessage) {
	ce.log.Debug("Consensus message received", "msg", msg.String(), "sender", hex.EncodeToString(msg.Sender))

	defer msg.Handled()

	switch v := msg.Msg.(type) {
	case *blockProposal:
		if err := ce.processBlockProposal(ctx, v); err != nil {
			ce.log.Error("Error processing block proposal", "error", err)
			return
		}

	case *vote:
		if ce.role.Load() != types.RoleLeader {
			return
		}
		if err := ce.addVote(ctx, v, hex.EncodeToString(msg.Sender)); err != nil {
			ce.log.Warn("Error adding vote", "vote", v, "error", err)
			return
		}

	case *blockAnnounce:
		preRole := ce.role.Load()
		if err := ce.commitBlock(ctx, v.blk, v.ci, v.blkID, v.done); err != nil {
			ce.log.Error("Error processing committed block announcement", "error", err)
			return
		}

		// apply the leader updates if any
		ce.applyLeaderUpdates()

		postRole := ce.role.Load()
		if preRole != postRole && postRole == types.RoleLeader {
			// trigger this only during the role change to leader, rest the leader state machine will take care of it.
			ce.newRound <- struct{}{}
		}

	default:
		ce.log.Warnf("Invalid message type received")
	}

}

// applyLeaderUpdates will apply any leader updates configured on this node
// using the `validators replace-leader` command. This method is called after
// processing a blockAnn message and after blocksync and at the init. This method
// ensures that only existing validators can be promoted to leader at the specified
// heights and updates the roles of the nodes if changed by this update.
// This method also ensures that the stale updates are removed from the disk.
func (ce *ConsensusEngine) applyLeaderUpdates() {
	leaderUpdates := ce.getLeaderUpdates()
	if leaderUpdates == nil { // no updates to apply
		return
	}

	candidate := leaderUpdates.Candidate
	height := leaderUpdates.Height
	lastCommitHeight := ce.lastCommitHeight()

	// this is a future update, nothing to do here
	if height > lastCommitHeight+1 {
		return
	}

	// stale updates to be cleared right away.
	if height <= lastCommitHeight {
		ce.log.Warn("Stale leader update, clearing it", "height", height, "validator", hex.EncodeToString(candidate.Bytes()))
		ce.storeLeaderUpdates(nil)
		return
	}

	ce.state.mtx.Lock()
	defer ce.state.mtx.Unlock()

	// ensure that the candidate is a validator
	if _, ok := ce.validatorSet[hex.EncodeToString(candidate.Bytes())]; !ok {
		ce.log.Warn("Invalid leader update, candidate is not a validator", "candidate", hex.EncodeToString(candidate.Bytes()))
		ce.storeLeaderUpdates(nil)
		return
	}

	if !ce.leader.Equals(candidate) {
		ce.log.Info("Applying leader update", "height", height, "from", hex.EncodeToString(ce.leader.Bytes()), "to", hex.EncodeToString(candidate.Bytes()))
	}

	ce.leader = ce.leaderUpdates.Candidate
	ce.updateRole()

	ce.state.leaderUpdate = &leaderUpdate{
		Candidate: ce.leaderUpdates.Candidate,
		Height:    ce.leaderUpdates.Height,
	}
}

func (ce *ConsensusEngine) initializeState(ctx context.Context) (int64, int64, error) {
	// Figure out the app state and initialize the node state.
	ce.state.mtx.Lock()
	defer ce.state.mtx.Unlock()

	readTx, err := ce.db.BeginReadTx(ctx)
	if err != nil {
		return -1, -1, err
	}
	defer readTx.Rollback(ctx)

	// retrieve the last committed block info from the blockstore
	storeHeight, _, storeAppHash, _ /* timestamp */ := ce.blockStore.Best()

	// retrieve the app state from the meta table
	appHeight, appHash, dirty, err := meta.GetChainState(ctx, readTx)
	if err != nil {
		return -1, -1, err
	}

	if dirty {
		return -1, -1, fmt.Errorf("app state is dirty, error in the blockprocessor initialization, height: %d, appHash: %x", appHeight, appHash)
	}

	var intent *commitIntent
	if ce.commitLog != nil {
		intent, err = ce.commitLog.Load()
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return -1, -1, fmt.Errorf("error loading commit intent: %w", err)
		}
		if intent != nil {
			ce.log.Debug("Found pending commit intent", "height", intent.Height, "hash", intent.BlockHash)
		}
	}

	if appHeight > storeHeight && appHeight != ce.genesisHeight {
		if err := ce.repairAppAheadOfStore(ctx, appHeight, appHash, intent); err != nil {
			return -1, -1, fmt.Errorf("app height %d is greater than the store height %d (did you forget to reset postgres?): %w", appHeight, storeHeight, err)
		}
		storeHeight, _, storeAppHash, _ = ce.blockStore.Best()
		if storeHeight < appHeight {
			return -1, -1, fmt.Errorf("blockstore repair failed to reach app height %d (best %d)", appHeight, storeHeight)
		}
	}

	ce.log.Info("Initial Node state: ", "appHeight", appHeight, "storeHeight", storeHeight, "appHash", appHash, "storeAppHash", storeAppHash)

	if appHeight == -1 {
		// This is the first time the node is bootstrapping
		// initialize the db with the genesis state
		appHeight, appHash, err = ce.blockProcessor.InitChain(ctx)
		if err != nil {
			return -1, -1, fmt.Errorf("error initializing the chain: %w", err)
		}

		ce.setLastCommitInfo(appHeight, appHash, nil, nil)
	} else if appHeight == 0 {
		// appHeight = 0 indicates that the app bootstrapped with the genesis state, but shutdown before the first block
		ce.setLastCommitInfo(appHeight, appHash, nil, nil)
	} else {
		// restart or statesync init or zdt init
		if appHeight == storeHeight && !bytes.Equal(appHash, storeAppHash[:]) {
			// This is not possible, PG mismatches with the Blockstore return error
			return -1, -1, fmt.Errorf("AppHash mismatch, appHash: %x, storeAppHash: %v", appHash, storeAppHash)
		}

		// retrieve the commit info from the blockstore
		_, blk, ci, err := ce.blockStore.GetByHeight(appHeight)
		if err != nil {
			return -1, -1, fmt.Errorf("error fetching the block from the blockstore: %w", err)
		}

		ce.setLastCommitInfo(appHeight, appHash, blk, ci)
	}

	// Set the role and validator set based on the initial state of the voters before starting the replay
	ce.updateValidatorSetAndRole()

	if intent != nil && ce.commitLog != nil {
		finalStoreHeight, _, _, _ := ce.blockStore.Best()
		if finalStoreHeight >= intent.Height && appHeight >= intent.Height {
			if err := ce.commitLog.Clear(); err != nil && !errors.Is(err, fs.ErrNotExist) {
				ce.log.Warn("Failed to clear commit intent after initialization", "error", err)
			}
		}
	}

	return appHeight, storeHeight, nil
}

func (ce *ConsensusEngine) repairAppAheadOfStore(ctx context.Context, height int64, appHash []byte, intent *commitIntent) error {
	if ce.blkRequester == nil {
		return fmt.Errorf("block requester is not configured")
	}

	ce.log.Warn("App height ahead of blockstore detected, attempting repair", "height", height)

	blkID, rawBlk, ci, _, err := ce.blkRequester(ctx, height)
	if err != nil {
		return fmt.Errorf("fetch block %d: %w", height, err)
	}

	if ci == nil {
		return fmt.Errorf("missing commit info for block %d", height)
	}

	if len(appHash) > 0 && !bytes.Equal(ci.AppHash[:], appHash) {
		return fmt.Errorf("commit info app hash mismatch for block %d: got %x expected %x", height, ci.AppHash[:], appHash)
	}

	if intent != nil {
		expectedHash, err := intent.hash()
		if err != nil {
			return fmt.Errorf("decode commit intent hash: %w", err)
		}
		var zeroHash ktypes.Hash
		if expectedHash != zeroHash && expectedHash != blkID {
			return fmt.Errorf("fetched block hash %s does not match commit intent %s at height %d", blkID.String(), expectedHash.String(), height)
		}
	}

	blk, err := ktypes.DecodeBlock(rawBlk)
	if err != nil {
		return fmt.Errorf("decode block %d: %w", height, err)
	}

	if err := ce.blockStore.Store(blk, ci); err != nil {
		return fmt.Errorf("store block %d: %w", height, err)
	}
	if err := ce.blockStore.Sync(); err != nil {
		return fmt.Errorf("sync blockstore %d: %w", height, err)
	}

	ce.log.Info("Blockstore repaired successfully", "height", height, "hash", blkID.String())
	return nil
}

// catchup syncs the node first with the local blockstore and then with the network.
func (ce *ConsensusEngine) catchup(ctx context.Context) error {
	// initialize the chain state
	appHeight, storeHeight, err := ce.initializeState(ctx)
	if err != nil {
		return err
	}

	// set inSync to true to indicate that the node is syncing with the network
	// and not accept txs till the sync is complete.
	ce.inSync.Store(true) // across replay from block store and network
	defer ce.inSync.Store(false)

	// Replay the blocks from the blockstore if the app hasn't played all the blocks yet.
	if appHeight < storeHeight {
		if err := ce.replayFromBlockStore(ctx, appHeight+1, storeHeight); err != nil {
			return err
		}
	}

	// Sync with the network using the blocksync
	return ce.doBlockSync(ctx)
}

// updateValidatorSetAndRole updates the validator set and the role of the node based on
// the current state of the network parameters. This method is called during the initialization
// of the consensus engine and at the end of each block commit.
func (ce *ConsensusEngine) updateValidatorSetAndRole() {
	// get the final consensus params
	params := ce.blockProcessor.ConsensusParams()
	valset := ce.blockProcessor.GetValidators()

	// update the leader
	prevLeader := ce.leader
	ce.leader = params.Leader
	if !prevLeader.Equals(ce.leader) {
		ce.log.Info("Leader updated", "from", hex.EncodeToString(prevLeader.Bytes()), "to", hex.EncodeToString(ce.leader.Bytes()))
	}

	// update the validator set
	ce.validatorSet = make(map[string]ktypes.Validator)
	for _, v := range valset {
		ce.validatorSet[hex.EncodeToString(v.Identifier)] = ktypes.Validator{
			AccountID: ktypes.AccountID{
				Identifier: v.Identifier,
				KeyType:    v.KeyType,
			},
			Power: v.Power,
		}
	}

	// update the role if changed
	ce.updateRole()
}

func (ce *ConsensusEngine) updateRole() {
	var finalRole types.Role
	if ce.privKey.Public().Equals(ce.leader) {
		finalRole = types.RoleLeader
	} else {
		_, ok := ce.validatorSet[hex.EncodeToString(ce.privKey.Public().Bytes())]
		if ok {
			finalRole = types.RoleValidator
		} else {
			finalRole = types.RoleSentry
		}
	}

	prevRole := ce.role.Swap(finalRole)
	if prevRole != finalRole {
		ce.log.Info("Role updated", "from", prevRole, "to", finalRole)
	}
}

func (ce *ConsensusEngine) setLastCommitInfo(height int64, appHash []byte, blk *ktypes.Block, ci *ktypes.CommitInfo) {
	var blkHash types.Hash
	if blk != nil {
		blkHash = blk.Header.Hash()
	}

	ce.state.lc.height = height
	ce.state.lc.blkHash = blkHash
	copy(ce.state.lc.appHash[:], appHash)
	ce.state.lc.blk = blk
	ce.state.lc.commitInfo = ci

	ce.stateInfo.mtx.Lock()
	defer ce.stateInfo.mtx.Unlock()
	ce.stateInfo.height = height
	ce.stateInfo.status = Committed
	ce.stateInfo.blkProp = nil
	ce.stateInfo.lastCommit = lastCommit{
		height:     height,
		blk:        blk,
		commitInfo: ci,
		blkHash:    blkHash,
	}
	copy(ce.stateInfo.lastCommit.appHash[:], appHash)

	ce.stateInfo.hasBlock.Store(height)
}

// replayBlocks replays all the blocks from the blockstore if the app hasn't played all the blocks yet.
func (ce *ConsensusEngine) replayFromBlockStore(ctx context.Context, startHeight, bestHeight int64) error {
	ce.state.mtx.Lock()
	defer ce.state.mtx.Unlock()

	height := startHeight
	t0 := time.Now()

	if startHeight >= bestHeight {
		return nil // already caught up with the blockstore
	}

	for height <= bestHeight {
		_, blk, ci, err := ce.blockStore.GetByHeight(height)
		if err != nil {
			if !errors.Is(err, types.ErrNotFound) {
				return fmt.Errorf("unexpected blockstore error: %w", err)
			}
			return nil // no more blocks to replay
		}

		err = ce.processAndCommit(ctx, blk, ci, blk.Hash(), true)
		if err != nil {
			return fmt.Errorf("failed replaying block: %w", err)
		}

		height++
	}

	ce.log.Info("Replayed blocks from the blockstore", "from", startHeight, "to", height, "elapsed", time.Since(t0), "appHash", ce.state.lc.appHash)
	return nil
}

// Blocksync need to be way quicker, whereas the others need not be that frequent.
func (ce *ConsensusEngine) reannounceMsgs(ctx context.Context) {
	// Leader should reannounce the blkProp and blkAnn messages
	// Validators should reannounce the Ack messages
	ce.state.mtx.RLock()
	defer ce.state.mtx.RUnlock()

	if ce.role.Load() == types.RoleLeader && ce.state.lc.height > 0 {
		// Announce block commit message for the last committed block
		if ce.state.lc.blk != nil && ce.state.commitInfo != nil {
			go ce.blkAnnouncer(ctx, ce.state.lc.blk, ce.state.lc.commitInfo)
		}
		return
	}

	if ce.role.Load() == types.RoleValidator {
		// reannounce the acks, if still waiting for the commit message
		if ce.state.blkProp != nil && ce.state.blockRes != nil &&
			!ce.state.blockRes.appHash.IsZero() {
			ce.log.Info("Reannouncing ACK", "ack", ce.state.blockRes.ack, "height", ce.state.blkProp.height, "hash", ce.state.blkProp.blkHash)
			vote := ce.state.blockRes.vote
			go ce.ackBroadcaster(vote.msg)
		}
	}
}

func (ce *ConsensusEngine) rebroadcastBlkProposal(ctx context.Context) {
	ce.state.mtx.RLock()
	defer ce.state.mtx.RUnlock()

	if ce.role.Load() == types.RoleLeader && ce.state.blkProp != nil {
		ce.log.Debug("Rebroadcasting block proposal", "height", ce.state.blkProp.height)
		go ce.proposalBroadcaster(ctx, ce.state.blkProp.blk, ce.pubKey.Bytes())
	}
}

func (ce *ConsensusEngine) doCatchup(ctx context.Context) error {
	// status check, nodes halt here if the migration is completed
	params := ce.blockProcessor.ConsensusParams()
	if params.MigrationStatus == ktypes.MigrationCompleted {
		ce.log.Info("Network halted due to migration, no more blocks will be produced")
		return nil
	}

	if ce.role.Load() == types.RoleLeader {
		// check if leader has any leader updates to apply
		ce.applyLeaderUpdates()

		if ce.role.Load() != types.RoleLeader {
			ce.log.Info("Leader demoted to %s", ce.role.Load())
		}

		return nil
	}

	ce.log.Infof("No consensus messages received for %s, initiating network catchup.", ce.catchupTimeout)
	ce.inSync.Store(true)
	defer ce.inSync.Store(false) // going back to consensusEventLoop

	startHeight := ce.lastCommitHeight()
	if err := ce.processCurrentBlock(ctx); err != nil {
		if errors.Is(err, types.ErrBlkNotFound) || errors.Is(err, types.ErrNotFound) || errors.Is(err, types.ErrPeersNotFound) {
			return nil // retry again next tick
		}
		ce.log.Error("error during block processing in catchup", "height", startHeight+1, "error", err)
		return err
	}

	err := ce.replayBlockFromNetwork(ctx)
	if err != nil {
		return err
	}

	// apply the leader updates if any
	ce.applyLeaderUpdates()

	// let it sync up with the network and if its promoted to a leader, trigger a new round
	if ce.role.Load() == types.RoleLeader {
		ce.newRound <- struct{}{}
	}

	return nil
}

func (ce *ConsensusEngine) processCurrentBlock(ctx context.Context) error {
	if ce.role.Load() != types.RoleValidator {
		return nil
	}

	ce.state.mtx.Lock()
	defer ce.state.mtx.Unlock()

	if ce.state.blkProp == nil || ce.state.blockRes == nil {
		return nil // not processing any block, or not ready to commit
	} // else waiting for the commit message

	// Fetch the block at this height and commit it, if it's the right one,
	// otherwise rollback.
	height := ce.state.blkProp.height
	blkHash, rawBlk, ci, err := ce.getBlockWithRetry(ctx, height)
	if err != nil {
		return err
	}

	if blkHash != ce.state.blkProp.blkHash { // processed incorrect block
		if err := ce.rollbackState(ctx); err != nil {
			return fmt.Errorf("error aborting incorrect block execution: height: %d, blockID: %v, error: %w", height, blkHash, err)
		}

		blk, err := ktypes.DecodeBlock(rawBlk)
		if err != nil {
			return fmt.Errorf("failed to decode the block, blkHeight: %d, blockID: %v, error: %w", height, blkHash, err)
		}

		if err := ce.processAndCommit(ctx, blk, ci, blkHash, false); err != nil {
			return fmt.Errorf("failed to replay the block: blkHeight: %d, blockID: %v, error: %w", height, blkHash, err)
		}
		// recovered to the correct block -> continue to replay blocks from network
		return nil
	}

	if ci.AppHash != ce.state.blockRes.appHash {
		// halt the node
		haltReason := fmt.Sprintf("Incorrect AppHash, received: %v, have: %v", ci.AppHash, ce.state.blockRes.appHash)
		ce.sendHalt(haltReason)
		return nil // or an error?
	}

	// All correct! Commit the block.
	if err := ce.acceptCommitInfo(ci, blkHash); err != nil {
		return fmt.Errorf("failed to validate the commit info: height: %d, error: %w", height, err)
	}

	if err := ce.commit(ctx, false); err != nil {
		return fmt.Errorf("failed to commit the block: height: %d, error: %w", height, err)
	}

	return ctx.Err()
}

func (ce *ConsensusEngine) sendHalt(reason string) {
	select {
	case ce.haltChan <- reason:
	default:
		ce.log.Warnf("Halt reason not sent (already halting): %s", reason)
	}
}

func (ce *ConsensusEngine) cancelBlock(height int64) bool {
	ce.stateInfo.mtx.RLock()
	defer ce.stateInfo.mtx.RUnlock()

	// We will only honor the reset request if it's from the leader (already verified by now)
	// and the height is same as the last committed block height + 1 and the
	// block is still executing or waiting for the block commit message.
	if ce.stateInfo.height+1 != height {
		ce.log.Warn("Invalid reset request", "height", height, "lastCommittedHeight", ce.state.lc.height)
		return false
	}

	if ce.stateInfo.blkProp == nil {
		ce.log.Info("Block already committed or executed, nothing to reset", "height", height)
		return false
	}

	ce.log.Info("Resetting the block proposal", "height", height)
	// cancel the context
	ce.cancelFnMtx.Lock()
	defer ce.cancelFnMtx.Unlock()
	if ce.blkExecCancelFn != nil {
		ce.blkExecCancelFn()
	}

	return true
}

// resetBlockProp aborts the block execution and resets the state to the last committed block.
func (ce *ConsensusEngine) resetBlockProp(ctx context.Context, height int64, txIDs []ktypes.Hash) {
	ce.log.Info("Reset msg: ", "height", height)

	rollback := ce.cancelBlock(height) // return here if false?

	// context is already cancelled, so try the lock
	ce.state.mtx.Lock() // block execution is cancelled by now
	defer ce.state.mtx.Unlock()

	// remove the long running txs from the mempool
	for _, txID := range txIDs {
		ce.mempool.Remove(txID)
	}

	if rollback {
		// rollback the state
		if err := ce.rollbackState(ctx); err != nil {
			ce.log.Error("Error aborting execution of block", "height", ce.state.blkProp.height, "blockID", ce.state.blkProp.blkHash, "error", err)
			return
		}
	}

	// recheck txs in the mempool, if we have deleted any txs from the mempool
	if len(txIDs) > 0 {
		ce.mempoolMtx.PriorityLock()
		lh, t := ce.lastBlockInternal()
		ce.blockProcessor.RecheckTxs(ctx, lh, t)
		ce.mempoolMtx.Unlock()
	}
}

func (ce *ConsensusEngine) Role() types.Role {
	return ce.role.Load().(types.Role)
}

func (ce *ConsensusEngine) hasMajority(cnt int) bool { // majority: > 50%
	threshold := len(ce.validatorSet)/2 + 1
	return cnt >= threshold
}

// hasEnoughNacks checks if the network has received enough Nacks for network to never make progress
func (ce *ConsensusEngine) hasEnoughNacks(cnt int) bool {
	threshold := ceilDiv(len(ce.validatorSet), 2)
	return cnt >= threshold
}

func ceilDiv(a, b int) int {
	return (a + b - 1) / b
}

func (ce *ConsensusEngine) InCatchup() bool {
	return ce.inSync.Load()
}

func (ce *ConsensusEngine) SubscribeTx(txHash ktypes.Hash) (<-chan ktypes.TxResult, error) {
	ce.subMtx.Lock()
	defer ce.subMtx.Unlock()

	ch := make(chan ktypes.TxResult, 1)

	_, ok := ce.txSubscribers[txHash]
	if ok {
		return nil, fmt.Errorf("tx already subscribed")
	}

	ce.txSubscribers[txHash] = ch
	return ch, nil
}

func (ce *ConsensusEngine) UnsubscribeTx(txHash ktypes.Hash) {
	ce.subMtx.Lock()
	defer ce.subMtx.Unlock()

	delete(ce.txSubscribers, txHash)
}

func (ce *ConsensusEngine) lastCommitHeight() int64 {
	ce.stateInfo.mtx.RLock()
	defer ce.stateInfo.mtx.RUnlock()

	return ce.stateInfo.height
}

func (ce *ConsensusEngine) PromoteLeader(candidate crypto.PublicKey, height int64) error {
	lastCommitHeight := ce.lastCommitHeight()

	if height <= lastCommitHeight {
		return fmt.Errorf("height %d is less than or equal to the current height %d", height, lastCommitHeight)
	}

	// save the leader update to the file
	update := &leaderUpdate{
		Candidate: candidate,
		Height:    height,
	}

	if err := ce.storeLeaderUpdates(update); err != nil {
		return fmt.Errorf("error saving the leader update: %w", err)
	}

	return nil
}

// loadLeaderUpdates loads the leader updates from the file if any
// at the start of the consensus engine.
func (ce *ConsensusEngine) loadLeaderUpdates() error {
	// check if the leader file exists
	if _, err := os.Stat(ce.leaderFile); os.IsNotExist(err) {
		return nil
	}

	// load the leader updates from the file
	data, err := os.ReadFile(ce.leaderFile)
	if err != nil {
		return fmt.Errorf("error reading the leader file: %w", err)
	}

	// unmarshal the leader updates
	update := struct {
		PubKey  string `json:"pubKey"`
		KeyType string `json:"keyType"`
		Height  int64  `json:"height"`
	}{}
	if err := json.Unmarshal(data, &update); err != nil {
		return fmt.Errorf("error unmarshalling the leader updates: %w", err)
	}

	pk, err := hex.DecodeString(update.PubKey)
	if err != nil {
		return fmt.Errorf("error decoding the pubkey from leader updates: %w", err)
	}

	candidate, err := crypto.UnmarshalPublicKey(pk, crypto.KeyType(update.KeyType))
	if err != nil {
		return fmt.Errorf("error unmarshalling the pubkey from leader updates: %w", err)
	}

	ce.leaderMtx.Lock()
	defer ce.leaderMtx.Unlock()
	ce.leaderUpdates = &leaderUpdate{
		Candidate: candidate,
		Height:    update.Height,
	}
	return nil
}

// storeLeaderUpdates persists the leader updates to the file.
func (ce *ConsensusEngine) storeLeaderUpdates(update *leaderUpdate) error {
	if update == nil {
		if err := os.Remove(ce.leaderFile); err != nil {
			return fmt.Errorf("error removing the leader file: %w", err)
		}

		ce.leaderMtx.Lock()
		defer ce.leaderMtx.Unlock()
		ce.leaderUpdates = update

		ce.log.Infof("Removed the leader updates file %s", ce.leaderFile)
		return nil
	}

	data, err := json.Marshal(struct {
		PubKey  string `json:"pubKey"`
		KeyType string `json:"keyType"`
		Height  int64  `json:"height"`
	}{
		PubKey:  hex.EncodeToString(update.Candidate.Bytes()),
		KeyType: update.Candidate.Type().String(),
		Height:  update.Height,
	})
	if err != nil {
		return fmt.Errorf("error marshalling the leader updates: %w", err)
	}

	if err := os.WriteFile(ce.leaderFile, data, 0644); err != nil {
		return fmt.Errorf("error writing the leader file: %w", err)
	}

	ce.leaderMtx.Lock()
	defer ce.leaderMtx.Unlock()
	ce.leaderUpdates = update

	return nil
}

func (ce *ConsensusEngine) getLeaderUpdates() *leaderUpdate {
	ce.leaderMtx.RLock()
	defer ce.leaderMtx.RUnlock()

	return ce.leaderUpdates
}
