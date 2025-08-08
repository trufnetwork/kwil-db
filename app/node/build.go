package node

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/rpc/transport"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node"
	"github.com/trufnetwork/kwil-db/node/accounts"
	blockprocessor "github.com/trufnetwork/kwil-db/node/block_processor"
	"github.com/trufnetwork/kwil-db/node/consensus"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/engine/interpreter"
	_ "github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/erc20"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/signersvc"
	"github.com/trufnetwork/kwil-db/node/listeners"
	"github.com/trufnetwork/kwil-db/node/mempool"
	"github.com/trufnetwork/kwil-db/node/meta"
	"github.com/trufnetwork/kwil-db/node/migrations"
	"github.com/trufnetwork/kwil-db/node/pg"
	rpcserver "github.com/trufnetwork/kwil-db/node/services/jsonrpc"
	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/adminsvc"
	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/chainsvc"
	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/funcsvc"
	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/usersvc"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
	"github.com/trufnetwork/kwil-db/node/store"
	"github.com/trufnetwork/kwil-db/node/txapp"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"
)

func buildServer(ctx context.Context, d *coreDependencies) *server {
	closers := &closeFuncs{
		closers: []func() error{}, // logger.Close is not in here; do it in a defer in Start
		logger:  d.logger,
	}
	d.closers = closers

	// verify dependencies
	verifyDependencies(d)

	// BlockStore
	bs := buildBlockStore(d, closers)

	// Initialize and start P2P service
	p2pSvc := initializeP2PService(ctx, d, closers)

	// SnapshotStore
	snapshotStore := buildSnapshotStore(d, bs)
	snapshotStore.RegisterSnapshotStreamHandlers(ctx, p2pSvc.Host(), p2pSvc.Discovery())

	// Statesync module
	ss := initializeStatesyncService(ctx, d, p2pSvc, snapshotStore, bs, closers)

	// Initialize DB
	db := buildDB(ctx, d, ss, closers)

	// metastore
	buildMetaStore(ctx, db)

	// accounts
	accounts := buildAccountStore(ctx, d, db)

	// eventstore, votestore
	es, vs := buildVoteStore(ctx, d, closers) // ev, vs

	// engine
	e := buildEngine(d, ctx, db, accounts, vs, d.namespaceManager)
	d.namespaceManager.Ready()

	// Mempool
	txSz := min(d.cfg.Mempool.MaxTxBytes, d.genesisCfg.MaxBlockSize) // txSz shouldn't exceed MaxBlockSize
	mp := mempool.New(d.cfg.Mempool.MaxSize, txSz)

	// TxAPP
	txApp := buildTxApp(ctx, d, db, accounts, vs, e)

	// Migrator
	migrator := buildMigrator(d, ctx, db, accounts, vs)

	// BlockProcessor
	bp := buildBlockProcessor(ctx, d, db, txApp, accounts, vs, snapshotStore, es, migrator, bs, mp)

	// Consensus
	ce := buildConsensusEngine(ctx, d, db, mp, bs, bp)

	// Node
	node := buildNode(d, mp, bs, ce, snapshotStore, db, bp, p2pSvc)

	// listeners
	lm := buildListenerManager(d, es, bp, node)

	// RPC Services
	rpcSvcLogger := d.logger.New("USER")
	jsonRPCTxSvc := usersvc.NewService(db, e, node, bp, vs, migrator, rpcSvcLogger,
		usersvc.WithReadTxTimeout(time.Duration(d.cfg.DB.ReadTxTimeout)),
		usersvc.WithPrivateMode(d.cfg.RPC.Private),
		usersvc.WithChallengeExpiry(time.Duration(d.cfg.RPC.ChallengeExpiry)),
		usersvc.WithChallengeRateLimit(d.cfg.RPC.ChallengeRateLimit),
		usersvc.WithBlockAgeHealth(6*time.Duration(max(d.cfg.Consensus.ProposeTimeout, d.cfg.Consensus.EmptyBlockTimeout))),
	)

	rpcServerLogger := d.logger.New("RPC")
	jsonRPCServer, err := rpcserver.NewServer(d.cfg.RPC.ListenAddress,
		rpcServerLogger, rpcserver.WithTimeout(time.Duration(d.cfg.RPC.Timeout)),
		rpcserver.WithReqSizeLimit(d.cfg.RPC.MaxReqSize),
		rpcserver.WithCORS(), rpcserver.WithServerInfo(&usersvc.SpecInfo))
	if err != nil {
		failBuild(err, "unable to create json-rpc server")
	}
	if !d.cfg.RPC.ServiceDisabled(config.RPCNamespaceUser) {
		jsonRPCServer.RegisterSvc(jsonRPCTxSvc)
	}
	if !d.cfg.RPC.ServiceDisabled(config.RPCNamespaceFunction) {
		jsonRPCServer.RegisterSvc(&funcsvc.Service{})
	}

	chainRpcSvcLogger := d.logger.New("CHAIN")
	jsonChainSvc := chainsvc.NewService(chainRpcSvcLogger, node, vs, d.genesisCfg)
	if !d.cfg.RPC.ServiceDisabled(config.RPCNamespaceChain) {
		jsonRPCServer.RegisterSvc(jsonChainSvc)
	}

	var jsonRPCAdminServer *rpcserver.Server
	if d.cfg.Admin.Enable {
		// admin service and server
		adminServerLogger := d.logger.New("ADMIN")
		// The admin service uses a client-style signer rather than just a private
		// key because it is used to sign transactions and provide an Identity for
		// account information (nonce and balance).
		txSigner := auth.GetNodeSigner(d.privKey)
		jsonAdminSvc := adminsvc.NewService(db, node, bp, vs, node.Whitelister(), node.Blacklister(),
			txSigner, d.cfg, d.genesisCfg.ChainID, adminServerLogger)
		jsonRPCAdminServer = buildJRPCAdminServer(d)
		jsonRPCAdminServer.RegisterSvc(jsonAdminSvc)
		jsonRPCAdminServer.RegisterSvc(jsonRPCTxSvc)
		jsonRPCAdminServer.RegisterSvc(&funcsvc.Service{})
		jsonRPCAdminServer.RegisterSvc(jsonChainSvc)
	}

	erc20BridgeSignerMgr := buildErc20BridgeSignerMgr(d, db, e, node, bp)

	s := &server{
		cfg:                d.cfg,
		closers:            closers,
		node:               node,
		ce:                 ce,
		listeners:          lm,
		jsonRPCServer:      jsonRPCServer,
		jsonRPCAdminServer: jsonRPCAdminServer,
		dbCtx:              db,
		log:                d.logger,
		erc20BridgeSigner:  erc20BridgeSignerMgr,
	}

	return s
}

func initializeP2PService(ctx context.Context, d *coreDependencies, closers *closeFuncs) *node.P2PService {
	p2pCfg := &node.P2PServiceConfig{
		PrivKey: d.privKey,
		RootDir: d.rootDir,
		ChainID: d.genesisCfg.ChainID,
		KwilCfg: d.cfg,
		Logger:  d.logger.New("P2P"),
	}

	// There's a separate constructor and start method presently, but the
	// constructor start things, and Start is non-blocking. Perhaps we change
	// this up, maybe merge them, maybe move some things between the two...

	p2pSvc, err := node.NewP2PService(ctx, p2pCfg, nil)
	if err != nil {
		failBuild(err, "failed to create p2p service")
	}

	if err := p2pSvc.Start(ctx, d.cfg.P2P.BootNodes...); err != nil {
		p2pSvc.Close() // the stuff started in NewP2PService...
		failBuild(err, "failed to start p2p service")
	}

	closers.addCloser(p2pSvc.Close, "Closing P2P service")

	return p2pSvc
}

// initializeStatesyncService initializes the statesync service if enabled.
// and discovers the snapshots from the trusted peers.
func initializeStatesyncService(ctx context.Context, d *coreDependencies, p2p *node.P2PService, snapshotter *snapshotter.SnapshotStore, bs *store.BlockStore, closers *closeFuncs) *node.StateSyncService {
	if !d.cfg.StateSync.Enable {
		return nil
	}
	poolDB, err := d.poolOpener(ctx, d.cfg.DB.DBName, 3)
	if err != nil {
		failBuild(err, "failed to open kwild postgres database for eventstore")
	}
	closers.addCloser(poolDB.Close, "Closing Eventstore DB")

	rcvdSnapsDir := config.ReceivedSnapshotsDir(d.rootDir)
	ssCfg := &node.StatesyncConfig{
		RcvdSnapsDir:  rcvdSnapsDir,
		StateSyncCfg:  &d.cfg.StateSync,
		DBConfig:      d.cfg.DB,
		BlockSyncCfg:  &d.cfg.BlockSync,
		Logger:        d.logger.New("STATESYNC"),
		SnapshotStore: snapshotter,
		BlockStore:    bs,
		P2PService:    p2p,
		DB:            poolDB,
	}
	ss, err := node.NewStateSyncService(ctx, ssCfg)
	if err != nil {
		failBuild(err, "failed to create statesync service")
	}
	return ss
}

func buildDB(ctx context.Context, d *coreDependencies, ss *node.StateSyncService, closers *closeFuncs) *pg.DB {
	pg.UseLogger(d.logger.New("PG"))

	fromGenesisSnapshot := restoreDB(d, ctx, ss)

	db, err := d.dbOpener(ctx, d.cfg.DB.DBName, d.cfg.DB.MaxConns)
	if err != nil {
		failBuild(err, "failed to open kwild postgres database")
	}
	closers.addCloser(db.Close, "Closing application DB")

	if fromGenesisSnapshot {
		// readjust the expiry heights of all the pending resolutions after snapshot restore for Zero-downtime migrations
		// snapshot tool handles the migration expiry height readjustment for offline migrations
		// adjustExpiration := false
		// startHeight := d.genesisCfg.ConsensusParams.Migration.StartHeight
		// if d.cfg.MigrationConfig.Enable && startHeight != 0 {
		// 	adjustExpiration = true
		// }

		err = migrations.CleanupResolutionsAfterMigration(ctx, db)
		if err != nil {
			failBuild(err, "failed to cleanup resolutions after snapshot restore")
		}

		if err = db.EnsureFullReplicaIdentityDatasets(ctx); err != nil {
			failBuild(err, "failed enable full replica identity on user datasets")
		}
	}
	return db
}

// restoreDB restores the database from a snapshot if the genesis apphash is specified.
// StateHash in the genesis config ensures that all the nodes in the network start from the same state.
// StateHash in the genesis config should match the hash of the snapshot file.
// Snapshot file can be compressed or uncompressed represented by .gz extension.
// DB restoration from snapshot is skipped in the following scenarios:
//   - If the DB is already initialized (i.e this is not a new node)
//   - If the StateHash is not set in the genesis config
//   - If statesync is enabled. Statesync will take care of syncing the database
//     to the network state using statesync snapshots.
//
// returns true if the DB was restored from genesis snapshot, false otherwise.
func restoreDB(d *coreDependencies, ctx context.Context, ss *node.StateSyncService) bool {
	if isDbInitialized(ctx, d) {
		return false
	}

	if d.cfg.StateSync.Enable {
		// discover and restore from snapshot using statesync service
		success, err := ss.DoStatesync(ctx)
		if err != nil {
			failBuild(err, "failed to do statesync")
		}

		if success {
			d.logger.Info("DB restored from statesync snapshot")
			return false
		}

		// If statesync is not successful, restore from the genesis snapshot if available
	}

	// offline migration -> restore from the genesis snapshot
	if len(d.genesisCfg.StateHash) == 0 {
		return false
	}

	genCfg := d.genesisCfg
	appCfg := d.cfg

	// DB is uninitialized and genesis statehash is set, so db should be restored from snapshot.
	// Ensure that the snapshot file exists and the snapshot hash matches the genesis apphash.

	if genCfg.StateHash != nil && appCfg.GenesisState == "" {
		failBuild(nil, "snapshot file not provided")
	}

	// Snapshot file exists
	snapFile, err := os.Open(appCfg.GenesisState)
	if err != nil {
		failBuild(err, "failed to open genesis state file")
	}
	defer snapFile.Close()

	// Check if the snapshot file is compressed, if yes decompress it
	var reader io.Reader
	if strings.HasSuffix(appCfg.GenesisState, ".gz") {
		// Decompress the snapshot file
		gzipReader, err := gzip.NewReader(snapFile)
		if err != nil {
			failBuild(err, "failed to create gzip reader")
		}
		defer gzipReader.Close()
		reader = gzipReader
	} else {
		reader = snapFile
	}

	// Restore DB from the snapshot if snapshot matches.
	err = node.RestoreDB(ctx, reader, appCfg.DB, genCfg.StateHash, d.logger)
	if err != nil {
		failBuild(err, "failed to restore DB from snapshot")
	}

	d.logger.Info("DB restored from snapshot", "snapshot", d.cfg.GenesisState)
	return true
}

// isDbInitialized checks if the database is already initialized.
func isDbInitialized(ctx context.Context, d *coreDependencies) bool {
	db, err := d.poolOpener(ctx, d.cfg.DB.DBName, 3)
	if err != nil {
		failBuild(err, "kwild database open failed")
	}
	defer db.Close()

	// Check if the kwild_voting schema exists
	exists, err := schemaExists(ctx, db, "kwild_voting")
	if err != nil {
		failBuild(err, "failed to check if schema exists")
	}

	// If the schema exists, the database is already initialized
	// If the schema does not exist, the database is not initialized
	return exists
}

// schemaExists checks if the schema with the given name exists in the database
func schemaExists(ctx context.Context, db sql.Executor, schema string) (bool, error) {
	query := fmt.Sprintf("SELECT 1 FROM information_schema.schemata WHERE schema_name = '%s'", schema)
	res, err := db.Execute(ctx, query)
	if err != nil {
		return false, err
	}

	if len(res.Rows) == 0 {
		return false, nil
	}

	if len(res.Rows) > 1 {
		return false, fmt.Errorf("more than one schema found with name %s", schema)
	}

	return true, nil
}

func buildBlockStore(d *coreDependencies, closers *closeFuncs) *store.BlockStore {
	blkStrDir := config.BlockstoreDir(d.rootDir)
	bs, err := store.NewBlockStore(blkStrDir, store.WithCompression(d.cfg.Store.Compression))
	if err != nil {
		failBuild(err, "failed to open blockstore")
	}
	closers.addCloser(bs.Close, "Closing blockstore") // Close DB after stopping p2p

	return bs
}

func buildAccountStore(ctx context.Context, d *coreDependencies, db *pg.DB) *accounts.Accounts {
	logger := d.logger.New("ACCOUNTS")
	accounts, err := accounts.InitializeAccountStore(ctx, db, logger)
	if err != nil {
		failBuild(err, "failed to initialize account store")
	}

	return accounts
}

func buildVoteStore(ctx context.Context, d *coreDependencies, closers *closeFuncs) (*voting.EventStore, *voting.VoteStore) {
	poolDB, err := d.poolOpener(ctx, d.cfg.DB.DBName, d.cfg.DB.MaxConns)
	if err != nil {
		failBuild(err, "failed to open kwild postgres database for eventstore")
	}
	closers.addCloser(poolDB.Close, "Closing Eventstore DB")

	ev, vs, err := voting.NewResolutionStore(ctx, poolDB)
	if err != nil {
		failBuild(err, "failed to create vote store")
	}

	return ev, vs
}

func buildMetaStore(ctx context.Context, db *pg.DB) {
	err := meta.InitializeMetaStore(ctx, db)
	if err != nil {
		failBuild(err, "failed to initialize meta store")
	}
}

// service returns a common.Service with the given logger name
func (c *coreDependencies) service(loggerName string) *common.Service {
	signer := auth.GetNodeSigner(c.privKey)

	return &common.Service{
		Logger:        c.logger.New(loggerName),
		GenesisConfig: c.genesisCfg,
		LocalConfig:   c.cfg,
		Identity:      signer.CompactID(),
	}
}

func buildTxApp(ctx context.Context, d *coreDependencies, db *pg.DB, accounts *accounts.Accounts,
	votestore *voting.VoteStore, engine common.Engine) *txapp.TxApp {
	signer := auth.GetNodeSigner(d.privKey)

	txapp, err := txapp.NewTxApp(ctx, db, engine, signer, nil, d.service("TxAPP"), accounts, votestore)
	if err != nil {
		failBuild(err, "failed to create txapp")
	}

	return txapp
}

func buildBlockProcessor(ctx context.Context, d *coreDependencies, db *pg.DB, txapp *txapp.TxApp, accounts *accounts.Accounts, vs *voting.VoteStore, ss *snapshotter.SnapshotStore, es *voting.EventStore, migrator *migrations.Migrator, bs *store.BlockStore, mp *mempool.Mempool) *blockprocessor.BlockProcessor {
	signer := auth.GetNodeSigner(d.privKey)

	bp, err := blockprocessor.NewBlockProcessor(ctx, db, txapp, accounts, vs, ss, es, migrator, bs, mp, d.genesisCfg, signer, d.logger.New("BP"))
	if err != nil {
		failBuild(err, "failed to create block processor")
	}

	return bp
}

func buildMigrator(d *coreDependencies, ctx context.Context, db *pg.DB, accounts *accounts.Accounts, vs *voting.VoteStore) *migrations.Migrator {
	migrationsDir := config.MigrationDir(d.rootDir)

	err := os.MkdirAll(migrations.ChangesetsDir(migrationsDir), 0755)
	if err != nil {
		failBuild(err, "failed to create changesets directory")
	}

	snapshotDir := migrations.SnapshotDir(migrationsDir)
	err = os.MkdirAll(snapshotDir, 0755)
	if err != nil {
		failBuild(err, "failed to create migrations snapshots directory")
	}

	ss, err := snapshotter.NewSnapshotStore(&snapshotter.SnapshotConfig{
		SnapshotDir:      snapshotDir,
		MaxSnapshots:     int(d.cfg.Snapshots.MaxSnapshots),
		RecurringHeight:  d.cfg.Snapshots.RecurringHeight,
		Enable:           d.cfg.Snapshots.Enable,
		DBConfig:         &d.cfg.DB,
		ChunkSendTimeout: time.Duration(d.cfg.Snapshots.ChunkSendTimeout),
	}, nil, d.namespaceManager, d.logger.New("SNAP"))
	if err != nil {
		failBuild(err, "failed to create migration's snapshot store")
	}

	migrator, err := migrations.SetupMigrator(ctx, db, ss, accounts, migrationsDir, d.genesisCfg.Migration, vs, d.logger.New(`MIGRATOR`))
	if err != nil {
		failBuild(err, "failed to create migrator")
	}

	return migrator
}

func buildConsensusEngine(_ context.Context, d *coreDependencies, db *pg.DB,
	mempool *mempool.Mempool, bs *store.BlockStore, bp *blockprocessor.BlockProcessor) *consensus.ConsensusEngine {
	ceCfg := &consensus.Config{
		RootDir:               d.rootDir,
		PrivateKey:            d.privKey,
		Leader:                d.genesisCfg.Leader.PublicKey,
		DB:                    db,
		BlockStore:            bs,
		BlockProcessor:        bp,
		Mempool:               mempool,
		Logger:                d.logger.New("CONS"),
		ProposeTimeout:        time.Duration(d.cfg.Consensus.ProposeTimeout),
		EmptyBlockTimeout:     time.Duration(d.cfg.Consensus.EmptyBlockTimeout),
		BlockProposalInterval: time.Duration(d.cfg.Consensus.BlockProposalInterval),
		BlockAnnInterval:      time.Duration(d.cfg.Consensus.BlockAnnInterval),
		BroadcastTxTimeout:    time.Duration(d.cfg.RPC.BroadcastTxTimeout),
		GenesisHeight:         d.genesisCfg.InitialHeight,
		Checkpoint:            d.cfg.Checkpoint,
	}

	ce, err := consensus.New(ceCfg)
	if err != nil {
		failBuild(err, "failed to create consensus engine")
	}

	return ce
}

func buildErc20BridgeSignerMgr(d *coreDependencies, db *pg.DB,
	engine *interpreter.ThreadSafeInterpreter, node *node.Node,
	bp *blockprocessor.BlockProcessor) *signersvc.ServiceMgr {
	// create shared state
	stateFile := signersvc.StateFilePath(d.rootDir)

	if !fileExists(stateFile) {
		emptyFile, err := os.Create(stateFile)
		if err != nil {
			failBuild(err, "Failed to create erc20 bridge signer state file")
		}
		_ = emptyFile.Close()
	}

	state, err := signersvc.LoadStateFromFile(stateFile)
	if err != nil {
		failBuild(err, "Failed to load erc20 bridge signer state file")
	}

	return signersvc.NewServiceMgr(d.genesisCfg.ChainID, db, engine, node, bp,
		d.cfg.Erc20Bridge, state, d.logger.New("EVMRW"))
}

func buildNode(d *coreDependencies, mp *mempool.Mempool, bs *store.BlockStore,
	ce *consensus.ConsensusEngine, ss *snapshotter.SnapshotStore, db *pg.DB,
	bp *blockprocessor.BlockProcessor, p2p *node.P2PService) *node.Node {
	logger := d.logger.New("NODE")
	nc := &node.Config{
		ChainID:     d.genesisCfg.ChainID,
		RootDir:     d.rootDir,
		PrivKey:     d.privKey,
		DB:          db,
		P2P:         &d.cfg.P2P,
		Mempool:     mp,
		BlockStore:  bs,
		Consensus:   ce,
		Statesync:   &d.cfg.StateSync,
		Snapshotter: ss,
		BlockProc:   bp,
		Logger:      logger,
		DBConfig:    &d.cfg.DB,
		P2PService:  p2p,
	}

	node, err := node.NewNode(nc)
	if err != nil {
		failBuild(err, "failed to create node")
	}

	logger.Infof("This node is %s @ %s, peerID: %s", node.ID(), node.Addrs(), p2p.Host().ID())
	return node
}

func failBuild(err error, msg string) {
	if err == nil {
		panic(panicErr{
			err: errors.New(msg),
			msg: msg,
		})
	}

	panic(panicErr{
		err: err,
		msg: fmt.Sprintf("%s: %s", msg, err),
	})
}

func buildEngine(d *coreDependencies, ctx context.Context, db *pg.DB, accounts common.Accounts, validators common.Validators, namespaceManager engine.NamespaceRegister) *interpreter.ThreadSafeInterpreter {
	extensions := precompiles.RegisteredPrecompiles()
	for name := range extensions {
		d.logger.Info("registered extension", "name", name)
	}

	tx, err := db.BeginTx(ctx)
	if err != nil {
		failBuild(err, "failed to start transaction")
	}
	defer tx.Rollback(ctx)

	interp, err := interpreter.NewInterpreter(ctx, tx, d.service("engine"), accounts, validators, namespaceManager)
	if err != nil {
		failBuild(err, "failed to initialize engine")
	}

	err = tx.Commit(ctx)
	if err != nil {
		failBuild(err, "failed to commit engine init db txn")
	}

	return interp
}

func buildSnapshotStore(d *coreDependencies, bs *store.BlockStore) *snapshotter.SnapshotStore {
	snapshotDir := config.LocalSnapshotsDir(d.rootDir)
	cfg := &snapshotter.SnapshotConfig{
		SnapshotDir:      snapshotDir,
		MaxSnapshots:     int(d.cfg.Snapshots.MaxSnapshots),
		RecurringHeight:  d.cfg.Snapshots.RecurringHeight,
		Enable:           d.cfg.Snapshots.Enable,
		DBConfig:         &d.cfg.DB,
		ChunkSendTimeout: time.Duration(d.cfg.Snapshots.ChunkSendTimeout),
	}

	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		failBuild(err, "failed to create snapshot directory")
	}

	ss, err := snapshotter.NewSnapshotStore(cfg, bs, d.namespaceManager, d.logger.New("SNAP"))
	if err != nil {
		failBuild(err, "failed to create snapshot store")
	}

	return ss
}

func buildListenerManager(d *coreDependencies, ev *voting.EventStore, bp *blockprocessor.BlockProcessor, node *node.Node) *listeners.ListenerManager {
	return listeners.NewListenerManager(d.service("ListenerManager"), ev, bp, node)
}

func buildJRPCAdminServer(d *coreDependencies) *rpcserver.Server {
	var wantTLS bool
	addr := d.cfg.Admin.ListenAddress
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			host = addr
			port = "8584"
		} else if strings.Contains(err.Error(), "too many colons in address") {
			u, err := url.Parse(addr)
			if err != nil {
				failBuild(err, "unknown admin service address "+addr)
			}
			host, port = u.Hostname(), u.Port()
			wantTLS = u.Scheme == "https"
		} else {
			failBuild(err, "unknown admin service address "+addr)
		}
	}

	opts := []rpcserver.Opt{rpcserver.WithTimeout(10 * time.Minute)} // this is an administrator

	adminPass := d.cfg.Admin.Pass
	if adminPass != "" {
		opts = append(opts, rpcserver.WithPass(adminPass))
	}

	// Require TLS only if not UNIX or not loopback TCP interface.
	if isUNIX := strings.HasPrefix(host, "/"); isUNIX {
		addr = host
		// no port and no TLS
		if wantTLS {
			failBuild(errors.New("unix socket with TLS is not supported"), "")
		}
	} else { // TCP
		addr = net.JoinHostPort(host, port)

		var loopback bool
		if netAddr, err := net.ResolveIPAddr("ip", host); err != nil {
			d.logger.Warn("unresolvable host, assuming not loopback, but will likely fail to listen",
				"host", host, "error", err)
		} else { // e.g. "localhost" usually resolves to a loopback IP address
			loopback = netAddr.IP.IsLoopback()
		}
		if !loopback || wantTLS { // use TLS for encryption, maybe also client auth
			if d.cfg.Admin.NoTLS {
				d.logger.Warn("disabling TLS on non-loopback admin service listen address",
					"addr", addr, "with_password", adminPass != "")
			} else {
				withTransportClientAuth := adminPass == "" // no basic http auth => use transport layer auth
				opts = append(opts, rpcserver.WithTLS(tlsConfig(d, withTransportClientAuth)))
			}
		}
	}

	// Note that rpcserver.WithPass is not mutually exclusive with TLS in
	// general, only mutual TLS. It could be a simpler alternative to mutual
	// TLS, or just coupled with TLS termination on a local reverse proxy.
	opts = append(opts, rpcserver.WithServerInfo(&adminsvc.SpecInfo))
	svcLogger := d.logger.New("ADMINRPC")
	jsonRPCAdminServer, err := rpcserver.NewServer(addr, svcLogger, opts...)
	if err != nil {
		failBuild(err, "unable to create json-rpc server")
	}

	return jsonRPCAdminServer
}

// verifyDependencies checks if the required dependencies are installed on the system, such as:
//   - pg_dump: required for snapshotting during migrations and when snapshots are enabled.
//     All nodes in the network must have 16.x version to produce consistent and deterministic snapshots.
//   - psql: required for state-sync to restore the state from a snapshot. Required version is 16.x.
func verifyDependencies(d *coreDependencies) {
	if d.cfg.SkipDependencyVerification {
		d.logger.Warn("Skipping runtime dependency verification of pg_dump and psql binaries")
		return
	}

	// Check if pg_dump is installed, which is necessary for snapshotting during migrations
	// and when snapshots are enabled. Ensure that the version is 16.x
	if err := checkVersion(d.cfg.PGDumpPath, 16); err != nil {
		failBuild(err, "pg_dump version check failure. Please ensure that 16.x version is installed")
	}

	if d.cfg.StateSync.Enable {
		// Check if psql is installed and is on version 16.x, which is required for state-sync
		if err := checkVersion(d.cfg.StateSync.PsqlPath, 16); err != nil {
			failBuild(err, "psql version check failure. Please ensure that 16.x version is installed")
		}
	}
}

func loadTLSCertificate(keyFile, certFile, hostname string) (*tls.Certificate, error) {
	keyExists, certExists := fileExists(keyFile), fileExists(certFile)
	if certExists != keyExists { // one but not both
		return nil, fmt.Errorf("missing a key/cert pair file")

	}
	if !keyExists {
		// Auto-generate a new key/cert pair using any provided host name in the
		// "Subject Alternate Name" section of the certificate (either IP or a
		// hostname like kwild23.applicationX.org).
		var extraHosts []string
		if hostname != "" {
			extraHosts = []string{hostname}
		}
		if err := genCertPair(certFile, keyFile, extraHosts); err != nil {
			return nil, fmt.Errorf("failed to generate TLS key pair: %v", err)
		}
		// TODO: generate a separate CA certificate. Browsers don't like that
		// the site certificate is also a CA, but Go clients are fine with it.
	}
	keyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %v", err)
	}
	return &keyPair, nil
}

// tlsConfig returns a tls.Config to be used with the admin RPC service. If
// withTransportClientAuth is true, the config will require client
// authentication (mutual TLS), otherwise it is standard TLS for encryption and
// server authentication.
func tlsConfig(d *coreDependencies, withTransportClientAuth bool) *tls.Config {
	if d.adminKey == nil {
		return nil
	}
	if !withTransportClientAuth {
		// TLS only for encryption and authentication of server to client.
		return &tls.Config{
			Certificates: []tls.Certificate{*d.adminKey},
		}
	} // else try to load authorized client certs/pubkeys

	var err error
	// client certs
	caCertPool := x509.NewCertPool()
	var clientsCerts []byte
	if clientsFile := filepath.Join(d.rootDir, defaultAdminClients); fileExists(clientsFile) {
		clientsCerts, err = os.ReadFile(clientsFile)
		if err != nil {
			failBuild(err, "failed to load client CAs file")
		}
		d.logger.Infoln("loaded client CAs from", clientsFile)
	} else if d.autogen {
		clientCredsFileBase := filepath.Join(d.rootDir, "adminclient")
		clientCertFile, clientKeyFile := clientCredsFileBase+".cert", clientCredsFileBase+".key"
		err = transport.GenTLSKeyPair(clientCertFile, clientKeyFile, "local kwild CA", nil)
		if err != nil {
			failBuild(err, "failed to generate admin client credentials")
		}
		d.logger.Info("generated admin service client key pair", "cert", clientCertFile, "key", clientKeyFile)
		if clientsCerts, err = os.ReadFile(clientCertFile); err != nil {
			failBuild(err, "failed to read auto-generate client certificate")
		}
		if err = os.WriteFile(clientsFile, clientsCerts, 0644); err != nil {
			failBuild(err, "failed to write client CAs file")
		}
		d.logger.Info("generated admin service client CAs file", "file", clientsFile)
	} else {
		d.logger.Info("No admin client CAs file. Use 'kwild admin gen-auth-key' to generate")
	}

	if len(clientsCerts) > 0 && !caCertPool.AppendCertsFromPEM(clientsCerts) {
		failBuild(err, "invalid client CAs file")
	}

	// TLS configuration for mTLS (mutual TLS) protocol-level authentication
	return &tls.Config{
		Certificates: []tls.Certificate{*d.adminKey},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}
}

func fileExists(file string) bool {
	fi, err := os.Stat(file)
	if err != nil {
		return false
	}
	return !fi.IsDir()
}
