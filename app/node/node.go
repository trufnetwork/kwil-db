package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/trufnetwork/kwil-db/app/key"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
	"github.com/trufnetwork/kwil-db/node"
	"github.com/trufnetwork/kwil-db/node/consensus"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/signersvc"
	"github.com/trufnetwork/kwil-db/node/listeners"
	rpcserver "github.com/trufnetwork/kwil-db/node/services/jsonrpc"
	"github.com/trufnetwork/kwil-db/version"
)

type server struct {
	cfg *config.Config // KwildConfig
	log log.Logger

	closers *closeFuncs
	dbCtx   interface {
		Done() <-chan struct{}
		Err() error
	}

	// subsystems
	node               *node.Node
	ce                 *consensus.ConsensusEngine
	listeners          *listeners.ListenerManager
	jsonRPCServer      *rpcserver.Server
	jsonRPCAdminServer *rpcserver.Server
	erc20BridgeSigner  *signersvc.ServiceMgr
}

func runNode(ctx context.Context, rootDir string, cfg *config.Config, autogen bool, dbOwner string) (err error) {
	logOutputPaths := slices.Clone(cfg.Log.Output)
	var logWriters []io.Writer
	if idx := slices.Index(cfg.Log.Output, "stdout"); idx != -1 {
		logWriters = append(logWriters, os.Stdout)
		cfg.Log.Output = slices.Delete(cfg.Log.Output, idx, idx+1)
	}
	if idx := slices.Index(cfg.Log.Output, "stderr"); idx != -1 {
		logWriters = append(logWriters, os.Stderr)
		cfg.Log.Output = slices.Delete(cfg.Log.Output, idx, idx+1)
	}

	for _, logFile := range cfg.Log.Output {
		rootedLogFile := rootedPath(logFile, rootDir)
		rot, err := log.NewRotatorWriter(rootedLogFile, cfg.Log.FileRollSize, cfg.Log.RetainMaxRolls)
		if err != nil {
			return fmt.Errorf("failed to create log rotator: %w", err)
		}
		defer func() {
			if err := rot.Close(); err != nil {
				fmt.Printf("failed to close log rotator: %v", err)
			}
		}()
		logWriters = append(logWriters, rot)
	}

	logger := log.DiscardLogger
	if len(logWriters) > 0 {
		logWriter := io.MultiWriter(logWriters...)

		logger = log.New(log.WithLevel(cfg.Log.Level), log.WithFormat(cfg.Log.Format),
			log.WithName("KWILD"), log.WithWriter(logWriter))
		// NOTE: level and name can be set independently for different systems
	}

	logger.Infof("Starting kwild version %v", version.KwilVersion)

	// sanity checks on config
	if cfg.Consensus.ProposeTimeout < config.MinProposeTimeout {
		return fmt.Errorf("propose timeout should be at least %s", config.MinProposeTimeout.String())
	}

	genFile := config.GenesisFilePath(rootDir)

	logger.Infof("Loading the genesis configuration from %s", genFile)

	privKey, genConfig, err := loadGenesisAndPrivateKey(rootDir, autogen, dbOwner)
	if err != nil {
		return fmt.Errorf("failed to load genesis and private key: %w", err)
	}

	logger.Infof("Node public key: %x (%s)", privKey.Public().Bytes(), privKey.Public().Type())

	logger.Info("loading TLS key pair for the admin server if TLS enabled",
		"key_file", config.AdminServerKeyName, "cert_file", config.AdminServerCertName)
	customHostname := "" // cfg TODO
	keyFile := rootedPath(config.AdminServerKeyName, rootDir)
	certFile := rootedPath(config.AdminServerCertName, rootDir)
	var tlsKeyPair *tls.Certificate
	tlsKeyPair, err = loadTLSCertificate(keyFile, certFile, customHostname)
	if err != nil {
		return err
	}

	host, port, user, pass := cfg.DB.Host, cfg.DB.Port, cfg.DB.User, cfg.DB.Pass

	// Prepare for migration if node is setup to use zero-downtime migrations
	// This includes fetching the genesis state from the nodes in the old chain
	if cfg.Migrations.Enable {
		cfg, genConfig, err = prepareForMigration(ctx, cfg, genConfig, rootDir, logger)
		if err != nil {
			return fmt.Errorf("failed to prepare for migration: %w", err)
		}
	}

	// migration status defaults
	if genConfig.Migration.IsMigration() {
		genConfig.MigrationStatus = types.GenesisMigration
	} else {
		genConfig.MigrationStatus = types.NoActiveMigration
	}

	if err := genConfig.SanityChecks(); err != nil {
		return fmt.Errorf("genesis configuration failed sanity checks: %w", err)
	}

	if cfg.GenesisState != "" {
		cfg.GenesisState = rootedPath(cfg.GenesisState, rootDir)
	}

	// if running in autogen mode, and config.toml does not exist, write it
	tomlFile := config.ConfigFilePath(rootDir)
	if autogen {
		// In autogen mode where there is one node (self) be quiet in the peer
		// manager when we cannot get peers.
		cfg.P2P.TargetConnections = 0

		if !fileExists(tomlFile) {
			logger.Infof("Writing config file to %s", tomlFile)
			cfg.Log.Output = logOutputPaths // restore log output paths before writing toml file
			if err := cfg.SaveAs(tomlFile); err != nil {
				return fmt.Errorf("failed to write config file: %w", err)
			}
		}
	}

	nsmgr := newNamespaceManager()

	d := &coreDependencies{
		rootDir:          rootDir,
		adminKey:         tlsKeyPair,
		cfg:              cfg,
		genesisCfg:       genConfig,
		privKey:          privKey,
		logger:           logger,
		autogen:          autogen,
		dbOpener:         newDBOpener(host, port, user, pass, nsmgr.Filter),
		namespaceManager: nsmgr,
		poolOpener:       newPoolBOpener(host, port, user, pass),
	}

	// Catch any panic from buildServer. We use a panic based build failure
	// system, which is detectable with panicErr. Spewing out a stack is sloppy
	// and a bad look; just return a meaningful error message. If the message is
	// ambiguous regarding its source, the errors needs more context.
	defer func() {
		if r := recover(); r != nil {
			if pe, ok := r.(panicErr); ok { // error on bringup, not a bug
				if errors.Is(pe.err, context.Canceled) {
					logger.Warnf("Shutdown signaled: %v", pe.msg)
					err = context.Canceled
				} else {
					err = pe
				}
			} else { // actual panic (bug)
				stack := make([]byte, 8192)
				length := runtime.Stack(stack, false)
				err = fmt.Errorf("panic while building kwild: %v\n\nstack:\n\n%v", r, string(stack[:length]))
			}
			d.closers.closeAll()
		}
	}()

	server := buildServer(ctx, d)

	return server.Start(ctx)
}

func (s *server) Start(ctx context.Context) error {
	defer func() {
		if err := recover(); err != nil {
			s.log.Error("Panic in server", "error", err)
		}

		s.log.Info("Closing server resources...")
		err := s.closers.closeAll()
		if err != nil {
			s.log.Error("failed to close resource:", "error", err)
		}
		s.log.Info("Server is now shut down.")
	}()

	s.log.Info("Starting the server")

	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		// If the DB dies unexpectedly, stop the entire error group.
		select {
		case <-s.dbCtx.Done(): // DB died
			s.log.Error("DB died unexpectedly, shutting down server.")
			return s.dbCtx.Err() // shutdown the server (this return cancels groupCtx)
		case <-groupCtx.Done(): // something else died or was shut down
			return nil
		}
	})

	// start rpc services
	group.Go(func() error {
		s.log.Info("starting user json-rpc server", "listen", s.cfg.RPC.ListenAddress)
		return s.jsonRPCServer.Serve(groupCtx)
	})

	if s.cfg.Admin.Enable {
		group.Go(func() error {
			s.log.Info("starting admin json-rpc server", "listen", s.cfg.Admin.ListenAddress)
			return s.jsonRPCAdminServer.Serve(groupCtx)
		})
	}

	// start node (p2p)
	group.Go(func() error {
		if err := s.node.Start(groupCtx); err != nil {
			if errors.Is(err, context.Canceled) {
				s.log.Infof("Shutdown signaled. Cancellation details: [%v]", err)
			} else {
				s.log.Error("Abnormal node termination", "error", err)
			}
			return err
		}
		return nil
	})

	// Start listener manager
	group.Go(func() error {
		go func() {
			<-groupCtx.Done()
			s.log.Info("stop listeners")
			s.listeners.Stop()
		}()
		return s.listeners.Start()
	})
	s.log.Info("listener manager started")

	// Start erc20 bridge signer svc
	if s.erc20BridgeSigner != nil {
		group.Go(func() error {
			return s.erc20BridgeSigner.Start(groupCtx)
		})
	}

	// TODO: node is starting the consensus engine for ease of testing
	// Start the consensus engine

	err := group.Wait()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			s.log.Info("server context is canceled")
			return nil
		}
		return err
	}

	return nil
}

// rootedPath returns an absolute path for the given path, relative to the root
// directory if it was a relative path.
func rootedPath(path, rootDir string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(rootDir, path)
}

// ReadOrCreatePrivateKeyFile will read the node key pair from the given file,
// or generate it if it does not exist and requested.
func readOrCreatePrivateKeyFile(rootDir string, autogen bool) (privKey crypto.PrivateKey, err error) {
	keyFile := config.NodeKeyFilePath(rootDir)
	privKey, err = key.LoadNodeKey(keyFile)
	if err == nil {
		return privKey, nil
	}

	if !autogen {
		return nil, fmt.Errorf("failed to load node key: %w", err)
	}

	privKey, err = crypto.GeneratePrivateKey(crypto.KeyTypeSecp256k1)
	if err != nil {
		return nil, fmt.Errorf("failed to generate node key: %w", err)
	}

	if err := key.SaveNodeKey(keyFile, privKey); err != nil {
		return nil, fmt.Errorf("failed to save node key: %w", err)
	}

	return privKey, nil
}

func loadGenesisAndPrivateKey(rootDir string, autogen bool, dbOwner string) (privKey crypto.PrivateKey, genCfg *config.GenesisConfig, err error) {
	privKey, err = readOrCreatePrivateKeyFile(rootDir, autogen)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read or create private key: %w", err)
	}

	genFile := config.GenesisFilePath(rootDir)
	if fileExists(genFile) {
		genCfg, err = config.LoadGenesisConfig(genFile)
		if err != nil {
			return nil, nil, fmt.Errorf("error loading genesis file %s: %w", genFile, err)
		}
		// If the genesis file exists and --autogen was used, disallow a genesis
		// file with either multiple validators or a different leader the self.
		if autogen && (len(genCfg.Validators) > 1 || !genCfg.Leader.PublicKey.Equals(privKey.Public())) {
			return nil, nil, errors.New("cannot use --autogen with genesis config for a multi-node network")
		}
		return privKey, genCfg, nil
	} else if !autogen {
		// If not using --autogen, the genesis file must exist!
		return nil, nil, fmt.Errorf("genesis file %s does not exist (did you mean to use --autogen for a test node?)", genFile)
	}

	genCfg = config.DefaultGenesisConfig()
	genCfg.Leader = types.PublicKey{PublicKey: privKey.Public()}
	genCfg.Validators = append(genCfg.Validators, &types.Validator{
		AccountID: types.AccountID{
			Identifier: privKey.Public().Bytes(),
			KeyType:    privKey.Type(),
		},
		Power: 1,
	})

	if dbOwner != "" {
		genCfg.DBOwner = dbOwner
	} else {
		signer := auth.GetUserSigner(privKey)
		ident, err := authExt.GetIdentifierFromSigner(signer)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get identifier from user signer: %w", err)
		}
		genCfg.DBOwner = ident
	}

	if err := genCfg.SaveAs(genFile); err != nil {
		return nil, nil, fmt.Errorf("failed to write genesis file in autogen mode %s: %w", genFile, err)
	}

	return privKey, genCfg, nil
}
