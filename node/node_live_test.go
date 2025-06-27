//go:build pglive

package node

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/accounts"
	blockprocessor "github.com/trufnetwork/kwil-db/node/block_processor"
	"github.com/trufnetwork/kwil-db/node/consensus"
	"github.com/trufnetwork/kwil-db/node/mempool"
	"github.com/trufnetwork/kwil-db/node/meta"
	"github.com/trufnetwork/kwil-db/node/migrations"
	"github.com/trufnetwork/kwil-db/node/pg"
	pgtest "github.com/trufnetwork/kwil-db/node/pg/test"
	"github.com/trufnetwork/kwil-db/node/store/memstore"
	"github.com/trufnetwork/kwil-db/node/txapp"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"
)

func TestMain(m *testing.M) {
	pg.UseLogger(log.New(log.WithName("DBS"), log.WithFormat(log.FormatUnstructured)))
	m.Run()
}

func TestSingleNodeMocknet(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	mn := mock.New()

	pk1, h1 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	bs1 := memstore.NewMemBS()
	mp1 := mempool.New(mempoolSz, maxTxSz)

	db1 := initDB(t, "5432", "kwil_test_db")

	root1 := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	privKeys, _ := newGenesis(t, []p2pcrypto.PrivKey{pk1})

	valSet := make(map[string]ktypes.Validator)
	for _, priv := range privKeys {
		valSet[hex.EncodeToString(priv.Public().Bytes())] = ktypes.Validator{
			AccountID: types.AccountID{
				Identifier: priv.Public().Bytes(),
				KeyType:    priv.Type(),
			},
			Power: 1,
		}
	}
	valSetList := make([]*ktypes.Validator, 0, len(valSet))
	for _, v := range valSet {
		valSetList = append(valSetList, &v)
	}

	ss := newSnapshotStore(bs1)

	_, vsReal, err := voting.NewResolutionStore(ctx, db1)
	require.NoError(t, err)

	genCfg := config.DefaultGenesisConfig()
	genCfg.Leader = ktypes.PublicKey{PublicKey: privKeys[0].Public()}
	genCfg.Validators = valSetList

	signer1 := auth.GetNodeSigner(privKeys[0])

	es := &mockEventStore{}
	// accounts := &mockAccounts{}
	mparams := config.MigrationParams{
		StartHeight: 0, EndHeight: 0,
	}

	accounts, err := accounts.InitializeAccountStore(ctx, db1, log.DiscardLogger)
	require.NoError(t, err)

	migrator, err := migrations.SetupMigrator(ctx, db1, newSnapshotStore(bs1), accounts, filepath.Join(root1, "migrations"), mparams, vsReal, log.New(log.WithName("MIGRATOR")))
	require.NoError(t, err)

	signer := auth.GetNodeSigner(privKeys[0])
	txapp, err := txapp.NewTxApp(ctx, db1, &mockEngine{}, signer, nil, &common.Service{
		Logger:        log.New(log.WithName("TXAPP"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured)),
		GenesisConfig: genCfg,
		LocalConfig:   config.DefaultConfig(),
		Identity:      signer.CompactID(),
	}, accounts, vsReal)
	require.NoError(t, err)

	bpl := log.New(log.WithName("BP1"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured))
	bp, err := blockprocessor.NewBlockProcessor(ctx, db1, txapp, accounts, vsReal, ss, es, migrator, bs1, mp1, genCfg, signer1, bpl)
	require.NoError(t, err)

	ceCfg1 := &consensus.Config{
		PrivateKey: privKeys[0],
		// ValidatorSet:          valSet,
		Leader:                privKeys[0].Public(),
		Mempool:               mp1,
		BlockStore:            bs1,
		BlockProcessor:        bp,
		Logger:                log.New(log.WithName("CE1"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured)),
		ProposeTimeout:        1 * time.Second,
		EmptyBlockTimeout:     1 * time.Second,
		BlockProposalInterval: 1 * time.Second,
		BlockAnnInterval:      3 * time.Second,
		BroadcastTxTimeout:    15 * time.Second,
		DB:                    db1,
	}
	ce1, err := consensus.New(ceCfg1)
	require.NoError(t, err)
	defaultConfigSet := config.DefaultConfig()

	psCfg := &P2PServiceConfig{
		PrivKey: privKeys[0],
		RootDir: root1,
		ChainID: genCfg.ChainID,
		KwilCfg: defaultConfigSet,
		Logger:  log.New(log.WithName("P2P"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured)),
	}
	ps, err := NewP2PService(ctx, psCfg, h1)
	require.NoError(t, err)

	log1 := log.New(log.WithName("NODE1"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured))
	cfg1 := &Config{
		ChainID:     genCfg.ChainID,
		RootDir:     root1,
		PrivKey:     privKeys[0],
		Logger:      log1,
		P2P:         &defaultConfigSet.P2P,
		Mempool:     mp1,
		BlockStore:  bs1,
		Consensus:   ce1,
		Snapshotter: ss,
		DBConfig:    &defaultConfigSet.DB,
		Statesync:   &defaultConfigSet.StateSync,
		BlockProc:   &dummyBP{vals: valSetList},
		P2PService:  ps,
	}
	node1, err := NewNode(cfg1)
	if err != nil {
		t.Fatalf("Failed to create Node 1: %v", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer os.RemoveAll(node1.Dir())
		node1.Start(ctx)
	}()

	time.Sleep(20 * time.Millisecond)

	reachHeight := int64(2)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		stat, err := node1.Status(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(c, stat.Sync.BestBlockHeight, reachHeight)
	}, 10*time.Second, 250*time.Millisecond)

	cancel()
	wg.Wait()
}

func TestDualNodeMocknet(t *testing.T) {
	keyTypes := []crypto.KeyType{crypto.KeyTypeEd25519, crypto.KeyTypeSecp256k1}

	for _, keyType := range keyTypes {
		t.Run(fmt.Sprintf("KeyType=%s", keyType), func(t *testing.T) {
			runDualNodeMocknetTest(t, keyType)
		})
	}
}
func runDualNodeMocknetTest(t *testing.T, keyType crypto.KeyType) {
	if testing.Short() {
		t.Skip()
	}
	mn := mock.New()

	pk1, h1 := newTestHost(t, mn, keyType)
	bs1 := memstore.NewMemBS()
	mp1 := mempool.New(mempoolSz, maxTxSz)

	db1 := initDB(t, "5432", "kwil_test_db")
	func() {
		ctx := context.Background()
		_, err := db1.Pool().Execute(ctx, `DROP DATABASE IF EXISTS kwil_test_db2;`)
		require.NoError(t, err)
		_, err = db1.Pool().Execute(ctx, `CREATE DATABASE kwil_test_db2 OWNER kwild;`)
		require.NoError(t, err)
	}()

	// priv1, _ := pk1.Raw()
	pub1, _ := pk1.GetPublic().Raw()
	host1, port1, _ := maHostPort(h1.Addrs()[0])
	var peerStr1 string
	if keyType == crypto.KeyTypeEd25519 {
		peerStr1 = hex.EncodeToString(pub1) + "#ed25519@" + net.JoinHostPort(host1, port1)
	} else {
		peerStr1 = hex.EncodeToString(pub1) + "#secp256k1@" + net.JoinHostPort(host1, port1)
	}

	pk2, h2 := newTestHost(t, mn, keyType)
	bs2 := memstore.NewMemBS()
	mp2 := mempool.New(mempoolSz, maxTxSz)
	db2 := initDB(t, "5432", "kwil_test_db2") // NOTE: using the same postgres host is a little wild

	// priv2, _ := pk2.Raw()
	// pub2, _ := pk2.GetPublic().Raw()

	root1 := t.TempDir()
	root2 := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	privKeys, _ := newGenesis(t, []p2pcrypto.PrivKey{pk1, pk2})

	valSet := make(map[string]ktypes.Validator)
	for _, priv := range privKeys {
		valSet[hex.EncodeToString(priv.Public().Bytes())] = ktypes.Validator{
			AccountID: types.AccountID{
				Identifier: priv.Public().Bytes(),
				KeyType:    priv.Type(),
			},
			Power: 1,
		}
	}
	valSetList := make([]*ktypes.Validator, 0, len(valSet))
	for _, v := range valSet {
		valSetList = append(valSetList, &v)
	}
	ss := newSnapshotStore(bs1)

	genCfg := config.DefaultGenesisConfig()
	genCfg.Leader = ktypes.PublicKey{PublicKey: privKeys[0].Public()}
	genCfg.Validators = valSetList

	es1 := &mockEventStore{}
	mparams := config.MigrationParams{
		StartHeight: 0, EndHeight: 0,
	}

	accounts1, err := accounts.InitializeAccountStore(ctx, db1, log.DiscardLogger)
	require.NoError(t, err)

	_, vstore1, err := voting.NewResolutionStore(ctx, db1)
	require.NoError(t, err)

	signer1 := auth.GetNodeSigner(privKeys[0])
	txapp1, err := txapp.NewTxApp(ctx, db1, &mockEngine{}, signer1, nil, &common.Service{
		Logger:        log.New(log.WithName("TXAPP"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured)),
		GenesisConfig: genCfg,
		LocalConfig:   config.DefaultConfig(),
		Identity:      signer1.CompactID(),
	}, accounts1, vstore1)
	require.NoError(t, err)

	migrator, err := migrations.SetupMigrator(ctx, db1, newSnapshotStore(bs1), accounts1, filepath.Join(root1, "migrations"), mparams, vstore1, log.New(log.WithName("MIGRATOR")))
	require.NoError(t, err)

	bpl1 := log.New(log.WithName("BP1"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured))
	bp1, err := blockprocessor.NewBlockProcessor(ctx, db1, txapp1, accounts1, vstore1, ss, es1, migrator, bs1, mp1, genCfg, signer1, bpl1)
	require.NoError(t, err)

	ceCfg1 := &consensus.Config{
		PrivateKey: privKeys[0],
		// ValidatorSet:          valSet,
		Leader:                privKeys[0].Public(),
		Mempool:               mp1,
		BlockStore:            bs1,
		Logger:                log.New(log.WithName("CE1"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured)),
		ProposeTimeout:        1 * time.Second,
		EmptyBlockTimeout:     1 * time.Second,
		BlockProposalInterval: 1 * time.Second,
		BlockAnnInterval:      3 * time.Second,
		DB:                    db1,
		BlockProcessor:        bp1,
	}
	ce1, err := consensus.New(ceCfg1)
	require.NoError(t, err)
	defaultConfigSet := config.DefaultConfig()
	log1 := log.New(log.WithName("NODE1"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured))

	psCfg1 := &P2PServiceConfig{
		PrivKey: privKeys[0],
		RootDir: root1,
		ChainID: genCfg.ChainID,
		KwilCfg: defaultConfigSet,
		Logger:  log.New(log.WithName("P2P1"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured)),
	}
	ps1, err := NewP2PService(ctx, psCfg1, h1)
	require.NoError(t, err)
	err = ps1.Start(ctx)
	defer ps1.Close()
	require.NoError(t, err, "failed to start p2p service")

	cfg1 := &Config{
		ChainID:     genCfg.ChainID,
		RootDir:     root1,
		PrivKey:     privKeys[0],
		Logger:      log1,
		P2P:         &defaultConfigSet.P2P,
		Mempool:     mp1,
		BlockStore:  bs1,
		Consensus:   ce1,
		Snapshotter: ss,
		DBConfig:    &defaultConfigSet.DB,
		Statesync:   &defaultConfigSet.StateSync,
		BlockProc:   &dummyBP{vals: valSetList},
		P2PService:  ps1,
	}

	// Node 2
	es2 := &mockEventStore{}

	accounts2, err := accounts.InitializeAccountStore(ctx, db2, log.DiscardLogger)
	require.NoError(t, err)

	_, vstore2, err := voting.NewResolutionStore(ctx, db2)
	require.NoError(t, err)

	migrator2, err := migrations.SetupMigrator(ctx, db2, newSnapshotStore(bs2), accounts2, filepath.Join(root2, "migrations"), mparams, vstore2, log.New(log.WithName("MIGRATOR")))
	require.NoError(t, err)

	signer2 := auth.GetNodeSigner(privKeys[1])
	txapp2, err := txapp.NewTxApp(ctx, db2, &mockEngine{}, signer2, nil, &common.Service{
		Logger:        log.New(log.WithName("TXAPP"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured)),
		GenesisConfig: genCfg,
		LocalConfig:   config.DefaultConfig(),
		Identity:      signer2.CompactID(),
	}, accounts2, vstore2)
	require.NoError(t, err)

	bpl2 := log.New(log.WithName("BP2"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured))
	bp2, err := blockprocessor.NewBlockProcessor(ctx, db2, txapp2, accounts2, vstore2, ss, es2, migrator2, bs2, mp2, genCfg, signer2, bpl2)
	require.NoError(t, err)

	ceCfg2 := &consensus.Config{
		PrivateKey: privKeys[1],
		// ValidatorSet:          valSet,
		Leader:                privKeys[0].Public(),
		Mempool:               mp2,
		BlockStore:            bs2,
		BlockProcessor:        bp2,
		Logger:                log.New(log.WithName("CE2"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured)),
		ProposeTimeout:        1 * time.Second,
		EmptyBlockTimeout:     1 * time.Second,
		BlockProposalInterval: 1 * time.Second,
		BlockAnnInterval:      3 * time.Second,
		DB:                    db2,
	}
	ce2, err := consensus.New(ceCfg2)
	require.NoError(t, err)

	log2 := log.New(log.WithName("NODE2"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured))

	// Link the hosts (allows them to actually connect)
	if err := mn.LinkAll(); err != nil {
		t.Fatalf("Failed to link hosts: %v", err)
	}

	psCfg2 := &P2PServiceConfig{
		PrivKey: privKeys[1],
		RootDir: root2,
		ChainID: genCfg.ChainID,
		KwilCfg: defaultConfigSet,
		Logger:  log.New(log.WithName("P2P2"), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured)),
	}
	ps2, err := NewP2PService(ctx, psCfg2, h2)
	require.NoError(t, err)
	err = ps2.Start(ctx, peerStr1)
	defer ps2.Close()
	require.NoError(t, err, "failed to start p2p service")

	cfg2 := &Config{
		ChainID:     cfg1.ChainID,
		RootDir:     root2,
		PrivKey:     privKeys[1],
		Logger:      log2,
		P2P:         &defaultConfigSet.P2P,
		Mempool:     mp2,
		BlockStore:  bs2,
		Consensus:   ce2,
		Snapshotter: ss,
		DBConfig:    &defaultConfigSet.DB,
		Statesync:   &defaultConfigSet.StateSync,
		BlockProc:   &dummyBP{vals: valSetList},
		P2PService:  ps2,
	}

	node1, err := NewNode(cfg1)
	if err != nil {
		t.Fatalf("Failed to create Node 1: %v", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer os.RemoveAll(node1.Dir())
		node1.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	node2, err := NewNode(cfg2)
	if err != nil {
		t.Fatalf("Failed to create Node 2: %v", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer os.RemoveAll(node2.Dir())
		node2.Start(ctx)
	}()

	reachHeight := int64(2)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		stat, err := node1.Status(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(c, stat.Sync.BestBlockHeight, reachHeight)
	}, 30*time.Second, 250*time.Millisecond)

	// Now disconnect and reconnect them to test the reconnect logic

	mn.DisconnectPeers(ps1.Host().ID(), ps2.Host().ID())
	time.Sleep(time.Second)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		connectedPeers, err := node1.Peers(ctx)
		require.NoError(c, err)
		assert.Equal(c, len(connectedPeers), 1)
	}, 30*time.Second, 250*time.Millisecond)

	cancel()
	wg.Wait()
}

func initDB(t *testing.T, port, dbName string) *pg.DB {
	cfg := &pg.DBConfig{
		PoolConfig: pg.PoolConfig{
			ConnConfig: pg.ConnConfig{
				Host:   "127.0.0.1",
				Port:   port,
				User:   "kwild",
				Pass:   "kwild", // would be ignored if pg_hba.conf set with trust
				DBName: dbName,
			},
			MaxConns: 11,
		},
		SchemaFilter: func(s string) bool {
			return strings.Contains(s, pg.DefaultSchemaFilterPrefix)
		},
	}
	db := pgtest.NewTestDBWithCfg(t, cfg, cleanupDB)

	ctx := context.Background()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = meta.InitializeMetaStore(ctx, tx)
	assert.NoError(t, err)

	assert.NoError(t, tx.Commit(ctx))
	return db
}

func cleanupDB(db *pg.DB) {
	defer db.Close()
	db.AutoCommit(true)
	ctx := context.Background()
	db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_chain CASCADE;`)
	db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_voting CASCADE;`)
	db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_events CASCADE;`)
	db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_migrations CASCADE;`)
	db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_internal CASCADE;`)
	db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_accounts CASCADE;`)
	db.AutoCommit(false)
}

// type dummyTxApp struct {
// 	vals []*ktypes.Validator
// }

// func newDummyTxApp(valset []*ktypes.Validator) *dummyTxApp {
// 	return &dummyTxApp{
// 		vals: valset,
// 	}
// }
// func (d *dummyTxApp) Begin(ctx context.Context, height int64) error {
// 	return nil
// }

// func (d *dummyTxApp) Execute(ctx *common.TxContext, db sql.DB, tx *ktypes.Transaction) *txapp.TxResponse {
// 	return &txapp.TxResponse{}
// }

// func (d *dummyTxApp) Finalize(ctx context.Context, db sql.DB, block *common.BlockContext) ([]*ktypes.Validator, error) {
// 	return d.vals, nil
// }

// func (d *dummyTxApp) Price(ctx context.Context, dbTx sql.DB, tx *ktypes.Transaction, chainContext *common.ChainContext) (*big.Int, error) {
// 	return big.NewInt(0), nil
// }

// func (d *dummyTxApp) Commit() error {
// 	return nil
// }

// func (d *dummyTxApp) Rollback() {}

// func (d *dummyTxApp) GenesisInit(ctx context.Context, db sql.DB, validators []*ktypes.Validator, genesisAccounts []*ktypes.Account, initialHeight int64, dbOwner string, chain *common.ChainContext) error {
// 	return nil
// }

// func (d *dummyTxApp) AccountInfo(ctx context.Context, dbTx sql.DB, identifier string, pending bool) (*big.Int, int64, error) {
// 	return big.NewInt(0), 0, nil
// }

// func (d *dummyTxApp) ApplyMempool(ctx *common.TxContext, db sql.DB, tx *ktypes.Transaction) error {
// 	return nil
// }

// type mockAccounts struct{}

// func (m *mockAccounts) Updates() []*ktypes.Account {
// 	return nil
// }

// func (m *mockAccounts) GetBlockSpends() []*accounts.Spend {
// 	return nil
// }

// func (m *mockAccounts) ApplySpend(ctx context.Context, tx sql.Executor, id string, bal *big.Int, nonce int64) error {
// 	return nil
// }

type mockEngine struct{}

func (me *mockEngine) Call(ctx *common.EngineContext, db sql.DB, namespace, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error) {
	return nil, nil
}

func (me *mockEngine) CallWithoutEngineCtx(ctx context.Context, db sql.DB, namespace, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error) {
	return nil, nil
}

func (me *mockEngine) Execute(ctx *common.EngineContext, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error) error {
	return nil
}

func (me *mockEngine) ExecuteWithoutEngineCtx(ctx context.Context, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error) error {
	return nil
}

type mockEventStore struct {
	events []*ktypes.VotableEvent
}

func (m *mockEventStore) MarkBroadcasted(ctx context.Context, ids []*ktypes.UUID) error {
	return nil
}

func (m *mockEventStore) GetUnbroadcastedEvents(ctx context.Context) ([]*ktypes.UUID, error) {
	var ids []*ktypes.UUID
	for _, event := range m.events {
		ids = append(ids, event.ID())
	}
	return ids, nil
}

func (m *mockEventStore) HasEvents() bool {
	return true
}

func (m *mockEventStore) UpdateStats(cnt int64) {}
