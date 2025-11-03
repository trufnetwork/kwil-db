//go:build testhooks && pglive

package consensus

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	auth "github.com/trufnetwork/kwil-db/core/crypto/auth"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	blockprocessor "github.com/trufnetwork/kwil-db/node/block_processor"
	"github.com/trufnetwork/kwil-db/node/mempool"
	"github.com/trufnetwork/kwil-db/node/meta"
	"github.com/trufnetwork/kwil-db/node/pg"
	dbtest "github.com/trufnetwork/kwil-db/node/pg/test"
	"github.com/trufnetwork/kwil-db/node/store"
	"github.com/trufnetwork/kwil-db/node/types"

	"github.com/trufnetwork/kwil-db/core/log"

	"github.com/stretchr/testify/require"
)

func TestCommitInvokesHookBeforeDBCommit(t *testing.T) {
	ceConfigs, _ := generateTestCEConfig(t, 1, true)
	cfg := ceConfigs[0]

	ce, err := New(cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		commitTestHook = nil
		closeBlockStore(t, ce.blockStore)
	})

	commitTestHook = func(stage string) {
		if stage == "after-blockstore" {
			panic("hook-fired")
		}
	}

	blk := ktypes.NewBlock(1, zeroHash, zeroHash, zeroHash, zeroHash, time.Now(), nil)
	blkHash := blk.Hash()

	ce.state.blockRes = &blockResult{
		ack:       true,
		appHash:   ktypes.Hash{},
		txResults: nil,
	}

	ce.state.commitInfo = &ktypes.CommitInfo{
		AppHash: ce.state.blockRes.appHash,
	}

	ce.state.blkProp = &blockProposal{
		height:  1,
		blkHash: blkHash,
		blk:     blk,
	}

	ctx := context.Background()
	require.PanicsWithValue(t, "hook-fired", func() {
		ce.commit(ctx, false)
	})

	height, _, _, _ := ce.blockStore.Best()
	require.Equal(t, int64(1), height)

	_, err = os.Stat(config.CommitIntentFilePath(cfg.RootDir))
	require.NoError(t, err)
}

func TestCrashRecoveryRepairsMissingBlock(t *testing.T) {
	root := t.TempDir()
	blockBytes, commitBytes := commitBlockAndReset(t, root)
	decodedBlock, err := ktypes.DecodeBlock(blockBytes)
	require.NoError(t, err)
	var decodedCommitInfo ktypes.CommitInfo
	require.NoError(t, decodedCommitInfo.UnmarshalBinary(commitBytes))

	restartCfg, _ := buildCrashConsensusConfig(t, root, false)
	restartCE, err := New(restartCfg)
	require.NoError(t, err)
	restartCE.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
		return decodedBlock.Hash(), blockBytes, &decodedCommitInfo, 1, nil
	}

	ctx := context.Background()
	appHeight, storeHeight, err := restartCE.initializeState(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), appHeight)
	require.Equal(t, int64(1), storeHeight)

	_, err = os.Stat(config.CommitIntentFilePath(root))
	require.Error(t, err)
	require.True(t, errors.Is(err, fs.ErrNotExist))

	bestHeight, _, _, _ := restartCE.blockStore.Best()
	require.Equal(t, int64(1), bestHeight)

	tx, err := restartCfg.DB.BeginReadTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	height, _, dirty, err := meta.GetChainState(ctx, tx)
	require.NoError(t, err)
	require.False(t, dirty)
	require.Equal(t, int64(1), height)
}

func TestCrashRecoveryHelper(t *testing.T) {
	if os.Getenv("KWIL_CRASH_MODE") != "helper" {
		return
	}

	root := os.Getenv("KWIL_CRASH_ROOT")
	blockPath := os.Getenv("KWIL_CRASH_BLOCK")
	commitPath := os.Getenv("KWIL_CRASH_COMMIT")
	require.NotEmpty(t, root)
	require.NotEmpty(t, blockPath)
	require.NotEmpty(t, commitPath)

	cfg, db := buildCrashConsensusConfig(t, root, true)
	defer db.Close()

	ce, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	block := ktypes.NewBlock(1, zeroHash, zeroHash, zeroHash, zeroHash, time.Now(), nil)
	blockHash := block.Hash()

	req := &ktypes.BlockExecRequest{
		Height:   1,
		Block:    block,
		BlockID:  blockHash,
		Proposer: cfg.PrivateKey.Public(),
	}

	res, err := ce.blockProcessor.ExecuteBlock(ctx, req, false)
	require.NoError(t, err)

	ce.state.blkProp = &blockProposal{
		height:  1,
		blkHash: blockHash,
		blk:     block,
	}
	ce.state.blockRes = &blockResult{
		ack:          true,
		appHash:      res.AppHash,
		txResults:    res.TxResults,
		paramUpdates: res.ParamUpdates,
		valUpdates:   res.ValidatorUpdates,
	}
	commitInfo := &ktypes.CommitInfo{
		AppHash: res.AppHash,
	}
	ce.state.commitInfo = commitInfo

	require.NoError(t, os.WriteFile(blockPath, ktypes.EncodeBlock(block), 0o644))
	commitBytes, err := commitInfo.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(commitPath, commitBytes, 0o644))

	require.NoError(t, ce.commit(ctx, false))

	require.NotNil(t, ce.commitLog)
	require.NoError(t, ce.commitLog.Record(1, blockHash))

	intentPath := config.CommitIntentFilePath(root)
	_, err = os.Stat(intentPath)
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(config.BlockstoreDir(root)))
}

func resetConsensusSchemas(t *testing.T) {
	db := dbtest.NewTestDB(t, nil)
	defer db.Close()

	ctx := context.Background()
	db.AutoCommit(true)
	db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_chain CASCADE;`)
	db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_voting CASCADE;`)
	db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_events CASCADE;`)
	db.AutoCommit(false)
}

func commitBlockAndReset(t *testing.T, root string) ([]byte, []byte) {
	require.NoError(t, os.MkdirAll(config.BlockstoreDir(root), 0o755))

	resetConsensusSchemas(t)

	cfg, db := buildCrashConsensusConfig(t, root, true)
	ce, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	block := ktypes.NewBlock(1, zeroHash, zeroHash, zeroHash, zeroHash, time.Now(), nil)
	blockHash := block.Hash()

	req := &ktypes.BlockExecRequest{
		Height:   1,
		Block:    block,
		BlockID:  blockHash,
		Proposer: cfg.PrivateKey.Public(),
	}
	res, err := ce.blockProcessor.ExecuteBlock(ctx, req, false)
	require.NoError(t, err)

	commitInfo := &ktypes.CommitInfo{AppHash: res.AppHash}
	require.NoError(t, ce.blockStore.Store(block, commitInfo))
	require.NoError(t, ce.blockStore.StoreResults(blockHash, res.TxResults))
	commitReq := &ktypes.CommitRequest{Height: 1, AppHash: res.AppHash, Syncing: false}
	require.NoError(t, ce.blockProcessor.Commit(ctx, commitReq))

	blockBytes := ktypes.EncodeBlock(block)
	commitBytes, err := commitInfo.MarshalBinary()
	require.NoError(t, err)

	require.NotNil(t, ce.commitLog)
	require.NoError(t, ce.commitLog.Record(1, blockHash))

	closeBlockStore(t, ce.blockStore)
	db.Close()

	require.NoError(t, os.RemoveAll(config.BlockstoreDir(root)))
	require.NoError(t, os.MkdirAll(config.BlockstoreDir(root), 0o755))

	return blockBytes, commitBytes
}

func buildCrashConsensusConfig(t *testing.T, root string, reset bool) (*Config, *pg.DB) {
	ctx := context.Background()
	privKey, pubKey, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)

	db := dbtest.NewTestDB(t, nil)
	if reset {
		db.AutoCommit(true)
		db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_chain CASCADE;`)
		db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_voting CASCADE;`)
		db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_events CASCADE;`)
		db.AutoCommit(false)

		tx, err := db.BeginTx(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		require.NoError(t, meta.InitializeMetaStore(ctx, tx))
		require.NoError(t, tx.Commit(ctx))
	}

	require.NoError(t, os.MkdirAll(root, 0o755))

	bs, err := store.NewBlockStore(root)
	require.NoError(t, err)

	logger := log.DiscardLogger
	mp := mempool.New(mempoolSz, maxTxSz)
	accounts := &mockAccounts{}
	valSet := []*ktypes.Validator{
		{
			AccountID: ktypes.AccountID{
				Identifier: types.HexBytes(pubKey.Bytes()),
				KeyType:    pubKey.Type(),
			},
			Power: 1,
		},
	}
	vStore := newValidatorStore(valSet)
	ev := &mockEventStore{}
	migrator := &mockMigrator{}
	ss := &snapshotStore{}
	genCfg := config.DefaultGenesisConfig()
	genCfg.Leader = ktypes.PublicKey{PublicKey: pubKey}
	genCfg.DisabledGasCosts = true

	bp, err := blockprocessor.NewBlockProcessor(ctx, db, newDummyTxApp(), accounts, vStore, ss, ev, migrator, bs, mp, genCfg, auth.GetNodeSigner(privKey), logger)
	require.NoError(t, err)

	cfg := &Config{
		PrivateKey:            privKey,
		Leader:                pubKey,
		Mempool:               mp,
		BlockStore:            bs,
		BlockProcessor:        bp,
		Logger:                logger,
		ProposeTimeout:        time.Second,
		EmptyBlockTimeout:     time.Second,
		BlockProposalInterval: time.Second,
		BlockAnnInterval:      3 * time.Second,
		BroadcastTxTimeout:    10 * time.Second,
		RootDir:               root,
		DB:                    db,
	}

	return cfg, db
}

func closeBlockStore(t *testing.T, bs BlockStore) {
	if closable, ok := bs.(interface{ Close() error }); ok {
		require.NoError(t, closable.Close())
	}
}
