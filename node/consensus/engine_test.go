//go:build pglive

package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	blockprocessor "github.com/trufnetwork/kwil-db/node/block_processor"
	"github.com/trufnetwork/kwil-db/node/mempool"
	"github.com/trufnetwork/kwil-db/node/meta"
	"github.com/trufnetwork/kwil-db/node/migrations"
	"github.com/trufnetwork/kwil-db/node/pg"
	dbtest "github.com/trufnetwork/kwil-db/node/pg/test"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
	"github.com/trufnetwork/kwil-db/node/store"
	"github.com/trufnetwork/kwil-db/node/txapp"
	"github.com/trufnetwork/kwil-db/node/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"

	"github.com/trufnetwork/kwil-db/core/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	mempoolSz = 200_000_000 // 200MB
	maxTxSz   = 1_000_000   // 1MB
)

var (
	broadcastFns = BroadcastFns{
		ProposalBroadcaster: mockBlockPropBroadcaster,
		TxAnnouncer:         mockTxAnnouncer,
		BlkAnnouncer:        mockBlkAnnouncer,
		BlkRequester:        mockBlkRequester,
		AckBroadcaster:      mockVoteBroadcaster,
		RstStateBroadcaster: mockResetStateBroadcaster,
		// DiscoveryReqBroadcaster: mockDiscoveryBroadcaster,
		TxBroadcaster: nil,
	}

	peerFns = WhitelistFns{
		AddPeer:    mockAddPeer,
		RemovePeer: mockRemovePeer,
	}
)

// leaderDB is set assigns DB to the leader, else DB is assigned to the follower
// Most of these tests expect only one working node instance either a leader or the
// first validator and all other nodes interactions are mocked out.
func generateTestCEConfig(t *testing.T, nodes int, leaderDB bool) ([]*Config, map[string]ktypes.Validator) {
	ceConfigs := make([]*Config, nodes)
	tempDir := t.TempDir()

	closers := make([]func(), 0)

	privKeys := make([]crypto.PrivateKey, nodes)
	pubKeys := make([]crypto.PublicKey, nodes)

	for i := range nodes {
		// generate a secp256k1 key pair
		privKey, pubKey, err := crypto.GenerateSecp256k1Key(nil)
		assert.NoError(t, err)

		privKeys[i] = privKey
		pubKeys[i] = pubKey
	}

	validatorSet := make(map[string]ktypes.Validator)
	var valSet []*ktypes.Validator
	for _, pubKey := range pubKeys {
		val := &ktypes.Validator{
			AccountID: ktypes.AccountID{
				Identifier: types.HexBytes(pubKey.Bytes()),
				KeyType:    pubKey.Type(),
			},
			Power: 1,
		}
		validatorSet[hex.EncodeToString(pubKey.Bytes())] = *val
		valSet = append(valSet, val)
	}

	ctx := context.Background()

	// Account Store
	// accounts, err := accounts.InitializeAccountStore(ctx, db)
	// assert.NoError(t, err)
	accounts := &mockAccounts{}

	v := newValidatorStore(valSet)

	// txapp, err := txapp.NewTxApp(ctx, db, nil, signer, nil, service, accounts, v)
	// assert.NoError(t, err)
	txapp := newDummyTxApp( /*valSet*/ )

	db := dbtest.NewTestDB(t, func(db *pg.DB) {
		db.AutoCommit(true)
		ctx := context.Background()
		db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_chain CASCADE;`)
		db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_voting CASCADE;`)
		db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_events CASCADE;`)
		db.Execute(ctx, `DROP SCHEMA IF EXISTS kwild_internal CASCADE;`)
		db.AutoCommit(false)
	})

	_, _, err := voting.NewResolutionStore(ctx, db) // create the voting resolution store
	require.NoError(t, err)

	func() {
		tx, err := db.BeginTx(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		err = meta.InitializeMetaStore(ctx, tx)
		require.NoError(t, err)

		require.NoError(t, tx.Commit(ctx))
	}()

	ss := &snapshotStore{}

	genCfg := config.DefaultGenesisConfig()
	genCfg.Leader = ktypes.PublicKey{PublicKey: pubKeys[0]}
	genCfg.DisabledGasCosts = true

	for i := range nodes {
		nodeStr := fmt.Sprintf("CE%d", i)
		nodeDir := filepath.Join(tempDir, nodeStr)

		logger := log.New(log.WithName(nodeStr), log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug), log.WithFormat(log.FormatUnstructured))
		// logger := log.DiscardLogger

		bs, err := store.NewBlockStore(nodeDir)
		assert.NoError(t, err)

		signer := auth.GetNodeSigner(privKeys[i])

		ev := &mockEventStore{}
		m := &mockMigrator{}
		mp := mempool.New(mempoolSz, maxTxSz)

		bp, err := blockprocessor.NewBlockProcessor(ctx, db, txapp, accounts, v, ss, ev, m, bs, mp, genCfg, signer, logger.New(fmt.Sprintf("BP%d", i)))
		assert.NoError(t, err)

		ceConfigs[i] = &Config{
			PrivateKey:     privKeys[i],
			Leader:         pubKeys[0],
			Mempool:        mp,
			BlockStore:     bs,
			BlockProcessor: bp,
			// ValidatorSet:          validatorSet,
			Logger:                logger,
			ProposeTimeout:        1 * time.Second,
			EmptyBlockTimeout:     1 * time.Second,
			BlockProposalInterval: 1 * time.Second,
			BlockAnnInterval:      3 * time.Second,
			BroadcastTxTimeout:    10 * time.Second,
			RootDir:               nodeDir,
		}

		closers = append(closers, func() {
			bs.Close()
		})
	}

	if leaderDB {
		ceConfigs[0].DB = db
	} else {
		ceConfigs[1].DB = db
	}

	t.Cleanup(func() {
		for _, closerFn := range closers {
			closerFn()
		}
	})

	return ceConfigs, validatorSet
}

var blockAppHash = nextHash()

func nextHash() types.Hash {
	newHash, err := ktypes.NewHashFromString("10453a9c0e733d40132228fc9eae3242d2aa9e62c9e35ecdd3d8318762a29bb4")
	if err != nil {
		panic(err)
	}
	return newHash
}

type triggerFn func(*testing.T, *ConsensusEngine, *ConsensusEngine)
type verifyFn func(*testing.T, *ConsensusEngine, *ConsensusEngine) error

func verifyStatus(_ *testing.T, val *ConsensusEngine, status Status, height int64, blkHash types.Hash) error {
	h, s, b := val.info()
	if height != h {
		return fmt.Errorf("expected height %d, got %d", height, h)
	}

	if status != s {
		return fmt.Errorf("expected status %s, got %s", status, s)
	}
	if blkHash != zeroHash && b != nil {
		if !bytes.Equal(blkHash[:], b.blkHash[:]) {
			return fmt.Errorf("expected block hash %s, got %s", blkHash, b.blkHash)
		}
	}

	return nil
}

func TestMain(m *testing.M) {
	pg.UseLogger(log.New(log.WithName("DBS"), log.WithFormat(log.FormatUnstructured)))
	m.Run()
}

func addVotes(t *testing.T, blkHash, appHash ktypes.Hash, n1, n2 *ConsensusEngine) *ktypes.CommitInfo {
	ci := &ktypes.CommitInfo{
		AppHash: appHash,
		Votes:   make([]*ktypes.VoteInfo, 0),
	}

	sig1, err := ktypes.SignVote(blkHash, true, &appHash, n1.privKey)
	require.NoError(t, err)

	ci.Votes = append(ci.Votes, &ktypes.VoteInfo{
		Signature: *sig1,
		AckStatus: ktypes.AckAgree,
	})

	sig2, err := ktypes.SignVote(blkHash, true, &appHash, n2.privKey)
	require.NoError(t, err)

	ci.Votes = append(ci.Votes, &ktypes.VoteInfo{
		Signature: *sig2,
		AckStatus: ktypes.AckAgree,
	})

	return ci
}

func TestMajorityFuncs(t *testing.T) {
	testcases := []struct {
		name        string
		valCnt      int
		acks        int
		nacks       int
		majority    bool
		enoughNacks bool
	}{
		{
			name:        "Majority(2, 2, 0)",
			valCnt:      2,
			acks:        2,
			nacks:       0,
			majority:    true,
			enoughNacks: false,
		},
		{
			name:        "Majority(2, 1, 0)",
			valCnt:      2,
			acks:        1,
			nacks:       0,
			majority:    false,
			enoughNacks: false,
		},
		{
			name:        "Majority(2, 1, 1)",
			valCnt:      2,
			acks:        1,
			nacks:       1,
			majority:    false,
			enoughNacks: true,
		},
		{
			name:        "Majority(2, 0, 2)",
			valCnt:      2,
			acks:        0,
			nacks:       2,
			majority:    false,
			enoughNacks: true,
		},
		{
			name:        "Majority(3, 3, 0)",
			valCnt:      3,
			acks:        3,
			nacks:       0,
			majority:    true,
			enoughNacks: false,
		},
		{
			name:        "Majority(3, 2, 1)",
			valCnt:      3,
			acks:        2,
			nacks:       1,
			majority:    true,
			enoughNacks: false,
		},
		{
			name:        "Majority(3, 1, 1)",
			valCnt:      3,
			acks:        1,
			nacks:       1,
			majority:    false,
			enoughNacks: false,
		},
		{
			name:        "Majority(3, 0, 2)",
			valCnt:      3,
			acks:        0,
			nacks:       2,
			majority:    false,
			enoughNacks: true,
		},
	}

	ce := &ConsensusEngine{}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ce.validatorSet = make(map[string]ktypes.Validator)
			for i := range tc.valCnt {
				ce.validatorSet[fmt.Sprintf("val%d", i)] = ktypes.Validator{}
			}

			assert.Equal(t, tc.majority, ce.hasMajority(tc.acks))
			assert.Equal(t, tc.enoughNacks, ce.hasEnoughNacks(tc.nacks))
		})
	}

}

func TestValidatorStateMachine(t *testing.T) {
	// t.Parallel()
	type action struct {
		name    string
		trigger triggerFn
		verify  verifyFn
	}

	var blkProp1, blkProp2 *blockProposal

	testcases := []struct {
		name    string
		setup   func(*testing.T) ([]*Config, map[string]ktypes.Validator)
		actions []action
	}{
		{
			name: "BlkPropAndCommit",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkProp",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "commit",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp1.blkHash, blockAppHash, leader, val)
						val.NotifyBlockCommit(blkProp1.blk, ci, blkProp1.blkHash, nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
			},
		},
		{
			name: "InvalidAppHash",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkProp",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "commit(InvalidAppHash)",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockCommit(blkProp1.blk, &ktypes.CommitInfo{AppHash: ktypes.Hash{}}, blkProp1.blkHash, nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						if val.lastCommitHeight() != 0 {
							return fmt.Errorf("expected height 0, got %d", val.lastCommitHeight())
						}
						return nil
					},
				},
			},
		},
		{
			name: "MultipleBlockProposals",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkPropOld",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "blkPropNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp2.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp2.blkHash)
					},
				},
				{
					name: "commitNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp2.blkHash, blockAppHash, leader, val)
						val.NotifyBlockCommit(blkProp2.blk, ci, blkProp2.blkHash, nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
			},
		},
		{
			name: "StaleBlockProposals",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkPropNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp2.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp2.blkHash)
					},
				},
				{
					name: "blkPropOld",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp2.blkHash)
					},
				},
				{
					name: "commitNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp2.blkHash, blockAppHash, leader, val)
						val.NotifyBlockCommit(blkProp2.blk, ci, blkProp2.blkHash, nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
			},
		},
		{
			name: "BlkAnnounceBeforeBlockProp",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkPropOld",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "commitNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp2.blkHash, blockAppHash, leader, val)
						val.NotifyBlockCommit(blkProp2.blk, ci, blkProp2.blkHash, nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
				{
					name: "blkPropNew (ignored)",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
			},
		},
		{
			name: "ValidResetFlow",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkPropOld",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "reset",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.sendResetMsg(&resetMsg{height: 1})
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 0, zeroHash)
					},
				},
				{
					name: "blkPropNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp2.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp2.blkHash)
					},
				},
				{
					name: "commitNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp2.blkHash, blockAppHash, leader, val)
						val.NotifyBlockCommit(blkProp2.blk, ci, blkProp2.blkHash, nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
			},
		},
		{
			name: "ResetAfterCommit(Ignored)",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkPropOld",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "commitNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp2.blkHash, blockAppHash, leader, val)
						val.NotifyBlockCommit(blkProp2.blk, ci, blkProp2.blkHash, nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
				{
					name: "reset",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.sendResetMsg(&resetMsg{height: 1})
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
			},
		},
		{
			name: "DuplicateReset",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkPropOld",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "reset",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.sendResetMsg(&resetMsg{height: 1})
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 0, zeroHash)
					},
				},
				{
					name: "reset",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.sendResetMsg(&resetMsg{height: 1})
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 0, zeroHash)
					},
				},
				{
					name: "commitNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp2.blkHash, blockAppHash, leader, val)
						val.NotifyBlockCommit(blkProp2.blk, ci, blkProp2.blkHash, nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
			},
		},
		{
			name: "InvalidFutureResetHeight",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkProp",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp1.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "reset",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.sendResetMsg(&resetMsg{height: 2})
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "reset",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.sendResetMsg(&resetMsg{height: 3})
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp1.blkHash)
					},
				},
				{
					name: "commitNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp2.blkHash, blockAppHash, leader, val)
						val.NotifyBlockCommit(blkProp2.blk, ci, blkProp2.blkHash, nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, zeroHash)
					},
				},
			},
		},
		{
			name: "Catchup mode with blk request fail",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkPropNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp2.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp2.blkHash)
					},
				},
				{
					name: "catchup",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp2.blkHash, blockAppHash, leader, val)

						rawBlk := ktypes.EncodeBlock(blkProp2.blk)
						cnt := 0
						bestHeight := blkProp2.height + 10 // TODO: update test when this is used
						val.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
							defer func() { cnt += 1 }()

							if cnt < 1 {
								return zeroHash, nil, nil, 0, types.ErrBlkNotFound
							}
							return blkProp2.blkHash, rawBlk, ci, bestHeight, nil
						}
						val.doCatchup(context.Background())
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, blkProp2.blkHash)
					},
				},
			},
		},
		{
			name: "Catchup mode with blk request success",
			setup: func(t *testing.T) ([]*Config, map[string]ktypes.Validator) {
				return generateTestCEConfig(t, 2, false)
			},
			actions: []action{
				{
					name: "blkPropNew",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						val.NotifyBlockProposal(blkProp2.blk, leader.pubKey.Bytes(), nil)
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Executed, 0, blkProp2.blkHash)
					},
				},
				{
					name: "catchup",
					trigger: func(t *testing.T, leader, val *ConsensusEngine) {
						ci := addVotes(t, blkProp2.blkHash, blockAppHash, leader, val)

						rawBlk := ktypes.EncodeBlock(blkProp2.blk)
						bestHeight := blkProp2.height + 10 // TODO: update test when this is used
						val.blkRequester = func(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
							return blkProp2.blkHash, rawBlk, ci, bestHeight, nil
						}
						val.doCatchup(context.Background())
					},
					verify: func(t *testing.T, leader, val *ConsensusEngine) error {
						return verifyStatus(t, val, Committed, 1, blkProp2.blkHash)
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Log(tc.name)
		t.Run(tc.name, func(t *testing.T) {
			ceConfigs, valset := tc.setup(t)

			leader, err := New(ceConfigs[0])
			require.NoError(t, err)

			val, err := New(ceConfigs[1])
			require.NoError(t, err)

			ctxM := context.Background()
			proposals := createBlockProposals(t, leader, valset)
			blkProp1, blkProp2 = proposals[0], proposals[1]

			t.Logf("blkProp1: %s, blkProp2: %s", blkProp1.blkHash.String(), blkProp2.blkHash.String())

			ctx, cancel := context.WithCancel(ctxM)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				val.Start(ctx, broadcastFns, peerFns)
			}()

			t.Cleanup(func() {
				cancel()
				wg.Wait()
			})

			for _, act := range tc.actions {
				t.Log("action", act.name)
				act.trigger(t, leader, val)
				require.Eventually(t, func() bool {
					err = act.verify(t, leader, val)
					if err != nil {
						t.Log(err)
						return false
					}
					return true
				}, 6*time.Second, 500*time.Millisecond)
			}
		})
	}
}

func createBlockProposals(t *testing.T, ce *ConsensusEngine, valSet map[string]ktypes.Validator) []*blockProposal {
	var txs []*ktypes.Transaction
	hasher := ktypes.NewHasher()
	keys := make([]string, 0, len(valSet))
	for _, v := range valSet {
		keys = append(keys, config.EncodePubKeyAndType(v.Identifier, v.KeyType))
	}
	slices.Sort(keys)

	for _, key := range keys {
		val := valSet[key]
		hasher.Write(val.AccountID.Bytes())
		binary.Write(hasher, binary.BigEndian, val.Power)
	}
	hash := hasher.Sum(nil)

	paramsHash := ce.blockProcessor.ConsensusParams().Hash()

	blk1 := ktypes.NewBlock(1, zeroHash, zeroHash, hash, paramsHash, time.Now(), txs)
	err := blk1.Sign(ce.privKey)
	require.NoError(t, err)

	blk2 := ktypes.NewBlock(1, zeroHash, zeroHash, hash, paramsHash, time.Now().Add(500*time.Millisecond), txs)
	err = blk2.Sign(ce.privKey)
	require.NoError(t, err)

	return []*blockProposal{
		{
			blk:     blk1,
			height:  1,
			blkHash: blk1.Hash(),
		},
		{
			blk:     blk2,
			height:  1,
			blkHash: blk2.Hash(),
		},
	}
}

func TestCELeaderSingleNode(t *testing.T) {
	// t.Parallel()
	ceConfigs, _ := generateTestCEConfig(t, 1, true)

	// bring up the node
	leader, err := New(ceConfigs[0])
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		leader.Start(ctx, broadcastFns, peerFns)
	}()

	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	require.Eventually(t, func() bool {
		return leader.lastCommitHeight() >= 1 // Ensure that the leader mines a block
	}, 10*time.Second, 100*time.Millisecond)
}

func TestCELeaderTwoNodesMajorityAcks(t *testing.T) {
	// Majority > n/2 -> 2
	ceConfigs, _ := generateTestCEConfig(t, 2, true)

	// bring up the nodes
	n1, err := New(ceConfigs[0])
	require.NoError(t, err)

	// start node 1 (Leader)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n1.Start(ctx, broadcastFns, peerFns)
	}()

	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	n1.bestHeightCh <- &discoveryMsg{
		BestHeight: 0,
		Sender:     ceConfigs[1].PrivateKey.Public().Bytes(),
	}

	time.Sleep(500 * time.Millisecond)
	_, _, blProp := n1.info()
	// appHash := nextAppHash()

	require.NotNil(t, blProp)

	// node2 should send a vote to node1
	sig, err := ktypes.SignVote(blProp.blkHash, true, &blockAppHash, ceConfigs[1].PrivateKey)
	assert.NoError(t, err)

	vote := &vote{
		msg: &types.AckRes{
			Height:    1,
			ACK:       true,
			BlkHash:   blProp.blkHash,
			AppHash:   &blockAppHash,
			Signature: sig,
		},
	}

	// Invalid sender
	err = n1.addVote(ctx, vote, "invalid")
	assert.Error(t, err)

	// Valid sender
	err = n1.addVote(ctx, vote, hex.EncodeToString(ceConfigs[1].PrivateKey.Public().Bytes()))
	assert.NoError(t, err)

	// ensure that the block is committed
	require.Eventually(t, func() bool {
		height := n1.lastCommitHeight()
		t.Logf("Height: %d", height)
		return height == 1
	}, 6*time.Second, 100*time.Millisecond)
}

func TestCELeaderTwoNodesMajorityNacks(t *testing.T) {
	// Majority > n/2 -> 2
	ceConfigs, _ := generateTestCEConfig(t, 3, true)

	// bring up the nodes
	n1, err := New(ceConfigs[0])
	require.NoError(t, err)

	// start node 1 (Leader)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)

	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	go func() {
		defer wg.Done()
		n1.Start(ctx, broadcastFns, peerFns)
	}()

	n1.bestHeightCh <- &discoveryMsg{
		BestHeight: 0,
		Sender:     ceConfigs[1].PrivateKey.Public().Bytes(),
	}

	require.Eventually(t, func() bool {
		blockRes := n1.blockResult()
		return blockRes != nil && !blockRes.appHash.IsZero()
	}, 6*time.Second, 100*time.Millisecond)

	_, _, b := n1.info()
	assert.NotNil(t, b)
	nextAppHash := nextAppHash(nextAppHash(zeroHash))

	sig1, err := ktypes.SignVote(b.blkHash, true, &nextAppHash, ceConfigs[1].PrivateKey)
	assert.NoError(t, err)

	sig2, err := ktypes.SignVote(b.blkHash, true, &nextAppHash, ceConfigs[2].PrivateKey)
	assert.NoError(t, err)

	// node2 should send a vote to node1
	vote := &vote{
		msg: &types.AckRes{
			Height:    1,
			ACK:       true,
			BlkHash:   b.blkHash,
			AppHash:   &nextAppHash,
			Signature: sig1,
		},
	}

	// Invalid sender -> vote ignored
	err = n1.addVote(ctx, vote, "invalid")
	assert.Error(t, err)

	// Valid sender
	err = n1.addVote(ctx, vote, hex.EncodeToString(ceConfigs[1].PrivateKey.Public().Bytes()))
	assert.NoError(t, err)

	vote.msg.Signature = sig2
	err = n1.addVote(ctx, vote, hex.EncodeToString(ceConfigs[2].PrivateKey.Public().Bytes()))
	assert.NoError(t, err)

	// node should not commit the block and halt
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, n1.lastCommitHeight(), int64(0))
}

// MockBroadcasters
func mockBlkRequester(ctx context.Context, height int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
	return types.Hash{}, nil, nil, 0, types.ErrBlkNotFound
}

func mockBlockPropBroadcaster(_ context.Context, blk *ktypes.Block, sender []byte) {}

func mockVoteBroadcaster(msg *types.AckRes) error {
	return nil
}

func mockBlkAnnouncer(_ context.Context, blk *ktypes.Block, ci *ktypes.CommitInfo) {}

func mockTxAnnouncer(ctx context.Context, txID types.Hash) {}

func mockResetStateBroadcaster(_ int64, _ []ktypes.Hash) error {
	return nil
}

func nextAppHash(prevHash types.Hash) types.Hash {
	hasher := sha256.New()
	txHash := types.Hash(hasher.Sum(nil))
	return sha256.Sum256(append(prevHash[:], txHash[:]...))
}

type dummyTxApp struct {
	// vals []*ktypes.Validator
}

func newDummyTxApp( /*valset []*ktypes.Validator*/ ) *dummyTxApp {
	return &dummyTxApp{
		// vals: valset,
	}
}
func (d *dummyTxApp) Begin(ctx context.Context, height int64) error {
	return nil
}

func (d *dummyTxApp) Execute(ctx *common.TxContext, db sql.DB, tx *ktypes.Transaction) *txapp.TxResponse {
	return &txapp.TxResponse{}
}

func (d *dummyTxApp) Finalize(ctx context.Context, db sql.DB, block *common.BlockContext) (aj, ej []*ktypes.AccountID, err error) {
	return nil, nil, nil
}

func (d *dummyTxApp) Price(ctx context.Context, dbTx sql.DB, tx *ktypes.Transaction, chainContext *common.ChainContext) (*big.Int, error) {
	return big.NewInt(0), nil
}

func (d *dummyTxApp) Commit() error {
	return nil
}

func (d *dummyTxApp) Rollback() {}

func (d *dummyTxApp) GenesisInit(ctx context.Context, db sql.DB, _ *config.GenesisConfig, chain *common.ChainContext) error {
	return nil
}
func (d *dummyTxApp) AccountInfo(ctx context.Context, dbTx sql.DB, identifier *ktypes.AccountID, pending bool) (balance *big.Int, nonce int64, err error) {
	return big.NewInt(0), 0, nil
}
func (a *dummyTxApp) NumAccounts(ctx context.Context, tx sql.Executor) (int64, int64, error) {
	return 1, 1, nil
}

func (d *dummyTxApp) ApplyMempool(ctx *common.TxContext, db sql.DB, tx *ktypes.Transaction) error {
	return nil
}

type validatorStore struct {
	valSet []*ktypes.Validator
}

func newValidatorStore(valSet []*ktypes.Validator) *validatorStore {
	return &validatorStore{
		valSet: valSet,
	}
}

func (v *validatorStore) GetValidators() []*ktypes.Validator {
	return v.valSet
}

func (v *validatorStore) ValidatorUpdates() map[string]*ktypes.Validator {
	return nil
}

func (v *validatorStore) LoadValidatorSet(ctx context.Context, db sql.Executor) error {
	return nil
}

type mockAccounts struct{}

func (m *mockAccounts) Updates() []*ktypes.Account {
	return nil
}

func (ce *ConsensusEngine) info() (int64, Status, *blockProposal) {
	ce.stateInfo.mtx.RLock()
	defer ce.stateInfo.mtx.RUnlock()

	return ce.stateInfo.height, ce.stateInfo.status, ce.stateInfo.blkProp
}

func (ce *ConsensusEngine) blockResult() *blockResult {
	ce.state.mtx.RLock()
	defer ce.state.mtx.RUnlock()

	return ce.state.blockRes
}

// should satisfy the SnapshotModule interface
type snapshotStore struct {
}

func (s *snapshotStore) Enabled() bool {
	return false
}

func (s *snapshotStore) ListSnapshots() []*snapshotter.Snapshot {
	return nil
}

func (s *snapshotStore) CreateSnapshot(ctx context.Context, height uint64, snapshotID string, schemas, excludedTables []string, excludeTableData []string) error {
	return nil
}

func (s *snapshotStore) IsSnapshotDue(height uint64) bool {
	return false
}

func (s *snapshotStore) LoadSnapshotChunk(height uint64, format uint32, chunkID uint32) ([]byte, error) {
	return nil, nil
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

type mockMigrator struct{}

func (m *mockMigrator) NotifyHeight(ctx context.Context, block *common.BlockContext, db migrations.Database, tx sql.Executor) error {
	return nil
}

func (m *mockMigrator) StoreChangesets(height int64, changes <-chan any) error {
	return nil
}

func (m *mockMigrator) PersistLastChangesetHeight(ctx context.Context, tx sql.Executor, height int64) error {
	return nil
}

func (m *mockMigrator) GetMigrationMetadata(ctx context.Context, status ktypes.MigrationStatus) (*ktypes.MigrationMetadata, error) {
	return nil, nil
}

func mockAddPeer(string) error    { return nil }
func mockRemovePeer(string) error { return nil }

func TestInitializeStateRepairsWhenAppAheadOfStore(t *testing.T) {
	ceConfigs, _ := generateTestCEConfig(t, 1, true)
	cfg := ceConfigs[0]

	ctx := context.Background()

	var appHash ktypes.Hash
	copy(appHash[:], bytes.Repeat([]byte{0xAB}, len(appHash)))

	tx, err := cfg.DB.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = meta.SetChainState(ctx, tx, 1, appHash[:], false)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	ce, err := New(cfg)
	require.NoError(t, err)

	blk := ktypes.NewBlock(1, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, time.Now(), nil)
	blkHash := blk.Hash()
	commitInfo := &ktypes.CommitInfo{
		AppHash: appHash,
	}

	ce.blkRequester = func(context.Context, int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
		return blkHash, ktypes.EncodeBlock(blk), commitInfo, 1, nil
	}

	require.NoError(t, ce.commitLog.Record(1, blkHash))

	appHeight, storeHeight, err := ce.initializeState(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), appHeight)
	require.Equal(t, int64(1), storeHeight)

	bestHeight, _, _, _ := ce.blockStore.Best()
	require.Equal(t, int64(1), bestHeight)

	if ce.commitLog != nil {
		_, err := ce.commitLog.Load()
		require.ErrorIs(t, err, fs.ErrNotExist)
	}
}
