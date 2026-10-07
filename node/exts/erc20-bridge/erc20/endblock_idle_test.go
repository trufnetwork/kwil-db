//go:build kwiltest

package erc20

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// countingEngine counts the two queries the reward hook runs to decide whether
// an epoch can finalize.
type countingEngine struct {
	common.Engine
	confirmQueries int
	rewardsQueries int
}

func (c *countingEngine) ExecuteWithoutEngineCtx(ctx context.Context, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error) error {
	switch {
	case strings.Contains(statement, "SELECT confirmed from epochs"):
		c.confirmQueries++
	case strings.Contains(statement, "SELECT recipient, amount") && strings.Contains(statement, "FROM epoch_rewards"):
		c.rewardsQueries++
	}
	return c.Engine.ExecuteWithoutEngineCtx(ctx, db, statement, params, fn)
}

const (
	idlePeriod = int64(600)    // distribution period; the grace period is 3x
	idleStart  = int64(10_000) // block time the instances' current epochs start at
)

// idleScenario is a database, an app whose engine counts the hook's queries,
// and reward instances whose epochs started at idleStart.
type idleScenario struct {
	t      *testing.T
	ctx    context.Context
	app    *common.App
	engine *countingEngine
	hook   func(height, blockTime int64)
}

func newIdleScenario(t *testing.T) *idleScenario {
	t.Helper()
	ctx := context.Background()
	db, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available")
	}
	t.Cleanup(func() { db.Close() })

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { tx.Rollback(ctx) })

	orderedsync.ForTestingReset()
	t.Cleanup(orderedsync.ForTestingReset)
	ForTestingResetSingleton()
	t.Cleanup(ForTestingResetSingleton)

	app := setup(t, tx)
	engine := &countingEngine{Engine: app.Engine}
	app.Engine = engine

	hook := rewardEndBlockHook(t)
	s := &idleScenario{t: t, ctx: ctx, app: app, engine: engine}
	s.hook = func(height, blockTime int64) {
		t.Helper()
		block := &common.BlockContext{Height: height, Timestamp: blockTime}
		block.Hash[0] = byte(height)
		require.NoError(t, hook(ctx, app, block))
	}
	return s
}

// addInstance creates a funded instance whose current epoch started at
// idleStart and height 100. With unconfirmedPrevious, an epoch before it was
// finalized at height 100 and is waiting for validators to confirm it; its
// root is returned so the test can confirm it.
func (s *idleScenario) addInstance(name string, unconfirmedPrevious bool) (instanceID, epochID *types.UUID, previousRoot []byte) {
	s.t.Helper()
	chainInfo, _ := chains.GetChainInfoByID("1")
	data := &userProvidedData{
		ID:                 types.NewUUIDV5([]byte("idle-instance-" + name)),
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.BytesToAddress([]byte("escrow-" + name)),
		DistributionPeriod: idlePeriod,
	}
	require.NoError(s.t, createNewRewardInstance(s.ctx, s.app, data))
	require.NoError(s.t, s.app.Engine.ExecuteWithoutEngineCtx(s.ctx, s.app.DB,
		`{kwil_erc20_meta}UPDATE reward_instances SET balance = 1000000::NUMERIC(78, 0) WHERE id = $id`,
		map[string]any{"id": data.ID}, nil))

	if unconfirmedPrevious {
		previous := &PendingEpoch{ID: types.NewUUIDV5([]byte("idle-previous-" + name)), StartHeight: 50, StartTime: idleStart - idlePeriod}
		require.NoError(s.t, createEpoch(s.ctx, s.app, previous, data.ID))
		amount, err := erc20ValueFromBigInt(big.NewInt(1))
		require.NoError(s.t, err)
		previousRoot = []byte("root-" + name)
		require.NoError(s.t, finalizeEpoch(s.ctx, s.app, previous.ID, 100, []byte{0x01}, previousRoot, amount))
	}

	epoch := &PendingEpoch{ID: types.NewUUIDV5([]byte("idle-epoch-" + name)), StartHeight: 100, StartTime: idleStart}
	require.NoError(s.t, createEpoch(s.ctx, s.app, epoch, data.ID))
	getSingleton().instances.Set(*data.ID, &rewardExtensionInfo{
		userProvidedData: *data,
		active:           true,
		currentEpoch:     epoch,
	})
	return data.ID, epoch.ID, previousRoot
}

// issue writes a reward to the instance's current epoch, the way a transaction
// in the block would.
func (s *idleScenario) issue(instanceID *types.UUID) {
	s.t.Helper()
	info, ok := getSingleton().instances.Get(*instanceID)
	require.True(s.t, ok)
	amount, err := erc20ValueFromBigInt(big.NewInt(5))
	require.NoError(s.t, err)
	require.NoError(s.t, issueReward(s.ctx, s.app, instanceID, info.currentEpoch.ID,
		ethcommon.HexToAddress("0x00000000000000000000000000000000000000b1"), amount))
}

func (s *idleScenario) queries() (confirm, rewards int) {
	return s.engine.confirmQueries, s.engine.rewardsQueries
}

func (s *idleScenario) currentEpoch(instanceID *types.UUID) types.UUID {
	info, ok := getSingleton().instances.Get(*instanceID)
	require.True(s.t, ok)
	return *info.currentEpoch.ID
}

// epochRow reads what the hook writes about an epoch.
func (s *idleScenario) epochRow(epochID *types.UUID) (endedAt *int64, root []byte, confirmed bool) {
	s.t.Helper()
	found := false
	require.NoError(s.t, s.app.Engine.ExecuteWithoutEngineCtx(s.ctx, s.app.DB,
		`{kwil_erc20_meta}SELECT ended_at, reward_root, confirmed FROM epochs WHERE id = $id`,
		map[string]any{"id": epochID}, func(r *common.Row) error {
			found = true
			if r.Values[0] != nil {
				v := r.Values[0].(int64)
				endedAt = &v
			}
			if r.Values[1] != nil {
				root = r.Values[1].([]byte)
			}
			confirmed = r.Values[2].(bool)
			return nil
		}))
	require.True(s.t, found, "epoch %s not found", epochID)
	return endedAt, root, confirmed
}

// An epoch past its distribution period with no rewards waits out the grace
// period, and every block of that wait used to query for its rewards again.
// Until a reward is written, the answer cannot change, so the hook asks once,
// skips the queries after that, and asks again as soon as a reward lands.
func TestEndBlock_SkipsQueriesWhileAwaitingRewards(t *testing.T) {
	s := newIdleScenario(t)
	instanceID, epochID, _ := s.addInstance("rewards", false)

	s.hook(200, idleStart+idlePeriod+100) // past the period, inside the grace period
	confirm, rewards := s.queries()
	require.Equal(t, 1, confirm)
	require.Equal(t, 1, rewards)

	s.hook(201, idleStart+idlePeriod+200)
	s.hook(202, idleStart+idlePeriod+300)
	confirm, rewards = s.queries()
	require.Equal(t, 1, confirm, "nothing changed, so the previous-epoch query is skipped")
	require.Equal(t, 1, rewards, "nothing changed, so the rewards query is skipped")

	s.issue(instanceID)
	s.hook(203, idleStart+idlePeriod+400)
	confirm, rewards = s.queries()
	require.Equal(t, 2, confirm, "a reward was written, so the hook checks again")
	require.Equal(t, 2, rewards)

	endedAt, root, _ := s.epochRow(epochID)
	require.NotNil(t, endedAt, "the epoch must finalize on the block after its first reward")
	require.Equal(t, int64(203), *endedAt)
	require.NotNil(t, root)
	require.NotEqual(t, *epochID, s.currentEpoch(instanceID), "a new epoch must start")
}

// lockAndIssue is the other way a reward reaches epoch_rewards (a user's locked
// balance paid out as a reward). It must end the wait the same way.
func TestEndBlock_ALockedRewardAlsoEndsTheWait(t *testing.T) {
	s := newIdleScenario(t)
	instanceID, epochID, _ := s.addInstance("locked", false)

	s.hook(200, idleStart+idlePeriod+100)
	s.hook(201, idleStart+idlePeriod+200)
	_, rewards := s.queries()
	require.Equal(t, 1, rewards, "the second block skips the rewards query")

	amount, err := erc20ValueFromBigInt(big.NewInt(7))
	require.NoError(t, err)
	require.NoError(t, lockAndIssue(s.ctx, s.app, instanceID, epochID,
		ethcommon.HexToAddress("0x00000000000000000000000000000000000000c1"),
		ethcommon.HexToAddress("0x00000000000000000000000000000000000000c2"), amount))

	s.hook(202, idleStart+idlePeriod+300)
	_, rewards = s.queries()
	require.Equal(t, 2, rewards, "a locked reward was written, so the hook checks again")
	endedAt, root, _ := s.epochRow(epochID)
	require.NotNil(t, endedAt, "the epoch must finalize on the block after the locked reward")
	require.NotNil(t, root)
}

// An epoch whose previous epoch is not confirmed cannot finalize until a
// confirmation is written, so the hook skips its check until one is.
func TestEndBlock_SkipsQueriesWhileAwaitingConfirmation(t *testing.T) {
	s := newIdleScenario(t)
	_, _, previousRoot := s.addInstance("confirmation", true)

	s.hook(200, idleStart+idlePeriod+100)
	confirm, rewards := s.queries()
	require.Equal(t, 1, confirm)
	require.Equal(t, 0, rewards, "the rewards are not read while the previous epoch is unconfirmed")

	s.hook(201, idleStart+idlePeriod+200)
	s.hook(202, idleStart+idlePeriod+300)
	confirm, _ = s.queries()
	require.Equal(t, 1, confirm, "nothing was confirmed, so the query is skipped")

	require.NoError(t, confirmEpoch(s.ctx, s.app, previousRoot))
	s.hook(203, idleStart+idlePeriod+400)
	confirm, rewards = s.queries()
	require.Equal(t, 2, confirm, "a confirmation was written, so the hook checks again")
	require.Equal(t, 1, rewards, "with the previous epoch confirmed, the hook reads the rewards")

	s.hook(204, idleStart+idlePeriod+500)
	confirm, rewards = s.queries()
	require.Equal(t, 2, confirm, "now waiting for rewards, with nothing written")
	require.Equal(t, 1, rewards)
}

// The skip covers the grace period only. On the first block after it, the hook
// runs its checks and finalizes the empty epoch, exactly as without the skip.
func TestEndBlock_FinalizesTheEmptyEpochWhenGraceEnds(t *testing.T) {
	s := newIdleScenario(t)
	instanceID, epochID, _ := s.addInstance("grace", false)

	grace := idlePeriod * emptyEpochGraceMultiplier
	s.hook(200, idleStart+idlePeriod+100)
	s.hook(201, idleStart+grace-1) // last second of the grace period: skipped
	confirm, rewards := s.queries()
	require.Equal(t, 1, confirm)
	require.Equal(t, 1, rewards)
	endedAt, _, _ := s.epochRow(epochID)
	require.Nil(t, endedAt)

	s.hook(202, idleStart+grace) // grace period over
	confirm, rewards = s.queries()
	require.Equal(t, 2, confirm)
	require.Equal(t, 2, rewards)

	endedAt, root, confirmed := s.epochRow(epochID)
	require.NotNil(t, endedAt, "the empty epoch must finalize when the grace period ends")
	require.Equal(t, int64(202), *endedAt)
	require.Nil(t, root, "an empty epoch has no reward root")
	require.True(t, confirmed, "an empty epoch is confirmed as it finalizes")
	require.NotEqual(t, *epochID, s.currentEpoch(instanceID))
}

// The skip must never change what the hook writes, or nodes would disagree on
// the app hash: a node that just restarted has no marks and runs every check.
// The same script runs twice, once keeping the marks and once dropping them
// before every block, and the two must leave identical epochs.
func TestEndBlock_IdleMarksDoNotChangeWhatTheHookWrites(t *testing.T) {
	// Each run is a subtest so its transaction rolls back before the next run
	// inserts the same instances.
	run := func(dropMarksEachBlock bool) (epochs []string, queries int) {
		t.Run(fmt.Sprintf("dropMarksEachBlock=%v", dropMarksEachBlock), func(t *testing.T) {
			epochs, queries = runIdleScript(t, dropMarksEachBlock)
		})
		return epochs, queries
	}

	withMarks, fewer := run(false)
	withoutMarks, all := run(true)
	require.NotEmpty(t, withMarks)
	require.Equal(t, withoutMarks, withMarks, "the hook must write the same epochs with and without the skip")
	require.Less(t, fewer, all, "the run with marks must have skipped queries, or this test proves nothing")
	t.Logf("%d epochs; %d queries with the skip, %d without", len(withMarks), fewer, all)
}

// runIdleScript runs a fixed script of blocks, rewards and confirmations over
// three instances and returns every epoch the hook left, and how many of its
// queries ran.
func runIdleScript(t *testing.T, dropMarksEachBlock bool) (epochs []string, queries int) {
	s := newIdleScenario(t)
	rewardsID, _, _ := s.addInstance("det-rewards", false)
	confirmID, _, previousRoot := s.addInstance("det-confirm", true)
	_, _, _ = s.addInstance("det-empty", false)

	for i := range int64(30) {
		height := 200 + i
		blockTime := idleStart + idlePeriod + 100*i // across the grace period's end
		switch i {
		case 4:
			s.issue(rewardsID)
		case 9:
			require.NoError(t, confirmEpoch(s.ctx, s.app, previousRoot))
		case 17:
			s.issue(confirmID)
		}
		if dropMarksEachBlock {
			resetIdleMarks()
		}
		s.hook(height, blockTime)
	}

	require.NoError(t, s.app.Engine.ExecuteWithoutEngineCtx(s.ctx, s.app.DB, `
			{kwil_erc20_meta}SELECT id, instance_id, created_at_block, ended_at, reward_root, confirmed
			FROM epochs ORDER BY created_at_block, id`, nil, func(r *common.Row) error {
		epochs = append(epochs, fmt.Sprint(r.Values...))
		return nil
	}))
	confirm, rewards := s.queries()
	return epochs, confirm + rewards
}
