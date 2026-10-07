//go:build kwiltest

package erc20

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/extensions/hooks"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

// rewardEndBlockHook returns the end-block hook this package registers, so a
// test runs the hook itself rather than a copy of its logic.
func rewardEndBlockHook(t *testing.T) hooks.EndBlockHook {
	t.Helper()
	for _, h := range hooks.ListEndBlockHooks() {
		if h.Name == RewardMetaExtensionName+"_end_block" {
			return h.Hook
		}
	}
	t.Fatal("reward end-block hook is not registered")
	return nil
}

// An empty block is the common case: no instance can finalize. One instance is
// still inside its distribution period, one has passed it with no rewards and
// is waiting out the empty-epoch grace period, and one is waiting for its
// previous epoch to be confirmed. Operators run at INFO, so on such a block the
// hook must print nothing there, and nothing at WARN for "no rewards", which is
// the expected state.
func TestEndBlock_EmptyBlockLogsNothingAtInfo(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	if err != nil {
		t.Skip("PostgreSQL not available")
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	app := setup(t, tx)

	const (
		period = int64(600)
		now    = int64(10_000)
	)
	chainInfo, _ := chains.GetChainInfoByID("1")
	addInstance := func(escrow ethcommon.Address, epochStart int64, unconfirmedPrevious bool) {
		data := &userProvidedData{
			ID:                 newUUID(),
			ChainInfo:          &chainInfo,
			EscrowAddress:      escrow,
			DistributionPeriod: period,
		}
		require.NoError(t, createNewRewardInstance(ctx, app, data))
		if unconfirmedPrevious {
			// Finalized at height 100 with a root, so validators still have
			// to confirm it before the epoch after it can finalize.
			previous := &PendingEpoch{ID: newUUID(), StartHeight: 50, StartTime: epochStart - period}
			require.NoError(t, createEpoch(ctx, app, previous, data.ID))
			amount, err := erc20ValueFromBigInt(big.NewInt(1))
			require.NoError(t, err)
			require.NoError(t, finalizeEpoch(ctx, app, previous.ID, 100, []byte{0x01}, []byte{0x02}, amount))
		}
		epoch := &PendingEpoch{ID: newUUID(), StartHeight: 100, StartTime: epochStart}
		require.NoError(t, createEpoch(ctx, app, epoch, data.ID))
		getSingleton().instances.Set(*data.ID, &rewardExtensionInfo{
			userProvidedData: *data,
			active:           true,
			currentEpoch:     epoch,
		})
	}
	// Half way through its distribution period.
	addInstance(ethcommon.HexToAddress("0x00000000000000000000000000000000000000a1"), now-period/2, false)
	// Two periods in: past the period, inside the 3x grace, and no rewards.
	addInstance(ethcommon.HexToAddress("0x00000000000000000000000000000000000000a2"), now-2*period, false)
	// Past the period, but its previous epoch is not confirmed yet.
	addInstance(ethcommon.HexToAddress("0x00000000000000000000000000000000000000a3"), now-2*period, true)

	block := &common.BlockContext{Height: 200, Timestamp: now}
	hook := rewardEndBlockHook(t)

	var out bytes.Buffer
	app.Service.Logger = log.New(log.WithWriter(&out), log.WithLevel(log.LevelInfo))
	require.NoError(t, hook(ctx, app, block))
	require.Empty(t, out.String(), "an empty block must log nothing at INFO or WARN")

	// The same block at DEBUG shows each instance took the path above, so the
	// silence at INFO is not the hook skipping them.
	out.Reset()
	app.Service.Logger = log.New(log.WithWriter(&out), log.WithLevel(log.LevelDebug))
	require.NoError(t, hook(ctx, app, block))
	require.Contains(t, out.String(), "Not ready to finalize")
	require.Contains(t, out.String(), "No rewards found")
	require.Contains(t, out.String(), "waiting for grace period")
	require.Contains(t, out.String(), "Previous epoch not confirmed yet")
}
