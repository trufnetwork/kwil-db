package erc20

import (
	"context"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine/interpreter"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

func newTestDB() (*pg.DB, error) {
	cfg := &pg.DBConfig{
		PoolConfig: pg.PoolConfig{
			ConnConfig: pg.ConnConfig{
				Host:   "127.0.0.1",
				Port:   "5432",
				User:   "kwild",
				Pass:   "kwild", // would be ignored if pg_hba.conf set with trust
				DBName: "kwil_test_db",
			},
			MaxConns: 11,
		},
	}

	ctx := context.Background()

	return pg.NewDB(ctx, cfg)
}

const defaultCaller = "owner"

func setup(t *testing.T, tx sql.DB) *common.App {
	interp, err := interpreter.NewInterpreter(context.Background(), tx, &common.Service{}, nil, nil, nil)
	require.NoError(t, err)

	err = interp.ExecuteWithoutEngineCtx(context.Background(), tx, "TRANSFER OWNERSHIP TO $user", map[string]any{
		"user": defaultCaller,
	}, nil)
	require.NoError(t, err)

	app := &common.App{
		DB:     tx,
		Engine: interp,
		Service: &common.Service{
			Logger: log.New(),
		},
	}

	err = genesisExec(context.Background(), app)
	require.NoError(t, err)

	return app
}

var lastID = types.NewUUIDV5([]byte("first"))

func newUUID() *types.UUID {
	id := types.NewUUIDV5WithNamespace(*lastID, []byte("next"))
	lastID = &id
	return &id
}

// TestCreateNewRewardInstance tests the createNewRewardInstance function.
func TestCreateNewRewardInstance(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback

	app := setup(t, tx)

	id := newUUID()
	// Create a userProvidedData object
	chainInfo, _ := chains.GetChainInfoByID("1") // or whichever chain ID you want
	testReward := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      zeroHex,
		DistributionPeriod: 3600,
	}

	err = createNewRewardInstance(ctx, app, testReward)
	require.NoError(t, err)

	pending := &PendingEpoch{
		ID:          newUUID(),
		StartHeight: 10,
		StartTime:   100,
	}
	err = createEpoch(ctx, app, pending, id)
	require.NoError(t, err)

	rewards, err := getStoredRewardInstances(ctx, app)
	require.NoError(t, err)
	require.Len(t, rewards, 1)
	require.Equal(t, testReward.ID, rewards[0].ID)
	require.False(t, rewards[0].synced)
	require.Equal(t, int64(3600), rewards[0].DistributionPeriod)
	require.Equal(t, zeroHex, rewards[0].EscrowAddress)
	require.Equal(t, chainInfo, *rewards[0].ChainInfo)
	require.Equal(t, pending.ID, rewards[0].currentEpoch.ID)
	require.Equal(t, pending.StartHeight, rewards[0].currentEpoch.StartHeight)
	require.Equal(t, pending.StartTime, rewards[0].currentEpoch.StartTime)

	// set synced to true, active to false
	err = setRewardSynced(ctx, app, testReward.ID, 102, &syncedRewardData{
		Erc20Address:  zeroHex,
		Erc20Decimals: 18,
	})
	require.NoError(t, err)
	err = setActiveStatus(ctx, app, testReward.ID, false)
	require.NoError(t, err)

	rewards, err = getStoredRewardInstances(ctx, app)
	require.NoError(t, err)

	require.Len(t, rewards, 1)
	// we will only check the new values
	require.True(t, rewards[0].synced)
	require.False(t, rewards[0].active)
	require.Equal(t, int64(102), rewards[0].syncedAt)
	require.Equal(t, zeroHex, rewards[0].syncedRewardData.Erc20Address)
	require.Equal(t, int64(18), rewards[0].syncedRewardData.Erc20Decimals)

	root := []byte{0x03, 0x04}
	amt, _ := erc20ValueFromBigInt(big.NewInt(100))
	// finalize the epoch
	err = finalizeEpoch(ctx, app, pending.ID, 20, []byte{0x01, 0x02}, root, amt)
	require.NoError(t, err)

	// confirm the epoch
	err = confirmEpoch(ctx, app, root)
	require.NoError(t, err)

	// TODO: we currently do not have queries for reading full epochs.
	// These will get added when we implement the rest of the extension.
}

var zeroHex = ethcommon.HexToAddress("0x0000000000000000000000000000000000000001")
