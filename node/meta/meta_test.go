//go:build pglive

package meta_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/meta"
	"github.com/trufnetwork/kwil-db/node/pg"
)

var cfg = &pg.DBConfig{
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

func Test_ChainState(t *testing.T) {
	ctx := context.Background()

	db, err := pg.NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback to reset the test

	err = meta.InitializeMetaStore(ctx, tx)
	require.NoError(t, err)

	h, _, _, err := meta.GetChainState(ctx, tx)
	require.NoError(t, err)
	require.EqualValues(t, int64(-1), h)

	err = meta.SetChainState(ctx, tx, 1, nil, false)
	require.NoError(t, err)

	h, ah, _, err := meta.GetChainState(ctx, tx)
	require.NoError(t, err)
	require.EqualValues(t, int64(1), h)
	require.Nil(t, ah)

	err = meta.SetChainState(ctx, tx, 2, []byte("app_hash"), true)
	require.NoError(t, err)

	h, ah, _, err = meta.GetChainState(ctx, tx)
	require.NoError(t, err)
	require.EqualValues(t, int64(2), h)
	require.EqualValues(t, []byte("app_hash"), ah)
}

func Test_NetworkParams(t *testing.T) {
	ctx := context.Background()

	db, err := pg.NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // always rollback to reset the test

	err = meta.InitializeMetaStore(ctx, tx)
	require.NoError(t, err)

	// getting params without any having been stored returns
	// ErrParamsNotFound

	_, err = meta.LoadParams(ctx, tx)
	require.Equal(t, meta.ErrParamsNotFound, err)

	_, pubkey, _ := crypto.GenerateSecp256k1Key(nil)

	param := &types.NetworkParameters{
		Leader:           types.PublicKey{PublicKey: pubkey},
		MaxBlockSize:     1000,
		JoinExpiry:       types.Duration(100 * time.Second),
		DisabledGasCosts: true,
		MaxVotesPerTx:    100,
	}

	err = meta.StoreParams(ctx, tx, param)
	require.NoError(t, err)

	param2, err := meta.LoadParams(ctx, tx)
	require.NoError(t, err)

	require.EqualValues(t, param, param2)

	// update some params and perform a diff
	param2.MaxBlockSize = 2000
	param2.JoinExpiry = 200
	param2.DisabledGasCosts = false
	param2.MigrationStatus = types.NoActiveMigration

	err = meta.StoreParams(ctx, tx, param2)
	require.NoError(t, err)

	param3, err := meta.LoadParams(ctx, tx)
	require.NoError(t, err)

	require.EqualValues(t, param2, param3)
}
