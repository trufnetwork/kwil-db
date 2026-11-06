//go:build kwiltest

package erc20

import (
	"context"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
	kwilTesting "github.com/trufnetwork/kwil-db/testing"
)

// TestLockWithoutBalanceRow runs lock the way a transaction reaches it: a
// top-level call on a USE erc20 alias by an account that never held the token
// and so has no balances row. lock_admin shares the same code and is SYSTEM,
// so it is reached through an action body.
func TestLockWithoutBalanceRow(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	app := setup(t, tx)
	require.NoError(t, orderedsync.ForTestingEnsureNamespace(ctx, &kwilTesting.Platform{DB: tx, Engine: app.Engine}))

	const chain = "sepolia"
	const escrow = "0x00000000000000000000000000000000000000cc"
	defer ForTestingUnregisterRuntimeFor(chain, escrow)

	require.NoError(t, app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB,
		"USE erc20 { chain: '"+chain+"', escrow: '"+escrow+"' } AS tt", nil, nil))

	// mark the instance synced, so a holder's lock goes all the way through
	id := uuidForChainAndEscrow(chain, escrow)
	synced := &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	}
	require.NoError(t, setRewardSynced(ctx, app, &id, 1, synced))
	info, ok := getSingleton().instances.Get(id)
	require.True(t, ok)
	info.mu.Lock()
	info.synced = true
	info.syncedRewardData = *synced
	info.ownedBalance = types.MustParseDecimalExplicit("0", 78, 0)
	info.mu.Unlock()

	require.NoError(t, app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
		CREATE ACTION lock_for($user TEXT, $amount NUMERIC(78,0)) PUBLIC {
			tt.lock_admin($user, $amount);
		}`, nil, nil))

	noBalance := "0x5555555555555555555555555555555555555555"
	holder := ethcommon.HexToAddress("0x6666666666666666666666666666666666666666")
	one := types.MustParseDecimalExplicit("1", 78, 0)

	callErr := func(caller, namespace, action string, args ...any) error {
		res, err := app.Engine.Call(lockTestEngineCtx(caller), app.DB, namespace, action, args, nil)
		if err != nil {
			return err
		}
		return res.Error
	}

	err = callErr(noBalance, "tt", "lock", one)
	require.ErrorContains(t, err, "insufficient balance")
	require.NotContains(t, err.Error(), "panic")

	err = callErr(noBalance, "main", "lock_for", noBalance, one)
	require.ErrorContains(t, err, "insufficient balance")
	require.NotContains(t, err.Error(), "panic")

	// a holder still locks through the same alias
	require.NoError(t, creditBalance(ctx, app, &id, holder, types.MustParseDecimalExplicit("5", 78, 0)))
	require.NoError(t, callErr(holder.Hex(), "tt", "lock", one))
	bal, err := balanceOf(ctx, app, &id, holder)
	require.NoError(t, err)
	require.Equal(t, "4", bal.String())
}

func lockTestEngineCtx(caller string) *common.EngineContext {
	return &common.EngineContext{TxContext: &common.TxContext{
		Ctx:           context.Background(),
		TxID:          "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Caller:        caller,
		Signer:        ethcommon.HexToAddress(caller).Bytes(),
		Authenticator: "secp256k1_ep",
		BlockContext: &common.BlockContext{
			Height: 1,
			ChainContext: &common.ChainContext{
				NetworkParameters: &common.NetworkParameters{},
				MigrationParams:   &common.MigrationContext{},
			},
		},
	}}
}
