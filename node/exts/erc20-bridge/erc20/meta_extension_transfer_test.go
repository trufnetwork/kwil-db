//go:build kwiltest

package erc20

import (
	"context"
	"encoding/hex"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

func TestTransferHistory(t *testing.T) {
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

	// 1. Setup instance
	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok, "chain 1 should be registered")

	upd := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}
	require.NoError(t, createNewRewardInstance(ctx, app, upd))
	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	}))

	// 2. Initial Balance
	sender := ethcommon.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient := ethcommon.HexToAddress("0x2222222222222222222222222222222222222222")
	initialAmount := types.MustParseDecimalExplicit("100", 78, 0)
	transferAmount := types.MustParseDecimalExplicit("10", 78, 0)

	require.NoError(t, creditBalance(ctx, app, id, sender, initialAmount))

	// 3. Perform Transfer
	block := &common.BlockContext{
		Height:    500,
		Timestamp: 1600000500,
	}

	txIDHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	engCtx := &common.EngineContext{
		TxContext: &common.TxContext{
			Ctx:          ctx,
			TxID:         txIDHex,
			Caller:       sender.Hex(),
			BlockContext: block,
		},
	}

	err = transferTokens(engCtx, app, id, sender, recipient, transferAmount)
	require.NoError(t, err)

	// 4. Verify History
	res, err := app.DB.Execute(ctx, "SELECT type, status, amount, from_address, to_address, internal_tx_hash, block_height, block_timestamp FROM kwil_erc20_meta.transaction_history WHERE instance_id = $1", id)
	require.NoError(t, err)
	require.Len(t, res.Rows, 1)

	row := res.Rows[0]
	typeVal := row[0].(string)
	statusVal := row[1].(string)
	amountVal := row[2].(*types.Decimal)
	fromVal := row[3].([]byte)
	toVal := row[4].([]byte)
	txHashVal := row[5].([]byte)
	heightVal := row[6].(int64)
	timestampVal := row[7].(int64)

	require.Equal(t, "transfer", typeVal)
	require.Equal(t, "completed", statusVal)
	require.Equal(t, transferAmount.String(), amountVal.String())
	require.Equal(t, sender.Bytes(), fromVal)
	require.Equal(t, recipient.Bytes(), toVal)

	expectedTxHash, _ := hex.DecodeString(txIDHex)
	require.Equal(t, expectedTxHash, txHashVal)
	require.Equal(t, int64(500), heightVal)
	require.Equal(t, int64(1600000500), timestampVal)

	// 5. Verify Balances
	senderBal, err := balanceOf(ctx, app, id, sender)
	require.NoError(t, err)
	// Since types.Decimal doesn't have Sub, we rely on DB correctness which we assume from transferTokens logic,
	// but let's check values from DB
	// 100 - 10 = 90
	require.Equal(t, "90", senderBal.String())

	recipientBal, err := balanceOf(ctx, app, id, recipient)
	require.NoError(t, err)
	require.Equal(t, "10", recipientBal.String())
}
