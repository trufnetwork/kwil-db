//go:build kwiltest

package erc20

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
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

func TestGetHistory(t *testing.T) {
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
	require.True(t, ok)

	upd := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0xaa"),
		DistributionPeriod: 3600,
	}
	require.NoError(t, createNewRewardInstance(ctx, app, upd))
	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0xbb"),
		Erc20Decimals: 18,
	}))

	sender := ethcommon.HexToAddress("0x11")
	recipient := ethcommon.HexToAddress("0x22")

	// 2. Deposit (Manual Insert for simplicity, or use applyDepositLog if easier)
	// Let's use applyDepositLog to test end-to-end integration
	depositAmount := big.NewInt(100)
	var data [32]byte
	copy(data[32-len(depositAmount.Bytes()):], depositAmount.Bytes())

	depositLog := ethtypes.Log{
		Address: upd.EscrowAddress,
		Topics: []ethcommon.Hash{
			depositEventID,
			ethcommon.BytesToHash(sender.Bytes()),
		},
		Data:        data[:],
		TxHash:      ethcommon.HexToHash("0x1111"),
		BlockNumber: 100,
	}
	block1 := &common.BlockContext{Height: 100, Timestamp: 1000}
	require.NoError(t, applyDepositLog(ctx, app, id, depositLog, block1, nil))

	// 3. Transfer
	transferAmount := types.MustParseDecimalExplicit("50", 78, 0)
	block2 := &common.BlockContext{Height: 200, Timestamp: 2000}
	engCtx := &common.EngineContext{
		TxContext: &common.TxContext{
			Ctx:          ctx,
			TxID:         "2222",
			Caller:       sender.Hex(),
			BlockContext: block2,
		},
	}
	require.NoError(t, transferTokens(engCtx, app, id, sender, recipient, transferAmount))

	// 4. Get History for Sender
	var history []*HistoryRecord
	err = getHistory(ctx, app, id, sender, 10, 0, func(rec *HistoryRecord) error {
		history = append(history, rec)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, history, 2)

	// Verify order (Newest first)
	require.Equal(t, "transfer", history[0].Type)
	require.Equal(t, int64(200), history[0].BlockHeight)
	require.Equal(t, "deposit", history[1].Type)
	require.Equal(t, int64(100), history[1].BlockHeight)

	// 5. Get History for Recipient
	history = nil
	err = getHistory(ctx, app, id, recipient, 10, 0, func(rec *HistoryRecord) error {
		history = append(history, rec)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Equal(t, "transfer", history[0].Type)
}
