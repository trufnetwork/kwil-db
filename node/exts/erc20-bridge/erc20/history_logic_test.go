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

// TestHistoryLogic verifies the end-to-end recording and status transitions
// of transaction history within the Kwil engine.
func TestHistoryLogic(t *testing.T) {
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

	// 1. Setup Instance
	instanceID := newUUID()
	chainInfo, _ := chains.GetChainInfoByID("1")
	testReward := &userProvidedData{
		ID:                 instanceID,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x123"),
		DistributionPeriod: 3600,
	}
	err = createNewRewardInstance(ctx, app, testReward)
	require.NoError(t, err)

	err = setRewardSynced(ctx, app, instanceID, 100, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0xTOKEN"),
		Erc20Decimals: 18,
	})
	require.NoError(t, err)

	epoch := &PendingEpoch{
		ID:          newUUID(),
		StartHeight: 1,
		StartTime:   1000,
	}
	err = createEpoch(ctx, app, epoch, instanceID)
	require.NoError(t, err)

	// 2. Test Deposit History
	testWallet := ethcommon.HexToAddress("0xABC")
	depositAmount := big.NewInt(1000)
	txHash := ethcommon.HexToHash("0xDEPOSIT_TX")
	
	depositLog := ethtypes.Log{
		Address:     testReward.EscrowAddress,
		Topics:      []ethcommon.Hash{depositEventHash, ethcommon.BytesToHash(testWallet.Bytes())},
		Data:        ethcommon.LeftPadBytes(depositAmount.Bytes(), 32),
		BlockNumber: 500,
		TxHash:      txHash,
		Index:       0,
	}

	blockCtx := &common.BlockContext{
		Height:    10,
		Timestamp: 1050,
	}

	err = applyDepositLog(ctx, app, instanceID, depositLog, blockCtx)
	require.NoError(t, err)

	// Verify Deposit record
	var records []*HistoryRecord
	err = getHistory(ctx, app, instanceID, testWallet, 10, 0, func(rec *HistoryRecord) error {
		records = append(records, rec)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "deposit", records[0].Type)
	require.Equal(t, "completed", records[0].Status)
	require.Equal(t, txHash.Bytes(), records[0].ExternalTxHash)
	require.Equal(t, int64(500), *records[0].ExternalBlockHeight)

	// 3. Test Withdrawal History (pending_epoch -> completed -> claimed)
	withdrawAmount, _ := types.ParseDecimalExplicit("500", 78, 0)
	withdrawalTxID := " withdrawal_tx_internal" // simplified hex
	withdrawalTxID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	
	// Withdrawal starts as 'pending_epoch'
	// Manually trigger the withdrawal history recording logic 
	err = lockAndIssue(ctx, app, instanceID, epoch.ID, testWallet, testWallet, withdrawAmount)
	require.NoError(t, err)
	
	// Record history manually to verify the SQL transitions
	internalTxHash, _ := hex.DecodeString(withdrawalTxID)
	txHistoryID := types.NewUUIDV5WithNamespace(
		types.NewUUIDV5WithNamespace(*instanceID, epoch.ID.Bytes()),
		append(append(append([]byte("withdrawal"), testWallet.Bytes()...), testWallet.Bytes()...), internalTxHash...))

	_, err = app.DB.Execute(ctx, `
		INSERT INTO kwil_erc20_meta.transaction_history
		(id, instance_id, type, from_address, to_address, amount, internal_tx_hash, status, block_height, block_timestamp, epoch_id)
		VALUES ($1, $2, 'withdrawal', $3, $4, $5, $6, 'pending_epoch', $7, $8, $9)
	`, txHistoryID, instanceID, testWallet.Bytes(), testWallet.Bytes(), withdrawAmount, internalTxHash, 20, 1100, epoch.ID)
	require.NoError(t, err)

	// Verify status is pending_epoch
	records = nil
	err = getHistory(ctx, app, instanceID, testWallet, 10, 0, func(rec *HistoryRecord) error {
		records = append(records, rec)
		return nil
	})
	require.NoError(t, err)
	foundWithdrawal := false
	for _, r := range records {
		if r.Type == "withdrawal" {
			require.Equal(t, "pending_epoch", r.Status)
			foundWithdrawal = true
		}
	}
	require.True(t, foundWithdrawal)

	// Finalize and Confirm Epoch -> Should move to 'completed'
	rewardRoot := []byte{0xEE}
	blockHash := [32]byte{0xBB}
	err = finalizeEpoch(ctx, app, epoch.ID, 30, blockHash[:], rewardRoot, withdrawAmount)
	require.NoError(t, err)
	
	err = confirmEpoch(ctx, app, rewardRoot)
	require.NoError(t, err)

	// Verify status is now 'completed'
	records = nil
	err = getHistory(ctx, app, instanceID, testWallet, 10, 0, func(rec *HistoryRecord) error {
		records = append(records, rec)
		return nil
	})
	require.NoError(t, err)
	for _, r := range records {
		if r.Type == "withdrawal" {
			require.Equal(t, "completed", r.Status, "withdrawal should be completed after epoch confirmation")
		}
	}

	// 4. Test Claimed Status (completed -> claimed)
	externalClaimTx := ethcommon.HexToHash("0xEXTERNAL_CLAIM")
	err = updateWithdrawalStatus(ctx, app, instanceID, testWallet, blockHash, externalClaimTx.Bytes(), 600, 1200)
	require.NoError(t, err)

	// Verify status is now 'claimed'
	records = nil
	err = getHistory(ctx, app, instanceID, testWallet, 10, 0, func(rec *HistoryRecord) error {
		records = append(records, rec)
		return nil
	})
	require.NoError(t, err)
	for _, r := range records {
		if r.Type == "withdrawal" {
			require.Equal(t, "claimed", r.Status)
			require.Equal(t, externalClaimTx.Bytes(), r.ExternalTxHash)
			require.Equal(t, int64(600), *r.ExternalBlockHeight)
		}
	}
}

var depositEventHash = ethcommon.HexToHash("0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c")
