//go:build kwiltest

package erc20

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/abigen"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

var (
	// Parse RewardDistributor ABI once for all tests
	rewardDistributorABI = func() abi.ABI {
		parsed, err := abi.JSON(strings.NewReader(abigen.RewardDistributorMetaData.ABI))
		if err != nil {
			panic(err)
		}
		return parsed
	}()

	// Get Deposit event signature programmatically (same for both contracts)
	depositEventID = rewardDistributorABI.Events["Deposit"].ID
)

// TestApplyDepositLog verifies that applyDepositLog credits the deposit recipient.
func TestApplyDepositLog(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()

	app := setup(t, tx)

	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("11155111")
	if !ok {
		t.Fatalf("missing chain info for test chain")
	}

	upd := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, upd))

	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	}))

	recipient := ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc")
	amount := big.NewInt(1_500_000_000_000_000_000)

	var data [64]byte
	copy(data[32-len(recipient.Bytes()):32], recipient.Bytes())
	copy(data[64-len(amount.Bytes()):], amount.Bytes())

	depositLog := ethtypes.Log{
		Address: upd.EscrowAddress,
		Topics: []ethcommon.Hash{
			depositEventID, // Programmatically derived from ABI
		},
		Data: data[:],
		TxHash: ethcommon.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		BlockNumber: 12345,
	}

	block := &common.BlockContext{
		Height:    100,
		Timestamp: 1600000000,
	}

	require.NoError(t, applyDepositLog(ctx, app, id, depositLog, block))

	balRecipient, err := balanceOf(ctx, app, id, recipient)
	require.NoError(t, err)
	require.NotNil(t, balRecipient)
	require.Equal(t, amount.String(), balRecipient.String())

	// Verify transaction history
	res, err := app.DB.Execute(ctx, "SELECT * FROM kwil_erc20_meta.transaction_history WHERE to_address = $1", recipient.Bytes())
	require.NoError(t, err)
	require.Len(t, res.Rows, 1)
	require.Equal(t, "deposit", res.Rows[0][2]) // type
	require.Equal(t, amount.String(), res.Rows[0][5].(*types.Decimal).String()) // amount (as *types.Decimal)
	require.Equal(t, depositLog.TxHash.Bytes(), res.Rows[0][7]) // external_tx_hash
	require.Equal(t, int64(100), res.Rows[0][9]) // block_height
	require.Equal(t, int64(1600000000), res.Rows[0][10]) // block_timestamp
	require.Equal(t, int64(12345), res.Rows[0][11]) // external_block_height

	other := ethcommon.HexToAddress("0x00000000000000000000000000000000000000dd")
	balOther, err := balanceOf(ctx, app, id, other)
	require.NoError(t, err)
	require.Nil(t, balOther)
}

// TestApplyDepositLog_TrufNetworkBridge verifies that applyDepositLog correctly handles
// TrufNetworkBridge Deposit events (indexed recipient, 32-byte data).
func TestApplyDepositLog_TrufNetworkBridge(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()

	app := setup(t, tx)

	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("11155111")
	if !ok {
		t.Fatalf("missing chain info for test chain")
	}

	upd := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, upd))

	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	}))

	recipient := ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc")
	amount := big.NewInt(2_500_000_000_000_000_000) // 2.5 tokens (18 decimals)

	// TrufNetworkBridge format: indexed recipient (in topics), amount only in data (32 bytes)
	var data [32]byte
	copy(data[32-len(amount.Bytes()):], amount.Bytes())

	depositLog := ethtypes.Log{
		Address: upd.EscrowAddress,
		Topics: []ethcommon.Hash{
			depositEventID,                           // Event signature (same for both contracts)
			ethcommon.BytesToHash(recipient.Bytes()), // Indexed recipient parameter
		},
		Data: data[:],
		TxHash: ethcommon.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
	}

	block := &common.BlockContext{
		Height:    200,
		Timestamp: 1600000200,
	}

	require.NoError(t, applyDepositLog(ctx, app, id, depositLog, block))

	balRecipient, err := balanceOf(ctx, app, id, recipient)
	require.NoError(t, err)
	require.NotNil(t, balRecipient)
	require.Equal(t, amount.String(), balRecipient.String())

	other := ethcommon.HexToAddress("0x00000000000000000000000000000000000000dd")
	balOther, err := balanceOf(ctx, app, id, other)
	require.NoError(t, err)
	require.Nil(t, balOther)
}

// TestApplyDepositLog_BothFormats verifies that both RewardDistributor and TrufNetworkBridge
// deposit events can be processed correctly in the same instance.
func TestApplyDepositLog_BothFormats(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()

	app := setup(t, tx)

	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("11155111")
	if !ok {
		t.Fatalf("missing chain info for test chain")
	}

	upd := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, upd))

	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	}))

	// User 1: RewardDistributor deposit (non-indexed recipient)
	recipient1 := ethcommon.HexToAddress("0x00000000000000000000000000000000000001aa")
	amount1 := big.NewInt(1_000_000_000_000_000_000) // 1 token

	var data1 [64]byte
	copy(data1[32-len(recipient1.Bytes()):32], recipient1.Bytes())
	copy(data1[64-len(amount1.Bytes()):], amount1.Bytes())

	depositLog1 := ethtypes.Log{
		Address: upd.EscrowAddress,
		Topics:  []ethcommon.Hash{depositEventID},
		Data:    data1[:],
		TxHash:  ethcommon.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
	}

	block := &common.BlockContext{
		Height:    300,
		Timestamp: 1600000300,
	}

	require.NoError(t, applyDepositLog(ctx, app, id, depositLog1, block))

	// User 2: TrufNetworkBridge deposit (indexed recipient)
	recipient2 := ethcommon.HexToAddress("0x00000000000000000000000000000000000002bb")
	amount2 := big.NewInt(3_000_000_000_000_000_000) // 3 tokens

	var data2 [32]byte
	copy(data2[32-len(amount2.Bytes()):], amount2.Bytes())

	depositLog2 := ethtypes.Log{
		Address: upd.EscrowAddress,
		Topics: []ethcommon.Hash{
			depositEventID,
			ethcommon.BytesToHash(recipient2.Bytes()),
		},
		Data: data2[:],
		TxHash: ethcommon.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
	}

	require.NoError(t, applyDepositLog(ctx, app, id, depositLog2, block))

	// Verify both deposits were processed correctly
	bal1, err := balanceOf(ctx, app, id, recipient1)
	require.NoError(t, err)
	require.NotNil(t, bal1)
	require.Equal(t, amount1.String(), bal1.String())

	bal2, err := balanceOf(ctx, app, id, recipient2)
	require.NoError(t, err)
	require.NotNil(t, bal2)
	require.Equal(t, amount2.String(), bal2.String())
}

// TestApplyDepositLog_InvalidFormat verifies that malformed deposit events are rejected.
func TestApplyDepositLog_InvalidFormat(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()

	app := setup(t, tx)

	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("11155111")
	if !ok {
		t.Fatalf("missing chain info for test chain")
	}

	upd := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
		DistributionPeriod: 3600,
	}

	require.NoError(t, createNewRewardInstance(ctx, app, upd))

	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	}))

	// Test case 1: Invalid data length (16 bytes - neither 32 nor 64)
	invalidLog1 := ethtypes.Log{
		Address: upd.EscrowAddress,
		Topics:  []ethcommon.Hash{depositEventID},
		Data:    make([]byte, 16),
	}

	block := &common.BlockContext{}

	err = applyDepositLog(ctx, app, id, invalidLog1, block)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown Deposit event format")

	// Test case 2: Invalid data length (96 bytes - too long)
	invalidLog2 := ethtypes.Log{
		Address: upd.EscrowAddress,
		Topics:  []ethcommon.Hash{depositEventID},
		Data:    make([]byte, 96),
	}

	err = applyDepositLog(ctx, app, id, invalidLog2, block)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown Deposit event format")
}
