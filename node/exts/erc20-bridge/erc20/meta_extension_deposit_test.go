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

	// Get Deposit event signature programmatically
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
	}

	require.NoError(t, applyDepositLog(ctx, app, id, depositLog))

	balRecipient, err := balanceOf(ctx, app, id, recipient)
	require.NoError(t, err)
	require.NotNil(t, balRecipient)
	require.Equal(t, amount.String(), balRecipient.String())

	other := ethcommon.HexToAddress("0x00000000000000000000000000000000000000dd")
	balOther, err := balanceOf(ctx, app, id, other)
	require.NoError(t, err)
	require.Nil(t, balOther)
}
