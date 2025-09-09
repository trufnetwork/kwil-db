//go:build kwiltest

package erc20

import (
	"context"

	ethcommon "github.com/ethereum/go-ethereum/common"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	evmsync "github.com/trufnetwork/kwil-db/node/exts/evm-sync"
)

// ForTestingTransferListenerTopic returns the transfer listener unique topic name for a given instance id.
func ForTestingTransferListenerTopic(id types.UUID) string {
	return transferListenerUniqueName(id)
}

// ForTestingForceSyncInstance marks an instance as synced and active using the existing internals.
// It reuses createSchema, callPrepare and setRewardSynced to ensure consistency with production logic.
func ForTestingForceSyncInstance(ctx context.Context, app *common.App, chainName, escrowAddr string, erc20Addr string, decimals int64) (*types.UUID, error) {
	// ensure schema exists (ignore if already created)
	if err := createSchema(ctx, app); err != nil {
		// ignore duplicate creation errors
		// we rely on existing schema if present
	}

	// get deterministic id without needing SYSTEM call
	idVal := uuidForChainAndEscrow(chainName, escrowAddr)
	id := &idVal

	// register ordered-sync topic idempotently at engine level
	_ = evmsync.EventSyncer.RegisterNewTopic(ctx, app.DB, app.Engine, transferListenerUniqueName(*id), transferEventResolutionName)

	// mark synced with provided ERC20 info
	info := &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress(erc20Addr),
		Erc20Decimals: decimals,
	}
	if err := setRewardSynced(ctx, app, id, 1, info); err != nil {
		return nil, err
	}

	// DB state is sufficient for resolution tests; no in-memory mutation required

	return id, nil
}

// ForTestingCreditBalance credits a user's balance for the given instance using existing creditBalance.
func ForTestingCreditBalance(ctx context.Context, app *common.App, id *types.UUID, user string, amount *types.Decimal) error {
	addr := ethcommon.HexToAddress(user)
	return creditBalance(ctx, app, id, addr, amount)
}
