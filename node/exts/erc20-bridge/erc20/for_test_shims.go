//go:build kwiltest

package erc20

import (
	"context"

	ethcommon "github.com/ethereum/go-ethereum/common"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	chains "github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

// ForTestingTransferListenerTopic returns the transfer listener unique topic name for a given instance id.
func ForTestingTransferListenerTopic(id types.UUID) string {
	return transferListenerUniqueName(id)
}

// ForTestingForceSyncInstance ensures the instance exists in DB (reward_instances + first epoch),
// registers the ordered-sync topic, and marks the instance as synced with ERC20 info (DB-only, idempotent).
func ForTestingForceSyncInstance(ctx context.Context, app *common.App, chainName, escrowAddr string, erc20Addr string, decimals int64) (*types.UUID, error) {
	// Ensure kwil_erc20_meta namespace and schema exist
	probeErr := app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `{kwil_erc20_meta}SELECT 1 FROM meta`, nil, nil)
	if probeErr != nil {
		// Create namespace if missing, then create schema and set version
		_ = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `CREATE NAMESPACE IF NOT EXISTS kwil_erc20_meta`, nil, nil)
		if err := createSchema(ctx, app); err != nil {
			// ignore if already exists
		}
		_ = setVersionToCurrent(ctx, app)
	}

	// get deterministic id without needing SYSTEM call
	idVal := uuidForChainAndEscrow(chainName, escrowAddr)
	id := &idVal

	topic := transferListenerUniqueName(*id)
	_ = orderedsync.ForTestingEnsureTopic(ctx, app, topic, transferEventResolutionName)

	// derive chain info
	c := chains.Chain(chainName)
	_ = c.Valid()
	cinfo, ok := chains.GetChainInfo(c)
	if !ok {
		if ci, ok2 := chains.GetChainInfoByID(chainName); ok2 {
			cinfo = ci
		}
	}

	// idempotently create reward instance if missing
	exists := false
	_ = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
	{kwil_erc20_meta}SELECT 1 FROM reward_instances WHERE id = $id
	`, map[string]any{"id": id}, func(r *common.Row) error {
		exists = true
		return nil
	})
	if !exists {
		upd := &userProvidedData{
			ID:                 id,
			ChainInfo:          &cinfo,
			EscrowAddress:      ethcommon.HexToAddress(escrowAddr),
			DistributionPeriod: 60,
		}
		if err := createNewRewardInstance(ctx, app, upd); err != nil {
			return nil, err
		}
	}

	// ensure there is at least one active epoch for this instance
	epochExists := false
	_ = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
	{kwil_erc20_meta}SELECT 1 FROM epochs WHERE instance_id = $id AND confirmed IS NOT TRUE LIMIT 1
	`, map[string]any{"id": id}, func(r *common.Row) error {
		epochExists = true
		return nil
	})
	if !epochExists {
		if err := createEpoch(ctx, app, newPendingEpoch(id, &common.BlockContext{Height: 1, Timestamp: 1}), id); err != nil {
			return nil, err
		}
	}

	// mark synced with provided ERC20 info (safe to re-run)
	info := &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress(erc20Addr),
		Erc20Decimals: decimals,
	}
	if err := setRewardSynced(ctx, app, id, 1, info); err != nil {
		return nil, err
	}

	return id, nil
}

// ForTestingCreditBalance credits a user's balance for the given instance using existing creditBalance.
func ForTestingCreditBalance(ctx context.Context, app *common.App, id *types.UUID, user string, amount *types.Decimal) error {
	addr := ethcommon.HexToAddress(user)
	return creditBalance(ctx, app, id, addr, amount)
}

// ForTestingInitializeExtension ensures the extension is properly initialized.
// This simulates calling the extension's OnStart method to load instances from DB.
func ForTestingInitializeExtension(ctx context.Context, app *common.App) error {
	// Load all stored reward instances from DB and put them in singleton
	instances, err := getStoredRewardInstances(ctx, app)
	if err != nil {
		return err
	}

	// Simulate OnStart behavior: load instances into singleton
	for _, instance := range instances {
		// Ensure ownedBalance is initialized to zero to avoid nil dereference in tests
		if instance.ownedBalance == nil {
			instance.ownedBalance = types.MustParseDecimalExplicit("0", 78, 0)
		}

		// Always mark instance as synced for tests
		instance.synced = true
		// Always update the instance in the singleton (overwrite if exists)
		_SINGLETON.instances.Set(*instance.ID, instance)
	}

	return nil
}

// ForTestingEnsureExtensionRegistered ensures the extension is properly registered
// and its methods are available for calling.
func ForTestingEnsureExtensionRegistered(ctx context.Context, app *common.App) error {
	// Try to call a simple extension method to ensure it's registered
	_, err := app.Engine.CallWithoutEngineCtx(ctx, app.DB, "kwil_erc20_meta", "list", []any{}, func(row *common.Row) error {
		return nil
	})
	return err
}

// ForTestingResetSingleton resets the test singleton to a clean state.
// This should be called at the beginning of each test to ensure isolation.
func ForTestingResetSingleton() {
	// Completely reinitialize the singleton to ensure clean state
	_SINGLETON = &extensionInfo{instances: newInstanceMap()}
}

// ForTestingResetSingletonForEscrow resets only the specific instance for the given escrow.
// This allows multiple tests to run with different escrows without conflicts.
func ForTestingResetSingletonForEscrow(escrowAddr string) {
	if _SINGLETON == nil {
		_SINGLETON = &extensionInfo{instances: newInstanceMap()}
	}
	// Generate the same ID that would be created for this escrow
	id := uuidForChainAndEscrow("sepolia", escrowAddr)
	_SINGLETON.instances.Delete(id)
}

// ForTestingActivateAndInitialize ensures an instance exists, sets distribution period (activates),
// and hydrates the singleton so it's active+synced in-memory for tests.
// This is a convenience wrapper to avoid state drift between DB and singleton.
func ForTestingActivateAndInitialize(ctx context.Context, app *common.App, chainName, escrowAddr string, erc20Addr string, decimals int64, distributionPeriodSeconds int64) error {
	// Ensure instance exists and is marked synced in DB (idempotent)
	if _, err := ForTestingForceSyncInstance(ctx, app, chainName, escrowAddr, erc20Addr, decimals); err != nil {
		return err
	}

	// Set period and activate in DB (idempotent)
	if err := ForTestingSetDistributionPeriod(ctx, app, chainName, escrowAddr, distributionPeriodSeconds); err != nil {
		return err
	}

	// Hydrate singleton to reflect DB state
	return ForTestingInitializeExtension(ctx, app)
}
