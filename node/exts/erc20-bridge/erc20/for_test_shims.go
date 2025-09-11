//go:build kwiltest

package erc20

import (
	"context"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	evmsync "github.com/trufnetwork/kwil-db/node/exts/evm-sync"
	chains "github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
	kwilTesting "github.com/trufnetwork/kwil-db/testing"
)

// ForTestingTransferListenerTopic returns the transfer listener unique topic name for a given instance id.
func ForTestingTransferListenerTopic(id types.UUID) string {
	return transferListenerUniqueName(id)
}

// ForTestingForceSyncInstance ensures the instance exists in DB (reward_instances + first epoch),
// registers the ordered-sync topic, and marks the instance as synced with ERC20 info (DB-only, idempotent).
func ForTestingForceSyncInstance(ctx context.Context, platform *kwilTesting.Platform, chainName, escrowAddr string, erc20Addr string, decimals int64) (*types.UUID, error) {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
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
	_ = orderedsync.ForTestingEnsureTopic(ctx, platform, topic, transferEventResolutionName)

	// derive chain info
	c := chains.Chain(chainName)
	_ = c.Valid()
	cinfo, ok := chains.GetChainInfo(c)
	if !ok {
		if ci, ok2 := chains.GetChainInfoByID(chainName); ok2 {
			cinfo = ci
		}
	}

	// check address is valid
	if !ethcommon.IsHexAddress(escrowAddr) {
		return nil, fmt.Errorf("invalid address: %s", escrowAddr)
	}
	if !ethcommon.IsHexAddress(erc20Addr) {
		return nil, fmt.Errorf("invalid address: %s", erc20Addr)
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
	// check address is valid
	if !ethcommon.IsHexAddress(user) {
		return fmt.Errorf("invalid address: %s", user)
	}
	addr := ethcommon.HexToAddress(user)
	return creditBalance(ctx, app, id, addr, amount)
}

// ForTestingInitializeExtension ensures the extension is properly initialized.
// This simulates calling the extension's OnStart method to load instances from DB.
func ForTestingInitializeExtension(ctx context.Context, platform *kwilTesting.Platform) error {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
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
func ForTestingEnsureExtensionRegistered(ctx context.Context, platform *kwilTesting.Platform) error {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
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

// ===== Additional test-only helpers to minimize coupling and avoid runtime collisions =====

// ForTestingUnregisterRuntimeFor unregisters state poller and transfer listener for the given chain/escrow.
func ForTestingUnregisterRuntimeFor(chain, escrow string) {
	id := uuidForChainAndEscrow(chain, escrow)
	_ = evmsync.StatePoller.UnregisterPoll(statePollerUniqueName(id))
	_ = evmsync.EventSyncer.UnregisterListener(transferListenerUniqueName(id))
}

// ForTestingSeedAndActivateInstance enables an instance by creating the alias, setting period/active and rehydrating, after unregistering runtimes.
// This includes creating an extension alias for convenient testing.
func ForTestingSeedAndActivateInstance(ctx context.Context, platform *kwilTesting.Platform, chain, escrow, erc20 string, decimals int64, periodSeconds int64, alias string) error {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
	// check address is valid
	if !ethcommon.IsHexAddress(alias) {
		return fmt.Errorf("invalid address: %s", alias)
	}
	if err := forTestingCreateExtensionAlias(ctx, platform, chain, escrow, alias); err != nil {
		return err
	}
	// check address is valid
	if !ethcommon.IsHexAddress(erc20) {
		return fmt.Errorf("invalid address: %s", erc20)
	}
	if _, err := ForTestingForceSyncInstance(ctx, platform, chain, escrow, erc20, decimals); err != nil {
		return err
	}
	// check period is valid
	if periodSeconds <= 0 {
		return fmt.Errorf("invalid period: %d", periodSeconds)
	}
	if err := ForTestingSetDistributionPeriod(ctx, app, chain, escrow, periodSeconds); err != nil {
		return err
	}
	return ForTestingInitializeExtension(ctx, platform)
}

// ForTestingDisableInstance disables an instance and tears down all runtimes deterministically.
// This includes unusing the extension alias for complete cleanup.
func ForTestingDisableInstance(ctx context.Context, platform *kwilTesting.Platform, chain, escrow, alias string) error {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
	// Unuse the extension alias first
	unuseSQL := fmt.Sprintf("UNUSE %s", alias)
	_ = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, unuseSQL, nil, nil) // ignore errors for idempotent behavior

	id := ForTestingGetInstanceID(chain, escrow)
	_, err := app.Engine.CallWithoutEngineCtx(ctx, app.DB, RewardMetaExtensionName, "disable", []any{id}, nil)
	if err != nil {
		// allow idempotent behavior in tests
		_ = err
	}
	ForTestingUnregisterRuntimeFor(chain, escrow)
	ForTestingResetSingleton()
	return ForTestingInitializeExtension(ctx, platform)
}

// forTestingCreateExtensionAlias creates an extension alias using the USE erc20 syntax.
// This executes the SQL command that creates the extension with the specified alias.
// The instance must already exist and be synced for this to work.
func forTestingCreateExtensionAlias(ctx context.Context, platform *kwilTesting.Platform, chain, escrow, alias string) error {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
	// Construct the USE erc20 SQL command
	sql := fmt.Sprintf("USE erc20 { chain: '%s', escrow: '%s' } AS %s", chain, escrow, alias)

	// Execute the SQL command
	err := app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, sql, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create extension alias %s: %w", alias, err)
	}

	return nil
}

// ForTestingClearAllInstances performs a comprehensive cleanup of ALL ERC20 runtime components.
func ForTestingClearAllInstances(ctx context.Context, platform *kwilTesting.Platform) error {
	return evmsync.ForTestingClearAllInstances(ctx, platform)
}
