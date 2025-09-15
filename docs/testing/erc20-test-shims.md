# ERC20 Test Shims Documentation

Comprehensive guide for using ERC20 extension test shims to effectively test ERC20 bridge functionality, epoch management, and reward distribution systems.

## Overview

The ERC20 test shims provide a testing framework for the ERC20 bridge extension that enables developers to:
- Set up and manage ERC20 reward instances
- Test epoch finalization and confirmation workflows
- Credit user balances and test reward distribution
- Manage extension lifecycle and cleanup between tests
- Test complete ERC20 bridge scenarios without external dependencies

## Prerequisites

### Required Imports

```go
import (
    "context"
    "github.com/trufnetwork/kwil-db/common"
    "github.com/trufnetwork/kwil-db/core/types"
    "github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/erc20"
    kwilTesting "github.com/trufnetwork/kwil-db/testing"
)
```

## Why Use Test Shims vs Plain SQL?

The ERC20 bridge extension has complex runtime wiring beyond SQL that requires proper initialization:

**Runtime Components:**
- Background ordered-sync topics/listeners for `Transfer` events
- State pollers for blockchain monitoring
- Singleton cache rehydrated on start
- Epoch lifecycle management
- Synced ERC20 metadata storage

**Plain SQL Limitations:**
- `USE erc20 { ... } AS alias` only creates the alias
- Doesn't initialize background components
- Missing schema/instance setup
- No singleton state management
- Leads to "already active"/missing-wiring failures

**Test Shims Benefits:**
- Production-faithful initialization
- Deterministic setup within test transactions
- Proper cleanup and isolation
- No external blockchain dependencies
- Complete extension lifecycle management

## Core Concepts

### Instance Lifecycle
- **Instance**: Represents an ERC20 bridge configuration for a specific chain and escrow contract
- **Instance ID**: Deterministic UUID based on chain name and escrow address
- **Sync State**: Instances must be synced with ERC20 contract info before use

### Epoch Management
- **Epochs**: Time-based periods for reward accumulation and distribution
- **Finalization**: Process of computing merkle root and ending an epoch
- **Confirmation**: Process of confirming finalized epochs for on-chain settlement

### Test Isolation
- **Singleton Reset**: Clean state management between tests
- **Runtime Cleanup**: Proper cleanup of background processes and listeners

## Function Reference

### Instance Management

#### `ForTestingForceSyncInstance`
Creates and configures a reward instance with ERC20 information.

```go
func ForTestingForceSyncInstance(ctx context.Context, platform *kwilTesting.Platform,
    chainName, escrowAddr string, erc20Addr string, decimals int64) (*types.UUID, error)
```

**Purpose**: Sets up a complete ERC20 instance for testing including:
- Database schema creation
- Instance registration with deterministic ID
- ERC20 contract synchronization
- First epoch creation
- Ordered-sync topic registration

**Example**:
```go
instanceID, err := erc20.ForTestingForceSyncInstance(ctx, platform,
    "ethereum", "0x1234567890123456789012345678901234567890",
    "0xA0b86a33E6441E47d4a71b34000000000000000", 18)
require.NoError(t, err)
```

#### `ForTestingInitializeExtension`
Loads instances from database into extension memory.

```go
func ForTestingInitializeExtension(ctx context.Context, platform *kwilTesting.Platform) error
```

**Purpose**: Simulates the extension's OnStart method to:
- Load stored reward instances from DB
- Initialize singleton state with instances
- Mark instances as synced for testing
- Prepare instances for use in tests

#### `ForTestingResetSingleton`
Resets extension singleton to clean state.

```go
func ForTestingResetSingleton()
```

**Purpose**: Ensures test isolation by completely reinitializing the extension singleton. **Must be called at the beginning of each test**.

### Instance Utilities

#### `ForTestingGetInstanceID`
Returns deterministic instance ID for chain and escrow pair.

```go
func ForTestingGetInstanceID(chain, escrow string) *types.UUID
```

#### `ForTestingSetDistributionPeriod`
Sets the distribution period (seconds) for an instance.

```go
func ForTestingSetDistributionPeriod(ctx context.Context, app *common.App,
    chain, escrow string, seconds int64) error
```

### Epoch Operations

#### `ForTestingFinalizeCurrentEpoch`
Finalizes the current epoch by computing merkle root and creating next epoch.

```go
func ForTestingFinalizeCurrentEpoch(ctx context.Context, app *common.App,
    chain, escrow string, endHeight int64, endHash [32]byte) error
```

**Purpose**:
- Computes merkle tree from rewards in current epoch
- Finalizes epoch with merkle root and total amount
- Creates next pending epoch
- Requires rewards to be present in current epoch

#### `ForTestingConfirmAllFinalizedEpochs`
Confirms all finalized epochs for an instance.

```go
func ForTestingConfirmAllFinalizedEpochs(ctx context.Context, app *common.App,
    chain, escrow string) error
```

**Purpose**: Marks finalized epochs as confirmed, simulating on-chain confirmation process.

#### `ForTestingFinalizeAndConfirmCurrentEpoch`
Convenience wrapper that finalizes and confirms current epoch.

```go
func ForTestingFinalizeAndConfirmCurrentEpoch(ctx context.Context, platform *kwilTesting.Platform,
    chain, escrow string, endHeight int64, endHash [32]byte) error
```

**Purpose**:
- Pre-validates that current epoch has rewards
- Finalizes current epoch
- Confirms all finalized epochs
- Post-validates that at least one epoch was confirmed

### Balance & Rewards

#### `ForTestingCreditBalance`
Credits a user's balance for testing reward scenarios.

```go
func ForTestingCreditBalance(ctx context.Context, app *common.App,
    id *types.UUID, user string, amount *types.Decimal) error
```

**Purpose**: Directly credits user balance bypassing normal reward mechanisms.

**Example**:
```go
amount := types.MustParseDecimalExplicit("100.5", 78, 0)
err := erc20.ForTestingCreditBalance(ctx, app, instanceID,
    "0x1234567890123456789012345678901234567890", amount)
require.NoError(t, err)
```

#### `ForTestingLockAndIssueDirect`
Atomically locks tokens and issues rewards into current epoch.

```go
func ForTestingLockAndIssueDirect(ctx context.Context, platform *kwilTesting.Platform,
    chain, escrow, from string, amountText string) error
```

**Purpose**: Simulates the complete lock-and-issue flow for testing epoch reward accumulation.

### Advanced Instance Management

#### `ForTestingSeedAndActivateInstance`
Complete instance setup including extension alias creation.

```go
func ForTestingSeedAndActivateInstance(ctx context.Context, platform *kwilTesting.Platform,
    chain, escrow, erc20 string, decimals int64, periodSeconds int64, alias string) error
```

**Purpose**:
- Creates extension alias using `USE erc20` syntax
- Forces instance sync
- Sets distribution period
- Initializes extension

#### `ForTestingDisableInstance`
Completely disables an instance and cleans up all resources.

```go
func ForTestingDisableInstance(ctx context.Context, platform *kwilTesting.Platform,
    chain, escrow, alias string) error
```

### Cleanup Utilities

#### `ForTestingClearAllInstances`
Comprehensive cleanup of ALL ERC20 runtime components.

```go
func ForTestingClearAllInstances(ctx context.Context, platform *kwilTesting.Platform) error
```

## Complete Code Examples

### Basic Instance Setup and Testing

```go
//go:build kwiltest

func TestERC20BasicFlow(t *testing.T) {
    // Clean state
    erc20.ForTestingResetSingleton()

    ctx := context.Background()
    platform := setupTestPlatform(t) // Your platform setup
    defer platform.Close()

    // Create and sync instance
    instanceID, err := erc20.ForTestingForceSyncInstance(ctx, platform,
        "ethereum", "0x1234567890123456789012345678901234567890",
        "0xA0b86a33E6441E47d4a71b34000000000000000", 18)
    require.NoError(t, err)

    // Initialize extension
    err = erc20.ForTestingInitializeExtension(ctx, platform)
    require.NoError(t, err)

    // Your test logic here...
}
```

### Epoch Management Workflow

```go
func TestEpochFinalization(t *testing.T) {
    erc20.ForTestingResetSingleton()

    ctx := context.Background()
    platform := setupTestPlatform(t)
    defer platform.Close()

    chain := "ethereum"
    escrow := "0x1234567890123456789012345678901234567890"
    erc20Addr := "0xA0b86a33E6441E47d4a71b34000000000000000"

    // Setup instance
    instanceID, err := erc20.ForTestingForceSyncInstance(ctx, platform,
        chain, escrow, erc20Addr, 18)
    require.NoError(t, err)

    err = erc20.ForTestingInitializeExtension(ctx, platform)
    require.NoError(t, err)

    // Add rewards to current epoch
    app := &common.App{DB: platform.DB, Engine: platform.Engine}
    amount := types.MustParseDecimalExplicit("100.0", 78, 0)
    err = erc20.ForTestingCreditBalance(ctx, app, instanceID,
        "0x1111111111111111111111111111111111111111", amount)
    require.NoError(t, err)

    // Finalize and confirm current epoch
    endHeight := int64(1000)
    endHash := [32]byte{0x01, 0x02, 0x03} // Example hash
    err = erc20.ForTestingFinalizeAndConfirmCurrentEpoch(ctx, platform,
        chain, escrow, endHeight, endHash)
    require.NoError(t, err)
}
```

### Multi-Instance Test Scenario

```go
func TestMultipleInstances(t *testing.T) {
    erc20.ForTestingResetSingleton()

    ctx := context.Background()
    platform := setupTestPlatform(t)
    defer platform.Close()

    // Setup multiple instances
    instances := []struct {
        chain, escrow, erc20 string
        decimals int64
    }{
        {"ethereum", "0x1111111111111111111111111111111111111111", "0xAAA", 18},
        {"polygon", "0x2222222222222222222222222222222222222222", "0xBBB", 6},
    }

    var instanceIDs []*types.UUID
    for _, inst := range instances {
        id, err := erc20.ForTestingForceSyncInstance(ctx, platform,
            inst.chain, inst.escrow, inst.erc20, inst.decimals)
        require.NoError(t, err)
        instanceIDs = append(instanceIDs, id)
    }

    err := erc20.ForTestingInitializeExtension(ctx, platform)
    require.NoError(t, err)

    // Test operations on each instance...
}
```

### Complete Workflow with Extension Alias

```go
func TestCompleteWorkflowWithAlias(t *testing.T) {
    erc20.ForTestingResetSingleton()

    ctx := context.Background()
    platform := setupTestPlatform(t)
    defer platform.Close()

    chain := "ethereum"
    escrow := "0x1234567890123456789012345678901234567890"
    erc20Addr := "0xA0b86a33E6441E47d4a71b34000000000000000"
    alias := "my_erc20"

    // Complete setup with alias
    err := erc20.ForTestingSeedAndActivateInstance(ctx, platform,
        chain, escrow, erc20Addr, 18, 3600, alias)
    require.NoError(t, err)

    // Use extension via alias
    app := &common.App{DB: platform.DB, Engine: platform.Engine}
    results, err := app.Engine.CallWithoutEngineCtx(ctx, app.DB,
        alias, "list", []any{}, nil)
    require.NoError(t, err)

    // Test lock and issue
    err = erc20.ForTestingLockAndIssueDirect(ctx, platform,
        chain, escrow, "0x1111111111111111111111111111111111111111", "50.0")
    require.NoError(t, err)

    // Cleanup
    defer func() {
        err := erc20.ForTestingDisableInstance(ctx, platform, chain, escrow, alias)
        require.NoError(t, err)
    }()
}
```

## Best Practices

### Test Isolation
1. **Always call `ForTestingResetSingleton()`** at the beginning of each test
2. Use `ForTestingClearAllInstances()` for comprehensive cleanup between test suites
3. Defer cleanup functions to ensure proper resource cleanup even if tests fail

```go
func TestExample(t *testing.T) {
    erc20.ForTestingResetSingleton()
    defer func() {
        err := erc20.ForTestingClearAllInstances(ctx, platform)
        require.NoError(t, err)
    }()
    // ... test logic
}
```

### Address Validation
All functions validate Ethereum addresses. Use proper hex format:
```go
// Correct
escrowAddr := "0x1234567890123456789012345678901234567890"

// Incorrect - will cause validation errors
escrowAddr := "1234567890123456789012345678901234567890"
```

### Amount Handling
Use the types.Decimal system for precise amount handling:
```go
// For balance operations
amount := types.MustParseDecimalExplicit("100.5", 78, 0)

// For lock and issue operations (string format)
err := ForTestingLockAndIssueDirect(ctx, platform, chain, escrow, user, "100.5")
```

### Error Handling Patterns
Most functions return meaningful errors. Always check for specific conditions:
```go
err := erc20.ForTestingFinalizeAndConfirmCurrentEpoch(ctx, platform, chain, escrow, height, hash)
if err != nil {
    if strings.Contains(err.Error(), "no rewards in current epoch") {
        // Handle case where epoch is empty
        t.Skip("Epoch has no rewards to finalize")
    }
    require.NoError(t, err)
}
```

## Common Testing Patterns

### Production-Faithful Test Pattern (Recommended)
Based on the production test suite, use transaction-based isolation:

```go
func TestERC20Feature(t *testing.T) {
    seedAndRun(t, "test_name", func(ctx context.Context, platform *kwilTesting.Platform) error {
        // Enable instance with alias in one step
        err := erc20.ForTestingSeedAndActivateInstance(ctx, platform,
            "ethereum", "0x1234567890123456789012345678901234567890",
            "0xA0b86a33E6441E47d4a71b34000000000000000", 18, 60, "test_alias")
        require.NoError(t, err)

        // Your test logic here
        return nil
    })
}

// Helper function for proper test isolation
func seedAndRun(t *testing.T, name string, fn kwilTesting.TestFunc) {
    wrappedFn := func(ctx context.Context, platform *kwilTesting.Platform) error {
        // Register cleanup (runs after transaction rollback)
        t.Cleanup(func() {
            erc20.ForTestingClearAllInstances(ctx, platform)
            erc20.ForTestingResetSingleton()
        })

        // Run test inside transaction for rollback isolation
        tx, err := platform.DB.BeginTx(ctx)
        if err != nil {
            return fmt.Errorf("begin tx: %w", err)
        }
        defer tx.Rollback(ctx)

        txPlatform := &kwilTesting.Platform{
            DB: tx, Engine: platform.Engine,
        }
        return fn(ctx, txPlatform)
    }

    kwilTesting.RunSchemaTest(t, kwilTesting.SchemaTest{
        Name: name,
        FunctionTests: []kwilTesting.TestFunc{wrappedFn},
    }, &kwilTesting.Options{UseTestContainer: true})
}
```

### Simple Setup Pattern (Alternative)
For simpler tests without transaction isolation:
```go
func TestPattern(t *testing.T) {
    // Setup
    erc20.ForTestingResetSingleton()
    ctx := context.Background()
    platform := setupTestPlatform(t)
    defer platform.Close()

    // Test operations
    instanceID, err := erc20.ForTestingForceSyncInstance(/*...*/)
    require.NoError(t, err)

    err = erc20.ForTestingInitializeExtension(ctx, platform)
    require.NoError(t, err)

    // Cleanup
    defer func() {
        err := erc20.ForTestingClearAllInstances(ctx, platform)
        require.NoError(t, err)
    }()
}
```

### Instance ID Consistency
```go
// Get consistent instance ID across function calls
chain, escrow := "ethereum", "0x1234567890123456789012345678901234567890"

// These will return the same UUID
id1, _ := erc20.ForTestingForceSyncInstance(ctx, platform, chain, escrow, erc20Addr, 18)
id2 := erc20.ForTestingGetInstanceID(chain, escrow)
// id1 and id2 are equal
```

## Troubleshooting

### Common Issues

#### "instance or current epoch not found"
```go
// Ensure proper setup order:
instanceID, err := erc20.ForTestingForceSyncInstance(/*...*/) // Creates instance
require.NoError(t, err)

err = erc20.ForTestingInitializeExtension(ctx, platform) // Loads into memory
require.NoError(t, err)

// Now epoch operations will work
```

#### "no rewards in current epoch; cannot finalize"
```go
// Add rewards before finalizing
app := &common.App{DB: platform.DB, Engine: platform.Engine}
amount := types.MustParseDecimalExplicit("1.0", 78, 0)
err := erc20.ForTestingCreditBalance(ctx, app, instanceID, userAddr, amount)
require.NoError(t, err)

// Now finalization will work
err = erc20.ForTestingFinalizeAndConfirmCurrentEpoch(/*...*/)
require.NoError(t, err)
```

#### "namespace not found" errors
```go
// Ensure ordered-sync namespace exists
err := orderedsync.ForTestingEnsureNamespace(ctx, platform)
require.NoError(t, err)

// Then proceed with ERC20 operations
```

### Performance Considerations

1. **Minimize instance creation**: Reuse instances across test cases when possible
2. **Use transaction rollback**: Let database transactions handle cleanup when appropriate
3. **Batch operations**: Group related operations in single transactions

### Integration with kwilTesting Framework

The ERC20 test shims are designed to work seamlessly with the kwilTesting framework:

```go
import (
    "github.com/trufnetwork/kwil-db/testing"
)

func TestWithKwilTesting(t *testing.T) {
    options := &testing.Options{
        UseTestContainer: true,
    }

    testing.RunSchemaTest(t, testing.SchemaTest{
        Name: "ERC20 Integration Test",
        FunctionTests: []testing.TestFunc{
            func(ctx context.Context, platform *testing.Platform) error {
                erc20.ForTestingResetSingleton()

                // Your ERC20 test logic using the shims
                instanceID, err := erc20.ForTestingForceSyncInstance(ctx, platform,
                    "ethereum", "0x1234567890123456789012345678901234567890",
                    "0xA0b86a33E6441E47d4a71b34000000000000000", 18)
                if err != nil {
                    return err
                }

                return erc20.ForTestingInitializeExtension(ctx, platform)
            },
        },
    }, options)
}
```

## Additional Resources

### Related Extensions

The ERC20 test shims integrate with other extension test shims:

- **EVM-Sync**: `evmsync.ForTestingMakeTransferLog()`, `evmsync.ForTestingClearAllInstances()`
- **Ordered-Sync**: `orderedsync.ForTestingEnsureTopic()`, `orderedsync.ForTestingStoreLogs()`
- **Core Types**: `types.BigIntToHash32()` for hash conversion utilities

## Summary

The ERC20 test shims provide comprehensive testing capabilities for the ERC20 bridge extension. Key takeaways:

1. **Always reset singleton state** between tests for proper isolation
2. **Follow the setup pattern**: Force sync → Initialize → Test → Cleanup
3. **Validate addresses and amounts** using proper formats
4. **Handle epoch workflows** by ensuring rewards exist before finalization
5. **Use cleanup functions** to prevent resource leaks between tests

This testing framework enables thorough validation of ERC20 bridge functionality without requiring external blockchain networks or complex setup procedures.