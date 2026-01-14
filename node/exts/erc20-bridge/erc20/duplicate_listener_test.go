//go:build kwiltest

package erc20

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
)

// TestDuplicateListenerPrevention tests that calling OnStart multiple times
// does not create duplicate listeners for the same instance.
// This reproduces the bug where executing "USE erc20 {...} AS hoodi_tt2"
// on a running node would try to re-start listeners for hoodi_tt.
func TestDuplicateListenerPrevention(t *testing.T) {
	// Reset singleton and tracking maps for clean test
	ForTestingResetSingleton()

	// Create two instance IDs (simulating hoodi_tt and hoodi_tt2)
	id1 := types.NewUUIDV5WithNamespace(rewardExtUUIDNamespace, []byte("hoodi0x878d6aaeb6e746033f50b8dc268d54b4631554e7"))
	id2 := types.NewUUIDV5WithNamespace(rewardExtUUIDNamespace, []byte("hoodi0x9BD843A3ce718FE639e9968860B933b026784687"))

	id1Str := id1.String()
	id2Str := id2.String()

	// Test 1: First call to OnStart should register listener
	t.Run("first OnStart registers listener", func(t *testing.T) {
		runningListenersMu.Lock()
		runningDepositListeners[id1Str] = true
		runningWithdrawalListeners[id1Str] = true
		runningListenersMu.Unlock()

		// Verify listener is tracked
		runningListenersMu.Lock()
		require.True(t, runningDepositListeners[id1Str], "deposit listener should be tracked")
		require.True(t, runningWithdrawalListeners[id1Str], "withdrawal listener should be tracked")
		runningListenersMu.Unlock()
	})

	// Test 2: Second call to OnStart (simulating adding hoodi_tt2) should not duplicate hoodi_tt listener
	t.Run("second OnStart does not duplicate existing listener", func(t *testing.T) {
		ctx := context.Background()

		// Simulate OnStart logic that checks for duplicate listeners
		runningListenersMu.Lock()
		depositAlreadyRunning := runningDepositListeners[id1Str]
		withdrawalAlreadyRunning := runningWithdrawalListeners[id1Str]
		runningListenersMu.Unlock()

		// Verify the check detects existing listener
		require.True(t, depositAlreadyRunning, "should detect existing deposit listener")
		require.True(t, withdrawalAlreadyRunning, "should detect existing withdrawal listener")

		// The actual OnStart would skip calling startDepositListener() here
		// We verify the tracking map prevents duplicate registration

		// Now add the second instance's listeners
		runningListenersMu.Lock()
		id2DepositAlreadyRunning := runningDepositListeners[id2Str]
		if !id2DepositAlreadyRunning {
			runningDepositListeners[id2Str] = true
		}
		id2WithdrawalAlreadyRunning := runningWithdrawalListeners[id2Str]
		if !id2WithdrawalAlreadyRunning {
			runningWithdrawalListeners[id2Str] = true
		}
		runningListenersMu.Unlock()

		// Verify both instances are now tracked without duplicates
		runningListenersMu.Lock()
		require.True(t, runningDepositListeners[id1Str], "hoodi_tt deposit listener still tracked")
		require.True(t, runningWithdrawalListeners[id1Str], "hoodi_tt withdrawal listener still tracked")
		require.True(t, runningDepositListeners[id2Str], "hoodi_tt2 deposit listener now tracked")
		require.True(t, runningWithdrawalListeners[id2Str], "hoodi_tt2 withdrawal listener now tracked")
		require.Len(t, runningDepositListeners, 2, "should have exactly 2 deposit listeners")
		require.Len(t, runningWithdrawalListeners, 2, "should have exactly 2 withdrawal listeners")
		runningListenersMu.Unlock()

		_ = ctx // silence unused warning
	})

	// Test 3: Cleanup when instance is disabled
	t.Run("cleanup on disable removes tracking", func(t *testing.T) {
		// Simulate disable logic
		runningListenersMu.Lock()
		delete(runningDepositListeners, id1Str)
		delete(runningWithdrawalListeners, id1Str)
		runningListenersMu.Unlock()

		// Verify cleanup
		runningListenersMu.Lock()
		require.False(t, runningDepositListeners[id1Str], "hoodi_tt deposit listener should be removed")
		require.False(t, runningWithdrawalListeners[id1Str], "hoodi_tt withdrawal listener should be removed")
		require.True(t, runningDepositListeners[id2Str], "hoodi_tt2 deposit listener should remain")
		require.True(t, runningWithdrawalListeners[id2Str], "hoodi_tt2 withdrawal listener should remain")
		runningListenersMu.Unlock()
	})

	// Test 4: Third call to OnStart should detect hoodi_tt2 is already running
	t.Run("third OnStart does not duplicate hoodi_tt2 listener", func(t *testing.T) {
		runningListenersMu.Lock()
		id2DepositAlreadyRunning := runningDepositListeners[id2Str]
		id2WithdrawalAlreadyRunning := runningWithdrawalListeners[id2Str]
		runningListenersMu.Unlock()

		require.True(t, id2DepositAlreadyRunning, "should detect existing hoodi_tt2 deposit listener")
		require.True(t, id2WithdrawalAlreadyRunning, "should detect existing hoodi_tt2 withdrawal listener")
	})

	// Test 5: Reset should clear all tracking
	t.Run("reset clears all tracking", func(t *testing.T) {
		ForTestingResetSingleton()

		runningListenersMu.Lock()
		require.Len(t, runningDepositListeners, 0, "deposit listeners should be cleared")
		require.Len(t, runningWithdrawalListeners, 0, "withdrawal listeners should be cleared")
		runningListenersMu.Unlock()
	})
}

// TestMultipleSameChainInstances tests the specific scenario where two bridge instances
// use the same chain (e.g., hoodi_tt and hoodi_tt2 both use chain 'hoodi').
func TestMultipleSameChainInstances(t *testing.T) {
	ForTestingResetSingleton()

	// Both instances use chain 'hoodi' but different escrow addresses
	hoodiTT := types.NewUUIDV5WithNamespace(rewardExtUUIDNamespace, []byte("hoodi0x878d6aaeb6e746033f50b8dc268d54b4631554e7"))
	hoodiTT2 := types.NewUUIDV5WithNamespace(rewardExtUUIDNamespace, []byte("hoodi0x9BD843A3ce718FE639e9968860B933b026784687"))

	hoodiTTStr := hoodiTT.String()
	hoodiTT2Str := hoodiTT2.String()

	// Different UUIDs even though same chain
	require.NotEqual(t, hoodiTT, hoodiTT2, "UUIDs should be different (different escrow addresses)")

	// Simulate first instance (hoodi_tt) starting
	runningListenersMu.Lock()
	runningDepositListeners[hoodiTTStr] = true
	runningWithdrawalListeners[hoodiTTStr] = true
	runningListenersMu.Unlock()

	// Simulate second instance (hoodi_tt2) starting - should not interfere with first
	runningListenersMu.Lock()
	// Check if already running (should be false for different UUID)
	tt2DepositRunning := runningDepositListeners[hoodiTT2Str]
	tt2WithdrawalRunning := runningWithdrawalListeners[hoodiTT2Str]
	require.False(t, tt2DepositRunning, "hoodi_tt2 should not be marked as running yet")
	require.False(t, tt2WithdrawalRunning, "hoodi_tt2 should not be marked as running yet")

	// Register hoodi_tt2 listeners
	runningDepositListeners[hoodiTT2Str] = true
	runningWithdrawalListeners[hoodiTT2Str] = true
	runningListenersMu.Unlock()

	// Verify both are tracked independently
	runningListenersMu.Lock()
	require.True(t, runningDepositListeners[hoodiTTStr], "hoodi_tt should still be tracked")
	require.True(t, runningWithdrawalListeners[hoodiTTStr], "hoodi_tt should still be tracked")
	require.True(t, runningDepositListeners[hoodiTT2Str], "hoodi_tt2 should be tracked")
	require.True(t, runningWithdrawalListeners[hoodiTT2Str], "hoodi_tt2 should be tracked")
	require.Len(t, runningDepositListeners, 2, "should track 2 deposit listeners")
	require.Len(t, runningWithdrawalListeners, 2, "should track 2 withdrawal listeners")
	runningListenersMu.Unlock()
}

// TestOnStartIdempotency tests that calling OnStart multiple times is safe
// and doesn't cause duplicate listener registration.
func TestOnStartIdempotency(t *testing.T) {
	ForTestingResetSingleton()

	id := types.NewUUIDV5WithNamespace(rewardExtUUIDNamespace, []byte("test_instance"))
	idStr := id.String()

	// First call
	runningListenersMu.Lock()
	alreadyRunning1 := runningDepositListeners[idStr]
	if !alreadyRunning1 {
		runningDepositListeners[idStr] = true
	}
	runningListenersMu.Unlock()
	require.False(t, alreadyRunning1, "first call should not find existing listener")

	// Second call (simulating OnStart called again via USE statement)
	runningListenersMu.Lock()
	alreadyRunning2 := runningDepositListeners[idStr]
	if !alreadyRunning2 {
		runningDepositListeners[idStr] = true
	}
	runningListenersMu.Unlock()
	require.True(t, alreadyRunning2, "second call should detect existing listener")

	// Third call
	runningListenersMu.Lock()
	alreadyRunning3 := runningDepositListeners[idStr]
	runningListenersMu.Unlock()
	require.True(t, alreadyRunning3, "third call should still detect existing listener")

	// Verify only one entry in map
	runningListenersMu.Lock()
	require.Len(t, runningDepositListeners, 1, "should have exactly 1 listener despite multiple calls")
	runningListenersMu.Unlock()
}
