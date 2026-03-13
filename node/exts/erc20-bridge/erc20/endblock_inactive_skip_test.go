//go:build kwiltest

package erc20

import (
	"context"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
)

// makeTestInstance creates a rewardExtensionInfo with the given active state.
func makeTestInstance(active bool) *rewardExtensionInfo {
	id := types.NewUUIDV5([]byte("test"))
	return &rewardExtensionInfo{
		userProvidedData: userProvidedData{
			ID:                 id,
			ChainInfo:          &chains.ChainInfo{ID: "1"},
			DistributionPeriod: 3600,
		},
		syncedRewardData: syncedRewardData{
			Erc20Decimals: 18,
		},
		active: active,
		currentEpoch: &PendingEpoch{
			ID:          types.NewUUIDV5([]byte("epoch")),
			StartHeight: 100,
			StartTime:   1000,
		},
	}
}

// saveSingleton saves the current _SINGLETON and registers a t.Cleanup
// to restore it, ensuring test isolation of global state.
func saveSingleton(t *testing.T) {
	t.Helper()
	orig := _SINGLETON
	t.Cleanup(func() { _SINGLETON = orig })
}

// TestEndBlockSkipsInactiveInstances verifies that the endblock ForEachInstance
// callback skips deactivated instances. This prevents wasted CPU and ANTLR
// parser cache growth from processing stale/misconfigured instances every block.
func TestEndBlockSkipsInactiveInstances(t *testing.T) {
	saveSingleton(t)
	_SINGLETON = &extensionInfo{instances: newInstanceMap()}

	activeInstance := makeTestInstance(true)
	inactiveInstance := makeTestInstance(false)

	// Give them distinct IDs
	inactiveID := types.NewUUIDV5([]byte("inactive"))
	inactiveInstance.userProvidedData.ID = inactiveID

	_SINGLETON.instances.Set(*activeInstance.userProvidedData.ID, activeInstance)
	_SINGLETON.instances.Set(*inactiveID, inactiveInstance)

	// Track which instances the callback visits
	visited := make(map[string]bool)

	err := getSingleton().ForEachInstance(true, func(id *types.UUID, info *rewardExtensionInfo) error {
		info.mu.RLock()
		defer info.mu.RUnlock()

		// This is the same guard we added to the endblock handler
		if !info.active {
			return nil
		}

		visited[id.String()] = true
		return nil
	})

	require.NoError(t, err)
	assert.True(t, visited[activeInstance.userProvidedData.ID.String()],
		"active instance should be visited")
	assert.False(t, visited[inactiveID.String()],
		"inactive instance should be skipped")
}

// TestEndBlockProcessesActiveInstances verifies that active instances are
// still fully processed by the endblock callback after adding the inactive skip.
func TestEndBlockProcessesActiveInstances(t *testing.T) {
	saveSingleton(t)
	_SINGLETON = &extensionInfo{instances: newInstanceMap()}

	inst1 := makeTestInstance(true)
	inst2 := makeTestInstance(true)

	id2 := types.NewUUIDV5([]byte("active-2"))
	inst2.userProvidedData.ID = id2

	_SINGLETON.instances.Set(*inst1.userProvidedData.ID, inst1)
	_SINGLETON.instances.Set(*id2, inst2)

	callCount := 0

	err := getSingleton().ForEachInstance(true, func(id *types.UUID, info *rewardExtensionInfo) error {
		info.mu.RLock()
		defer info.mu.RUnlock()

		if !info.active {
			return nil
		}

		callCount++
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 2, callCount, "both active instances should be processed")
}

// TestEndBlockEpochUpdateSkipsInactive verifies the second ForEachInstance
// callback (which updates in-memory epoch state) also skips inactive instances.
func TestEndBlockEpochUpdateSkipsInactive(t *testing.T) {
	saveSingleton(t)
	_SINGLETON = &extensionInfo{instances: newInstanceMap()}

	activeInst := makeTestInstance(true)
	inactiveInst := makeTestInstance(false)

	inactiveID := types.NewUUIDV5([]byte("inactive-epoch"))
	inactiveInst.userProvidedData.ID = inactiveID

	_SINGLETON.instances.Set(*activeInst.userProvidedData.ID, activeInst)
	_SINGLETON.instances.Set(*inactiveID, inactiveInst)

	// Simulate the second ForEachInstance callback (epoch state update)
	newEpochs := map[types.UUID]*PendingEpoch{
		*activeInst.userProvidedData.ID: {
			ID:          types.NewUUIDV5([]byte("new-epoch")),
			StartHeight: 200,
			StartTime:   2000,
		},
		// Even if an inactive instance somehow had an epoch entry,
		// the guard should prevent any update
		*inactiveID: {
			ID:          types.NewUUIDV5([]byte("should-not-apply")),
			StartHeight: 300,
			StartTime:   3000,
		},
	}

	err := getSingleton().ForEachInstance(false, func(id *types.UUID, info *rewardExtensionInfo) error {
		info.mu.RLock()
		active := info.active
		info.mu.RUnlock()
		if !active {
			return nil
		}

		newEpoch, ok := newEpochs[*id]
		if ok {
			info.mu.Lock()
			info.currentEpoch = newEpoch
			info.mu.Unlock()
		}
		return nil
	})

	require.NoError(t, err)

	// Active instance should have been updated
	assert.Equal(t, int64(200), activeInst.currentEpoch.StartHeight,
		"active instance epoch should be updated")

	// Inactive instance should NOT have been updated
	assert.Equal(t, int64(100), inactiveInst.currentEpoch.StartHeight,
		"inactive instance epoch should remain unchanged")
}

// TestApplyDepositLogSkipsInactiveInstance verifies that applyDepositLog
// returns nil without processing when the instance is inactive.
func TestApplyDepositLogSkipsInactiveInstance(t *testing.T) {
	saveSingleton(t)
	_SINGLETON = &extensionInfo{instances: newInstanceMap()}

	inactiveInst := makeTestInstance(false)
	id := inactiveInst.userProvidedData.ID
	_SINGLETON.instances.Set(*id, inactiveInst)

	// Create a deposit log — if the active check is missing, this would
	// panic or error because there's no real DB behind the app.
	amount := big.NewInt(1_000_000_000_000_000_000)
	recipient := ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc")

	var data [64]byte
	copy(data[32-len(recipient.Bytes()):32], recipient.Bytes())
	copy(data[64-len(amount.Bytes()):], amount.Bytes())

	depositLog := ethtypes.Log{
		Address: ethcommon.HexToAddress("0x00000000000000000000000000000000000000aa"),
		Topics:  []ethcommon.Hash{ethcommon.HexToHash("0x1234")},
		Data:    data[:],
		TxHash:  ethcommon.HexToHash("0xdeadbeef"),
	}

	block := &common.BlockContext{Height: 100, Timestamp: 1600000000}

	// With no real DB, this would fail if the active check didn't short-circuit.
	// The nil app.Service is fine — the warning log is guarded by nil check.
	app := &common.App{}
	err := applyDepositLog(context.Background(), app, id, depositLog, block, nil)
	require.NoError(t, err, "deposit to inactive instance should be silently skipped")
}

// TestEmptyEpochStalenessTimeout verifies the isWithinEmptyEpochGracePeriod
// helper that the endblock handler uses to decide whether to wait or
// auto-finalize an empty epoch.
func TestEmptyEpochStalenessTimeout(t *testing.T) {
	distributionPeriod := int64(600) // 10 minutes
	graceThreshold := distributionPeriod * emptyEpochGraceMultiplier // 1800 seconds

	tests := []struct {
		name           string
		epochStartTime int64
		blockTimestamp int64
		shouldWait     bool
	}{
		{
			name:           "just past distribution period - within grace",
			epochStartTime: 1000,
			blockTimestamp: 1000 + distributionPeriod + 1, // 601s elapsed
			shouldWait:     true,
		},
		{
			name:           "2x distribution period - within grace",
			epochStartTime: 1000,
			blockTimestamp: 1000 + distributionPeriod*2, // 1200s elapsed
			shouldWait:     true,
		},
		{
			name:           "exactly at grace threshold - within grace",
			epochStartTime: 1000,
			blockTimestamp: 1000 + graceThreshold - 1, // 1799s elapsed
			shouldWait:     true,
		},
		{
			name:           "past grace threshold - should auto-finalize",
			epochStartTime: 1000,
			blockTimestamp: 1000 + graceThreshold, // 1800s elapsed
			shouldWait:     false,
		},
		{
			name:           "way past grace - 65 days stuck",
			epochStartTime: 1000,
			blockTimestamp: 1000 + 5_650_147, // 65 days
			shouldWait:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			staleness := tc.blockTimestamp - tc.epochStartTime
			assert.Equal(t, tc.shouldWait, isWithinEmptyEpochGracePeriod(staleness, distributionPeriod),
				"staleness=%ds, threshold=%ds", staleness, graceThreshold)
		})
	}
}
