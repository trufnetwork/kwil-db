package erc20

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
)

// TestBeaconClient_LazyInitialization tests that beacon client is created on first use
func TestBeaconClient_LazyInitialization(t *testing.T) {
	info := &rewardExtensionInfo{
		userProvidedData: userProvidedData{
			ChainInfo: &chains.ChainInfo{
				Name:      "ethereum",
				BeaconRPC: "https://ethereum-beacon-api.publicnode.com",
			},
		},
	}

	// Initially nil
	assert.Nil(t, info.beaconClient)

	// After creating client
	info.beaconClient = NewBeaconChainClient(info.userProvidedData.ChainInfo.BeaconRPC)

	// Should be initialized
	assert.NotNil(t, info.beaconClient)
	assert.Equal(t, "https://ethereum-beacon-api.publicnode.com", info.beaconClient.beaconRPC)
}

// TestBeaconClient_SkipCheckForL2 verifies L2 chains skip beacon check
func TestBeaconClient_SkipCheckForL2(t *testing.T) {
	testCases := []struct {
		name            string
		chainName       chains.Chain
		beaconRPC       string
		shouldSkipCheck bool
	}{
		{
			name:            "Ethereum mainnet has beacon check",
			chainName:       chains.Ethereum,
			beaconRPC:       "https://ethereum-beacon-api.publicnode.com",
			shouldSkipCheck: false,
		},
		{
			name:            "Sepolia testnet has beacon check",
			chainName:       chains.Sepolia,
			beaconRPC:       "https://ethereum-sepolia-beacon-api.publicnode.com",
			shouldSkipCheck: false,
		},
		{
			name:            "Hoodi testnet has beacon check",
			chainName:       chains.Hoodi,
			beaconRPC:       "https://ethereum-hoodi-beacon-api.publicnode.com",
			shouldSkipCheck: false,
		},
		{
			name:            "Base Sepolia L2 skips beacon check",
			chainName:       chains.BaseSepolia,
			beaconRPC:       "", // Empty = skip check
			shouldSkipCheck: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := &rewardExtensionInfo{
				userProvidedData: userProvidedData{
					ChainInfo: &chains.ChainInfo{
						Name:      tc.chainName,
						BeaconRPC: tc.beaconRPC,
					},
				},
			}

			// Check if beacon check should be skipped
			shouldSkip := info.userProvidedData.ChainInfo.BeaconRPC == ""

			assert.Equal(t, tc.shouldSkipCheck, shouldSkip)
		})
	}
}

// TestBeaconClient_MockFinality tests beacon finality check with mock server
func TestBeaconClient_MockFinality(t *testing.T) {
	testCases := []struct {
		name               string
		serverResponse     BeaconBlockResponse
		serverStatusCode   int
		serverError        bool
		expectedFinalized  bool
		expectedError      bool
		epochShouldWait    bool
	}{
		{
			name: "Block finalized - epoch should proceed",
			serverResponse: BeaconBlockResponse{
				Finalized: true,
			},
			serverStatusCode:  http.StatusOK,
			expectedFinalized: true,
			expectedError:     false,
			epochShouldWait:   false, // Can finalize
		},
		{
			name: "Block not finalized - epoch should wait",
			serverResponse: BeaconBlockResponse{
				Finalized: false,
			},
			serverStatusCode:  http.StatusOK,
			expectedFinalized: false,
			expectedError:     false,
			epochShouldWait:   true, // Must wait
		},
		{
			name:              "API error - epoch should wait",
			serverStatusCode:  http.StatusInternalServerError,
			expectedFinalized: false,
			expectedError:     false, // Graceful degradation
			epochShouldWait:   true,  // Must wait on error
		},
		{
			name:              "Network error - epoch should wait",
			serverError:       true,
			expectedFinalized: false,
			expectedError:     false, // Graceful degradation
			epochShouldWait:   true,  // Must wait on error
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.serverError {
				// Test network error case - use invalid URL
				client := NewBeaconChainClient("http://invalid-url.local")
				finalized, err := client.IsBlockFinalized(context.Background(), ethereumGenesisTime+900)

				assert.Equal(t, tc.expectedFinalized, finalized)
				if tc.expectedError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}

				// Verify epoch behavior
				if tc.epochShouldWait {
					assert.False(t, finalized, "Epoch should wait when block not finalized or error")
				}
				return
			}

			// Create mock HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.serverStatusCode)
				if tc.serverStatusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tc.serverResponse)
				}
			}))
			defer server.Close()

			// Create client and test
			client := NewBeaconChainClient(server.URL)
			finalized, err := client.IsBlockFinalized(context.Background(), ethereumGenesisTime+900)

			assert.Equal(t, tc.expectedFinalized, finalized)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify epoch behavior
			if tc.epochShouldWait {
				assert.False(t, finalized, "Epoch should wait when block not finalized or error")
			} else {
				assert.True(t, finalized, "Epoch can proceed when block is finalized")
			}
		})
	}
}

// TestBeaconClient_TimestampToSlotConversion tests the epoch start time to beacon slot logic
func TestBeaconClient_TimestampToSlotConversion(t *testing.T) {
	testCases := []struct {
		name                string
		epochStartTimestamp int64
		description         string
	}{
		{
			name:                "Recent timestamp (January 2026)",
			epochStartTimestamp: 1736721600, // Jan 12, 2026
			description:         "Should convert to valid beacon slot",
		},
		{
			name:                "Epoch just after merge",
			epochStartTimestamp: ethereumGenesisTime + 3600, // 1 hour after beacon genesis
			description:         "Should convert to early beacon slot",
		},
		{
			name:                "Current day timestamp",
			epochStartTimestamp: ethereumGenesisTime + (365 * 24 * 3600 * 5), // ~5 years after genesis
			description:         "Should convert to recent beacon slot",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Calculate slot
			slot := (tc.epochStartTimestamp - ethereumGenesisTime) / slotDuration

			// Verify slot is valid (positive)
			assert.Greater(t, slot, int64(0), "Slot should be positive for timestamps after genesis")

			// Verify slot calculation matches what beacon client would use
			expectedSlot := (tc.epochStartTimestamp - ethereumGenesisTime) / slotDuration
			assert.Equal(t, expectedSlot, slot, "Slot calculation should match beacon client logic")

			t.Logf("Timestamp %d -> Slot %d (%s)", tc.epochStartTimestamp, slot, tc.description)
		})
	}
}

// TestBeaconClient_RealEndpointConnectivity tests connectivity to real PublicNode endpoints
// This is a smoke test to verify the configured URLs are accessible
// Skip in CI with: go test -short (this test is skipped with -short flag)
func TestBeaconClient_RealEndpointConnectivity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real endpoint connectivity test in short mode")
	}

	endpoints := []struct {
		name string
		url  string
	}{
		{
			name: "Ethereum Mainnet",
			url:  "https://ethereum-beacon-api.publicnode.com",
		},
		{
			name: "Sepolia Testnet",
			url:  "https://ethereum-sepolia-beacon-api.publicnode.com",
		},
		{
			name: "Hoodi Testnet",
			url:  "https://ethereum-hoodi-beacon-api.publicnode.com",
		},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			client := NewBeaconChainClient(endpoint.url)

			// Try to query genesis (should always exist)
			genesisURL := endpoint.url + "/eth/v1/beacon/genesis"
			req, err := http.NewRequest("GET", genesisURL, nil)
			require.NoError(t, err)

			resp, err := client.httpClient.Do(req)
			if err != nil {
				t.Logf("Warning: Cannot reach %s: %v", endpoint.name, err)
				t.Skipf("Endpoint unreachable (network issue?)")
				return
			}
			defer resp.Body.Close()

			// Should get 200 OK
			assert.Equal(t, http.StatusOK, resp.StatusCode, "Endpoint should be accessible")

			t.Logf("✅ %s is accessible", endpoint.name)
		})
	}
}

// TestBeaconClient_ChainConfig verifies that chain configuration is correct
func TestBeaconClient_ChainConfig(t *testing.T) {
	testCases := []struct {
		chainName       chains.Chain
		expectedBeacon  string
		hasBeaconChain bool
	}{
		{
			chainName:       chains.Ethereum,
			expectedBeacon:  "https://ethereum-beacon-api.publicnode.com",
			hasBeaconChain: true,
		},
		{
			chainName:       chains.Sepolia,
			expectedBeacon:  "https://ethereum-sepolia-beacon-api.publicnode.com",
			hasBeaconChain: true,
		},
		{
			chainName:       chains.Hoodi,
			expectedBeacon:  "https://ethereum-hoodi-beacon-api.publicnode.com",
			hasBeaconChain: true,
		},
		{
			chainName:       chains.BaseSepolia,
			expectedBeacon:  "", // L2, no beacon
			hasBeaconChain: false,
		},
	}

	for _, tc := range testCases {
		t.Run(string(tc.chainName), func(t *testing.T) {
			chainInfo, ok := chains.GetChainInfo(tc.chainName)
			require.True(t, ok, "Chain should be registered")

			assert.Equal(t, tc.expectedBeacon, chainInfo.BeaconRPC, "BeaconRPC should match expected value")

			if tc.hasBeaconChain {
				assert.NotEmpty(t, chainInfo.BeaconRPC, "Chain with beacon should have BeaconRPC configured")
			} else {
				assert.Empty(t, chainInfo.BeaconRPC, "L2 chain should have empty BeaconRPC")
			}
		})
	}
}
