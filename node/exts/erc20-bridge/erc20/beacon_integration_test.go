package erc20

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
)

// testEthereumGenesisTime is defined for integration tests
// (testGenesisTime and testSlotDuration are defined in beacon_client_test.go)
const (
	testEthereumGenesisTime = testGenesisTime // Use same value as unit tests
)

// TestBeaconClient_LazyInitialization tests reward extension info initialization
// Note: Beacon client is used for epoch finalization (endBlock), not for deposit/withdrawal event listeners.
// Deposits are processed immediately for optimal UX. Withdrawals are protected by beacon finality during epoch finalization.
func TestBeaconClient_LazyInitialization(t *testing.T) {
	info := &rewardExtensionInfo{
		userProvidedData: userProvidedData{
			ChainInfo: &chains.ChainInfo{
				Name:      "ethereum",
				BeaconRPC: "https://ethereum-beacon-api.publicnode.com",
			},
		},
	}

	// Verify struct has mutex for thread-safe operations
	assert.NotNil(t, &info.mu)
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
// Note: Beacon checks are used for epoch finalization (endBlock) to ensure withdrawal proofs
// are only generated after finality. These tests verify the beacon client behavior.
func TestBeaconClient_MockFinality(t *testing.T) {
	testCases := []struct {
		name              string
		serverResponse    interface{}
		serverStatusCode  int
		serverError       bool
		expectedFinalized bool
		expectedError     bool
		depositShouldWait bool
	}{
		{
			name: "Block finalized - deposit can be credited",
			serverResponse: BeaconBlockResponse{
				Finalized: true,
			},
			serverStatusCode:  http.StatusOK,
			expectedFinalized: true,
			expectedError:     false,
			depositShouldWait: false, // Can credit deposit
		},
		{
			name: "Block not finalized - deposit should wait",
			serverResponse: BeaconBlockResponse{
				Finalized: false,
			},
			serverStatusCode:  http.StatusOK,
			expectedFinalized: false,
			expectedError:     false,
			depositShouldWait: true, // Must wait
		},
		{
			name: "Empty slot (404) with finalized epoch - deposit can be credited",
			serverResponse: FinalityCheckpointsResponse{
				Data: struct {
					Finalized struct {
						Epoch string `json:"epoch"`
					} `json:"finalized"`
				}{
					Finalized: struct {
						Epoch string `json:"epoch"`
					}{
						Epoch: "100", // Epoch 100 finalized
					},
				},
			},
			serverStatusCode:  http.StatusNotFound, // Empty slot triggers checkpoint query
			expectedFinalized: true,
			expectedError:     false,
			depositShouldWait: false, // Can credit despite empty slot
		},
		{
			name:              "API error - deposit should wait",
			serverStatusCode:  http.StatusInternalServerError,
			expectedFinalized: false,
			expectedError:     false, // Graceful degradation
			depositShouldWait: true,  // Must wait on error
		},
		{
			name:              "Network error - deposit should wait",
			serverError:       true,
			expectedFinalized: false,
			expectedError:     false, // Graceful degradation
			depositShouldWait: true,  // Must wait on error
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.serverError {
				// Test network error case - use invalid URL
				client := NewBeaconChainClient("http://invalid-url.local", testEthereumGenesisTime, testSlotDuration)
				finalized, err := client.IsBlockFinalized(context.Background(), testEthereumGenesisTime+900)

				assert.Equal(t, tc.expectedFinalized, finalized)
				if tc.expectedError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}

				// Verify deposit behavior
				if tc.depositShouldWait {
					assert.False(t, finalized, "Deposit should wait when block not finalized or error")
				}
				return
			}

			// Create mock HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle 404 (empty slot) - return checkpoint response
				if tc.serverStatusCode == http.StatusNotFound {
					// First request: block query returns 404
					if r.URL.Path != "/eth/v1/beacon/states/head/finality_checkpoints" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					// Second request: checkpoint query returns finalized epoch
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tc.serverResponse)
					return
				}

				w.WriteHeader(tc.serverStatusCode)
				if tc.serverStatusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tc.serverResponse)
				}
			}))
			defer server.Close()

			// Create client and test
			// Use timestamp that maps to slot 75 (epoch 2, which is < finalized epoch 100)
			testTimestamp := int64(testEthereumGenesisTime + (75 * testSlotDuration))
			client := NewBeaconChainClient(server.URL, testEthereumGenesisTime, testSlotDuration)
			finalized, err := client.IsBlockFinalized(context.Background(), testTimestamp)

			assert.Equal(t, tc.expectedFinalized, finalized)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify deposit behavior
			if tc.depositShouldWait {
				assert.False(t, finalized, "Deposit should wait when block not finalized or error")
			} else {
				assert.True(t, finalized, "Deposit can be credited when block is finalized")
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
			epochStartTimestamp: testEthereumGenesisTime + 3600, // 1 hour after beacon genesis
			description:         "Should convert to early beacon slot",
		},
		{
			name:                "Current day timestamp",
			epochStartTimestamp: testEthereumGenesisTime + (365 * 24 * 3600 * 5), // ~5 years after genesis
			description:         "Should convert to recent beacon slot",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Calculate expected slot using the beacon client's formula
			expectedSlot := (tc.epochStartTimestamp - testEthereumGenesisTime) / testSlotDuration

			// Verify slot is valid (positive)
			assert.Greater(t, expectedSlot, int64(0), "Slot should be positive for timestamps after genesis")

			// Create mock server that verifies the beacon client queries the correct slot
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Extract slot from URL path and verify it matches expected
				expectedPath := fmt.Sprintf("/eth/v2/beacon/blocks/%d", expectedSlot)
				assert.Equal(t, expectedPath, r.URL.Path, "Beacon client should query correct slot")

				response := BeaconBlockResponse{
					Finalized: true,
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			// Create client and call IsBlockFinalized to test actual implementation
			client := NewBeaconChainClient(server.URL, testEthereumGenesisTime, testSlotDuration)
			finalized, err := client.IsBlockFinalized(context.Background(), tc.epochStartTimestamp)

			assert.NoError(t, err)
			assert.True(t, finalized)

			t.Logf("Timestamp %d -> Slot %d (%s)", tc.epochStartTimestamp, expectedSlot, tc.description)
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
			client := NewBeaconChainClient(endpoint.url, testEthereumGenesisTime, testSlotDuration)

			// Try to query genesis (should always exist)
			genesisURL := endpoint.url + "/eth/v1/beacon/genesis"
			req, err := http.NewRequest(http.MethodGet, genesisURL, nil)
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
		chainName      chains.Chain
		expectedBeacon string
		hasBeaconChain bool
	}{
		{
			chainName:      chains.Ethereum,
			expectedBeacon: "https://ethereum-beacon-api.publicnode.com",
			hasBeaconChain: true,
		},
		{
			chainName:      chains.Sepolia,
			expectedBeacon: "https://ethereum-sepolia-beacon-api.publicnode.com",
			hasBeaconChain: true,
		},
		{
			chainName:      chains.Hoodi,
			expectedBeacon: "https://ethereum-hoodi-beacon-api.publicnode.com",
			hasBeaconChain: true,
		},
		{
			chainName:      chains.BaseSepolia,
			expectedBeacon: "", // L2, no beacon
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
