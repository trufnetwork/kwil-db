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
)

// TestBeaconChainClient_IsBlockFinalized_Success tests successful finality check
func TestBeaconChainClient_IsBlockFinalized_Success(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := BeaconBlockResponse{
			Finalized: true,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client pointing to mock server
	client := NewBeaconChainClient(server.URL)

	// Test with timestamp (15 minutes after genesis)
	timestamp := int64(ethereumGenesisTime + 900)
	finalized, err := client.IsBlockFinalized(context.Background(), timestamp)

	require.NoError(t, err)
	assert.True(t, finalized)
}

// TestBeaconChainClient_IsBlockFinalized_NotFinalized tests not finalized case
func TestBeaconChainClient_IsBlockFinalized_NotFinalized(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := BeaconBlockResponse{
			Finalized: false,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client pointing to mock server
	client := NewBeaconChainClient(server.URL)

	// Test with timestamp
	timestamp := int64(ethereumGenesisTime + 900)
	finalized, err := client.IsBlockFinalized(context.Background(), timestamp)

	require.NoError(t, err)
	assert.False(t, finalized)
}

// TestBeaconChainClient_IsBlockFinalized_NetworkError tests network error handling
func TestBeaconChainClient_IsBlockFinalized_NetworkError(t *testing.T) {
	// Create client with invalid URL (will cause network error)
	client := NewBeaconChainClient("http://invalid-url-that-does-not-exist.local")

	// Test with timestamp
	timestamp := int64(ethereumGenesisTime + 900)
	finalized, err := client.IsBlockFinalized(context.Background(), timestamp)

	// Should return false but no error (graceful degradation)
	assert.NoError(t, err)
	assert.False(t, finalized)
}

// TestBeaconChainClient_IsBlockFinalized_APIError tests API error handling
func TestBeaconChainClient_IsBlockFinalized_APIError(t *testing.T) {
	// Create mock HTTP server that returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create client pointing to mock server
	client := NewBeaconChainClient(server.URL)

	// Test with timestamp
	timestamp := int64(ethereumGenesisTime + 900)
	finalized, err := client.IsBlockFinalized(context.Background(), timestamp)

	// Should return false but no error (graceful degradation)
	assert.NoError(t, err)
	assert.False(t, finalized)
}

// TestBeaconChainClient_IsBlockFinalized_InvalidSlot tests invalid timestamp before genesis
func TestBeaconChainClient_IsBlockFinalized_InvalidSlot(t *testing.T) {
	// Create mock HTTP server (won't be called)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Should not reach server for invalid timestamp")
	}))
	defer server.Close()

	// Create client
	client := NewBeaconChainClient(server.URL)

	// Test with timestamp before genesis
	timestamp := int64(ethereumGenesisTime - 1000)
	finalized, err := client.IsBlockFinalized(context.Background(), timestamp)

	// Should return error for invalid timestamp
	require.Error(t, err)
	assert.False(t, finalized)
	assert.Contains(t, err.Error(), "invalid slot")
}

// TestBeaconChainClient_SlotCalculation tests slot calculation accuracy
func TestBeaconChainClient_SlotCalculation(t *testing.T) {
	testCases := []struct {
		name              string
		timestamp         int64
		expectedSlot      int64
		shouldBeValidSlot bool
	}{
		{
			name:              "Genesis block",
			timestamp:         ethereumGenesisTime,
			expectedSlot:      0,
			shouldBeValidSlot: true,
		},
		{
			name:              "15 minutes after genesis",
			timestamp:         ethereumGenesisTime + 900, // 900 seconds = 15 minutes
			expectedSlot:      75,                        // 900 / 12 = 75 slots
			shouldBeValidSlot: true,
		},
		{
			name:              "1 hour after genesis",
			timestamp:         ethereumGenesisTime + 3600, // 3600 seconds = 1 hour
			expectedSlot:      300,                        // 3600 / 12 = 300 slots
			shouldBeValidSlot: true,
		},
		{
			name:              "Before genesis",
			timestamp:         ethereumGenesisTime - 100,
			expectedSlot:      -8, // negative slot
			shouldBeValidSlot: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Calculate slot
			slot := (tc.timestamp - ethereumGenesisTime) / slotDuration

			// Verify calculation
			assert.Equal(t, tc.expectedSlot, slot)

			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify slot in URL path
				expectedPath := fmt.Sprintf("/eth/v2/beacon/blocks/%d", tc.expectedSlot)
				assert.Equal(t, expectedPath, r.URL.Path)

				response := BeaconBlockResponse{
					Finalized: true,
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			client := NewBeaconChainClient(server.URL)

			_, err := client.IsBlockFinalized(context.Background(), tc.timestamp)

			if tc.shouldBeValidSlot {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestBeaconChainClient_DecodeError tests JSON decode error handling
func TestBeaconChainClient_DecodeError(t *testing.T) {
	// Create mock HTTP server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	// Create client
	client := NewBeaconChainClient(server.URL)

	// Test with timestamp
	timestamp := int64(ethereumGenesisTime + 900)
	finalized, err := client.IsBlockFinalized(context.Background(), timestamp)

	// Should return error for JSON decode failure
	require.Error(t, err)
	assert.False(t, finalized)
	assert.Contains(t, err.Error(), "decode response")
}
