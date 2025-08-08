package adminsvc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	adminjson "github.com/trufnetwork/kwil-db/core/rpc/json/admin"
	"github.com/trufnetwork/kwil-db/node/peers"
)

// mockBlacklister implements the Blacklister interface for testing
type mockBlacklister struct {
	blacklistedPeers map[string]peers.BlacklistEntry
	shouldError      bool
	errorMessage     string
}

func newMockBlacklister() *mockBlacklister {
	return &mockBlacklister{
		blacklistedPeers: make(map[string]peers.BlacklistEntry),
	}
}

func (m *mockBlacklister) BlacklistPeer(nodeID string, reason string, duration time.Duration) error {
	if m.shouldError {
		return &jsonrpc.Error{Message: m.errorMessage}
	}

	// Convert nodeID to PeerID for mock storage
	pubKey, err := peers.NodeIDToPubKey(nodeID)
	if err != nil {
		return &jsonrpc.Error{Message: "invalid node ID: " + err.Error()}
	}
	peerID, err := peers.PeerIDFromPubKey(pubKey)
	if err != nil {
		return &jsonrpc.Error{Message: "invalid node ID conversion: " + err.Error()}
	}

	entry := peers.BlacklistEntry{
		PeerID:    peerID,
		Reason:    reason,
		Timestamp: time.Now(),
		Permanent: duration == 0,
	}

	if !entry.Permanent {
		entry.ExpiresAt = time.Now().Add(duration)
	}

	m.blacklistedPeers[nodeID] = entry
	return nil
}

func (m *mockBlacklister) RemoveFromBlacklist(nodeID string) error {
	if m.shouldError {
		return &jsonrpc.Error{Message: m.errorMessage}
	}

	_, exists := m.blacklistedPeers[nodeID]
	if !exists {
		return &jsonrpc.Error{Message: "peer not found in blacklist"}
	}

	delete(m.blacklistedPeers, nodeID)
	return nil
}

func (m *mockBlacklister) ListBlacklisted() ([]peers.BlacklistEntry, error) {
	if m.shouldError {
		return nil, &jsonrpc.Error{Message: m.errorMessage}
	}

	var entries []peers.BlacklistEntry
	for _, entry := range m.blacklistedPeers {
		entries = append(entries, entry)
	}
	return entries, nil
}

func (m *mockBlacklister) setError(shouldError bool, message string) {
	m.shouldError = shouldError
	m.errorMessage = message
}

func createTestService() *Service {
	return &Service{
		log:       log.DiscardLogger,
		blacklist: newMockBlacklister(),
	}
}

func TestService_BlacklistPeer(t *testing.T) {
	svc := createTestService()
	ctx := context.Background()

	tests := []struct {
		name          string
		req           *adminjson.BlacklistPeerRequest
		expectError   bool
		errorContains string
		setupError    bool
		setupErrorMsg string
	}{
		{
			name: "successful permanent blacklist",
			req: &adminjson.BlacklistPeerRequest{
				PeerID: "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
				Reason: "manual blacklist",
			},
			expectError: false,
		},
		{
			name: "successful temporary blacklist",
			req: &adminjson.BlacklistPeerRequest{
				PeerID:   "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
				Reason:   "temporary block",
				Duration: "1h",
			},
			expectError: false,
		},
		{
			name: "default reason when empty",
			req: &adminjson.BlacklistPeerRequest{
				PeerID: "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
			},
			expectError: false,
		},
		{
			name: "invalid duration format",
			req: &adminjson.BlacklistPeerRequest{
				PeerID:   "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
				Duration: "invalid-duration",
			},
			expectError:   true,
			errorContains: "invalid duration format",
		},
		{
			name: "blacklist service error",
			req: &adminjson.BlacklistPeerRequest{
				PeerID: "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
				Reason: "test",
			},
			expectError:   true,
			errorContains: "failed to blacklist peer",
			setupError:    true,
			setupErrorMsg: "mock blacklist error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock error if needed
			if tt.setupError {
				svc.blacklist.(*mockBlacklister).setError(true, tt.setupErrorMsg)
			} else {
				svc.blacklist.(*mockBlacklister).setError(false, "")
			}

			resp, jsonErr := svc.BlacklistPeer(ctx, tt.req)

			if tt.expectError {
				require.Nil(t, resp)
				require.NotNil(t, jsonErr)
				require.Contains(t, jsonErr.Message, tt.errorContains)
			} else {
				require.NotNil(t, resp)
				require.Nil(t, jsonErr)

				// Verify the peer was added to mock blacklist
				mockBL := svc.blacklist.(*mockBlacklister)
				_, exists := mockBL.blacklistedPeers[tt.req.PeerID]
				require.True(t, exists)
			}
		})
	}
}

func TestService_RemoveBlacklistedPeer(t *testing.T) {
	svc := createTestService()
	ctx := context.Background()

	tests := []struct {
		name          string
		req           *adminjson.RemoveBlacklistedPeerRequest
		setupPeer     bool
		expectError   bool
		errorContains string
		setupError    bool
		setupErrorMsg string
	}{
		{
			name: "successful removal",
			req: &adminjson.RemoveBlacklistedPeerRequest{
				PeerID: "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
			},
			setupPeer:   true,
			expectError: false,
		},
		{
			name: "peer not in blacklist",
			req: &adminjson.RemoveBlacklistedPeerRequest{
				PeerID: "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa#secp256k1",
			},
			setupPeer:     false,
			expectError:   true,
			errorContains: "failed to remove blacklisted peer",
		},
		{
			name: "blacklist service error",
			req: &adminjson.RemoveBlacklistedPeerRequest{
				PeerID: "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
			},
			setupPeer:     true,
			expectError:   true,
			errorContains: "failed to remove blacklisted peer",
			setupError:    true,
			setupErrorMsg: "mock remove error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: add peer to blacklist if needed
			mockBL := svc.blacklist.(*mockBlacklister)
			if tt.setupPeer {
				mockBL.blacklistedPeers[tt.req.PeerID] = peers.BlacklistEntry{
					Reason:    "test setup",
					Timestamp: time.Now(),
					Permanent: true,
				}
			}

			// Setup mock error if needed
			if tt.setupError {
				mockBL.setError(true, tt.setupErrorMsg)
			} else {
				mockBL.setError(false, "")
			}

			resp, jsonErr := svc.RemoveBlacklistedPeer(ctx, tt.req)

			if tt.expectError {
				require.Nil(t, resp)
				require.NotNil(t, jsonErr)
				require.Contains(t, jsonErr.Message, tt.errorContains)
			} else {
				require.NotNil(t, resp)
				require.Nil(t, jsonErr)
				require.True(t, resp.Removed)

				// Verify the peer was removed from mock blacklist
				_, exists := mockBL.blacklistedPeers[tt.req.PeerID]
				require.False(t, exists)
			}
		})
	}
}

func TestService_ListBlacklistedPeers(t *testing.T) {
	svc := createTestService()
	ctx := context.Background()

	tests := []struct {
		name          string
		setupPeers    map[string]peers.BlacklistEntry
		expectError   bool
		errorContains string
		setupError    bool
		setupErrorMsg string
		expectedCount int
	}{
		{
			name:          "empty blacklist",
			setupPeers:    map[string]peers.BlacklistEntry{},
			expectError:   false,
			expectedCount: 0,
		},
		{
			name:          "single peer",
			setupPeers:    nil, // Will be created by test setup
			expectError:   false,
			expectedCount: 1,
		},
		{
			name:          "multiple peers",
			setupPeers:    nil, // Will be created by test setup
			expectError:   false,
			expectedCount: 2,
		},
		{
			name:          "blacklist service error",
			setupPeers:    nil, // Will be created by test setup
			expectError:   true,
			errorContains: "failed to list blacklisted peers",
			setupError:    true,
			setupErrorMsg: "mock list error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: populate mock blacklist using BlacklistPeer method
			mockBL := svc.blacklist.(*mockBlacklister)
			mockBL.blacklistedPeers = make(map[string]peers.BlacklistEntry)

			// Setup test data based on test name
			if tt.name == "single peer" {
				mockBL.BlacklistPeer("0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1", "manual blacklist", 0)
			} else if tt.name == "multiple peers" {
				mockBL.BlacklistPeer("0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1", "manual blacklist", 0)
				mockBL.BlacklistPeer("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa#secp256k1", "temporary block", 1*time.Hour)
			} else if tt.name == "blacklist service error" {
				mockBL.BlacklistPeer("0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1", "test", 0)
			}

			// Setup mock error if needed
			if tt.setupError {
				mockBL.setError(true, tt.setupErrorMsg)
			} else {
				mockBL.setError(false, "")
			}

			req := &adminjson.ListBlacklistedPeersRequest{}
			resp, jsonErr := svc.ListBlacklistedPeers(ctx, req)

			if tt.expectError {
				require.Nil(t, resp)
				require.NotNil(t, jsonErr)
				require.Contains(t, jsonErr.Message, tt.errorContains)
			} else {
				require.NotNil(t, resp)
				require.Nil(t, jsonErr)
				require.Len(t, resp.BlacklistedPeers, tt.expectedCount)

				// Verify JSON formatting
				for _, entry := range resp.BlacklistedPeers {
					require.NotEmpty(t, entry.PeerID)
					require.NotEmpty(t, entry.Reason)
					require.NotEmpty(t, entry.Timestamp)

					// Verify timestamp format (should be RFC3339)
					_, err := time.Parse(time.RFC3339, entry.Timestamp)
					require.NoError(t, err)

					// Check expires_at format for temporary entries
					if !entry.Permanent && entry.ExpiresAt != "" {
						_, err := time.Parse(time.RFC3339, entry.ExpiresAt)
						require.NoError(t, err)
					}
				}
			}
		})
	}
}

func TestService_BlacklistRPC_Integration(t *testing.T) {
	svc := createTestService()
	ctx := context.Background()

	peerID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"

	t.Run("complete blacklist workflow", func(t *testing.T) {
		// 1. List should be empty initially
		listReq := &adminjson.ListBlacklistedPeersRequest{}
		listResp, jsonErr := svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, listResp)
		require.Empty(t, listResp.BlacklistedPeers)

		// 2. Blacklist a peer
		blacklistReq := &adminjson.BlacklistPeerRequest{
			PeerID:   peerID,
			Reason:   "integration test",
			Duration: "1h",
		}
		blacklistResp, jsonErr := svc.BlacklistPeer(ctx, blacklistReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, blacklistResp)

		// 3. List should now contain the peer
		listResp, jsonErr = svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, listResp)
		require.Len(t, listResp.BlacklistedPeers, 1)
		require.Equal(t, peerID, listResp.BlacklistedPeers[0].PeerID)
		require.Equal(t, "integration test", listResp.BlacklistedPeers[0].Reason)
		require.False(t, listResp.BlacklistedPeers[0].Permanent)
		require.NotEmpty(t, listResp.BlacklistedPeers[0].ExpiresAt)

		// 4. Remove the peer
		removeReq := &adminjson.RemoveBlacklistedPeerRequest{
			PeerID: peerID,
		}
		removeResp, jsonErr := svc.RemoveBlacklistedPeer(ctx, removeReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, removeResp)
		require.True(t, removeResp.Removed)

		// 5. List should be empty again
		listResp, jsonErr = svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, listResp)
		require.Empty(t, listResp.BlacklistedPeers)
	})
}

func TestService_BlacklistRPC_DurationParsing(t *testing.T) {
	svc := createTestService()
	ctx := context.Background()

	validDurations := []string{
		"1h",       // 1 hour
		"30m",      // 30 minutes
		"1h30m",    // 1 hour 30 minutes
		"2h15m30s", // complex duration
		"0",        // zero duration (permanent)
	}

	for _, duration := range validDurations {
		t.Run("valid_duration_"+duration, func(t *testing.T) {
			req := &adminjson.BlacklistPeerRequest{
				PeerID:   "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
				Reason:   "duration test",
				Duration: duration,
			}

			resp, jsonErr := svc.BlacklistPeer(ctx, req)
			require.Nil(t, jsonErr)
			require.NotNil(t, resp)
		})
	}

	invalidDurations := []string{
		"invalid",
		"1x",    // invalid unit
		"1hour", // wrong format
		"-1h",   // negative
	}

	for _, duration := range invalidDurations {
		t.Run("invalid_duration_"+duration, func(t *testing.T) {
			req := &adminjson.BlacklistPeerRequest{
				PeerID:   "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
				Reason:   "duration test",
				Duration: duration,
			}

			resp, jsonErr := svc.BlacklistPeer(ctx, req)
			require.NotNil(t, jsonErr)
			require.Nil(t, resp)
			require.Contains(t, jsonErr.Message, "invalid duration format")
		})
	}
}
