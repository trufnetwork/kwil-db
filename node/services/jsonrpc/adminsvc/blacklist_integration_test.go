package adminsvc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/log"
	adminjson "github.com/trufnetwork/kwil-db/core/rpc/json/admin"
)

// createMockIntegrationService creates a service with working mock for basic integration testing
func createMockIntegrationService(t *testing.T) *Service {
	return &Service{
		log:       log.DiscardLogger,
		blacklist: newMockBlacklister(),
	}
}

func TestBlacklistRPC_FullIntegration(t *testing.T) {
	svc := createMockIntegrationService(t)
	ctx := context.Background()

	// Use valid node ID format (matching what unit tests use)
	nodeID1 := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"
	nodeID2 := "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa#secp256k1"

	t.Run("full_blacklist_workflow", func(t *testing.T) {
		// Step 1: Initial state - no blacklisted peers
		listReq := &adminjson.ListBlacklistedPeersRequest{}
		listResp, jsonErr := svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, listResp)
		require.Empty(t, listResp.BlacklistedPeers)

		// Step 2: Blacklist first peer permanently
		blacklistReq1 := &adminjson.BlacklistPeerRequest{
			PeerID: nodeID1,
			Reason: "integration test permanent",
		}
		blacklistResp1, jsonErr := svc.BlacklistPeer(ctx, blacklistReq1)
		require.Nil(t, jsonErr)
		require.NotNil(t, blacklistResp1)

		// Step 3: Blacklist second peer temporarily
		blacklistReq2 := &adminjson.BlacklistPeerRequest{
			PeerID:   nodeID2,
			Reason:   "integration test temporary",
			Duration: "1h",
		}
		blacklistResp2, jsonErr := svc.BlacklistPeer(ctx, blacklistReq2)
		require.Nil(t, jsonErr)
		require.NotNil(t, blacklistResp2)

		// Step 4: List should now contain both peers
		listResp, jsonErr = svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, listResp)
		require.Len(t, listResp.BlacklistedPeers, 2)

		// Verify peer details
		var permanentEntry, temporaryEntry *adminjson.BlacklistEntryJSON
		for i := range listResp.BlacklistedPeers {
			entry := &listResp.BlacklistedPeers[i]
			if entry.Permanent {
				permanentEntry = entry
			} else {
				temporaryEntry = entry
			}
		}

		require.NotNil(t, permanentEntry)
		require.NotNil(t, temporaryEntry)

		// Check permanent entry
		require.Equal(t, "integration test permanent", permanentEntry.Reason)
		require.True(t, permanentEntry.Permanent)
		require.Empty(t, permanentEntry.ExpiresAt)

		// Check temporary entry
		require.Equal(t, "integration test temporary", temporaryEntry.Reason)
		require.False(t, temporaryEntry.Permanent)
		require.NotEmpty(t, temporaryEntry.ExpiresAt)

		// Verify timestamp format
		_, err := time.Parse(time.RFC3339, temporaryEntry.Timestamp)
		require.NoError(t, err)
		_, err = time.Parse(time.RFC3339, temporaryEntry.ExpiresAt)
		require.NoError(t, err)

		// Step 5: Remove first peer
		removeReq1 := &adminjson.RemoveBlacklistedPeerRequest{
			PeerID: nodeID1,
		}
		removeResp1, jsonErr := svc.RemoveBlacklistedPeer(ctx, removeReq1)
		require.Nil(t, jsonErr)
		require.NotNil(t, removeResp1)
		require.True(t, removeResp1.Removed)

		// Step 6: List should now contain only second peer
		listResp, jsonErr = svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, listResp)
		require.Len(t, listResp.BlacklistedPeers, 1)
		require.Equal(t, nodeID2, listResp.BlacklistedPeers[0].PeerID)

		// Step 7: Remove second peer
		removeReq2 := &adminjson.RemoveBlacklistedPeerRequest{
			PeerID: nodeID2,
		}
		removeResp2, jsonErr := svc.RemoveBlacklistedPeer(ctx, removeReq2)
		require.Nil(t, jsonErr)
		require.NotNil(t, removeResp2)
		require.True(t, removeResp2.Removed)

		// Step 8: List should be empty again
		listResp, jsonErr = svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, listResp)
		require.Empty(t, listResp.BlacklistedPeers)
	})
}

func TestBlacklistRPC_ErrorScenarios(t *testing.T) {
	svc := createMockIntegrationService(t)
	ctx := context.Background()

	t.Run("invalid_peer_id", func(t *testing.T) {
		req := &adminjson.BlacklistPeerRequest{
			PeerID: "invalid-peer-id-format",
			Reason: "test",
		}
		resp, jsonErr := svc.BlacklistPeer(ctx, req)
		require.NotNil(t, jsonErr)
		require.Nil(t, resp)
		require.Contains(t, jsonErr.Message, "failed to blacklist peer")
	})

	t.Run("remove_nonexistent_peer", func(t *testing.T) {
		validNodeID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"
		req := &adminjson.RemoveBlacklistedPeerRequest{
			PeerID: validNodeID,
		}
		resp, jsonErr := svc.RemoveBlacklistedPeer(ctx, req)
		require.NotNil(t, jsonErr)
		require.Nil(t, resp)
		require.Contains(t, jsonErr.Message, "failed to remove blacklisted peer")
	})

	t.Run("invalid_duration", func(t *testing.T) {
		validNodeID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"
		req := &adminjson.BlacklistPeerRequest{
			PeerID:   validNodeID,
			Reason:   "test",
			Duration: "invalid-duration",
		}
		resp, jsonErr := svc.BlacklistPeer(ctx, req)
		require.NotNil(t, jsonErr)
		require.Nil(t, resp)
		require.Contains(t, jsonErr.Message, "invalid duration format")
	})
}

func TestBlacklistRPC_EdgeCases(t *testing.T) {
	svc := createMockIntegrationService(t)
	ctx := context.Background()

	nodeID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"

	t.Run("empty_reason", func(t *testing.T) {
		req := &adminjson.BlacklistPeerRequest{
			PeerID: nodeID,
			Reason: "", // Empty reason should default to "manual"
		}
		resp, jsonErr := svc.BlacklistPeer(ctx, req)
		require.Nil(t, jsonErr)
		require.NotNil(t, resp)

		// Verify the entry exists and has default reason
		listReq := &adminjson.ListBlacklistedPeersRequest{}
		listResp, jsonErr := svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.Len(t, listResp.BlacklistedPeers, 1)
		require.Equal(t, "manual", listResp.BlacklistedPeers[0].Reason)

		// Cleanup
		removeReq := &adminjson.RemoveBlacklistedPeerRequest{PeerID: nodeID}
		_, jsonErr = svc.RemoveBlacklistedPeer(ctx, removeReq)
		require.Nil(t, jsonErr)
	})

	t.Run("zero_duration", func(t *testing.T) {
		req := &adminjson.BlacklistPeerRequest{
			PeerID:   nodeID,
			Reason:   "zero duration test",
			Duration: "0",
		}
		resp, jsonErr := svc.BlacklistPeer(ctx, req)
		require.Nil(t, jsonErr)
		require.NotNil(t, resp)

		// Verify it's permanent
		listReq := &adminjson.ListBlacklistedPeersRequest{}
		listResp, jsonErr := svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.Len(t, listResp.BlacklistedPeers, 1)
		require.True(t, listResp.BlacklistedPeers[0].Permanent)
		require.Empty(t, listResp.BlacklistedPeers[0].ExpiresAt)

		// Cleanup
		removeReq := &adminjson.RemoveBlacklistedPeerRequest{PeerID: nodeID}
		_, jsonErr = svc.RemoveBlacklistedPeer(ctx, removeReq)
		require.Nil(t, jsonErr)
	})

	t.Run("double_blacklist", func(t *testing.T) {
		req := &adminjson.BlacklistPeerRequest{
			PeerID: nodeID,
			Reason: "first blacklist",
		}

		// First blacklist should succeed
		resp, jsonErr := svc.BlacklistPeer(ctx, req)
		require.Nil(t, jsonErr)
		require.NotNil(t, resp)

		// Second blacklist should also succeed (overwrites)
		req.Reason = "second blacklist"
		resp, jsonErr = svc.BlacklistPeer(ctx, req)
		require.Nil(t, jsonErr)
		require.NotNil(t, resp)

		// Verify only one entry with updated reason
		listReq := &adminjson.ListBlacklistedPeersRequest{}
		listResp, jsonErr := svc.ListBlacklistedPeers(ctx, listReq)
		require.Nil(t, jsonErr)
		require.Len(t, listResp.BlacklistedPeers, 1)
		require.Equal(t, "second blacklist", listResp.BlacklistedPeers[0].Reason)

		// Cleanup
		removeReq := &adminjson.RemoveBlacklistedPeerRequest{PeerID: nodeID}
		_, jsonErr = svc.RemoveBlacklistedPeer(ctx, removeReq)
		require.Nil(t, jsonErr)
	})

	t.Run("double_remove", func(t *testing.T) {
		// First blacklist the peer
		blacklistReq := &adminjson.BlacklistPeerRequest{
			PeerID: nodeID,
			Reason: "test",
		}
		_, jsonErr := svc.BlacklistPeer(ctx, blacklistReq)
		require.Nil(t, jsonErr)

		// First remove should succeed
		removeReq := &adminjson.RemoveBlacklistedPeerRequest{PeerID: nodeID}
		resp, jsonErr := svc.RemoveBlacklistedPeer(ctx, removeReq)
		require.Nil(t, jsonErr)
		require.NotNil(t, resp)
		require.True(t, resp.Removed)

		// Second remove should fail
		resp, jsonErr = svc.RemoveBlacklistedPeer(ctx, removeReq)
		require.NotNil(t, jsonErr)
		require.Nil(t, resp)
		require.Contains(t, jsonErr.Message, "failed to remove blacklisted peer")
	})
}

func TestBlacklistRPC_ComplexDurations(t *testing.T) {
	svc := createMockIntegrationService(t)
	ctx := context.Background()

	nodeID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1"

	durations := []struct {
		input    string
		expected time.Duration
	}{
		{"1s", 1 * time.Second},
		{"1m", 1 * time.Minute},
		{"1h", 1 * time.Hour},
		{"1h30m", 90 * time.Minute},
		{"2h15m30s", 2*time.Hour + 15*time.Minute + 30*time.Second},
	}

	for _, d := range durations {
		t.Run(d.input, func(t *testing.T) {
			req := &adminjson.BlacklistPeerRequest{
				PeerID:   nodeID,
				Reason:   "duration test " + d.input,
				Duration: d.input,
			}

			start := time.Now()
			resp, jsonErr := svc.BlacklistPeer(ctx, req)
			require.Nil(t, jsonErr)
			require.NotNil(t, resp)

			// Verify the entry
			listReq := &adminjson.ListBlacklistedPeersRequest{}
			listResp, jsonErr := svc.ListBlacklistedPeers(ctx, listReq)
			require.Nil(t, jsonErr)

			// Should have exactly one entry (previous ones removed)
			require.Len(t, listResp.BlacklistedPeers, 1)
			entry := listResp.BlacklistedPeers[0]

			require.False(t, entry.Permanent)
			require.NotEmpty(t, entry.ExpiresAt)

			// Parse and verify expiration time is approximately correct
			expiresAt, err := time.Parse(time.RFC3339, entry.ExpiresAt)
			require.NoError(t, err)

			expectedExpiry := start.Add(d.expected)
			timeDiff := expiresAt.Sub(expectedExpiry)

			// Allow 1 second tolerance for processing time
			require.True(t, timeDiff >= -time.Second && timeDiff <= time.Second,
				"Expected expiry around %v, got %v (diff: %v)", expectedExpiry, expiresAt, timeDiff)

			// Cleanup for next iteration
			removeReq := &adminjson.RemoveBlacklistedPeerRequest{PeerID: nodeID}
			_, jsonErr = svc.RemoveBlacklistedPeer(ctx, removeReq)
			require.Nil(t, jsonErr)
		})
	}
}
