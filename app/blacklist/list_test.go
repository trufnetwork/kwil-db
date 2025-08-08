package blacklist

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	adminTypes "github.com/trufnetwork/kwil-db/core/types/admin"
)

func TestListBlacklistedPeersMsg_MarshalText(t *testing.T) {
	now := time.Now().UTC()
	expiry := now.Add(1 * time.Hour)

	tests := []struct {
		name     string
		msg      *listBlacklistedPeersMsg
		expected []string // strings that should be in the output
	}{
		{
			name: "empty blacklist",
			msg: &listBlacklistedPeersMsg{
				peers: []*adminTypes.BlacklistEntry{},
			},
			expected: []string{"No blacklisted nodes"},
		},
		{
			name: "single permanent peer",
			msg: &listBlacklistedPeersMsg{
				peers: []*adminTypes.BlacklistEntry{
					{
						PeerID:    "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
						Reason:    "manual",
						Timestamp: now,
						Permanent: true,
						ExpiresAt: nil,
					},
				},
			},
			expected: []string{
				"Blacklisted Nodes:",
				"NODE ID",
				"REASON",
				"TYPE",
				"manual",
				"Permanent",
				"0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#...",
			},
		},
		{
			name: "single temporary peer",
			msg: &listBlacklistedPeersMsg{
				peers: []*adminTypes.BlacklistEntry{
					{
						PeerID:    "test-peer-123",
						Reason:    "connection issues",
						Timestamp: now,
						Permanent: false,
						ExpiresAt: &expiry,
					},
				},
			},
			expected: []string{
				"Blacklisted Nodes:",
				"test-peer-123",
				"connection issues",
				"Temporary",
				expiry.Format("2006-01-02T15:04:05Z"),
			},
		},
		{
			name: "multiple peers",
			msg: &listBlacklistedPeersMsg{
				peers: []*adminTypes.BlacklistEntry{
					{
						PeerID:    "peer1",
						Reason:    "manual",
						Timestamp: now,
						Permanent: true,
						ExpiresAt: nil,
					},
					{
						PeerID:    "peer2",
						Reason:    "timeout",
						Timestamp: now,
						Permanent: false,
						ExpiresAt: &expiry,
					},
				},
			},
			expected: []string{
				"Blacklisted Nodes:",
				"peer1",
				"peer2",
				"manual",
				"timeout",
				"Permanent",
				"Temporary",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.msg.MarshalText()
			require.NoError(t, err)

			resultStr := string(result)
			for _, expected := range tt.expected {
				require.Contains(t, resultStr, expected, "Output should contain: %s", expected)
			}
		})
	}
}

func TestListBlacklistedPeersMsg_MarshalJSON(t *testing.T) {
	now := time.Now().UTC()
	expiry := now.Add(1 * time.Hour)

	tests := []struct {
		name     string
		msg      *listBlacklistedPeersMsg
		expected []map[string]interface{}
	}{
		{
			name: "empty blacklist",
			msg: &listBlacklistedPeersMsg{
				peers: []*adminTypes.BlacklistEntry{},
			},
			expected: []map[string]interface{}{},
		},
		{
			name: "single peer",
			msg: &listBlacklistedPeersMsg{
				peers: []*adminTypes.BlacklistEntry{
					{
						PeerID:    "test-peer",
						Reason:    "manual",
						Timestamp: now,
						Permanent: true,
						ExpiresAt: nil,
					},
				},
			},
			expected: []map[string]interface{}{
				{
					"peer_id":   "test-peer",
					"reason":    "manual",
					"timestamp": now.Format(time.RFC3339),
					"permanent": true,
				},
			},
		},
		{
			name: "multiple peers",
			msg: &listBlacklistedPeersMsg{
				peers: []*adminTypes.BlacklistEntry{
					{
						PeerID:    "peer1",
						Reason:    "manual",
						Timestamp: now,
						Permanent: true,
						ExpiresAt: nil,
					},
					{
						PeerID:    "peer2",
						Reason:    "timeout",
						Timestamp: now,
						Permanent: false,
						ExpiresAt: &expiry,
					},
				},
			},
			expected: []map[string]interface{}{
				{
					"peer_id":   "peer1",
					"reason":    "manual",
					"timestamp": now.Format(time.RFC3339),
					"permanent": true,
				},
				{
					"peer_id":    "peer2",
					"reason":     "timeout",
					"timestamp":  now.Format(time.RFC3339),
					"permanent":  false,
					"expires_at": expiry.Format(time.RFC3339),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := tt.msg.MarshalJSON()
			require.NoError(t, err)

			var result []map[string]interface{}
			err = json.Unmarshal(jsonBytes, &result)
			require.NoError(t, err)

			require.Equal(t, tt.expected, result)
		})
	}
}

func TestListBlacklistedPeersMsg_PeerIDTruncation(t *testing.T) {
	// Test that very long peer IDs are properly truncated in text output
	longPeerID := "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1-extra-long-suffix-that-should-be-truncated"
	msg := &listBlacklistedPeersMsg{
		peers: []*adminTypes.BlacklistEntry{
			{
				PeerID:    longPeerID,
				Reason:    "test",
				Timestamp: time.Now().UTC(),
				Permanent: true,
				ExpiresAt: nil,
			},
		},
	}

	result, err := msg.MarshalText()
	require.NoError(t, err)

	resultStr := string(result)
	// Should contain truncated version with ellipsis
	require.Contains(t, resultStr, "...")
	// Should not contain the full long peer ID
	require.NotContains(t, resultStr, "extra-long-suffix-that-should-be-truncated")
}

func TestListBlacklistedPeersMsg_TimeFormatting(t *testing.T) {
	// Test proper time formatting in text output
	testTime := time.Date(2025, 1, 8, 14, 30, 0, 0, time.UTC)
	expiryTime := testTime.Add(1 * time.Hour)
	msg := &listBlacklistedPeersMsg{
		peers: []*adminTypes.BlacklistEntry{
			{
				PeerID:    "test-peer",
				Reason:    "test",
				Timestamp: testTime,
				Permanent: false,
				ExpiresAt: &expiryTime,
			},
		},
	}

	result, err := msg.MarshalText()
	require.NoError(t, err)

	resultStr := string(result)
	// Should contain formatted timestamps
	require.Contains(t, resultStr, "2025-01-08T14:30:00Z")
	require.Contains(t, resultStr, "2025-01-08T15:30:00Z")
}

func TestListBlacklistedPeersMsg_Interface(t *testing.T) {
	// Verify listBlacklistedPeersMsg implements display.MsgFormatter interface
	var msg interface{} = &listBlacklistedPeersMsg{}
	_, ok := msg.(interface {
		MarshalText() ([]byte, error)
		MarshalJSON() ([]byte, error)
	})
	require.True(t, ok, "listBlacklistedPeersMsg should implement MsgFormatter interface")
}
