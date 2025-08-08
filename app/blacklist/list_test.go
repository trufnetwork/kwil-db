package blacklist

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	adminjson "github.com/trufnetwork/kwil-db/core/rpc/json/admin"
)

func TestListBlacklistedPeersMsg_MarshalText(t *testing.T) {
	now := time.Now()
	expiry := now.Add(1 * time.Hour)

	tests := []struct {
		name     string
		msg      *listBlacklistedPeersMsg
		expected []string // strings that should be in the output
	}{
		{
			name: "empty blacklist",
			msg: &listBlacklistedPeersMsg{
				peers: []adminjson.BlacklistEntryJSON{},
			},
			expected: []string{"No blacklisted peers"},
		},
		{
			name: "single permanent peer",
			msg: &listBlacklistedPeersMsg{
				peers: []adminjson.BlacklistEntryJSON{
					{
						PeerID:    "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
						Reason:    "manual",
						Timestamp: now.Format(time.RFC3339),
						Permanent: true,
						ExpiresAt: "",
					},
				},
			},
			expected: []string{
				"Blacklisted Peers:",
				"PEER ID",
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
				peers: []adminjson.BlacklistEntryJSON{
					{
						PeerID:    "test-peer-123",
						Reason:    "connection issues",
						Timestamp: now.Format(time.RFC3339),
						Permanent: false,
						ExpiresAt: expiry.Format(time.RFC3339),
					},
				},
			},
			expected: []string{
				"Blacklisted Peers:",
				"test-peer-123",
				"connection issues",
				"Temporary",
				expiry.Format("2006-01-02T15:04:05Z"),
			},
		},
		{
			name: "multiple peers",
			msg: &listBlacklistedPeersMsg{
				peers: []adminjson.BlacklistEntryJSON{
					{
						PeerID:    "peer1",
						Reason:    "manual",
						Timestamp: now.Format(time.RFC3339),
						Permanent: true,
					},
					{
						PeerID:    "peer2",
						Reason:    "timeout",
						Timestamp: now.Format(time.RFC3339),
						Permanent: false,
						ExpiresAt: expiry.Format(time.RFC3339),
					},
				},
			},
			expected: []string{
				"Blacklisted Peers:",
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
	now := time.Now()
	expiry := now.Add(1 * time.Hour)

	tests := []struct {
		name     string
		msg      *listBlacklistedPeersMsg
		expected []adminjson.BlacklistEntryJSON
	}{
		{
			name: "empty blacklist",
			msg: &listBlacklistedPeersMsg{
				peers: []adminjson.BlacklistEntryJSON{},
			},
			expected: []adminjson.BlacklistEntryJSON{},
		},
		{
			name: "single peer",
			msg: &listBlacklistedPeersMsg{
				peers: []adminjson.BlacklistEntryJSON{
					{
						PeerID:    "test-peer",
						Reason:    "manual",
						Timestamp: now.Format(time.RFC3339),
						Permanent: true,
					},
				},
			},
			expected: []adminjson.BlacklistEntryJSON{
				{
					PeerID:    "test-peer",
					Reason:    "manual",
					Timestamp: now.Format(time.RFC3339),
					Permanent: true,
				},
			},
		},
		{
			name: "multiple peers",
			msg: &listBlacklistedPeersMsg{
				peers: []adminjson.BlacklistEntryJSON{
					{
						PeerID:    "peer1",
						Reason:    "manual",
						Timestamp: now.Format(time.RFC3339),
						Permanent: true,
					},
					{
						PeerID:    "peer2",
						Reason:    "timeout",
						Timestamp: now.Format(time.RFC3339),
						Permanent: false,
						ExpiresAt: expiry.Format(time.RFC3339),
					},
				},
			},
			expected: []adminjson.BlacklistEntryJSON{
				{
					PeerID:    "peer1",
					Reason:    "manual",
					Timestamp: now.Format(time.RFC3339),
					Permanent: true,
				},
				{
					PeerID:    "peer2",
					Reason:    "timeout",
					Timestamp: now.Format(time.RFC3339),
					Permanent: false,
					ExpiresAt: expiry.Format(time.RFC3339),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := tt.msg.MarshalJSON()
			require.NoError(t, err)

			var result []adminjson.BlacklistEntryJSON
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
		peers: []adminjson.BlacklistEntryJSON{
			{
				PeerID:    longPeerID,
				Reason:    "test",
				Timestamp: time.Now().Format(time.RFC3339),
				Permanent: true,
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
	msg := &listBlacklistedPeersMsg{
		peers: []adminjson.BlacklistEntryJSON{
			{
				PeerID:    "test-peer",
				Reason:    "test",
				Timestamp: testTime.Format(time.RFC3339),
				Permanent: false,
				ExpiresAt: testTime.Add(1 * time.Hour).Format(time.RFC3339),
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
