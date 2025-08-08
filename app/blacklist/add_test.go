package blacklist

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddMsg_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		msg      *addMsg
		expected string
	}{
		{
			name: "permanent blacklist",
			msg: &addMsg{
				peerID:   "test-peer-123",
				reason:   "manual",
				duration: "",
			},
			expected: "Blacklisted peer test-peer-123 (reason: manual, permanent)",
		},
		{
			name: "temporary blacklist",
			msg: &addMsg{
				peerID:   "test-peer-456",
				reason:   "connection issues",
				duration: "1h",
			},
			expected: "Blacklisted peer test-peer-456 (reason: connection issues, duration: 1h)",
		},
		{
			name: "custom reason permanent",
			msg: &addMsg{
				peerID:   "malicious-peer",
				reason:   "malicious behavior",
				duration: "",
			},
			expected: "Blacklisted peer malicious-peer (reason: malicious behavior, permanent)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.msg.MarshalText()
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(result))
		})
	}
}

func TestAddMsg_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		msg      *addMsg
		expected map[string]interface{}
	}{
		{
			name: "permanent blacklist",
			msg: &addMsg{
				peerID:   "test-peer-123",
				reason:   "manual",
				duration: "",
			},
			expected: map[string]interface{}{
				"peer_id":   "test-peer-123",
				"reason":    "manual",
				"permanent": true,
			},
		},
		{
			name: "temporary blacklist",
			msg: &addMsg{
				peerID:   "test-peer-456",
				reason:   "connection issues",
				duration: "1h",
			},
			expected: map[string]interface{}{
				"peer_id":   "test-peer-456",
				"reason":    "connection issues",
				"duration":  "1h",
				"permanent": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := tt.msg.MarshalJSON()
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal(jsonBytes, &result)
			require.NoError(t, err)

			require.Equal(t, tt.expected["peer_id"], result["peer_id"])
			require.Equal(t, tt.expected["reason"], result["reason"])
			require.Equal(t, tt.expected["permanent"], result["permanent"])

			if duration, ok := tt.expected["duration"]; ok {
				require.Equal(t, duration, result["duration"])
			} else {
				// For permanent blacklists, duration should not be present or be empty
				if val, exists := result["duration"]; exists {
					require.Equal(t, "", val)
				}
			}
		})
	}
}

func TestAddMsg_Interface(t *testing.T) {
	// Verify addMsg implements display.MsgFormatter interface
	var msg interface{} = &addMsg{}
	_, ok := msg.(interface {
		MarshalText() ([]byte, error)
		MarshalJSON() ([]byte, error)
	})
	require.True(t, ok, "addMsg should implement MsgFormatter interface")
}
