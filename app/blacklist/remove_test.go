package blacklist

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveMsg_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		msg      *removeMsg
		expected string
	}{
		{
			name: "simple peer ID",
			msg: &removeMsg{
				peerID: "test-peer-123",
			},
			expected: "Removed node test-peer-123 from blacklist",
		},
		{
			name: "long peer ID",
			msg: &removeMsg{
				peerID: "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
			},
			expected: "Removed node 0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1 from blacklist",
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

func TestRemoveMsg_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		msg      *removeMsg
		expected map[string]interface{}
	}{
		{
			name: "simple peer ID",
			msg: &removeMsg{
				peerID: "test-peer-123",
			},
			expected: map[string]interface{}{
				"node_id": "test-peer-123",
				"removed": true,
			},
		},
		{
			name: "node ID format",
			msg: &removeMsg{
				peerID: "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
			},
			expected: map[string]interface{}{
				"node_id": "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
				"removed": true,
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

			require.Equal(t, tt.expected["node_id"], result["node_id"])
			require.Equal(t, tt.expected["removed"], result["removed"])
		})
	}
}

func TestRemoveMsg_Interface(t *testing.T) {
	// Verify removeMsg implements display.MsgFormatter interface
	var msg interface{} = &removeMsg{}
	_, ok := msg.(interface {
		MarshalText() ([]byte, error)
		MarshalJSON() ([]byte, error)
	})
	require.True(t, ok, "removeMsg should implement MsgFormatter interface")
}
