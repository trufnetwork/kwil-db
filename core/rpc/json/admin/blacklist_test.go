package adminjson

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlacklistPeerRequest_JSON(t *testing.T) {
	tests := []struct {
		name     string
		req      BlacklistPeerRequest
		expected string
	}{
		{
			name: "permanent blacklist with reason",
			req: BlacklistPeerRequest{
				PeerID: "12D3KooWExample123456",
				Reason: "malicious behavior",
			},
			expected: `{"peerid":"12D3KooWExample123456","reason":"malicious behavior"}`,
		},
		{
			name: "temporary blacklist with duration",
			req: BlacklistPeerRequest{
				PeerID:   "12D3KooWExample123456",
				Reason:   "testing",
				Duration: "1h30m",
			},
			expected: `{"peerid":"12D3KooWExample123456","reason":"testing","duration":"1h30m"}`,
		},
		{
			name: "minimal request (peer ID only)",
			req: BlacklistPeerRequest{
				PeerID: "12D3KooWExample123456",
			},
			expected: `{"peerid":"12D3KooWExample123456"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			jsonData, err := json.Marshal(tt.req)
			require.NoError(t, err)
			require.JSONEq(t, tt.expected, string(jsonData))

			// Test unmarshaling
			var unmarshaled BlacklistPeerRequest
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)
			require.Equal(t, tt.req, unmarshaled)
		})
	}
}

func TestRemoveBlacklistedPeerRequest_JSON(t *testing.T) {
	req := RemoveBlacklistedPeerRequest{
		PeerID: "12D3KooWExample123456",
	}
	expected := `{"peerid":"12D3KooWExample123456"}`

	// Test marshaling
	jsonData, err := json.Marshal(req)
	require.NoError(t, err)
	require.JSONEq(t, expected, string(jsonData))

	// Test unmarshaling
	var unmarshaled RemoveBlacklistedPeerRequest
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)
	require.Equal(t, req, unmarshaled)
}

func TestListBlacklistedPeersRequest_JSON(t *testing.T) {
	req := ListBlacklistedPeersRequest{}
	expected := `{}`

	// Test marshaling
	jsonData, err := json.Marshal(req)
	require.NoError(t, err)
	require.JSONEq(t, expected, string(jsonData))

	// Test unmarshaling
	var unmarshaled ListBlacklistedPeersRequest
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)
	require.Equal(t, req, unmarshaled)
}

func TestBlacklistEntryJSON_JSON(t *testing.T) {
	tests := []struct {
		name     string
		entry    BlacklistEntryJSON
		expected string
	}{
		{
			name: "permanent blacklist entry",
			entry: BlacklistEntryJSON{
				PeerID:    "12D3KooWExample123456",
				Reason:    "manual blacklist",
				Timestamp: "2023-10-01T12:00:00Z",
				Permanent: true,
			},
			expected: `{
				"peer_id":"12D3KooWExample123456",
				"reason":"manual blacklist",
				"timestamp":"2023-10-01T12:00:00Z",
				"permanent":true
			}`,
		},
		{
			name: "temporary blacklist entry",
			entry: BlacklistEntryJSON{
				PeerID:    "12D3KooWExample123456",
				Reason:    "connection exhaustion",
				Timestamp: "2023-10-01T12:00:00Z",
				Permanent: false,
				ExpiresAt: "2023-10-01T13:00:00Z",
			},
			expected: `{
				"peer_id":"12D3KooWExample123456",
				"reason":"connection exhaustion",
				"timestamp":"2023-10-01T12:00:00Z",
				"permanent":false,
				"expires_at":"2023-10-01T13:00:00Z"
			}`,
		},
		{
			name: "empty reason handling",
			entry: BlacklistEntryJSON{
				PeerID:    "12D3KooWExample123456",
				Reason:    "",
				Timestamp: "2023-10-01T12:00:00Z",
				Permanent: true,
			},
			expected: `{
				"peer_id":"12D3KooWExample123456",
				"reason":"",
				"timestamp":"2023-10-01T12:00:00Z",
				"permanent":true
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			jsonData, err := json.Marshal(tt.entry)
			require.NoError(t, err)
			require.JSONEq(t, tt.expected, string(jsonData))

			// Test unmarshaling
			var unmarshaled BlacklistEntryJSON
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)
			require.Equal(t, tt.entry, unmarshaled)
		})
	}
}

func TestListBlacklistedPeersResponse_JSON(t *testing.T) {
	tests := []struct {
		name     string
		resp     ListBlacklistedPeersResponse
		expected string
	}{
		{
			name: "empty list",
			resp: ListBlacklistedPeersResponse{
				BlacklistedPeers: []BlacklistEntryJSON{},
			},
			expected: `{}`,
		},
		{
			name: "single entry",
			resp: ListBlacklistedPeersResponse{
				BlacklistedPeers: []BlacklistEntryJSON{
					{
						PeerID:    "12D3KooWExample123456",
						Reason:    "testing",
						Timestamp: "2023-10-01T12:00:00Z",
						Permanent: true,
					},
				},
			},
			expected: `{
				"blacklisted_peers": [{
					"peer_id":"12D3KooWExample123456",
					"reason":"testing",
					"timestamp":"2023-10-01T12:00:00Z",
					"permanent":true
				}]
			}`,
		},
		{
			name: "multiple entries",
			resp: ListBlacklistedPeersResponse{
				BlacklistedPeers: []BlacklistEntryJSON{
					{
						PeerID:    "12D3KooWExample123456",
						Reason:    "manual",
						Timestamp: "2023-10-01T12:00:00Z",
						Permanent: true,
					},
					{
						PeerID:    "12D3KooWExample789012",
						Reason:    "timeout",
						Timestamp: "2023-10-01T13:00:00Z",
						Permanent: false,
						ExpiresAt: "2023-10-01T14:00:00Z",
					},
				},
			},
			expected: `{
				"blacklisted_peers": [
					{
						"peer_id":"12D3KooWExample123456",
						"reason":"manual",
						"timestamp":"2023-10-01T12:00:00Z",
						"permanent":true
					},
					{
						"peer_id":"12D3KooWExample789012",
						"reason":"timeout",
						"timestamp":"2023-10-01T13:00:00Z",
						"permanent":false,
						"expires_at":"2023-10-01T14:00:00Z"
					}
				]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			jsonData, err := json.Marshal(tt.resp)
			require.NoError(t, err)
			require.JSONEq(t, tt.expected, string(jsonData))

			// Test unmarshaling
			var unmarshaled ListBlacklistedPeersResponse
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			// For empty slice, after unmarshaling it becomes nil, which is equivalent
			if len(tt.resp.BlacklistedPeers) == 0 {
				require.Empty(t, unmarshaled.BlacklistedPeers)
			} else {
				require.Equal(t, tt.resp, unmarshaled)
			}
		})
	}
}

func TestBlacklistPeerResponse_JSON(t *testing.T) {
	resp := BlacklistPeerResponse{}
	expected := `{}`

	// Test marshaling
	jsonData, err := json.Marshal(resp)
	require.NoError(t, err)
	require.JSONEq(t, expected, string(jsonData))

	// Test unmarshaling
	var unmarshaled BlacklistPeerResponse
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)
	require.Equal(t, resp, unmarshaled)
}

func TestRemoveBlacklistedPeerResponse_JSON(t *testing.T) {
	tests := []struct {
		name     string
		resp     RemoveBlacklistedPeerResponse
		expected string
	}{
		{
			name:     "removed successfully",
			resp:     RemoveBlacklistedPeerResponse{Removed: true},
			expected: `{"removed":true}`,
		},
		{
			name:     "not removed",
			resp:     RemoveBlacklistedPeerResponse{Removed: false},
			expected: `{"removed":false}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			jsonData, err := json.Marshal(tt.resp)
			require.NoError(t, err)
			require.JSONEq(t, tt.expected, string(jsonData))

			// Test unmarshaling
			var unmarshaled RemoveBlacklistedPeerResponse
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)
			require.Equal(t, tt.resp, unmarshaled)
		})
	}
}

func TestBlacklistMethodConstants(t *testing.T) {
	// Verify method names are correctly defined
	require.Equal(t, "admin.blacklist_peer", string(MethodBlacklistPeer))
	require.Equal(t, "admin.remove_blacklisted_peer", string(MethodRemoveBlacklistedPeer))
	require.Equal(t, "admin.list_blacklisted_peers", string(MethodListBlacklistedPeers))
}
