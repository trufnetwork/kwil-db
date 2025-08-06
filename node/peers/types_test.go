package peers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestPeerInfoJSON(t *testing.T) {
	addr1, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1234")
	addr2, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/5678")
	pid, _ := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")

	tests := []struct {
		name     string
		peerInfo PeerInfo
	}{
		{
			name: "basic peer info",
			peerInfo: PeerInfo{
				AddrInfo: AddrInfo{
					ID:    pid,
					Addrs: []multiaddr.Multiaddr{addr1, addr2},
				},
				Protos: []protocol.ID{"/proto/1.0.0", "/proto/2.0.0"},
			},
		},
		{
			name: "empty addresses",
			peerInfo: PeerInfo{
				AddrInfo: AddrInfo{
					ID:    pid,
					Addrs: []multiaddr.Multiaddr{},
				},
				Protos: []protocol.ID{"/proto/1.0.0"},
			},
		},
		{
			name: "empty protocols",
			peerInfo: PeerInfo{
				AddrInfo: AddrInfo{
					ID:    pid,
					Addrs: []multiaddr.Multiaddr{addr1},
				},
				Protos: []protocol.ID{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.peerInfo)
			require.NoError(t, err)

			t.Log(string(data))

			var decoded PeerInfo
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			require.Equal(t, tt.peerInfo.ID, decoded.ID)
			require.Equal(t, len(tt.peerInfo.Addrs), len(decoded.Addrs))
			require.Equal(t, len(tt.peerInfo.Protos), len(decoded.Protos))

			for i, addr := range tt.peerInfo.Addrs {
				require.Equal(t, addr.String(), decoded.Addrs[i].String())
			}
			for i, proto := range tt.peerInfo.Protos {
				require.Equal(t, proto, decoded.Protos[i])
			}
		})
	}
}

func TestPersistentPeerInfoJSON(t *testing.T) {
	addr1, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1234")
	pid, _ := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	pk, err := pubKeyFromPeerID(pid)
	if err != nil {
		t.Fatal(err)
	}
	nid := NodeIDFromPubKey(pk)

	t.Log(nid)

	tests := []struct {
		name     string
		peerInfo PersistentPeerInfo
	}{
		{
			name: "whitelisted peer",
			peerInfo: PersistentPeerInfo{
				NodeID:      nid,
				Addrs:       []multiaddr.Multiaddr{addr1},
				Protos:      []protocol.ID{"/proto/1.0.0"},
				Whitelisted: true,
			},
		},
		{
			name: "non-whitelisted peer",
			peerInfo: PersistentPeerInfo{
				NodeID:      nid,
				Addrs:       []multiaddr.Multiaddr{addr1},
				Protos:      []protocol.ID{"/proto/1.0.0"},
				Whitelisted: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.peerInfo)
			require.NoError(t, err)

			t.Log(string(data))

			var decoded PersistentPeerInfo
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			require.Equal(t, tt.peerInfo.NodeID, decoded.NodeID)
			require.Equal(t, tt.peerInfo.Whitelisted, decoded.Whitelisted)
			require.Equal(t, len(tt.peerInfo.Addrs), len(decoded.Addrs))
			require.Equal(t, len(tt.peerInfo.Protos), len(decoded.Protos))

			for i, addr := range tt.peerInfo.Addrs {
				require.Equal(t, addr.String(), decoded.Addrs[i].String())
			}
			for i, proto := range tt.peerInfo.Protos {
				require.Equal(t, proto, decoded.Protos[i])
			}
		})
	}
}
func TestBlacklistEntryJSON(t *testing.T) {
	pid, _ := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")

	tests := []struct {
		name  string
		entry BlacklistEntry
	}{
		{
			name: "permanent blacklist entry",
			entry: BlacklistEntry{
				PeerID:    pid,
				Reason:    "manual blacklist",
				Timestamp: mustParseTime("2023-10-01T12:00:00Z"),
				Permanent: true,
			},
		},
		{
			name: "temporary blacklist entry",
			entry: BlacklistEntry{
				PeerID:    pid,
				Reason:    "connection exhaustion",
				Timestamp: mustParseTime("2023-10-01T12:00:00Z"),
				Permanent: false,
				ExpiresAt: mustParseTime("2023-10-01T13:00:00Z"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.entry)
			require.NoError(t, err)

			t.Log(string(data))

			var decoded BlacklistEntry
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			require.Equal(t, tt.entry.PeerID, decoded.PeerID)
			require.Equal(t, tt.entry.Reason, decoded.Reason)
			require.Equal(t, tt.entry.Permanent, decoded.Permanent)
			require.True(t, tt.entry.Timestamp.Equal(decoded.Timestamp))

			if !tt.entry.Permanent {
				require.True(t, tt.entry.ExpiresAt.Equal(decoded.ExpiresAt))
			}
		})
	}
}

func TestBlacklistEntryIsExpired(t *testing.T) {
	pid, _ := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")

	tests := []struct {
		name     string
		entry    BlacklistEntry
		expected bool
	}{
		{
			name: "permanent entry never expires",
			entry: BlacklistEntry{
				PeerID:    pid,
				Permanent: true,
			},
			expected: false,
		},
		{
			name: "future expiry not expired",
			entry: BlacklistEntry{
				PeerID:    pid,
				Permanent: false,
				ExpiresAt: mustParseTime("2099-01-01T00:00:00Z"),
			},
			expected: false,
		},
		{
			name: "past expiry is expired",
			entry: BlacklistEntry{
				PeerID:    pid,
				Permanent: false,
				ExpiresAt: mustParseTime("2020-01-01T00:00:00Z"),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.IsExpired()
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestPersistentPeerInfoWithBlacklist(t *testing.T) {
	addr1, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1234")
	pid, _ := peer.Decode("16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv")
	pk, err := pubKeyFromPeerID(pid)
	require.NoError(t, err)
	nid := NodeIDFromPubKey(pk)

	blacklistEntry := &BlacklistEntry{
		PeerID:    pid,
		Reason:    "test blacklist",
		Timestamp: mustParseTime("2023-10-01T12:00:00Z"),
		Permanent: true,
	}

	tests := []struct {
		name     string
		peerInfo PersistentPeerInfo
	}{
		{
			name: "peer with blacklist entry",
			peerInfo: PersistentPeerInfo{
				NodeID:      nid,
				Addrs:       []multiaddr.Multiaddr{addr1},
				Protos:      []protocol.ID{"/proto/1.0.0"},
				Whitelisted: false,
				Blacklisted: blacklistEntry,
			},
		},
		{
			name: "peer without blacklist entry",
			peerInfo: PersistentPeerInfo{
				NodeID:      nid,
				Addrs:       []multiaddr.Multiaddr{addr1},
				Protos:      []protocol.ID{"/proto/1.0.0"},
				Whitelisted: true,
				Blacklisted: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.peerInfo)
			require.NoError(t, err)

			t.Log(string(data))

			var decoded PersistentPeerInfo
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			require.Equal(t, tt.peerInfo.NodeID, decoded.NodeID)
			require.Equal(t, tt.peerInfo.Whitelisted, decoded.Whitelisted)

			if tt.peerInfo.Blacklisted != nil {
				require.NotNil(t, decoded.Blacklisted)
				require.Equal(t, tt.peerInfo.Blacklisted.PeerID, decoded.Blacklisted.PeerID)
				require.Equal(t, tt.peerInfo.Blacklisted.Reason, decoded.Blacklisted.Reason)
				require.Equal(t, tt.peerInfo.Blacklisted.Permanent, decoded.Blacklisted.Permanent)
			} else {
				require.Nil(t, decoded.Blacklisted)
			}
		})
	}
}

// Helper function for parsing time in tests
func mustParseTime(timeStr string) time.Time {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		panic(err)
	}
	return t
}
