package peers

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

var blackholeIP6 = net.ParseIP("100::")

func newTestHost(t *testing.T, mn mock.Mocknet) ([]byte, host.Host) {
	privKey, _, err := p2pcrypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	id, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		t.Fatalf("Failed to get private key: %v", err)
	}
	suffix := id
	if len(id) > 8 {
		suffix = id[len(id)-8:]
	}
	ip := append(net.IP{}, blackholeIP6...)
	copy(ip[net.IPv6len-len(suffix):], suffix)
	addr, err := ma.NewMultiaddr(fmt.Sprintf("/ip6/%s/tcp/4242", ip))
	if err != nil {
		t.Fatalf("Failed to create multiaddress: %v", err)
	}
	// t.Log(addr) // e.g. /ip6/100::1bb1:760e:df55:9ed1/tcp/4242
	host, err := mn.AddPeer(privKey, addr)
	if err != nil {
		t.Fatalf("Failed to add peer to mocknet: %v", err)
	}

	pkBytes, err := privKey.Raw()
	if err != nil {
		t.Fatalf("Failed to get private key bytes: %v", err)
	}
	return pkBytes, host
}

func makeTestHosts(t *testing.T, n int) ([]host.Host, mock.Mocknet) {
	mn := mock.New()
	t.Cleanup(func() {
		mn.Close()
	})

	var hosts []host.Host

	for range n {
		_, h := newTestHost(t, mn)
		// t.Logf("node host is %v", h.ID())

		// setupStreamHandlers(t, h)
		hosts = append(hosts, h)
	}

	return hosts, mn
}

/*func linkAll(t *testing.T, mn mock.Mocknet) {
	if err := mn.LinkAll(); err != nil {
		t.Fatalf("Failed to link hosts: %v", err)
	}
	if err := mn.ConnectAllButSelf(); err != nil {
		t.Fatalf("Failed to connect hosts: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
}*/

func linkPeers(t *testing.T, mn mock.Mocknet, p1, p2 peer.ID) {
	if _, err := mn.LinkPeers(p1, p2); err != nil {
		t.Fatalf("Failed to link hosts: %v", err)
	}
	if _, err := mn.ConnectPeers(p1, p2); err != nil {
		t.Fatalf("Failed to connect hosts: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
}

func TestPeerDiscoverStream(t *testing.T) {
	hosts, mn := makeTestHosts(t, 3)
	// linkAll(t, mn)

	h1, h2, h3 := hosts[0], hosts[1], hosts[2]
	pid1, pid2, pid3 := h1.ID(), h2.ID(), h3.ID()

	dir1 := t.TempDir()
	pm1, err := NewPeerMan(&Config{
		PEX:      true,
		AddrBook: filepath.Join(dir1, "addrbook.json"),
		Host:     h1,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, pm1.Close()) }()

	dir2 := t.TempDir()
	pm2, err := NewPeerMan(&Config{
		PEX:      true,
		AddrBook: filepath.Join(dir2, "addrbook.json"),
		Host:     h2,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, pm2.Close()) }()

	// connect h1 and h2 (not h3)
	linkPeers(t, mn, pid1, pid2)

	ctx := context.Background()

	t.Run("discover myself w/ requestPeersProto", func(t *testing.T) {
		s, err := h2.NewStream(ctx, pid1, ProtocolIDDiscover)
		if err != nil {
			t.Fatalf("Failed create new stream: %v", err)
		}

		chainID, addrs, err := recvPeersProto(s)
		if err != nil {
			t.Fatalf("failed to read peer discover response: %v", err)
		}

		t.Log(chainID)

		// They know me and only me
		if len(addrs) != 1 {
			t.Fatalf("expected one address, got %d", len(addrs))
		}

		require.Equal(t, h2.ID().String(), addrs[0].ID.String())
	})

	t.Run("discover myself w/ requestPeers", func(t *testing.T) {
		addrs, err := pm1.RequestPeers(ctx, pid2)
		if err != nil {
			t.Fatalf("failed to read peer discover response: %v", err)
		}

		// They know me and only me
		if len(addrs) != 1 {
			t.Fatalf("expected one address, got %d", len(addrs))
		}

		require.Equal(t, h1.ID(), addrs[0].ID)
	})

	t.Run("discover myself and h3 w/ requestPeers", func(t *testing.T) {
		// Connect h2 to h3
		linkPeers(t, mn, pid2, pid3)
		defer mn.UnlinkPeers(pid2, pid3)
		defer mn.DisconnectPeers(pid2, pid3)

		addrs, err := pm1.RequestPeers(ctx, h2.ID())
		if err != nil {
			t.Fatalf("failed to read peer discover response: %v", err)
		}

		// They know me *and* h2 now
		if len(addrs) != 2 {
			t.Fatalf("expected 2 addresses, got %d", len(addrs))
		}

		if !slices.ContainsFunc(addrs, func(addr PeerInfo) bool {
			return addr.ID == h1.ID()
		}) {
			t.Errorf("self was not included in returned addresses")
		}

		if !slices.ContainsFunc(addrs, func(addr PeerInfo) bool {
			return addr.ID == pid3
		}) {
			t.Errorf("h2 was not included in returned addresses")
		}
	})
}
