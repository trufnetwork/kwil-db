package peers

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"slices"
	"testing"
	"time"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// The address set measured on the mainnet leader's address book for node-1 on
// 2026-09-10: 24 addresses, exactly one of which is routable.
var (
	node1Routable = []string{
		"/ip4/3.134.167.133/tcp/26656",
	}
	node1Ephemeral = []string{ // public IP, source ports observed via identify
		"/ip4/3.134.167.133/tcp/13335",
		"/ip4/3.134.167.133/tcp/15519",
		"/ip4/3.134.167.133/tcp/24414",
		"/ip4/3.134.167.133/tcp/33221",
		"/ip4/3.134.167.133/tcp/34191",
		"/ip4/3.134.167.133/tcp/42534",
		"/ip4/3.134.167.133/tcp/46247",
		"/ip4/3.134.167.133/tcp/47356",
		"/ip4/3.134.167.133/tcp/62215",
	}
	node1Loopback = []string{
		"/ip4/127.0.0.1/tcp/26656",
	}
	node1Private = []string{ // other operators' docker bridges
		"/ip4/172.19.0.5/tcp/26656",
		"/ip4/172.20.0.3/tcp/26656",
		"/ip4/172.21.0.9/tcp/26656",
		"/ip4/172.22.0.4/tcp/26656",
		"/ip4/172.23.0.2/tcp/26656",
		"/ip4/172.25.0.2/tcp/26656",
		"/ip4/172.26.0.4/tcp/26656",
		"/ip4/172.28.0.5/tcp/26656",
		"/ip4/172.30.0.7/tcp/26656",
		"/ip4/192.168.16.2/tcp/26656",
		"/ip4/192.168.32.4/tcp/26656",
		"/ip4/192.168.112.6/tcp/26656",
		"/ip4/192.168.224.3/tcp/26656",
	}
)

func mustAddrs(t *testing.T, strs ...[]string) []multiaddr.Multiaddr {
	t.Helper()
	var addrs []multiaddr.Multiaddr
	for _, group := range strs {
		for _, s := range group {
			a, err := multiaddr.NewMultiaddr(s)
			if err != nil {
				t.Fatalf("invalid multiaddr %q: %v", s, err)
			}
			addrs = append(addrs, a)
		}
	}
	return addrs
}

func mustAddr(t *testing.T, s string) multiaddr.Multiaddr {
	t.Helper()
	return mustAddrs(t, []string{s})[0]
}

func node1Fixture(t *testing.T) []multiaddr.Multiaddr {
	t.Helper()
	return mustAddrs(t, node1Routable, node1Ephemeral, node1Loopback, node1Private)
}

func addrStrings(addrs []multiaddr.Multiaddr) []string {
	strs := make([]string, len(addrs))
	for i, a := range addrs {
		strs[i] = a.String()
	}
	return strs
}

func requireSameAddrs(t *testing.T, got []multiaddr.Multiaddr, want []string) {
	t.Helper()
	gotStrs := addrStrings(got)
	if len(gotStrs) != len(want) {
		t.Fatalf("got %d addresses %v, want %d %v", len(gotStrs), gotStrs, len(want), want)
	}
	for _, w := range want {
		if !slices.Contains(gotStrs, w) {
			t.Errorf("missing expected address %v in %v", w, gotStrs)
		}
	}
}

// The five classes of "via" (the connection we learned the addresses over).
const (
	viaPublic   = "/ip4/3.17.146.5/tcp/6600"
	viaPrivate  = "/ip4/10.4.0.7/tcp/6600"
	viaLoopback = "/ip4/127.0.0.1/tcp/6600"
	viaMocknet  = "/ip6/100::1/tcp/4242" // neither loopback, private, nor public
)

func TestUsableAddrs(t *testing.T) {
	t.Run("mainnet fixture", func(t *testing.T) {
		tests := []struct {
			name string
			via  multiaddr.Multiaddr
			want []string
		}{{
			name: "public via keeps only public",
			via:  mustAddr(t, viaPublic),
			want: append(append([]string{}, node1Routable...), node1Ephemeral...),
		}, {
			// This is the docker integration harness guard: nodes peer over a
			// private bridge subnet and must keep each other's bridge addresses.
			name: "private via drops only loopback",
			via:  mustAddr(t, viaPrivate),
			want: append(append(append([]string{}, node1Routable...), node1Ephemeral...), node1Private...),
		}, {
			// This is the `kwild setup testnet` guard: everything on loopback.
			name: "loopback via keeps everything",
			via:  mustAddr(t, viaLoopback),
			want: append(append(append(append([]string{}, node1Routable...), node1Ephemeral...), node1Loopback...), node1Private...),
		}, {
			// This is the mocknet guard. If the switch is ever "simplified" to
			// a two-case public/private test, this fails before CI does.
			name: "unclassifiable via keeps everything",
			via:  mustAddr(t, viaMocknet),
			want: append(append(append(append([]string{}, node1Routable...), node1Ephemeral...), node1Loopback...), node1Private...),
		}, {
			name: "nil via keeps everything",
			via:  nil,
			want: append(append(append(append([]string{}, node1Routable...), node1Ephemeral...), node1Loopback...), node1Private...),
		}}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				requireSameAddrs(t, usableAddrs(node1Fixture(t), tt.via), tt.want)
			})
		}
	})

	allVias := []string{viaPublic, viaPrivate, viaLoopback, viaMocknet}

	t.Run("unspecified always dropped", func(t *testing.T) {
		addrs := mustAddrs(t, []string{"/ip4/0.0.0.0/tcp/6600", "/ip6/::/tcp/6600"})
		for _, v := range allVias {
			if got := usableAddrs(addrs, mustAddr(t, v)); len(got) != 0 {
				t.Errorf("via %v: kept unspecified addresses %v", v, addrStrings(got))
			}
		}
		if got := usableAddrs(addrs, nil); len(got) != 0 {
			t.Errorf("via nil: kept unspecified addresses %v", addrStrings(got))
		}
	})

	// go-multiaddr classifies CGNAT (100.64/10) and link-local (169.254/16) as
	// private, so a tailnet address is withheld from a public counterparty.
	t.Run("cgnat and link local are private", func(t *testing.T) {
		for _, s := range []string{"/ip4/100.64.1.1/tcp/6600", "/ip4/169.254.1.1/tcp/6600"} {
			addrs := mustAddrs(t, []string{s})
			if got := usableAddrs(addrs, mustAddr(t, viaPublic)); len(got) != 0 {
				t.Errorf("%v survived a public via", s)
			}
			if got := usableAddrs(addrs, mustAddr(t, viaPrivate)); len(got) != 1 {
				t.Errorf("%v did not survive a private via", s)
			}
		}
	})

	// Docker bootnode service names and the contrib compose subnet are both
	// classified public, so they survive a public via.
	t.Run("dns and quirk subnet survive a public via", func(t *testing.T) {
		for _, s := range []string{"/dns4/node0/tcp/6600", "/ip4/172.5.200.1/tcp/6600"} {
			if got := usableAddrs(mustAddrs(t, []string{s}), mustAddr(t, viaPublic)); len(got) != 1 {
				t.Errorf("%v was dropped over a public via", s)
			}
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if got := usableAddrs(nil, mustAddr(t, viaPublic)); len(got) != 0 {
			t.Errorf("got %v, want empty", addrStrings(got))
		}
	})
}

func TestRoutablePeers(t *testing.T) {
	privateOnly := mustAddrs(t, node1Private)
	publicOnly := mustAddrs(t, []string{"/ip4/3.17.146.5/tcp/6600"})

	newPeers := func() []PeerInfo {
		return []PeerInfo{
			{AddrInfo: AddrInfo{ID: peer.ID("node1"), Addrs: node1Fixture(t)}},
			{AddrInfo: AddrInfo{ID: peer.ID("privateonly"), Addrs: privateOnly}},
			{AddrInfo: AddrInfo{ID: peer.ID("publiconly"), Addrs: publicOnly}},
			{AddrInfo: AddrInfo{ID: peer.ID("noaddrs")}},
		}
	}

	t.Run("public via", func(t *testing.T) {
		in := newPeers()
		out, dropped := routablePeers(in, mustAddr(t, viaPublic))
		if len(out) != 3 {
			t.Fatalf("got %d peers, want 3", len(out))
		}
		// 14 from node1 (loopback + 13 private), plus the all-private peer.
		if want := 14 + len(node1Private); dropped != want {
			t.Errorf("dropped %d addresses, want %d", dropped, want)
		}
		requireSameAddrs(t, out[0].Addrs, append(append([]string{}, node1Routable...), node1Ephemeral...))
		if out[1].ID != peer.ID("publiconly") || len(out[1].Addrs) != 1 {
			t.Errorf("public-only peer was altered: %+v", out[1])
		}
		if out[2].ID != peer.ID("noaddrs") || len(out[2].Addrs) != 0 {
			t.Errorf("addressless peer was altered: %+v", out[2])
		}
		// The input must not have been mutated.
		if len(in[0].Addrs) != 24 {
			t.Errorf("input peer was mutated: %d addresses", len(in[0].Addrs))
		}
		if len(in[1].Addrs) != len(node1Private) {
			t.Errorf("input peer was mutated: %d addresses", len(in[1].Addrs))
		}
	})

	t.Run("unclassifiable via changes nothing", func(t *testing.T) {
		out, dropped := routablePeers(newPeers(), mustAddr(t, viaMocknet))
		if len(out) != 4 || dropped != 0 {
			t.Fatalf("got %d peers and %d dropped, want 4 and 0", len(out), dropped)
		}
		if len(out[0].Addrs) != 24 || len(out[1].Addrs) != len(node1Private) {
			t.Errorf("addresses were filtered over a mocknet via")
		}
	})
}

func TestPersistAddrs(t *testing.T) {
	fixture := node1Fixture(t)

	t.Run("nil via keeps everything", func(t *testing.T) {
		if got := persistAddrs(fixture, nil); len(got) != 24 {
			t.Errorf("got %d addresses, want 24", len(got))
		}
	})

	t.Run("loopback via keeps everything", func(t *testing.T) {
		if got := persistAddrs(fixture, mustAddr(t, viaLoopback)); len(got) != 24 {
			t.Errorf("got %d addresses, want 24", len(got))
		}
	})

	t.Run("public via keeps the public ten", func(t *testing.T) {
		got := persistAddrs(fixture, mustAddr(t, viaPublic))
		requireSameAddrs(t, got, append(append([]string{}, node1Routable...), node1Ephemeral...))
	})

	// An all-private peer reached over a public connection persists as an empty
	// set rather than writing its junk back. The entry stays, so its flags do
	// too; see TestSavePeersPrunesAllPrivatePeer.
	t.Run("public via drops an all-private set", func(t *testing.T) {
		privateOnly := mustAddrs(t, node1Private[:3])
		if got := persistAddrs(privateOnly, mustAddr(t, viaPublic)); len(got) != 0 {
			t.Fatalf("got %v, want none persisted", addrStrings(got))
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if got := persistAddrs(nil, mustAddr(t, viaPublic)); len(got) != 0 {
			t.Errorf("got %v, want empty", addrStrings(got))
		}
	})
}

// The tests above cover the filter in isolation. Those below go through the
// three call sites, so removing any of them fails the suite.

func newTestHostAt(t *testing.T, mn mock.Mocknet, addr string) host.Host {
	t.Helper()
	privKey, _, err := p2pcrypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	h, err := mn.AddPeer(privKey, mustAddr(t, addr))
	require.NoError(t, err)
	// Advertise the chain protocol, as NewPeerMan does for its own host. Without
	// it, PeerMan.Connected's identify goroutine decides the peer is on another
	// chain and removes it, racing anything the test asserts about that peer.
	h.SetStreamHandler(ProtocolIDPrefixChainID, func(s network.Stream) { s.Close() })
	return h
}

func newTestPeerID(t *testing.T) peer.ID {
	t.Helper()
	privKey, _, err := p2pcrypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	pid, err := peer.IDFromPrivateKey(privKey)
	require.NoError(t, err)
	return pid
}

func newTestPeerMan(t *testing.T, h host.Host, opts ...func(*Config)) *PeerMan {
	t.Helper()
	cfg := &Config{
		PEX:      true,
		AddrBook: filepath.Join(t.TempDir(), "addrbook.json"),
		Host:     h,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	pm, err := NewPeerMan(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pm.Close()) })
	return pm
}

func hasPeer(peers []PeerInfo, pid peer.ID) bool {
	return slices.ContainsFunc(peers, func(p PeerInfo) bool { return p.ID == pid })
}

// TestDiscoveryStreamHandlerWithholdsUnroutable covers the serve side: this
// node must not relay a peer that the requester could not dial from where it
// is, such as another operator's docker bridge address.
func TestDiscoveryStreamHandlerWithholdsUnroutable(t *testing.T) {
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	server := newTestHostAt(t, mn, "/ip4/3.134.167.133/tcp/6600")
	publicPeer := newTestHostAt(t, mn, "/ip4/3.17.146.5/tcp/6600")
	privatePeer := newTestHostAt(t, mn, "/ip4/172.19.0.5/tcp/6600")

	newTestPeerMan(t, server)

	linkPeers(t, mn, server.ID(), publicPeer.ID())
	linkPeers(t, mn, server.ID(), privatePeer.ID())

	served := func(t *testing.T, from host.Host) []PeerInfo {
		t.Helper()
		s, err := from.NewStream(context.Background(), server.ID(), ProtocolIDDiscover)
		require.NoError(t, err)
		defer s.Close()
		_, peers, err := recvPeersProto(s)
		require.NoError(t, err)
		return peers
	}

	t.Run("public requester", func(t *testing.T) {
		peers := served(t, publicPeer)
		require.True(t, hasPeer(peers, publicPeer.ID()), "public peer was withheld")
		require.False(t, hasPeer(peers, privatePeer.ID()), "private peer was relayed to the public network")
	})

	t.Run("private requester", func(t *testing.T) {
		// A requester on a private network is the docker-compose and LAN case:
		// it must still be told about the peer on a private address.
		privateRequester := newTestHostAt(t, mn, "/ip4/10.4.0.7/tcp/6600")
		linkPeers(t, mn, server.ID(), privateRequester.ID())

		peers := served(t, privateRequester)
		require.True(t, hasPeer(peers, privatePeer.ID()), "private peer was withheld from a private requester")
		require.True(t, hasPeer(peers, publicPeer.ID()), "public peer was withheld")
	})
}

// TestRequestPeersDiscardsUnroutable covers the ingest side: addresses we could
// not route to, learned from a peer that has not been upgraded, must not enter
// the peerstore.
func TestRequestPeersDiscardsUnroutable(t *testing.T) {
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	local := newTestHostAt(t, mn, "/ip4/3.17.146.5/tcp/6600")
	pm := newTestPeerMan(t, local)

	// What an unfiltered informant serves: one peer reachable over the public
	// internet, one reachable only on a docker bridge.
	publicID, privateID := newTestPeerID(t), newTestPeerID(t)
	advertised := []PeerInfo{
		{AddrInfo: AddrInfo{ID: publicID, Addrs: mustAddrs(t, node1Routable)}},
		{AddrInfo: AddrInfo{ID: privateID, Addrs: mustAddrs(t, node1Private[:3])}},
	}

	newInformant := func(t *testing.T, addr string) host.Host {
		t.Helper()
		h := newTestHostAt(t, mn, addr)
		h.SetStreamHandler(ProtocolIDDiscover, func(s network.Stream) {
			defer s.Close()
			if err := writePeers(s, "", advertised); err != nil {
				t.Errorf("failed to write peer list: %v", err)
			}
		})
		linkPeers(t, mn, local.ID(), h.ID())
		return h
	}

	ctx := context.Background()

	t.Run("public informant", func(t *testing.T) {
		informant := newInformant(t, "/ip4/3.134.167.133/tcp/6600")
		peers, err := pm.RequestPeers(ctx, informant.ID())
		require.NoError(t, err)
		require.True(t, hasPeer(peers, publicID), "public peer was discarded")
		require.False(t, hasPeer(peers, privateID), "private peer was accepted over a public connection")
	})

	t.Run("private informant", func(t *testing.T) {
		informant := newInformant(t, "/ip4/172.20.0.9/tcp/6600")
		peers, err := pm.RequestPeers(ctx, informant.ID())
		require.NoError(t, err)
		require.True(t, hasPeer(peers, privateID), "private peer was discarded over a private connection")
		require.True(t, hasPeer(peers, publicID), "public peer was discarded")
	})
}

// TestConnectedRecordsConnAddr covers the other half of the persist side: the
// vantage point is captured when the connection is made, which is the only
// moment we are certain of it.
func TestConnectedRecordsConnAddr(t *testing.T) {
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	local := newTestHostAt(t, mn, "/ip4/3.17.146.5/tcp/6600")
	remote := newTestHostAt(t, mn, "/ip4/3.134.167.133/tcp/6600")
	pm := newTestPeerMan(t, local)

	linkPeers(t, mn, local.ID(), remote.ID())
	conns := local.Network().ConnsToPeer(remote.ID())
	require.Len(t, conns, 1)

	// Recording is synchronous, ahead of the identify goroutine Connected
	// starts. Assert the map rather than connAddr, which would read the live
	// connection and so mask a missing record.
	pm.Connected(local.Network(), conns[0])

	pm.connAddrsMtx.Lock()
	defer pm.connAddrsMtx.Unlock()
	require.NotNil(t, pm.connAddrs[remote.ID()], "Connected did not record the connection address")
	require.Equal(t, "/ip4/3.134.167.133/tcp/6600", pm.connAddrs[remote.ID()].String())
}

// TestSavePeersPrunesAddrBook covers the persist side, including that the
// vantage point outlives the connection. Without that, the first save tick
// after a peer goes offline writes its unfiltered address set back to disk and
// the whole prune is undone.
func TestSavePeersPrunesAddrBook(t *testing.T) {
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	local := newTestHostAt(t, mn, "/ip4/3.17.146.5/tcp/6600")
	remote := newTestHostAt(t, mn, "/ip4/3.134.167.133/tcp/6600")

	addrBook := filepath.Join(t.TempDir(), "addrbook.json")
	pm := newTestPeerMan(t, local, func(cfg *Config) {
		cfg.AddrBook = addrBook
		cfg.ConnGater = NewWhitelistGater(nil)
	})
	linkPeers(t, mn, local.ID(), remote.ID())

	// Record where we reached the peer with the production recorder, rather
	// than registering as a network notifee: that would also start PeerMan's
	// async identify goroutine, which races the fixture seeded below.
	conns := local.Network().ConnsToPeer(remote.ID())
	require.Len(t, conns, 1)
	pm.rememberConnAddr(remote.ID(), conns[0].RemoteMultiaddr())

	// The pre-upgrade address book: the one address we actually reached the
	// peer on, plus the junk gossiped in from elsewhere.
	pm.ps.AddAddrs(remote.ID(), mustAddrs(t,
		[]string{"/ip4/3.134.167.133/tcp/6600"}, node1Loopback, node1Private), time.Hour)

	// Flags that must survive the round trip.
	pm.wlMtx.Lock()
	pm.persistentWhitelist[remote.ID()] = true
	pm.wlMtx.Unlock()
	pm.blacklistMtx.Lock()
	pm.blacklistedPeers[remote.ID()] = BlacklistEntry{
		PeerID:    remote.ID(),
		Reason:    "test",
		Timestamp: time.Now(),
		Permanent: true,
	}
	pm.blacklistMtx.Unlock()

	requireSaved := func(t *testing.T) PersistentPeerInfo {
		t.Helper()
		require.NoError(t, pm.savePeers())
		saved, err := loadPeers(addrBook)
		require.NoError(t, err)
		require.Len(t, saved, 1)
		requireSameAddrs(t, saved[0].Addrs, []string{"/ip4/3.134.167.133/tcp/6600"})
		return saved[0]
	}

	t.Run("while connected", func(t *testing.T) {
		requireSaved(t)
	})

	t.Run("after disconnect", func(t *testing.T) {
		require.NoError(t, mn.DisconnectPeers(local.ID(), remote.ID()))
		require.NoError(t, mn.UnlinkPeers(local.ID(), remote.ID()))
		require.Empty(t, local.Network().ConnsToPeer(remote.ID()))
		require.NotEmpty(t, pm.ps.Addrs(remote.ID()), "peer was forgotten, nothing left to prune")

		saved := requireSaved(t)
		require.True(t, saved.Whitelisted)
		require.NotNil(t, saved.Blacklisted)
	})

	t.Run("reloads pruned", func(t *testing.T) {
		fresh := newTestHostAt(t, mn, "/ip4/3.17.146.6/tcp/6600")
		pm2 := newTestPeerMan(t, fresh, func(cfg *Config) {
			cfg.AddrBook = addrBook
			cfg.ConnGater = NewWhitelistGater(nil)
		})
		requireSameAddrs(t, pm2.ps.Addrs(remote.ID()), []string{"/ip4/3.134.167.133/tcp/6600"})

		pm2.wlMtx.RLock()
		defer pm2.wlMtx.RUnlock()
		require.True(t, pm2.persistentWhitelist[remote.ID()])
	})
}

// TestSavePeersPrunesAllPrivatePeer covers the case where the filter empties a
// peer's address set completely: an inbound peer reached over a public
// connection whose every stored address is junk inherited before the upgrade.
// The entry is written with no addresses rather than having its junk restored,
// and loadAddrBook still restores its flags, which is why writing an empty set
// is safe.
func TestSavePeersPrunesAllPrivatePeer(t *testing.T) {
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	local := newTestHostAt(t, mn, "/ip4/3.17.146.5/tcp/6600")
	remote := newTestHostAt(t, mn, "/ip4/3.134.167.133/tcp/6600")

	addrBook := filepath.Join(t.TempDir(), "addrbook.json")
	pm := newTestPeerMan(t, local, func(cfg *Config) {
		cfg.AddrBook = addrBook
		cfg.ConnGater = NewWhitelistGater(nil)
	})
	linkPeers(t, mn, local.ID(), remote.ID())

	conns := local.Network().ConnsToPeer(remote.ID())
	require.Len(t, conns, 1)
	pm.rememberConnAddr(remote.ID(), conns[0].RemoteMultiaddr())

	// An inbound peer: libp2p does not add the remote of an inbound connection
	// to the peerstore, since its source port is ephemeral. So the only stored
	// addresses are the ones gossiped in, and none of them is dialable here.
	pm.ps.ClearAddrs(remote.ID())
	pm.ps.AddAddrs(remote.ID(), mustAddrs(t, node1Loopback, node1Private), time.Hour)
	requireSameAddrs(t, pm.ps.Addrs(remote.ID()), append(append([]string{}, node1Loopback...), node1Private...))

	pm.wlMtx.Lock()
	pm.persistentWhitelist[remote.ID()] = true
	pm.wlMtx.Unlock()
	pm.blacklistMtx.Lock()
	pm.blacklistedPeers[remote.ID()] = BlacklistEntry{
		PeerID:    remote.ID(),
		Reason:    "test",
		Timestamp: time.Now(),
		Permanent: true,
	}
	pm.blacklistMtx.Unlock()

	require.NoError(t, pm.savePeers())
	saved, err := loadPeers(addrBook)
	require.NoError(t, err)
	require.Len(t, saved, 1, "the entry itself must survive")
	require.Empty(t, saved[0].Addrs, "unroutable addresses were written back")
	require.True(t, saved[0].Whitelisted)
	require.NotNil(t, saved[0].Blacklisted)

	// The flags still load, which is what makes an empty address set safe.
	fresh := newTestHostAt(t, mn, "/ip4/3.17.146.7/tcp/6600")
	pm2 := newTestPeerMan(t, fresh, func(cfg *Config) {
		cfg.AddrBook = addrBook
		cfg.ConnGater = NewWhitelistGater(nil)
	})
	require.Empty(t, pm2.ps.Addrs(remote.ID()))

	pm2.wlMtx.RLock()
	whitelisted := pm2.persistentWhitelist[remote.ID()]
	pm2.wlMtx.RUnlock()
	require.True(t, whitelisted, "whitelist flag lost for a zero-address entry")

	pm2.blacklistMtx.RLock()
	_, blacklisted := pm2.blacklistedPeers[remote.ID()]
	pm2.blacklistMtx.RUnlock()
	require.True(t, blacklisted, "blacklist flag lost for a zero-address entry")
}
