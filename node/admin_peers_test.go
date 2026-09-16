package node

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/peers"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// newAdminPeersPair links two mocknet hosts and connects the first to the
// second, so one has an outbound connection and the other an inbound one.
func newAdminPeersPair(t *testing.T) (dialer, listener host.Host) {
	t.Helper()

	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	_, dialer = newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, listener = newTestHost(t, mn, crypto.KeyTypeSecp256k1)

	require.NoError(t, mn.LinkAll())
	_, err := mn.ConnectPeers(dialer.ID(), listener.ID())
	require.NoError(t, err)

	return dialer, listener
}

// nodeOn builds the node that the admin service queries, on the given host.
func nodeOn(t *testing.T, h host.Host) *Node {
	t.Helper()

	pm, err := peers.NewPeerMan(&peers.Config{
		PEX:      true,
		AddrBook: filepath.Join(t.TempDir(), "addrbook.json"),
		Host:     h,
		Logger:   log.DiscardLogger,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pm.Close()) })

	return &Node{
		P2PService: P2PService{host: h, pm: pm, log: log.DiscardLogger},
		log:        log.DiscardLogger,
	}
}

// newTestPeerID returns a peer ID that belongs to no running host.
func newTestPeerID(t *testing.T) peer.ID {
	t.Helper()
	privKey, _, err := p2pcrypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	pid, err := peer.IDFromPrivateKey(privKey)
	require.NoError(t, err)
	return pid
}

// TestPeersListsAConnectedPeerWithNoAddress covers the peer an operator cannot
// see today: one that is connected but holds no dialable address, which is what
// a peer behind NAT looks like from here.
func TestPeersListsAConnectedPeerWithNoAddress(t *testing.T) {
	dialer, listener := newAdminPeersPair(t)
	n := nodeOn(t, dialer)

	n.host.Peerstore().ClearAddrs(listener.ID())

	listed, err := n.Peers(context.Background())
	require.NoError(t, err)
	require.Len(t, listed, 1, "a connected peer with no recorded address was left out of admin peers")
	require.Equal(t, multiAddrToHostPort(n.host.Network().ConnsToPeer(listener.ID())[0].RemoteMultiaddr()),
		listed[0].RemoteAddr, "the listed peer is not the connected one")
}

// TestPeersOmitsAPeerThatIsKnownButNotConnected keeps the list to live
// connections: an address book is not a connection list.
func TestPeersOmitsAPeerThatIsKnownButNotConnected(t *testing.T) {
	dialer, listener := newAdminPeersPair(t)
	n := nodeOn(t, dialer)

	absent := newTestPeerID(t)
	addr, err := ma.NewMultiaddr("/ip4/3.17.146.5/tcp/6600")
	require.NoError(t, err)
	n.host.Peerstore().AddAddr(absent, addr, peerstore.PermanentAddrTTL)

	listed, err := n.Peers(context.Background())
	require.NoError(t, err)
	require.Len(t, listed, 1, "a peer we merely know an address for was reported as connected")
	require.Equal(t, multiAddrToHostPort(n.host.Network().ConnsToPeer(listener.ID())[0].RemoteMultiaddr()),
		listed[0].RemoteAddr)
}

// TestPeersReportsDirectionFromTheConnection checks the same connection from
// both ends, since direction is the one field an operator cannot infer.
func TestPeersReportsDirectionFromTheConnection(t *testing.T) {
	dialer, listener := newAdminPeersPair(t)

	outbound, err := nodeOn(t, dialer).Peers(context.Background())
	require.NoError(t, err)
	require.Len(t, outbound, 1)
	require.False(t, outbound[0].Inbound, "the side that dialed reported an inbound connection")

	inbound, err := nodeOn(t, listener).Peers(context.Background())
	require.NoError(t, err)
	require.Len(t, inbound, 1)
	require.True(t, inbound[0].Inbound, "the side that accepted reported an outbound connection")

	require.Equal(t, outbound[0].RemoteAddr, inbound[0].LocalAddr, "the two ends disagree on the address")
	require.Equal(t, outbound[0].LocalAddr, inbound[0].RemoteAddr, "the two ends disagree on the address")
}
