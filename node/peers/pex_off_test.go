package peers

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/core/log"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/require"
)

// closesWithoutAnswering is the discovery handler a node with PEX disabled
// registered before this change, and the one every node still on an older
// release registers today.
func closesWithoutAnswering(s network.Stream) { s.Close() }

// TestDiscoveryStreamAnswersWhenPexIsOff covers the serving side: a node that
// does not participate in peer exchange still has to answer the stream it
// advertises, because refusing to register the protocol would fail the
// required-protocol check every peer runs on connect.
func TestDiscoveryStreamAnswersWhenPexIsOff(t *testing.T) {
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	server := newTestHostAt(t, mn, "/ip4/3.134.167.133/tcp/6600")
	client := newTestHostAt(t, mn, "/ip4/3.17.146.5/tcp/6600")

	newTestPeerMan(t, server, func(c *Config) { c.PEX = false })
	linkPeers(t, mn, server.ID(), client.ID())

	s, err := client.NewStream(context.Background(), server.ID(), ProtocolIDDiscover)
	require.NoError(t, err, "a node with PEX off no longer advertises the discovery protocol")
	defer s.Close()

	_, peers, err := recvPeersProto(s)
	require.NoError(t, err, "a node with PEX off closed the discovery stream without answering")
	require.Empty(t, peers, "a node with PEX off served a peer list")
}

// TestRequestPeersClassifiesAPeerThatServesNothing covers the receiving side
// against a peer on an older release, which is what stops the warning on a
// running network without waiting for the other operator to upgrade.
func TestRequestPeersClassifiesAPeerThatServesNothing(t *testing.T) {
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	local := newTestHostAt(t, mn, "/ip4/3.17.146.5/tcp/6600")
	legacy := newTestHostAt(t, mn, "/ip4/3.134.167.133/tcp/6600")
	legacy.SetStreamHandler(ProtocolIDDiscover, closesWithoutAnswering)

	pm := newTestPeerMan(t, local)
	linkPeers(t, mn, local.ID(), legacy.ID())

	_, err := pm.RequestPeers(context.Background(), legacy.ID())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPeerServesNoPeers,
		"a peer that answered with nothing is indistinguishable from a broken one")
}

// TestRequestPeersStillReportsATruncatedAnswer guards the discrimination: a
// peer that starts a peer list and stops partway through is broken, and must
// not be filed under the peer that answered honestly with nothing.
func TestRequestPeersStillReportsATruncatedAnswer(t *testing.T) {
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	local := newTestHostAt(t, mn, "/ip4/3.17.146.5/tcp/6600")
	truncating := newTestHostAt(t, mn, "/ip4/3.134.167.133/tcp/6600")
	truncating.SetStreamHandler(ProtocolIDDiscover, func(s network.Stream) {
		defer s.Close()
		_, _ = s.Write([]byte(`{"chain_id":"x","peers":[`))
	})

	pm := newTestPeerMan(t, local)
	linkPeers(t, mn, local.ID(), truncating.ID())

	_, err := pm.RequestPeers(context.Background(), truncating.ID())
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPeerServesNoPeers,
		"a peer that stopped mid-message was read as a peer with nothing to say")
}

// againstALegacyPexPeer connects a peer manager to a peer running the handler
// that hangs up, and captures everything the peer manager logs.
func againstALegacyPexPeer(t *testing.T) (*PeerMan, peer.ID, *bytes.Buffer) {
	t.Helper()

	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	local := newTestHostAt(t, mn, "/ip4/3.17.146.5/tcp/6600")
	legacy := newTestHostAt(t, mn, "/ip4/3.134.167.133/tcp/6600")
	legacy.SetStreamHandler(ProtocolIDDiscover, closesWithoutAnswering)

	logged := &bytes.Buffer{}
	pm := newTestPeerMan(t, local, func(c *Config) {
		c.Logger = log.New(log.WithWriter(logged), log.WithLevel(log.LevelDebug))
	})
	linkPeers(t, mn, local.ID(), legacy.ID())

	return pm, legacy.ID(), logged
}

func requireNoWarning(t *testing.T, logged *bytes.Buffer) {
	t.Helper()
	for _, line := range strings.Split(logged.String(), "\n") {
		if strings.Contains(line, "WRN") || strings.Contains(line, "WARN") {
			t.Errorf("a peer that does not serve peers was reported as a failure: %s", line)
		}
	}
}

// TestFindPeersDoesNotWarnAboutAPeerThatServesNothing pins the reason the issue
// was filed: a healthy peer read as a failing one, every 20 seconds, forever.
func TestFindPeersDoesNotWarnAboutAPeerThatServesNothing(t *testing.T) {
	pm, _, logged := againstALegacyPexPeer(t)

	peerChan, err := pm.FindPeers(context.Background(), "kwil_namespace")
	require.NoError(t, err)
	for range peerChan { //nolint:revive // drain
	}
	time.Sleep(100 * time.Millisecond)

	requireNoWarning(t, logged)
}

// TestCrawlPeerDoesNotWarnAboutAPeerThatServesNothing covers the second caller.
// A crawl reaches the same peer over the same protocol, so it reads the same
// answer the same way.
func TestCrawlPeerDoesNotWarnAboutAPeerThatServesNothing(t *testing.T) {
	pm, legacy, logged := againstALegacyPexPeer(t)

	pm.crawlPeer(context.Background(), legacy)

	requireNoWarning(t, logged)
}
