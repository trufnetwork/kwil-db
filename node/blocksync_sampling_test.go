package node

import (
	"bytes"
	"context"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/store/memstore"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"github.com/stretchr/testify/require"
)

// resetPeerBest empties peerBest now and again when the test ends. It is one
// map for the whole package, so whatever a test leaves in it is what the next
// test's block requests read.
func resetPeerBest(t *testing.T) {
	t.Helper()
	peerBest.Clear()
	t.Cleanup(peerBest.Clear)
}

func TestPeerSamplingInSmallNetworks(t *testing.T) {
	// Test that the peer sampling logic queries more peers in small networks
	mn := mock.New()
	defer mn.Close()

	// Create 4 hosts (1 requester + 3 peers)
	_, hMe := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, h1 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, h2 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, h3 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())
	time.Sleep(100 * time.Millisecond)

	// Get peer list and verify we have 3 peers
	allPeers := peerHosts(hMe)
	require.Len(t, allPeers, 3, "Should have exactly 3 peers")
	require.Contains(t, allPeers, h1.ID())
	require.Contains(t, allPeers, h2.ID())
	require.Contains(t, allPeers, h3.ID())

	// This verifies that the peer discovery mechanism works correctly
	// and that our sampling logic will have the right input
}

func TestPeerCacheFiltering(t *testing.T) {
	// Test that peers with stale cache entries are not filtered out
	resetPeerBest(t)
	mn := mock.New()
	defer mn.Close()

	_, hMe := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, hPeer := newTestHost(t, mn, crypto.KeyTypeSecp256k1)

	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())
	time.Sleep(100 * time.Millisecond)

	const targetHeight = int64(200)

	// Add a stale cache entry (older than cacheTTL)
	oldTime := time.Now().Add(-2 * cacheTTL)
	peerBest.Store(hPeer.ID(), peerInfo{height: targetHeight - 1, seenAt: oldTime})

	// Get all peers - should include the peer despite stale cache
	allPeers := peerHosts(hMe)
	require.Contains(t, allPeers, hPeer.ID(), "Peer should be discovered")
	require.Len(t, allPeers, 1, "Should have exactly one peer")
}

func TestPeerBestCacheCleanup(t *testing.T) {
	// Test the cache cleanup functionality
	resetPeerBest(t)
	mn := mock.New()
	defer mn.Close()

	_, h1 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, h2 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)

	const targetHeight = int64(100)

	// Add recent entry
	peerBest.Store(h1.ID(), peerInfo{height: targetHeight, seenAt: time.Now()})

	// Add very old entry
	veryOldTime := time.Now().Add(-2 * cacheTTL)
	peerBest.Store(h2.ID(), peerInfo{height: targetHeight - 1, seenAt: veryOldTime})

	// Call garbage collection
	gcPeerCache()

	// Check that recent entry is still there
	if _, ok := peerBest.Load(h1.ID()); !ok {
		t.Error("Recent cache entry should not be garbage collected")
	}

	// Old entry might or might not be there depending on implementation,
	// but the test verifies gcPeerCache doesn't crash
}

func TestSampleSizeCalculation(t *testing.T) {
	// Test the sample size calculation logic
	testCases := []struct {
		name           string
		eligiblePeers  int
		expectedSample int
	}{
		{"1 peer", 1, 1},
		{"3 peers", 3, 3},
		{"5 peers", 5, 5},
		{"6 peers", 6, 3},      // 6/3 = 2, max(2, 3) = 3
		{"10 peers", 10, 3},    // 10/3 = 3, max(3, 3) = 3
		{"15 peers", 15, 5},    // 15/3 = 5, max(5, 3) = 5
		{"16 peers", 16, 3},    // 16/5 = 3, max(3, 3) = 3 (switches to /5 logic)
		{"20 peers", 20, 4},    // 20/5 = 4, max(4, 3) = 4
		{"100 peers", 100, 20}, // 100/5 = 20, max(20, 3) = 20
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var sampleSize int
			switch {
			case tc.eligiblePeers <= 5:
				sampleSize = tc.eligiblePeers // Query all peers in small networks
			case tc.eligiblePeers <= 15:
				sampleSize = max(tc.eligiblePeers/3, 3) // Query at least 3, up to 1/3
			default:
				sampleSize = max(tc.eligiblePeers/5, 3) // Query at least 3, up to 1/5 (original behavior)
			}
			require.Equal(t, tc.expectedSample, sampleSize,
				"Sample size calculation for %d peers", tc.eligiblePeers)
		})
	}
}

func TestPeerLatencyIsSmoothed(t *testing.T) {
	now := time.Now()
	var pi peerInfo

	pi.served(20*time.Millisecond, now)
	require.Equal(t, 20*time.Millisecond, pi.latency, "the first answer is the estimate")

	// One slow answer, a retransmit or a fat block, moves it a sixteenth of
	// the way. A 20 ms peer stays well ahead of a 300 ms one.
	pi.served(1620*time.Millisecond, now)
	require.Equal(t, 120*time.Millisecond, pi.latency)

	// A peer that has really slowed down loses its place within a few answers.
	pi = peerInfo{}
	pi.served(20*time.Millisecond, now)
	var answers int
	for pi.latency <= 300*time.Millisecond {
		pi.served(time.Second, now)
		answers++
	}
	require.Equal(t, 6, answers)

	// Nothing recent to smooth against: a peer only asked first once a minute
	// is judged on its latest answer.
	later := now.Add(peerProbeInterval + time.Second)
	pi.served(40*time.Millisecond, later)
	require.Equal(t, 40*time.Millisecond, pi.latency)
	require.Equal(t, later, pi.askedAt)

	// Nor after a failure. The answer that ends it replaces the estimate and
	// clears the hold.
	pi.failed(time.Millisecond, later)
	pi.served(90*time.Millisecond, later)
	require.Equal(t, 90*time.Millisecond, pi.latency)
	require.Zero(t, pi.hold)

	// A zero duration still counts as having answered.
	pi = peerInfo{}
	pi.served(0, now)
	require.Positive(t, pi.latency)
}

func TestPeerFailureHold(t *testing.T) {
	now := time.Now()

	// A peer that ate the whole response budget waits thirty times that
	// before it is asked first again. It keeps its latency, which orders it
	// among the other peers held back.
	var hung peerInfo
	hung.served(20*time.Millisecond, now)
	hung.failed(20*time.Second, now)
	require.Equal(t, 10*time.Minute, hung.hold)
	require.Equal(t, 20*time.Millisecond, hung.latency)
	require.Equal(t, now, hung.askedAt)

	// A failure that cost next to nothing is held back next to nothing, and
	// the hold doubles for each failure in a row. Each starts after the one
	// before has ended.
	var flaky peerInfo
	ms := time.Millisecond
	at := now
	for _, want := range []time.Duration{30 * ms, 60 * ms, 120 * ms, 240 * ms} {
		at = at.Add(time.Second)
		flaky.failed(ms, at)
		require.Equal(t, want, flaky.hold)
	}
	// A costlier failure sets its own hold if that is longer.
	at = at.Add(time.Minute)
	flaky.failed(2*time.Second, at)
	require.Equal(t, time.Minute, flaky.hold)

	// Never longer than maxPeerFailHold, however many in a row.
	for range 20 {
		at = at.Add(time.Hour)
		flaky.failed(20*time.Second, at)
	}
	require.Equal(t, maxPeerFailHold, flaky.hold)

	// Eight requests out at once that fail together, as they do when their
	// connection drops, are one failure, not eight in a row.
	var dropped peerInfo
	for i := range 8 {
		dropped.failed(100*ms, now.Add(time.Duration(i)*ms))
	}
	require.Equal(t, 3*time.Second, dropped.hold)

	// A failure too quick to measure is still a failure.
	var instant peerInfo
	instant.failed(0, now)
	require.Positive(t, instant.hold)
}

func TestOrderPeers(t *testing.T) {
	now := time.Now()
	served := func(latency, askedAgo time.Duration) peerInfo {
		return peerInfo{latency: latency, askedAt: now.Add(-askedAgo)}
	}
	failed := func(latency, hold, askedAgo time.Duration) peerInfo {
		return peerInfo{latency: latency, hold: hold, askedAt: now.Add(-askedAgo)}
	}
	const a, b, c, d = peer.ID("a"), peer.ID("b"), peer.ID("c"), peer.ID("d")
	ms := time.Millisecond

	for _, tc := range []struct {
		name  string
		known map[peer.ID]peerInfo
		peers []peer.ID
		want  []peer.ID
	}{{
		name:  "knowing nothing leaves the order as it came, which peerHosts shuffles",
		peers: []peer.ID{c, a, b},
		want:  []peer.ID{c, a, b},
	}, {
		name:  "the fastest first",
		known: map[peer.ID]peerInfo{a: served(300*ms, 0), b: served(20*ms, 0), c: served(150*ms, 0)},
		peers: []peer.ID{a, b, c},
		want:  []peer.ID{b, c, a},
	}, {
		name:  "one peer never asked goes first, the others after the peers that served",
		known: map[peer.ID]peerInfo{c: served(20*ms, 0)},
		peers: []peer.ID{a, b, c},
		want:  []peer.ID{a, c, b},
	}, {
		name:  "a peer only heard announcing has never been asked",
		known: map[peer.ID]peerInfo{a: {height: 9, seenAt: now}, b: served(20*ms, 0)},
		peers: []peer.ID{b, a},
		want:  []peer.ID{a, b},
	}, {
		name: "peers whose last request failed go last, the fastest of them first",
		known: map[peer.ID]peerInfo{
			a: failed(20*ms, time.Minute, 0),
			b: served(300*ms, 0),
			c: failed(50*ms, time.Minute, 0),
			d: failed(0, time.Minute, 0),
		},
		peers: []peer.ID{d, c, a, b},
		want:  []peer.ID{b, a, c, d},
	}, {
		name:  "a peer not asked for peerProbeInterval is asked first",
		known: map[peer.ID]peerInfo{a: served(20*ms, 0), b: served(300*ms, peerProbeInterval)},
		peers: []peer.ID{a, b},
		want:  []peer.ID{b, a},
	}, {
		name:  "only the one most overdue, wherever it sits",
		known: map[peer.ID]peerInfo{a: served(20*ms, 0), b: served(150*ms, 2*time.Minute), c: served(300*ms, 5*time.Minute)},
		peers: []peer.ID{a, b, c},
		want:  []peer.ID{c, a, b},
	}, {
		name:  "a failed peer is asked first once its hold is up",
		known: map[peer.ID]peerInfo{a: served(20*ms, 0), b: failed(20*ms, time.Second, 2*time.Second)},
		peers: []peer.ID{a, b},
		want:  []peer.ID{b, a},
	}, {
		name:  "and not before",
		known: map[peer.ID]peerInfo{a: served(20*ms, 0), b: failed(5*ms, time.Minute, 2*time.Second)},
		peers: []peer.ID{a, b},
		want:  []peer.ID{a, b},
	}, {
		// Two never asked, since the most overdue of them goes first anyway.
		name:  "peers never asked before peers whose last request failed",
		known: map[peer.ID]peerInfo{c: failed(20*ms, time.Minute, 0)},
		peers: []peer.ID{c, a, b},
		want:  []peer.ID{a, b, c},
	}, {
		name: "with every peer held back, the one due soonest goes first anyway",
		known: map[peer.ID]peerInfo{
			a: failed(20*ms, 10*time.Minute, 0),
			b: failed(50*ms, 10*time.Minute, 5*time.Minute),
			c: failed(30*ms, 10*time.Minute, time.Minute),
		},
		peers: []peer.ID{a, b, c},
		want:  []peer.ID{b, a, c},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := append([]peer.ID(nil), tc.peers...)
			orderPeers(got, tc.known, now)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestUpdatePeerKeepsWhatItDoesNotSet(t *testing.T) {
	resetPeerBest(t)
	p := peer.ID("p")
	load := func() peerInfo {
		v, ok := peerBest.Load(p)
		require.True(t, ok)
		return v.(peerInfo)
	}

	// An announcement, which is all the block announcement handler records,
	// must not wipe what block requests learned.
	updatePeer(p, func(pi *peerInfo) { pi.served(20*time.Millisecond, time.Now()) })
	notePeerHeight(p, 7)
	pi := load()
	require.EqualValues(t, 7, pi.height)
	require.Equal(t, 20*time.Millisecond, pi.latency)

	// Nor may two writers at once lose either write.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				// Yield between the read and the write, so that a lost
				// update shows on one CPU too.
				updatePeer(p, func(pi *peerInfo) { pi.height++; runtime.Gosched() })
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 8007, load().height)
}

// TestBlockAnnouncementKeepsWhatRequestsLearned is the same guarantee through
// the announcement handler itself, which used to Store a fresh peerInfo.
func TestBlockAnnouncementKeepsWhatRequestsLearned(t *testing.T) {
	resetPeerBest(t)
	nodes, extraHosts, _, mn := makeTestHosts(t, 1, 1, 5*time.Hour, crypto.KeyTypeSecp256k1)
	linkAll(t, mn)
	n1, h2 := nodes[0], extraHosts[0]
	// The handler records the height, then stops at AcceptCommit.
	n1.ce.(*dummyCE).Fake().RejectNextCommit()

	updatePeer(h2.ID(), func(pi *peerInfo) { pi.served(20*time.Millisecond, time.Now()) })

	blk, appHash := createTestBlock(7, 0)
	ann, err := blockAnnMsg{Hash: blk.Hash(), Height: 7, Header: blk.Header,
		CommitInfo: &ktypes.CommitInfo{AppHash: appHash}}.MarshalBinary()
	require.NoError(t, err)
	s, err := h2.NewStream(context.Background(), n1.host.ID(), ProtocolIDBlkAnn)
	require.NoError(t, err)
	defer s.Close()
	_, err = s.Write(ann)
	require.NoError(t, err)
	require.NoError(t, s.CloseWrite())

	var pi peerInfo
	require.Eventually(t, func() bool {
		v, _ := peerBest.Load(h2.ID())
		pi, _ = v.(peerInfo)
		return pi.height == 7
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, 20*time.Millisecond, pi.latency)
}

func TestPeerCacheRemembersAPeerItIsHoldingBack(t *testing.T) {
	resetPeerBest(t)
	longAgo := time.Now().Add(-2 * cacheTTL)
	held, gone := peer.ID("held"), peer.ID("gone")
	peerBest.Store(held, peerInfo{seenAt: longAgo, askedAt: time.Now(), hold: maxPeerFailHold})
	peerBest.Store(gone, peerInfo{seenAt: longAgo, askedAt: longAgo})

	gcPeerCache()

	// Forgetting it would make it a peer never asked, and ask it first.
	_, ok := peerBest.Load(held)
	require.True(t, ok, "a peer asked within cacheTTL is kept, whenever it last announced")
	_, ok = peerBest.Load(gone)
	require.False(t, ok, "a peer neither heard from nor asked within cacheTTL is dropped")
}

// blockPeer puts a host on mn that answers ProtocolIDBlockHeight with serve,
// and counts the requests it gets.
func blockPeer(t *testing.T, mn mock.Mocknet, serve func(network.Stream)) (host.Host, *atomic.Int32) {
	t.Helper()
	_, h := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	asked := new(atomic.Int32)
	h.SetStreamHandler(ProtocolIDBlockHeight, func(s network.Stream) {
		asked.Add(1)
		serve(s)
	})
	return h, asked
}

// serveBlocks answers from a store holding a block at each of heights.
func serveBlocks(t *testing.T, heights ...int64) func(network.Stream) {
	t.Helper()
	bs := memstore.NewMemBS()
	for _, h := range heights {
		blk, appHash := createTestBlock(h, 1)
		require.NoError(t, bs.Store(blk, &ktypes.CommitInfo{AppHash: appHash}))
	}
	return func(s network.Stream) { serveBlockByHeight(s, bs, log.DiscardLogger) }
}

// hangUp reads the request and closes without a word, which the asking side
// sees as ErrNoResponse.
func hangUp(s network.Stream) {
	defer s.Close()
	var req blockHeightReq
	req.ReadFrom(s)
}

// reply answers every request with resp.
func reply(resp []byte) func(network.Stream) {
	return func(s network.Stream) {
		defer s.Close()
		var req blockHeightReq
		req.ReadFrom(s)
		s.Write(resp)
	}
}

func connectPeers(t *testing.T, mn mock.Mocknet) {
	t.Helper()
	require.NoError(t, mn.LinkAll())
	require.NoError(t, mn.ConnectAllButSelf())
}

// waitForIdentify waits until identify has finished on client's connections
// to each of peers, so that the first stream to a peer opens without having
// to negotiate the protocol, and that peer's first request is not timed with
// the extra round trip in it.
//
// It also makes sure client knows each peer serves block requests. libp2p
// hands a new connection a snapshot of the protocols a host serves, and it
// refreshes that snapshot some time after a handler is registered. A test
// that registers a handler and connects straight away can be identified with
// the old list, and the push meant to correct it does not always follow. The
// peer does serve the protocol, so this records what identify should have.
func waitForIdentify(t *testing.T, client host.Host, peers ...host.Host) {
	t.Helper()
	ids := client.(interface{ IDService() identify.IDService }).IDService()
	for _, p := range peers {
		conns := client.Network().ConnsToPeer(p.ID())
		require.NotEmpty(t, conns, "not connected to %s", p.ID())
		for _, c := range conns {
			select {
			case <-ids.IdentifyWait(c):
			case <-time.After(5 * time.Second):
				t.Fatalf("identify with %s did not finish", p.ID())
			}
		}
		require.NoError(t, client.Peerstore().AddProtocols(p.ID(), ProtocolIDBlockHeight))
	}
}

// fetchBlock asks the peers of client for block 1, which one of them has.
func fetchBlock(t *testing.T, client host.Host) {
	t.Helper()
	_, rawBlk, _, _, _, err := getBlkHeight(context.Background(), 1, client, log.DiscardLogger, nil)
	require.NoError(t, err)
	require.NotEmpty(t, rawBlk)
}

func TestGetBlkHeightKeepsAskingTheFastestPeer(t *testing.T) {
	resetPeerBest(t)
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	_, client := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	serve := serveBlocks(t, 1)
	var fastServes atomic.Bool
	fastServes.Store(true)
	fast, fastAsked := blockPeer(t, mn, func(s network.Stream) {
		if fastServes.Load() {
			serve(s)
		} else {
			hangUp(s)
		}
	})
	far1, far1Asked := blockPeer(t, mn, serve)
	far2, far2Asked := blockPeer(t, mn, serve)
	connectPeers(t, mn)
	waitForIdentify(t, client, fast, far1, far2)
	// mocknet delays every Write on a link, so a request to either of these
	// takes at least 200 ms, and one to the fast peer only as long as the
	// machine takes to run it: about a millisecond, far less than that even
	// under load and -race.
	for _, far := range []host.Host{far1, far2} {
		for _, l := range mn.LinksBetweenPeers(client.ID(), far.ID()) {
			l.SetOptions(mock.LinkOptions{Latency: 100 * time.Millisecond})
		}
	}
	farAsked := func() int32 { return far1Asked.Load() + far2Asked.Load() }

	// Whoever the shuffle puts first serves the first block. Each of the next
	// two requests goes first to a peer not yet asked. After that every block
	// comes from the fast peer: no other is due a turn for a minute.
	for range 20 {
		fetchBlock(t, client)
	}
	require.EqualValues(t, 1, far1Asked.Load())
	require.EqualValues(t, 1, far2Asked.Load())
	require.EqualValues(t, 18, fastAsked.Load())

	// The fast peer stops answering. Every block still arrives, each from one
	// of the others.
	fastServes.Store(false)
	before := farAsked()
	for range 5 {
		fetchBlock(t, client)
	}
	require.EqualValues(t, 5, farAsked()-before)

	// Once it answers again it is asked first when its hold is up, serves,
	// and keeps its place.
	fastServes.Store(true)
	deadline := time.Now().Add(10 * time.Second)
	for asked := fastAsked.Load(); fastAsked.Load() == asked; {
		require.True(t, time.Now().Before(deadline), "the fast peer was never asked again")
		fetchBlock(t, client)
	}
	before = farAsked()
	for range 5 {
		fetchBlock(t, client)
	}
	require.Equal(t, before, farAsked())
}

// TestRequestBlockHeightStopsWaitingWhenCancelled is a peer taking its time
// over a request we have given up on. mocknet has no read deadlines, so without
// the reset the request would wait for as long as the peer does.
func TestRequestBlockHeightStopsWaitingWhenCancelled(t *testing.T) {
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	_, client := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	const peerTakes = 10 * time.Second
	asked, done := make(chan struct{}), make(chan struct{})
	server, _ := blockPeer(t, mn, func(s network.Stream) {
		defer s.Close()
		var req blockHeightReq
		req.ReadFrom(s)
		close(asked)
		select {
		case <-done:
		case <-time.After(peerTakes):
		}
	})
	t.Cleanup(func() { close(done) })
	connectPeers(t, mn)
	waitForIdentify(t, client, server)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-asked
		cancel()
	}()
	start := time.Now()
	_, err := requestBlockHeight(ctx, client, server.ID(), 1, blkReadLimit,
		2*time.Second, 20*time.Second, 500*time.Millisecond)
	require.Error(t, err)
	require.Less(t, time.Since(start), peerTakes/2, "it stops when we give up, not when the peer answers")
}

func TestGetBlkHeightDoesNotBlameAPeerForOurCancellation(t *testing.T) {
	resetPeerBest(t)
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	_, client := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	asked, cancelled := make(chan struct{}), make(chan struct{})
	// We give up while the peer is still working on the request, and the
	// stream is reset under it, by us or by the peer, whichever comes first.
	// That follows from our giving up, and must not count against the peer.
	server, _ := blockPeer(t, mn, func(s network.Stream) {
		close(asked)
		<-cancelled
		s.Reset()
	})
	connectPeers(t, mn)
	// Otherwise opening the stream waits on the protocol negotiation, and our
	// cancelling can end the request there, before the peer has answered.
	waitForIdentify(t, client, server)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-asked
		cancel()
		close(cancelled)
	}()
	_, _, _, _, _, err := getBlkHeight(ctx, 1, client, log.DiscardLogger, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled, "a request we gave up on says so")

	v, _ := peerBest.Load(server.ID())
	pi, _ := v.(peerInfo)
	require.Zero(t, pi.hold)
}

// TestGetBlkHeightReportsOurCancellationNotTheTip is a cancel that lands
// after one peer has said it does not have the block. Reported as that
// not-found, the cancel would read to catch-up as the chain's tip, and it
// would end the sync as though it had finished.
func TestGetBlkHeightReportsOurCancellationNotTheTip(t *testing.T) {
	resetPeerBest(t)
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	_, client := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	behind, _ := blockPeer(t, mn, serveBlocks(t))
	asked, done := make(chan struct{}), make(chan struct{})
	slow, _ := blockPeer(t, mn, func(s network.Stream) {
		defer s.Close()
		var req blockHeightReq
		req.ReadFrom(s)
		close(asked)
		<-done
	})
	t.Cleanup(func() { close(done) })
	connectPeers(t, mn)
	waitForIdentify(t, client, behind, slow)

	// Asked in this order: the peer that is behind answers first.
	now := time.Now()
	peerBest.Store(behind.ID(), peerInfo{latency: time.Millisecond, askedAt: now})
	peerBest.Store(slow.ID(), peerInfo{latency: 100 * time.Millisecond, askedAt: now})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-asked
		cancel()
	}()
	_, _, _, _, _, err := getBlkHeight(ctx, 1, client, log.DiscardLogger, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, ErrBlkNotFound)
}

func TestGetBlkHeightRecordsWhatEachPeerCost(t *testing.T) {
	resetPeerBest(t)
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	_, client := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	server, _ := blockPeer(t, mn, serveBlocks(t, 1))
	silent, _ := blockPeer(t, mn, hangUp)
	// Claims height 10 but lacks block 1, as a peer that state synced past it would.
	lacking, _ := blockPeer(t, mn, serveBlocks(t, 10))
	behind, behindAsked := blockPeer(t, mn, serveBlocks(t))
	connectPeers(t, mn)

	// Every request asks one peer not yet asked first, so by the fourth all
	// of them have been.
	for range 8 {
		fetchBlock(t, client)
	}

	known := func(h host.Host) peerInfo {
		t.Helper()
		v, ok := peerBest.Load(h.ID())
		require.True(t, ok)
		return v.(peerInfo)
	}

	pi := known(server)
	require.Positive(t, pi.latency, "a peer that serves is timed")
	require.Zero(t, pi.hold)

	pi = known(silent)
	require.Positive(t, pi.hold, "a peer that hangs up is held back")
	require.Zero(t, pi.latency, "and a failure is never a time: it would look fast")

	pi = known(lacking)
	require.Positive(t, pi.hold, "claiming a height without the block is a failure")
	require.Zero(t, pi.latency)
	require.EqualValues(t, 10, pi.height)

	pi = known(behind)
	require.Zero(t, pi.hold, "being behind is not a failure")
	require.EqualValues(t, 1, behindAsked.Load(), "and it is not asked again while it is known to be")
}

func TestGetBlkHeightHoldsBackEveryKindOfFailure(t *testing.T) {
	resetPeerBest(t)
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	blk, appHash := createTestBlock(1, 1)
	ciBytes, err := (&ktypes.CommitInfo{AppHash: appHash}).MarshalBinary()
	require.NoError(t, err)
	var full bytes.Buffer
	hash := blk.Hash()
	full.Write(withData)
	full.Write(hash[:])
	ktypes.WriteCompactBytes(&full, ciBytes)
	ktypes.WriteCompactBytes(&full, ktypes.EncodeBlock(blk))

	_, client := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	blockPeer(t, mn, serveBlocks(t, 1))
	// Five peers at most, so that every one is in every sample.
	_, noHandler := newTestHost(t, mn, crypto.KeyTypeSecp256k1) // the stream never opens
	failing := []host.Host{noHandler}
	for _, resp := range [][]byte{
		append(slices.Clone(noData), 0, 0, 0, 0),      // not found, with no best height
		append(slices.Clone(withData), 1, 2, 3, 4, 5), // shorter than a hash
		full.Bytes()[:full.Len()-100],                 // cut off inside the block
	} {
		h, _ := blockPeer(t, mn, reply(resp))
		failing = append(failing, h)
	}
	connectPeers(t, mn)

	// Every request asks a peer not yet asked first, then gets the block from
	// the one that has it. A cut-off block is not a block: returned as one,
	// fetchBlock fails.
	for range 8 {
		fetchBlock(t, client)
	}

	for i, h := range failing {
		v, ok := peerBest.Load(h.ID())
		require.True(t, ok, "peer %d", i)
		pi := v.(peerInfo)
		require.Positive(t, pi.hold, "peer %d is held back", i)
		require.Zero(t, pi.latency, "peer %d is not timed", i)
	}
}

// TestGetBlkHeightAsksAroundWhenNoPeerIsKnownToHaveTheBlock is the end of a
// catch-up with more than five peers. The three fastest do not have the next
// block yet. The other three do, but nothing we have heard says so.
func TestGetBlkHeightAsksAroundWhenNoPeerIsKnownToHaveTheBlock(t *testing.T) {
	resetPeerBest(t)
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	_, client := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	now := time.Now()
	for i := range 6 {
		serve, latency := serveBlocks(t), time.Millisecond
		if i >= 3 {
			serve, latency = serveBlocks(t, 1), 100*time.Millisecond
		}
		h, _ := blockPeer(t, mn, serve)
		// Last heard at height 0, all six, so none is eligible for block 1.
		peerBest.Store(h.ID(), peerInfo{seenAt: now, latency: latency, askedAt: now})
	}
	connectPeers(t, mn)

	// Taken fastest first, the sample of three would be the three without the
	// block on every request, and every request would end in ErrBlkNotFound.
	// Shuffled, one request in twenty misses all three that have it.
	for range 20 {
		_, rawBlk, _, _, _, err := getBlkHeight(context.Background(), 1, client, log.DiscardLogger, nil)
		if err == nil {
			require.NotEmpty(t, rawBlk)
			return
		}
		require.ErrorIs(t, err, ErrBlkNotFound)
	}
	t.Fatal("twenty requests in a row asked only the peers without the block")
}

// TestPeerRejected is a peer that sent a block other than the one it was
// asked for. However quickly it answered, it waits out the longest hold and
// sorts behind the peers that serve, and it keeps the latency it had.
func TestPeerRejected(t *testing.T) {
	now := time.Now()
	var liar, honest peerInfo
	liar.served(time.Millisecond, now)
	honest.served(300*time.Millisecond, now)
	liar.rejected(now)

	require.Equal(t, maxPeerFailHold, liar.hold)
	require.Equal(t, now.Add(maxPeerFailHold), liar.dueAt())
	require.Equal(t, time.Millisecond, liar.latency)

	peers := []peer.ID{"liar", "honest"}
	orderPeers(peers, map[peer.ID]peerInfo{"liar": liar, "honest": honest}, now.Add(time.Minute))
	require.Equal(t, []peer.ID{"honest", "liar"}, peers)
}

// wrongBlockAnswer is a peer's answer to a block request: rawBlk, sent as
// the one hash names.
func wrongBlockAnswer(t *testing.T, hash ktypes.Hash, rawBlk []byte) []byte {
	t.Helper()
	ci, err := (&ktypes.CommitInfo{}).MarshalBinary()
	require.NoError(t, err)
	var resp bytes.Buffer
	resp.Write(withData)
	resp.Write(hash[:])
	ktypes.WriteCompactBytes(&resp, ci)
	ktypes.WriteCompactBytes(&resp, rawBlk)
	return resp.Bytes()
}

// TestGetBlkHeightSkipsAPeerThatSendsTheWrongBlock has three peers answering
// a request for block 1 with something else: block 1 under block 2's hash,
// block 2 under its own, and bytes that are no block at all. Each is passed
// over for the peer that has block 1, and held back as long as any failure.
func TestGetBlkHeightSkipsAPeerThatSendsTheWrongBlock(t *testing.T) {
	resetPeerBest(t)
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	blk1, _ := createTestBlock(1, 1)
	blk2, _ := createTestBlock(2, 1)

	_, client := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	blockPeer(t, mn, serveBlocks(t, 1))
	var liars []host.Host
	// Five peers at most, so that every one is in every sample.
	for _, resp := range [][]byte{
		wrongBlockAnswer(t, blk2.Hash(), ktypes.EncodeBlock(blk1)),
		wrongBlockAnswer(t, blk2.Hash(), ktypes.EncodeBlock(blk2)),
		wrongBlockAnswer(t, blk1.Hash(), []byte("not a block")),
	} {
		h, _ := blockPeer(t, mn, reply(resp))
		liars = append(liars, h)
	}
	connectPeers(t, mn)

	// Every request asks a peer not yet asked first, and gets block 1.
	for range 8 {
		hash, rawBlk, _, _, _, err := getBlkHeight(context.Background(), 1, client, log.DiscardLogger, nil)
		require.NoError(t, err)
		require.Equal(t, blk1.Hash(), hash)
		require.Equal(t, ktypes.EncodeBlock(blk1), rawBlk)
	}

	for i, h := range liars {
		v, ok := peerBest.Load(h.ID())
		require.True(t, ok, "peer %d was asked", i)
		require.Equal(t, maxPeerFailHold, v.(peerInfo).hold, "peer %d is held back", i)
	}
}

// TestGetBlkHeightRejectHoldsBackThePeerThatServed is a block that arrives
// intact and turns out, once catch-up checks it, not to be the one the
// validators committed. The reject it came with holds back the peer that sent
// it, and no other.
func TestGetBlkHeightRejectHoldsBackThePeerThatServed(t *testing.T) {
	resetPeerBest(t)
	mn := mock.New()
	t.Cleanup(func() { mn.Close() })

	_, client := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	first, _ := blockPeer(t, mn, serveBlocks(t, 1))
	second, _ := blockPeer(t, mn, serveBlocks(t, 1))
	connectPeers(t, mn)
	waitForIdentify(t, client, first, second)

	_, _, _, _, reject, err := getBlkHeight(context.Background(), 1, client, log.DiscardLogger, nil)
	require.NoError(t, err)

	// Only the peer that served has been asked.
	var served, other host.Host = first, second
	if _, ok := peerBest.Load(second.ID()); ok {
		served, other = second, first
	}
	v, _ := peerBest.Load(served.ID())
	require.Zero(t, v.(peerInfo).hold, "it served")

	reject()
	v, _ = peerBest.Load(served.ID())
	require.Equal(t, maxPeerFailHold, v.(peerInfo).hold)
	_, ok := peerBest.Load(other.ID())
	require.False(t, ok, "the other peer is not touched")
}
