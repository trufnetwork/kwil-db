package consensus

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

// blockID stands in for the hash of block h.
func blockID(h int64) types.Hash {
	var id types.Hash
	binary.LittleEndian.PutUint64(id[:], uint64(h))
	return id
}

// fakeNetwork answers block requests the way getBlkHeight does, for heights
// up to tip, and counts who asked for what.
type fakeNetwork struct {
	tip  int64
	size int   // of every block, in bytes
	sees int64 // how far past a block its answer reports the tip; 0 for all the way

	delay func(h int64) time.Duration      // before answering; nil for none
	hang  func(h int64) bool               // never answer, until the request is cancelled
	fail  func(h int64, attempt int) error // fail this attempt at h

	mtx    sync.Mutex
	asked  map[int64]int
	active int
	direct int // blocks the applier had to fetch itself
}

func newFakeNetwork(tip int64, size int) *fakeNetwork {
	return &fakeNetwork{tip: tip, size: size, asked: make(map[int64]int)}
}

func (f *fakeNetwork) request(ctx context.Context, h int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
	f.mtx.Lock()
	f.asked[h]++
	attempt := f.asked[h]
	f.active++
	f.mtx.Unlock()
	defer func() {
		f.mtx.Lock()
		f.active--
		f.mtx.Unlock()
	}()

	var wait <-chan time.Time
	if f.delay != nil {
		wait = time.After(f.delay(h))
	} else {
		wait = time.After(0)
	}
	if f.hang != nil && f.hang(h) {
		wait = nil
	}
	select {
	case <-wait:
	case <-ctx.Done():
		return types.Hash{}, nil, nil, 0, ctx.Err()
	}

	if h > f.tip {
		return types.Hash{}, nil, nil, 0, types.ErrBlkNotFound
	}
	if f.fail != nil {
		if err := f.fail(h, attempt); err != nil {
			return types.Hash{}, nil, nil, 0, err
		}
	}
	best := f.tip
	if f.sees > 0 {
		best = min(h+f.sees, f.tip)
	}
	if applier, _ := ctx.Value(applierKey{}).(*int); applier != nil {
		f.direct++
	}
	return blockID(h), make([]byte, f.size), &ktypes.CommitInfo{}, best, nil
}

// applierKey marks the context catch-up itself fetches with, as opposed to
// the prefetcher's workers.
type applierKey struct{}

func (f *fakeNetwork) timesAsked(h int64) int {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return f.asked[h]
}

func (f *fakeNetwork) requests() (total, active int) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	for _, n := range f.asked {
		total += n
	}
	return total, f.active
}

// take gets block h from p the way the catch-up loop does, asking again after
// an error that is not a not-found.
func take(t *testing.T, ctx context.Context, p *prefetcher, h int64) {
	t.Helper()
	for range 5 {
		hash, _, _, _, err := p.get(ctx, h)
		if err == nil {
			require.Equal(t, blockID(h), hash, "block %d", h)
			return
		}
		require.NotErrorIs(t, err, types.ErrBlkNotFound, "block %d", h)
	}
	t.Fatalf("block %d never arrived", h)
}

func TestPrefetcherHandsBlocksOverInOrder(t *testing.T) {
	ctx := context.Background()
	net := newFakeNetwork(50, 10)
	// Later blocks answer sooner, so they arrive out of order.
	net.delay = func(h int64) time.Duration { return time.Duration(60-h) * 100 * time.Microsecond }

	p := newPrefetcher(ctx, net.request, 1, 1<<20)
	defer p.stop()

	for h := int64(1); h <= 50; h++ {
		take(t, ctx, p, h)
	}
	_, _, _, _, err := p.get(ctx, 51)
	require.ErrorIs(t, err, types.ErrBlkNotFound, "the tip ends it, as it always did")

	for h := int64(1); h <= 51; h++ {
		require.Equal(t, 1, net.timesAsked(h), "block %d is asked for once", h)
	}
	require.Zero(t, net.timesAsked(52), "nothing is asked for past the height peers report")
}

// TestPrefetcherAsksOnceWhenInSync is a node already at the tip, running
// catch-up on its tick. It sends the one request it always did.
func TestPrefetcherAsksOnceWhenInSync(t *testing.T) {
	ctx := context.Background()
	net := newFakeNetwork(0, 10)

	p := newPrefetcher(ctx, net.request, 1, 1<<20)
	_, _, _, _, err := p.get(ctx, 1)
	require.ErrorIs(t, err, types.ErrBlkNotFound)
	p.stop()

	total, _ := net.requests()
	require.Equal(t, 1, total)
}

func TestPrefetcherKeepsToItsByteBudget(t *testing.T) {
	ctx := context.Background()
	const size, budget = 100, 1000
	net := newFakeNetwork(1000, size)

	p := newPrefetcher(ctx, net.request, 1, budget)
	defer p.stop()
	take(t, ctx, p, 1) // tells it how far ahead there is to fetch

	idle := func() bool {
		p.mtx.Lock()
		defer p.mtx.Unlock()
		return len(p.inflight) == 0 && p.bytes >= budget
	}
	require.Eventually(t, idle, 5*time.Second, time.Millisecond)

	// It stops claiming once the budget is spent, which can overshoot by the
	// blocks that were already on their way.
	p.mtx.Lock()
	held, claimed := p.bytes, p.claimed
	p.mtx.Unlock()
	require.Less(t, held, int64(budget+prefetchWorkers*size))
	time.Sleep(20 * time.Millisecond)
	p.mtx.Lock()
	require.Equal(t, claimed, p.claimed, "nothing more is fetched while the budget is spent")
	p.mtx.Unlock()

	// Taking blocks frees the budget, and fetching resumes. While the budget
	// is spent at least ten blocks are held, so every block taken here is one
	// already fetched, and only a worker can move claimed on.
	over := func() bool {
		p.mtx.Lock()
		defer p.mtx.Unlock()
		return p.bytes >= budget
	}
	for h := int64(2); over(); h++ {
		require.Less(t, h, int64(20), "taking blocks never freed the budget")
		take(t, ctx, p, h)
	}
	require.Eventually(t, func() bool {
		p.mtx.Lock()
		defer p.mtx.Unlock()
		return p.claimed > claimed
	}, 5*time.Second, time.Millisecond)
}

// TestPrefetcherFillsAHoleItself is one request failing mid-sync. The blocks
// after it that were already on their way are still used, and nothing is
// asked for twice once the workers start again from the failure. When they do
// races with the applier taking those blocks, so it runs ten times.
func TestPrefetcherFillsAHoleItself(t *testing.T) {
	ctx := context.Background()
	for range 10 {
		net := newFakeNetwork(20, 10)
		net.fail = func(h int64, attempt int) error {
			if h == 5 && attempt == 1 {
				return errors.New("stream reset")
			}
			return nil
		}

		p := newPrefetcher(ctx, net.request, 1, 1<<20)
		for h := int64(1); h <= 20; h++ {
			take(t, ctx, p, h)
		}
		p.stop()

		require.Equal(t, 2, net.timesAsked(5), "a block that failed is asked for again, once")
		for h := int64(1); h <= 20; h++ {
			if h != 5 {
				require.Equal(t, 1, net.timesAsked(h), "block %d", h)
			}
		}
	}
}

// TestPrefetcherStopEndsRequestsInFlight is a peer that has stopped answering
// when catch-up ends. Nothing the prefetcher sent may outlive it.
func TestPrefetcherStopEndsRequestsInFlight(t *testing.T) {
	ctx := context.Background()
	net := newFakeNetwork(100, 10)
	net.hang = func(h int64) bool { return h > 1 }

	p := newPrefetcher(ctx, net.request, 1, 1<<20)
	take(t, ctx, p, 1)
	require.Eventually(t, func() bool {
		_, active := net.requests()
		return active == prefetchWorkers
	}, 5*time.Second, time.Millisecond)

	before, _ := net.requests()
	stopped := make(chan struct{})
	go func() {
		p.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop waited on requests it had cancelled")
	}
	total, active := net.requests()
	require.Zero(t, active)
	require.Equal(t, before, total, "stopping sends nothing new, only ends what was out")

	time.Sleep(20 * time.Millisecond)
	after, _ := net.requests()
	require.Equal(t, total, after, "nothing is asked for after stop")
}

func TestPrefetcherGetGivesUpWhenCancelled(t *testing.T) {
	net := newFakeNetwork(100, 10)
	net.hang = func(h int64) bool { return h > 1 }

	p := newPrefetcher(context.Background(), net.request, 1, 1<<20)
	defer p.stop()
	take(t, context.Background(), p, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, _, _, err := p.get(ctx, 2)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestPrefetcherFollowsTheTipAsPeersReportIt is a catch-up where each answer
// only reports a few blocks further, as when the chain grows during it. Each
// answer a worker gets moves the tip on, so the applier fetches the first
// block itself and hardly any after. If only the applier's own answers moved
// the tip, it would fetch every fourth block itself.
func TestPrefetcherFollowsTheTipAsPeersReportIt(t *testing.T) {
	net := newFakeNetwork(50, 10)
	net.sees = 3
	applier := 0
	ctx := context.WithValue(context.Background(), applierKey{}, &applier)

	p := newPrefetcher(context.Background(), net.request, 1, 1<<20)
	defer p.stop()
	for h := int64(1); h <= 50; h++ {
		take(t, ctx, p, h)
		time.Sleep(5 * time.Millisecond) // applying it
	}
	_, _, _, _, err := p.get(ctx, 51)
	require.ErrorIs(t, err, types.ErrBlkNotFound)

	// A worker woken late can lose a block to the applier now and then.
	net.mtx.Lock()
	defer net.mtx.Unlock()
	require.LessOrEqual(t, net.direct, 5, "the applier fetched %d of 50 blocks itself", net.direct)
}

func TestNewTakesThePrefetchBudget(t *testing.T) {
	priv, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	ce, err := New(&Config{RootDir: t.TempDir(), PrivateKey: priv, Logger: log.DiscardLogger, PrefetchBytes: 1 << 20})
	require.NoError(t, err)
	require.EqualValues(t, 1<<20, ce.prefetchBytes)
}

// TestPrefetcherStopsAtAFailure is a node that loses its peers mid-sync, so
// every request fails at once. The workers stop at the first failure rather
// than claim every height up to the tip, and once peers are back they, not
// the applier, refill what failed.
func TestPrefetcherStopsAtAFailure(t *testing.T) {
	net := newFakeNetwork(1000, 10)
	var outage atomic.Bool
	outage.Store(true)
	// Slow enough to fail that every worker has a request out when they do,
	// which leaves holes above the first.
	net.delay = func(h int64) time.Duration {
		if h > 1 && outage.Load() {
			return 20 * time.Millisecond
		}
		return 0
	}
	net.fail = func(h int64, _ int) error {
		if h > 1 && outage.Load() {
			return types.ErrPeersNotFound
		}
		return nil
	}
	applier := 0
	ctx := context.WithValue(context.Background(), applierKey{}, &applier)

	p := newPrefetcher(context.Background(), net.request, 1, 1<<20)
	defer p.stop()
	take(t, ctx, p, 1) // peers are at 1000, then they are gone

	require.Eventually(t, func() bool {
		p.mtx.Lock()
		defer p.mtx.Unlock()
		return p.ceiling > 0 && len(p.inflight) == 0
	}, 5*time.Second, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	total, _ := net.requests()
	require.LessOrEqual(t, total, 1+2*prefetchWorkers, "the workers stopped at the failure, not at the tip")

	outage.Store(false)
	for h := int64(2); h <= 50; h++ {
		take(t, ctx, p, h)
		time.Sleep(5 * time.Millisecond) // applying it
	}
	net.mtx.Lock()
	defer net.mtx.Unlock()
	require.LessOrEqual(t, net.direct, 5, "the applier fetched %d of 50 blocks itself", net.direct)
}

// TestPrefetcherNeverFetchesABlockTwice has an applier that takes blocks as
// fast as they come, so it keeps asking for blocks no worker has claimed yet
// and fetches them itself, while workers wake to claim them too. Each block is
// still asked for once. It is a race, so it runs the catch-up ten times.
func TestPrefetcherNeverFetchesABlockTwice(t *testing.T) {
	ctx := context.Background()
	for range 10 {
		net := newFakeNetwork(2000, 10)
		p := newPrefetcher(ctx, net.request, 1, 1<<20)
		for h := int64(1); h <= 2000; h++ {
			take(t, ctx, p, h)
		}
		p.stop()

		for h, n := range net.asked {
			require.Equal(t, 1, n, "block %d", h)
		}
	}
}

// TestPrefetcherWorkersSkipWhatWasTaken is the state just after the applier
// has got past a failure: claims start again above it, and the applier has
// already taken some of the blocks there. A worker picks up where there is
// something left to fetch.
func TestPrefetcherWorkersSkipWhatWasTaken(t *testing.T) {
	net := newFakeNetwork(20, 10)
	ctx, cancel := context.WithCancel(context.Background())
	p := &prefetcher{
		fetch:    net.request,
		limit:    1 << 20,
		cancel:   cancel,
		changed:  make(chan struct{}),
		next:     10, // blocks up to 9 are taken
		claimed:  5,
		tip:      20,
		inflight: make(map[int64]bool),
		results:  make(map[int64]prefetched),
	}
	p.wg.Add(1)
	go p.work(ctx)
	require.Eventually(t, func() bool {
		p.mtx.Lock()
		defer p.mtx.Unlock()
		return p.claimed > p.tip && len(p.inflight) == 0
	}, 5*time.Second, time.Millisecond)
	p.stop()

	for h := int64(5); h < 10; h++ {
		require.Zero(t, net.timesAsked(h), "block %d was already taken", h)
	}
	for h := int64(10); h <= 20; h++ {
		require.Equal(t, 1, net.timesAsked(h), "block %d", h)
	}
}
