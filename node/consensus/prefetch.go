package consensus

import (
	"context"
	"sync"

	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

// prefetchWorkers is how many blocks catch-up fetches at once ahead of the one
// it is applying. Enough requests have to be in flight to cover a round trip
// while blocks apply: about 300 ms / 49 ms, so six, for a distant node at
// mainnet's median apply time. libp2p lets a peer take 64 inbound streams per
// protocol by default, so eight at once is well inside what any peer accepts.
const prefetchWorkers = 8

// prefetched is a block as the requester returned it: never decoded, since
// applyBlock decodes it, and a decoded block allocates per transaction.
type prefetched struct {
	hash ktypes.Hash
	raw  []byte
	ci   *ktypes.CommitInfo
	best int64
}

// prefetcher fetches the blocks after the one catch-up is applying, so that
// the round trip for a block overlaps with applying the ones before it.
//
// Its workers only call the requester. They never read consensus state or the
// block processor, both of which apply holds for the whole of a block, and
// nothing they fetch reaches the block store or applyBlock except through get,
// in height order. A block that fails to apply is as fatal as it always was.
//
// Workers fetch only up to the best height a peer has reported with a block,
// and nothing until the first block has arrived. So a node that is already in
// sync, running catch-up on a tick, sends the one request it always did.
//
// A request a worker makes that fails stops the workers at that height until
// get has fetched it itself. get retries under catch-up's own backoff, so a
// node that loses its peers mid-sync makes a handful of failed requests, not
// one per height up to the tip.
//
// Memory: blocks waiting for get are held to limit bytes, over by at most what
// the requests in flight bring back. Each of those also holds its read buffer
// until the block is copied out of it, so with honest peers the peak is about
// limit plus prefetchWorkers × 2 blocks. A block larger than max_block_size is
// only caught when it is applied, as it always was, which is fatal.
type prefetcher struct {
	fetch  BlkRequester
	limit  int64 // bytes of fetched blocks waiting for get
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mtx      sync.Mutex
	changed  chan struct{} // closed and replaced on every change below
	next     int64         // the height get will be asked for next
	claimed  int64         // the next height a worker takes
	tip      int64         // the best height a peer has reported; no claims above it
	ceiling  int64         // where a worker's request failed; no claims from there. 0 for none
	inflight map[int64]bool
	results  map[int64]prefetched
	bytes    int64
}

// newPrefetcher starts prefetching for a catch-up whose first block is from.
// It stops when ctx is done or stop is called, whichever comes first.
func newPrefetcher(ctx context.Context, fetch BlkRequester, from, limit int64) *prefetcher {
	ctx, cancel := context.WithCancel(ctx)
	p := &prefetcher{
		fetch:    fetch,
		limit:    limit,
		cancel:   cancel,
		changed:  make(chan struct{}),
		next:     from,
		claimed:  from,
		tip:      from - 1,
		inflight: make(map[int64]bool),
		results:  make(map[int64]prefetched),
	}
	p.wg.Add(prefetchWorkers)
	for range prefetchWorkers {
		go p.work(ctx)
	}
	return p
}

// stop cancels every request in flight, waits for the workers to return, and
// drops whatever was fetched and not taken.
func (p *prefetcher) stop() {
	p.cancel()
	p.wg.Wait()
}

// notify wakes whoever is waiting for a change. Call it with p.mtx held.
func (p *prefetcher) notify() {
	close(p.changed)
	p.changed = make(chan struct{})
}

// wait releases p.mtx until something changes or ctx is done, then takes it
// back. Call it with p.mtx held.
func (p *prefetcher) wait(ctx context.Context) error {
	changed := p.changed
	p.mtx.Unlock()
	defer p.mtx.Lock()
	select {
	case <-changed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// learn raises tip to best. Call it with p.mtx held.
func (p *prefetcher) learn(best int64) {
	if best > p.tip {
		p.tip = best
		p.notify()
	}
}

func (p *prefetcher) work(ctx context.Context) {
	defer p.wg.Done()
	p.mtx.Lock()
	defer p.mtx.Unlock()
	for {
		for p.bytes >= p.limit || p.claimed > p.tip || (p.ceiling > 0 && p.claimed >= p.ceiling) {
			if p.wait(ctx) != nil {
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		h := p.claimed
		p.claimed++
		if _, have := p.results[h]; have || p.inflight[h] || h < p.next {
			continue // claimed again after a ceiling was lifted, and got already
		}
		p.inflight[h] = true
		p.mtx.Unlock()

		hash, raw, ci, best, err := p.fetch(ctx, h)

		p.mtx.Lock()
		delete(p.inflight, h)
		switch {
		case h < p.next || ctx.Err() != nil:
		case err == nil:
			p.results[h] = prefetched{hash, raw, ci, best}
			p.bytes += int64(len(raw))
			p.learn(best)
		case p.ceiling == 0 || h < p.ceiling:
			// A hole at h, which get fills by asking for h itself. No claims
			// from here until it has.
			p.ceiling = h
		}
		p.notify()
	}
}

// get returns block h, the next one catch-up needs, with BlkRequester's
// signature. It hands over the block if a worker has fetched it and waits if
// one is fetching it. Otherwise it asks for h itself, as catch-up did before
// there was a prefetcher, so what ends a catch-up is unchanged: a fresh
// not-found for the height it needs.
func (p *prefetcher) get(ctx context.Context, h int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
	p.mtx.Lock()
	for {
		if r, ok := p.results[h]; ok {
			delete(p.results, h)
			p.bytes -= int64(len(r.raw))
			p.next = h + 1
			p.notify()
			p.mtx.Unlock()
			return r.hash, r.raw, r.ci, r.best, nil
		}
		if !p.inflight[h] {
			break
		}
		if err := p.wait(ctx); err != nil {
			p.mtx.Unlock()
			return types.Hash{}, nil, nil, 0, err
		}
	}
	// Nobody has it or is fetching it, and no worker will take it now.
	p.claimed = max(p.claimed, h+1)
	p.mtx.Unlock()

	hash, raw, ci, best, err := p.fetch(ctx, h)

	p.mtx.Lock()
	defer p.mtx.Unlock()
	if err == nil {
		p.next = h + 1
		if p.ceiling > 0 && h >= p.ceiling {
			// Past where a worker failed. Claim from here again, so the
			// workers, not get, fill any holes the failure left above it.
			p.ceiling = 0
			p.claimed = h + 1
		}
		p.learn(best)
		p.notify()
	}
	return hash, raw, ci, best, err
}
