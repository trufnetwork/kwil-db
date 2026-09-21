package consensus

import (
	"fmt"
	"time"
)

// syncProgress tracks where a catch-up run spends its time, split between
// waiting on peers and applying what they send. That split is the number
// catch-up performance turns on, and a node writes no per-block line while
// syncing, so without it an operator has one combined rate and no way to tell
// a slow link from a slow apply.
//
// It carries a window, reset at every progress log, alongside a total for the
// whole run.
//
// Backoff between failed fetches lands in neither bucket. A run whose network
// and apply times fall well short of its elapsed time spent the difference
// sleeping between retries, which is worth seeing on its own.
type syncProgress struct {
	start  time.Time // when the run began
	window time.Time // when the current reporting window began

	blocks  int64         // blocks applied in the current window
	network time.Duration // time spent requesting blocks, current window
	apply   time.Duration // time spent executing and committing them

	runNetwork time.Duration // the same two, for the whole run
	runApply   time.Duration
}

func newSyncProgress(now time.Time) *syncProgress {
	return &syncProgress{start: now, window: now}
}

// fetched records one call to the block requester, whether or not it came back
// with a block. A request that failed still cost the run its round trip.
func (p *syncProgress) fetched(d time.Duration) {
	p.network += d
	p.runNetwork += d
}

// applied records one block executed and committed.
func (p *syncProgress) applied(d time.Duration) {
	p.apply += d
	p.runApply += d
	p.blocks++
}

// windowArgs returns the log fields for the window ending at now, and opens the
// next one.
func (p *syncProgress) windowArgs(height int64, now time.Time) []any {
	elapsed := now.Sub(p.window)
	args := []any{
		"from", height - p.blocks,
		"to", height,
		"elapsed", elapsed.Truncate(time.Millisecond),
		"network", p.network.Truncate(time.Millisecond),
		"apply", p.apply.Truncate(time.Millisecond),
		"rate", fmt.Sprintf("%.04f", float64(p.blocks)/elapsed.Seconds()),
	}

	p.blocks, p.network, p.apply = 0, 0, 0
	p.window = now

	return args
}

// runArgs returns the log fields for the whole run, which the window resets
// leave alone.
func (p *syncProgress) runArgs(now time.Time) []any {
	return []any{
		"elapsed", now.Sub(p.start),
		"network", p.runNetwork.Truncate(time.Millisecond),
		"apply", p.runApply.Truncate(time.Millisecond),
	}
}
