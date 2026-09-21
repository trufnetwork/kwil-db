package consensus

import (
	"testing"
	"time"
)

// argsMap turns the flat key/value list a logger takes into something a test
// can assert against.
func argsMap(t *testing.T, args []any) map[string]any {
	t.Helper()
	if len(args)%2 != 0 {
		t.Fatalf("log args must pair up, got %d values: %v", len(args), args)
	}
	m := make(map[string]any, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			t.Fatalf("log key %d is %T, not a string", i, args[i])
		}
		m[key] = args[i+1]
	}
	return m
}

func TestSyncProgressSplitsAWindow(t *testing.T) {
	start := time.Now()
	p := newSyncProgress(start)

	p.fetched(300 * time.Millisecond)
	p.applied(40 * time.Millisecond)
	p.fetched(500 * time.Millisecond)
	p.applied(60 * time.Millisecond)

	got := argsMap(t, p.windowArgs(100, start.Add(time.Second)))

	if got["network"] != 800*time.Millisecond {
		t.Errorf("network = %v, want 800ms", got["network"])
	}
	if got["apply"] != 100*time.Millisecond {
		t.Errorf("apply = %v, want 100ms", got["apply"])
	}
	if got["from"] != int64(98) || got["to"] != int64(100) {
		t.Errorf("window covers from=%v to=%v, want 98..100", got["from"], got["to"])
	}
	if got["elapsed"] != time.Second {
		t.Errorf("elapsed = %v, want 1s", got["elapsed"])
	}
	if got["rate"] != "2.0000" {
		t.Errorf("rate = %v, want 2.0000", got["rate"])
	}
}

func TestSyncProgressStartsTheNextWindowClean(t *testing.T) {
	start := time.Now()
	p := newSyncProgress(start)

	p.fetched(900 * time.Millisecond)
	p.applied(100 * time.Millisecond)
	p.windowArgs(100, start.Add(time.Second))

	// A window reports its own stretch. Carrying the last one forward would
	// make every window look worse than the one before it.
	p.fetched(200 * time.Millisecond)
	p.applied(50 * time.Millisecond)
	got := argsMap(t, p.windowArgs(200, start.Add(2*time.Second)))

	if got["network"] != 200*time.Millisecond {
		t.Errorf("network = %v, want 200ms from this window alone", got["network"])
	}
	if got["apply"] != 50*time.Millisecond {
		t.Errorf("apply = %v, want 50ms from this window alone", got["apply"])
	}
	if got["from"] != int64(199) {
		t.Errorf("from = %v, want 199 — the block count reset with the window", got["from"])
	}
	if got["elapsed"] != time.Second {
		t.Errorf("elapsed = %v, want 1s measured from the last log, not the run start", got["elapsed"])
	}
}

func TestSyncProgressKeepsTheRunTotal(t *testing.T) {
	start := time.Now()
	p := newSyncProgress(start)

	p.fetched(900 * time.Millisecond)
	p.applied(100 * time.Millisecond)
	p.windowArgs(100, start.Add(time.Second))
	p.fetched(200 * time.Millisecond)
	p.applied(50 * time.Millisecond)
	p.windowArgs(200, start.Add(2*time.Second))

	// The completion line answers the Goal's question for the whole sync, so
	// the window resets must not touch it.
	got := argsMap(t, p.runArgs(start.Add(3*time.Second)))

	if got["network"] != 1100*time.Millisecond {
		t.Errorf("run network = %v, want 1.1s across both windows", got["network"])
	}
	if got["apply"] != 150*time.Millisecond {
		t.Errorf("run apply = %v, want 150ms across both windows", got["apply"])
	}
	if got["elapsed"] != 3*time.Second {
		t.Errorf("run elapsed = %v, want 3s from the run start", got["elapsed"])
	}
}

func TestSyncProgressCountsAFailedFetch(t *testing.T) {
	start := time.Now()
	p := newSyncProgress(start)

	// A request that came back empty still cost the run its round trip, and a
	// run that spends its time on requests that fail is the case an operator
	// most needs to see.
	p.fetched(700 * time.Millisecond)

	got := argsMap(t, p.runArgs(start.Add(time.Second)))
	if got["network"] != 700*time.Millisecond {
		t.Errorf("run network = %v, want the failed fetch counted", got["network"])
	}
	if got["apply"] != time.Duration(0) {
		t.Errorf("run apply = %v, want 0 — nothing was applied", got["apply"])
	}
}

func TestSyncProgressTruncatesToMilliseconds(t *testing.T) {
	start := time.Now()
	p := newSyncProgress(start)

	p.fetched(300*time.Millisecond + 456*time.Microsecond)
	p.applied(40*time.Millisecond + 789*time.Microsecond)

	got := argsMap(t, p.windowArgs(100, start.Add(time.Second)))
	if got["network"] != 300*time.Millisecond {
		t.Errorf("network = %v, want it truncated to 300ms like elapsed", got["network"])
	}
	if got["apply"] != 40*time.Millisecond {
		t.Errorf("apply = %v, want it truncated to 40ms like elapsed", got["apply"])
	}
}
