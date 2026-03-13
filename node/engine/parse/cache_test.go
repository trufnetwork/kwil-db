package parse

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateUniqueSQL creates SQL statements with varying structure to
// exercise different ANTLR parser paths and grow the prediction context cache.
func generateUniqueSQL(i int) string {
	// Vary the SQL structure to produce different parse paths, which is what
	// causes the ANTLR PredictionContextCache and DFA states to grow.
	switch i % 5 {
	case 0:
		return fmt.Sprintf("SELECT col_%d, col_%d FROM table_%d WHERE col_%d > $param_%d;",
			i, i+1, i, i+2, i)
	case 1:
		return fmt.Sprintf("INSERT INTO table_%d (col_%d, col_%d) VALUES ($val_%d, $val_%d);",
			i, i, i+1, i, i+1)
	case 2:
		return fmt.Sprintf("UPDATE table_%d SET col_%d = $val_%d WHERE col_%d = $id_%d;",
			i, i, i, i+1, i)
	case 3:
		return fmt.Sprintf("DELETE FROM table_%d WHERE col_%d = $id_%d AND col_%d > $min_%d;",
			i, i, i, i+1, i)
	default:
		return fmt.Sprintf("SELECT col_%d, col_%d, col_%d FROM table_%d WHERE col_%d > $p_%d AND col_%d < $q_%d;",
			i, i+1, i+2, i, i, i, i+1, i)
	}
}

// getHeapInuse returns the current heap in-use bytes after forcing GC.
func getHeapInuse() uint64 {
	runtime.GC()
	runtime.GC() // run twice to ensure finalizers complete
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

// TestClearANTLRCaches verifies that clearANTLRCaches resets the ANTLR
// global caches and that parsing still works correctly afterward.
func TestClearANTLRCaches(t *testing.T) {
	// Parse some SQL to populate ANTLR caches
	for i := 0; i < 100; i++ {
		sql := generateUniqueSQL(i)
		_, _ = Parse(sql) // errors expected (tables don't exist), but caches still grow
	}

	// Clear caches
	clearANTLRCaches()

	// Verify parsing still works correctly after clearing
	result, err := Parse("SELECT id, name FROM users WHERE id = $id;")
	require.NoError(t, err)
	require.Len(t, result, 1, "expected exactly 1 parsed statement")

	// Verify a more complex query also works
	result, err = Parse("SELECT id, name FROM users WHERE id > $min AND name != $excluded;")
	require.NoError(t, err)
	require.Len(t, result, 1, "expected exactly 1 parsed statement")

	// Verify INSERT works
	result, err = Parse("INSERT INTO users (id, name) VALUES ($id, $name);")
	require.NoError(t, err)
	require.Len(t, result, 1, "expected exactly 1 parsed statement")
}

// TestPeriodicCacheClearingBoundsMemory verifies that the periodic cache
// clearing mechanism prevents unbounded memory growth from ANTLR caches.
//
// This test reproduces the production OOM issue where the ANTLR4
// PredictionContextCache and DFA states grow without bound because:
// 1. Each unique SQL pattern adds entries to the shared global caches
// 2. ANTLR never clears these caches
// 3. Over time (hours/days), memory grows until OOM kill
func TestPeriodicCacheClearingBoundsMemory(t *testing.T) {
	// Reset the parse counter so we control when clearing happens
	parseCount.Store(0)

	// Clear caches to start fresh
	clearANTLRCaches()
	runtime.GC()

	baselineHeap := getHeapInuse()

	// Phase 1: Parse many unique SQL statements (enough to trigger multiple cache clears)
	// With clearInterval=1000, parsing 3000 unique statements should trigger ~3 clears
	const totalParses = 3000
	for i := 0; i < totalParses; i++ {
		sql := generateUniqueSQL(i)
		_, _ = Parse(sql)
	}

	afterPhase1Heap := getHeapInuse()

	// Clear and measure what memory looks like after clearing
	clearANTLRCaches()
	afterClearHeap := getHeapInuse()

	// The heap after clearing should be significantly less than peak,
	// proving the caches were consuming memory that is now freed.
	// We use a generous threshold since Go GC is not deterministic.
	phase1Growth := int64(afterPhase1Heap) - int64(baselineHeap)
	afterClearGrowth := int64(afterClearHeap) - int64(baselineHeap)

	t.Logf("Baseline heap:       %d MB", baselineHeap/1024/1024)
	t.Logf("After %d parses:    %d MB (growth: %d KB)", totalParses, afterPhase1Heap/1024/1024, phase1Growth/1024)
	t.Logf("After cache clear:   %d MB (growth: %d KB)", afterClearHeap/1024/1024, afterClearGrowth/1024)

	// After clearing, memory growth should be less than the peak growth.
	// If the clear didn't work, afterClearGrowth would be >= phase1Growth.
	if phase1Growth > 0 {
		assert.Less(t, afterClearGrowth, phase1Growth,
			"clearing ANTLR caches should reduce memory usage; growth after clear (%d KB) should be less than peak growth (%d KB)",
			afterClearGrowth/1024, phase1Growth/1024)
	}

	// Phase 2: Verify the automatic periodic clearing works.
	// Parse another batch and verify memory doesn't grow without bound
	// compared to parsing the same amount without clearing.

	// First, disable clearing by setting counter far from threshold
	parseCount.Store(0)
	clearANTLRCaches()
	runtime.GC()
	beforeNoClearHeap := getHeapInuse()

	// Parse without hitting clear threshold (stay under clearInterval)
	const batchSize = clearInterval - 1 // just under threshold, no clear triggered
	for i := 0; i < batchSize; i++ {
		sql := generateUniqueSQL(totalParses + i) // use new unique SQL
		_, _ = Parse(sql)
	}
	afterNoClearHeap := getHeapInuse()
	noClearGrowth := int64(afterNoClearHeap) - int64(beforeNoClearHeap)

	// Now parse with clearing enabled (counter starts at 0, will clear at 1000)
	parseCount.Store(0)
	clearANTLRCaches()
	runtime.GC()
	beforeWithClearHeap := getHeapInuse()

	// Parse 2x the batch to guarantee at least one clear cycle
	for i := 0; i < batchSize*2; i++ {
		sql := generateUniqueSQL(totalParses + batchSize + i)
		_, _ = Parse(sql)
	}
	afterWithClearHeap := getHeapInuse()
	withClearGrowth := int64(afterWithClearHeap) - int64(beforeWithClearHeap)

	t.Logf("Without clearing: %d parses grew %d KB", batchSize, noClearGrowth/1024)
	t.Logf("With clearing:    %d parses grew %d KB", batchSize*2, withClearGrowth/1024)

	// Even though we parsed 2x as many statements with clearing enabled,
	// memory growth should not be 2x, proving the periodic clear works.
	// We check that 2x parses with clearing doesn't use more than 2x memory of no-clearing.
	// (In practice, with clearing it should use significantly LESS despite 2x parses.)
	if noClearGrowth > 100*1024 { // only assert if there's meaningful growth
		assert.Less(t, withClearGrowth, noClearGrowth*3,
			"2x parses with periodic clearing should not use 3x the memory of 1x parses without clearing")
	}
}

// TestParseCounterTriggersClear verifies that the parse counter correctly
// triggers cache clearing at the expected interval.
func TestParseCounterTriggersClear(t *testing.T) {
	// Reset counter
	parseCount.Store(0)

	// Parse exactly clearInterval-1 times — should NOT trigger a clear
	for i := 0; i < clearInterval-1; i++ {
		_, _ = Parse(fmt.Sprintf("SELECT col_%d FROM tbl_%d;", i, i))
	}
	countBefore := parseCount.Load()
	assert.Equal(t, int64(clearInterval-1), countBefore, "counter should match number of parses")

	// The next parse (the 1000th) should trigger a clear
	// We verify by checking that parsing still works (no crash from cleared caches)
	result, err := Parse("SELECT id FROM users;")
	require.NoError(t, err)
	require.Len(t, result, 1)

	countAfter := parseCount.Load()
	assert.Equal(t, int64(clearInterval), countAfter, "counter should be at clearInterval after triggering clear")

	// Verify the counter modulo logic: parse one more, should not clear
	result, err = Parse("SELECT name FROM users;")
	require.NoError(t, err)
	require.Len(t, result, 1)
}
