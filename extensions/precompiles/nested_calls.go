package precompiles

import "sync"

// nestedCallChecks holds, per chain ID, the block height from which the engine
// checks the calls that precompile methods make through app.Engine.
var nestedCallChecks = struct {
	mu      sync.RWMutex
	heights map[string]int64
}{heights: make(map[string]int64)}

// SetNestedCallChecksHeight sets the block height from which, on the chain with
// the given ID, an action or method that a precompile method calls through
// app.Engine must be one that the calling method may call:
//   - a PRIVATE target must be in the calling method's namespace;
//   - a SYSTEM target needs a calling method that is not PUBLIC, since a PUBLIC
//     method can be called directly by any user.
//
// Calls made from OnStart, OnUse and OnUnuse are not affected. The height is
// compared with the block of the top-level call when that call can change
// state, as every call that executes a block does, and every call nested in it
// follows that decision. A top-level call on a read-only database cannot change
// state and never reaches consensus, so it is checked at every height, even on
// a node that is still syncing.
//
// A chain with no height keeps the earlier behaviour at every height, so its
// existing blocks replay unchanged. The engine logs a warning the first time a
// call runs on a chain with no height. A height of zero or less removes the
// height set for the chain. Set the height before the node starts executing
// blocks, for example in an init function.
func SetNestedCallChecksHeight(chainID string, height int64) {
	nestedCallChecks.mu.Lock()
	defer nestedCallChecks.mu.Unlock()

	if height <= 0 {
		delete(nestedCallChecks.heights, chainID)
		return
	}
	nestedCallChecks.heights[chainID] = height
}

// NestedCallChecksHeight returns the height set with SetNestedCallChecksHeight
// for the chain with the given ID, and whether one is set.
func NestedCallChecksHeight(chainID string) (int64, bool) {
	nestedCallChecks.mu.RLock()
	defer nestedCallChecks.mu.RUnlock()

	height, ok := nestedCallChecks.heights[chainID]
	return height, ok
}
