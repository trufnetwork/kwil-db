package erc20

import (
	"sync"
	"sync/atomic"

	"github.com/trufnetwork/kwil-db/core/types"
)

// The reward end-block hook runs two queries for every instance past its
// distribution period, on every block: whether the previous epoch is confirmed,
// and which rewards the current epoch holds. Most blocks find the same answer
// as the block before, "wait", and finalize nothing.
//
// rewardStateVersion lets the hook skip those queries until something they read
// changes. Every write to epochs or epoch_rewards raises it. The hook records,
// per instance, why its epoch was waiting and the version it saw. While both
// still match, the queries would return the same answer, so the hook skips them.
//
// This only ever skips a query whose answer is "wait". A skipped block makes the
// same writes as a full check, which are none, so nodes that skip and nodes that
// just restarted with no marks agree on the app hash. The version only goes up
// and is deliberately not part of the extension's copied cache: a write rolled
// back with its transaction leaves the version raised, which costs one extra
// query, and a rollback can only remove rewards or confirmations, so a "wait"
// recorded before it stays true.
var rewardStateVersion atomic.Uint64

// noteRewardStateWrite records a write to epochs or epoch_rewards. Call it from
// every function that writes either table.
func noteRewardStateWrite() {
	rewardStateVersion.Add(1)
}

// idleReason is why an instance's current epoch could not finalize at its last
// full check.
type idleReason uint8

const (
	// idleAwaitingConfirmation: the previous epoch exists and is not confirmed.
	idleAwaitingConfirmation idleReason = iota + 1
	// idleAwaitingRewards: the epoch has no rewards and is inside the
	// empty-epoch grace period.
	idleAwaitingRewards
)

func (r idleReason) String() string {
	switch r {
	case idleAwaitingConfirmation:
		return "previous epoch not confirmed"
	case idleAwaitingRewards:
		return "no rewards, inside the grace period"
	default:
		return "unknown"
	}
}

// idleMark is the outcome of an instance's last full check.
type idleMark struct {
	epochID types.UUID
	version uint64
	reason  idleReason
}

var (
	idleMarksMu sync.Mutex
	idleMarks   = map[types.UUID]idleMark{}
)

// idleSince returns why the instance's epoch was waiting at its last full
// check, if that check saw this epoch and no write to epochs or epoch_rewards
// has happened since.
func idleSince(instanceID, epochID types.UUID, version uint64) (idleReason, bool) {
	idleMarksMu.Lock()
	defer idleMarksMu.Unlock()
	mark, ok := idleMarks[instanceID]
	if !ok || mark.epochID != epochID || mark.version != version {
		return 0, false
	}
	return mark.reason, true
}

// markIdle records that the instance's epoch could not finalize, for the
// version read before the queries that found it so.
func markIdle(instanceID, epochID types.UUID, version uint64, reason idleReason) {
	idleMarksMu.Lock()
	defer idleMarksMu.Unlock()
	idleMarks[instanceID] = idleMark{epochID: epochID, version: version, reason: reason}
}

// resetIdleMarks forgets every mark, as a restart does.
func resetIdleMarks() {
	idleMarksMu.Lock()
	defer idleMarksMu.Unlock()
	idleMarks = map[types.UUID]idleMark{}
}
