package precompiles

import (
	"sync"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
)

const (
	AttestationPrecompileName = "tn_attestation"
)

// AttestationQueue is a thread-safe queue for managing attestation hashes that need signing.
// It is shared between the queue_for_signing() precompile and the leader signing extension.
type AttestationQueue struct {
	mu     sync.RWMutex
	hashes map[string]struct{} // Using map for O(1) deduplication
}

// NewAttestationQueue creates a new attestation queue.
func NewAttestationQueue() *AttestationQueue {
	return &AttestationQueue{
		hashes: make(map[string]struct{}),
	}
}

// Enqueue adds an attestation hash to the queue if it doesn't already exist.
// Returns true if the hash was added, false if it already existed.
func (q *AttestationQueue) Enqueue(hash string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if _, exists := q.hashes[hash]; exists {
		return false
	}

	q.hashes[hash] = struct{}{}
	return true
}

// DequeueAll removes and returns all attestation hashes from the queue.
func (q *AttestationQueue) DequeueAll() []string {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.hashes) == 0 {
		return nil
	}

	hashes := make([]string, 0, len(q.hashes))
	for hash := range q.hashes {
		hashes = append(hashes, hash)
	}

	// Clear the queue
	q.hashes = make(map[string]struct{})

	return hashes
}

// Len returns the current number of hashes in the queue.
func (q *AttestationQueue) Len() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.hashes)
}

// Clear removes all hashes from the queue.
func (q *AttestationQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.hashes = make(map[string]struct{})
}

// Copy creates a deep copy of the queue.
func (q *AttestationQueue) Copy() *AttestationQueue {
	q.mu.RLock()
	defer q.mu.RUnlock()

	newQueue := NewAttestationQueue()
	for hash := range q.hashes {
		newQueue.hashes[hash] = struct{}{}
	}
	return newQueue
}

// attestationQueueSingleton is the global queue shared between precompile and extension.
// This will be accessed by both queue_for_signing() precompile and the leader signing extension.
var attestationQueueSingleton *AttestationQueue
var queueOnce sync.Once

// GetAttestationQueue returns the global attestation queue singleton.
// This function is exported so the leader signing extension can access it.
func GetAttestationQueue() *AttestationQueue {
	queueOnce.Do(func() {
		attestationQueueSingleton = NewAttestationQueue()
	})
	return attestationQueueSingleton
}

// attestationCache implements the precompiles.Cache interface.
// It maintains a snapshot of the queue state for consensus determinism.
type attestationCache struct {
	queue *AttestationQueue
}

// Copy creates a deep copy of the cache.
func (c *attestationCache) Copy() Cache {
	return &attestationCache{
		queue: c.queue.Copy(),
	}
}

// Apply applies a previously created deep copy of the cache.
func (c *attestationCache) Apply(cache Cache) {
	other := cache.(*attestationCache)
	c.queue = other.queue
}

func init() {
	err := RegisterPrecompile(AttestationPrecompileName, Precompile{
		Cache: &attestationCache{
			queue: GetAttestationQueue(),
		},
		Methods: []Method{
			{
				Name: "queue_for_signing",
				Parameters: []PrecompileValue{
					NewPrecompileValue("attestation_hash", types.TextType, false),
				},
				AccessModifiers: []Modifier{SYSTEM},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					attestationHash := inputs[0].(string)

					// Check if the current node is the leader
					// We check by comparing the proposer's public key with our own identity
					isLeader := false
					if ctx.TxContext.BlockContext.Proposer != nil && app.Service.Identity != nil {
						proposerBytes := ctx.TxContext.BlockContext.Proposer.Bytes()
						isLeader = string(proposerBytes) == string(app.Service.Identity)
					}

					// Only queue if we are the leader
					// For non-leaders, this is a no-op to maintain determinism
					if isLeader {
						queue := GetAttestationQueue()
						queue.Enqueue(attestationHash)

						app.Service.Logger.Debug("Queued attestation for signing",
							"hash", attestationHash,
							"queue_size", queue.Len())
					}

					// Always return nil (no return value) for all validators
					// This maintains determinism while only affecting leader's in-memory state
					return nil
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
}
