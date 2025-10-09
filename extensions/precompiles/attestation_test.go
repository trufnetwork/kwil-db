package precompiles

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
)

func TestAttestationQueue(t *testing.T) {
	t.Run("NewQueue", func(t *testing.T) {
		q := NewAttestationQueue()
		assert.NotNil(t, q)
		assert.Equal(t, 0, q.Len())
	})

	t.Run("Enqueue", func(t *testing.T) {
		q := NewAttestationQueue()

		// First enqueue should succeed
		added := q.Enqueue("hash1")
		assert.True(t, added)
		assert.Equal(t, 1, q.Len())

		// Duplicate enqueue should fail
		added = q.Enqueue("hash1")
		assert.False(t, added)
		assert.Equal(t, 1, q.Len())

		// Different hash should succeed
		added = q.Enqueue("hash2")
		assert.True(t, added)
		assert.Equal(t, 2, q.Len())
	})

	t.Run("DequeueAll", func(t *testing.T) {
		q := NewAttestationQueue()
		q.Enqueue("hash1")
		q.Enqueue("hash2")
		q.Enqueue("hash3")

		hashes := q.DequeueAll()
		assert.Len(t, hashes, 3)
		assert.Contains(t, hashes, "hash1")
		assert.Contains(t, hashes, "hash2")
		assert.Contains(t, hashes, "hash3")

		// Queue should be empty after dequeue all
		assert.Equal(t, 0, q.Len())

		// Dequeuing empty queue should return nil
		hashes = q.DequeueAll()
		assert.Nil(t, hashes)
	})

	t.Run("Clear", func(t *testing.T) {
		q := NewAttestationQueue()
		q.Enqueue("hash1")
		q.Enqueue("hash2")
		assert.Equal(t, 2, q.Len())

		q.Clear()
		assert.Equal(t, 0, q.Len())
	})

	t.Run("Copy", func(t *testing.T) {
		q1 := NewAttestationQueue()
		q1.Enqueue("hash1")
		q1.Enqueue("hash2")

		q2 := q1.Copy()
		assert.Equal(t, q1.Len(), q2.Len())

		// Modifying copy shouldn't affect original
		q2.Enqueue("hash3")
		assert.Equal(t, 2, q1.Len())
		assert.Equal(t, 3, q2.Len())
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		q := NewAttestationQueue()
		done := make(chan bool)

		// Multiple goroutines enqueueing
		for i := 0; i < 10; i++ {
			go func(id int) {
				for j := 0; j < 100; j++ {
					q.Enqueue(string(rune('a' + id)))
				}
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Should have exactly 10 unique hashes (one per goroutine)
		assert.Equal(t, 10, q.Len())
	})
}

func TestAttestationCache(t *testing.T) {
	t.Run("Copy", func(t *testing.T) {
		q := NewAttestationQueue()
		q.Enqueue("hash1")

		c1 := &attestationCache{queue: q}
		c2 := c1.Copy()

		assert.IsType(t, &attestationCache{}, c2)
		assert.Equal(t, c1.queue.Len(), c2.(*attestationCache).queue.Len())

		// Modifying copy shouldn't affect original
		c2.(*attestationCache).queue.Enqueue("hash2")
		assert.Equal(t, 1, c1.queue.Len())
		assert.Equal(t, 2, c2.(*attestationCache).queue.Len())
	})

	t.Run("Apply", func(t *testing.T) {
		q1 := NewAttestationQueue()
		q1.Enqueue("hash1")

		q2 := NewAttestationQueue()
		q2.Enqueue("hash2")
		q2.Enqueue("hash3")

		c1 := &attestationCache{queue: q1}
		c2 := &attestationCache{queue: q2}

		c1.Apply(c2)
		assert.Equal(t, q2.Len(), c1.queue.Len())
	})
}

func TestQueueForSigningPrecompile(t *testing.T) {
	// Reset singleton for test isolation
	queueOnce = sync.Once{}
	attestationQueueSingleton = nil

	t.Run("RegistrationSuccess", func(t *testing.T) {
		precompiles := RegisteredPrecompiles()
		require.Contains(t, precompiles, AttestationPrecompileName)
	})

	t.Run("LeaderQueuesHash", func(t *testing.T) {
		// Reset queue
		queue := GetAttestationQueue()
		queue.Clear()

		// Create mock leader identity
		leaderPriv, leaderPub, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)
		_ = leaderPriv // unused

		// Create context where node IS the leader
		ctx := &common.EngineContext{
			TxContext: &common.TxContext{
				Ctx: context.Background(),
				BlockContext: &common.BlockContext{
					Proposer: leaderPub,
				},
			},
		}

		app := &common.App{
			Service: &common.Service{
				Logger:   log.DiscardLogger,
				Identity: leaderPub.Bytes(),
			},
		}

		// Initialize the precompile
		initializer := RegisteredPrecompiles()[AttestationPrecompileName]
		precompile, err := initializer(context.Background(), app.Service, nil, "", nil)
		require.NoError(t, err)

		// Call queue_for_signing
		handler := precompile.Methods[0].Handler
		err = handler(ctx, app, []any{"test_hash_123"}, func([]any) error { return nil })
		require.NoError(t, err)

		// Verify hash was queued
		assert.Equal(t, 1, queue.Len())
		hashes := queue.DequeueAll()
		assert.Contains(t, hashes, "test_hash_123")
	})

	t.Run("NonLeaderDoesNotQueue", func(t *testing.T) {
		// Reset queue
		queue := GetAttestationQueue()
		queue.Clear()

		// Create different keys for leader and validator
		leaderPriv, leaderPub, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)
		_ = leaderPriv

		validatorPriv, validatorPub, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)
		_ = validatorPriv

		// Create context where node is NOT the leader
		ctx := &common.EngineContext{
			TxContext: &common.TxContext{
				Ctx: context.Background(),
				BlockContext: &common.BlockContext{
					Proposer: leaderPub, // Different from validator's identity
				},
			},
		}

		app := &common.App{
			Service: &common.Service{
				Logger:   log.DiscardLogger,
				Identity: validatorPub.Bytes(), // Validator's identity
			},
		}

		// Initialize the precompile
		initializer := RegisteredPrecompiles()[AttestationPrecompileName]
		precompile, err := initializer(context.Background(), app.Service, nil, "", nil)
		require.NoError(t, err)

		// Call queue_for_signing
		handler := precompile.Methods[0].Handler
		err = handler(ctx, app, []any{"test_hash_456"}, func([]any) error { return nil })
		require.NoError(t, err)

		// Verify hash was NOT queued (non-leader is no-op)
		assert.Equal(t, 0, queue.Len())
	})

	t.Run("NoProposerIsNoOp", func(t *testing.T) {
		// Reset queue
		queue := GetAttestationQueue()
		queue.Clear()

		// Create context with no proposer
		ctx := &common.EngineContext{
			TxContext: &common.TxContext{
				Ctx: context.Background(),
				BlockContext: &common.BlockContext{
					Proposer: nil, // No proposer
				},
			},
		}

		app := &common.App{
			Service: &common.Service{
				Logger:   log.DiscardLogger,
				Identity: []byte("some_identity"),
			},
		}

		// Initialize the precompile
		initializer := RegisteredPrecompiles()[AttestationPrecompileName]
		precompile, err := initializer(context.Background(), app.Service, nil, "", nil)
		require.NoError(t, err)

		// Call queue_for_signing
		handler := precompile.Methods[0].Handler
		err = handler(ctx, app, []any{"test_hash_789"}, func([]any) error { return nil })
		require.NoError(t, err)

		// Verify hash was NOT queued
		assert.Equal(t, 0, queue.Len())
	})

	t.Run("PreservesDeterminism", func(t *testing.T) {
		// Reset queue
		queue := GetAttestationQueue()
		queue.Clear()

		leaderPriv, leaderPub, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)
		_ = leaderPriv

		// Call from leader
		ctxLeader := &common.EngineContext{
			TxContext: &common.TxContext{
				Ctx: context.Background(),
				BlockContext: &common.BlockContext{
					Proposer: leaderPub,
				},
			},
		}

		appLeader := &common.App{
			Service: &common.Service{
				Logger:   log.DiscardLogger,
				Identity: leaderPub.Bytes(),
			},
		}

		validatorPriv, validatorPub, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)
		_ = validatorPriv

		// Call from non-leader
		ctxValidator := &common.EngineContext{
			TxContext: &common.TxContext{
				Ctx: context.Background(),
				BlockContext: &common.BlockContext{
					Proposer: leaderPub,
				},
			},
		}

		appValidator := &common.App{
			Service: &common.Service{
				Logger:   log.DiscardLogger,
				Identity: validatorPub.Bytes(),
			},
		}

		// Initialize the precompile
		initializer := RegisteredPrecompiles()[AttestationPrecompileName]
		precompile, err := initializer(context.Background(), appLeader.Service, nil, "", nil)
		require.NoError(t, err)

		handler := precompile.Methods[0].Handler

		// Both should return nil error (deterministic)
		err1 := handler(ctxLeader, appLeader, []any{"test_hash"}, func([]any) error { return nil })
		err2 := handler(ctxValidator, appValidator, []any{"test_hash"}, func([]any) error { return nil })

		assert.NoError(t, err1)
		assert.NoError(t, err2)

		// Both return the same error status (deterministic)
		// But only leader's queue is affected (non-deterministic side effect)
		assert.Equal(t, 1, queue.Len())
	})
}
