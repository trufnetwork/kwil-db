package pg

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAwaitCommitIDWaitsWhileDataArrives checks that a commit ID arriving well
// after the stall is still received while the stream keeps delivering data, as
// it does for a large transaction hashed after PREPARE.
func TestAwaitCommitIDWaitsWhileDataArrives(t *testing.T) {
	const stall = 150 * time.Millisecond
	resChan := make(chan []byte, 1)
	received := new(atomic.Uint64)
	go func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		end := time.After(4 * stall)
		for {
			select {
			case <-tick.C:
				received.Add(1)
			case <-end:
				resChan <- []byte{1}
				return
			}
		}
	}()

	id, err := awaitCommitID(context.Background(), resChan, make(chan struct{}), received, stall)
	require.NoError(t, err)
	require.Equal(t, []byte{1}, id)
}

// TestAwaitCommitIDGivesUpOnASilentStream checks that the wait ends once the
// stream has delivered nothing for the stall.
func TestAwaitCommitIDGivesUpOnASilentStream(t *testing.T) {
	const stall = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 4*stall)
	defer cancel()

	t0 := time.Now()
	_, err := awaitCommitID(ctx, make(chan []byte), make(chan struct{}), new(atomic.Uint64), stall)
	require.ErrorContains(t, err, "timed out waiting for commit ID")
	require.GreaterOrEqual(t, time.Since(t0), stall)
}

// TestAwaitCommitIDEndsWithTheStream checks that the wait ends when the
// replication monitor stops.
func TestAwaitCommitIDEndsWithTheStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	close(done)
	_, err := awaitCommitID(ctx, make(chan []byte), done, new(atomic.Uint64), time.Minute)
	require.ErrorContains(t, err, "interrupted")
}
