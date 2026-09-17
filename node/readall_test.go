package node

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/stretchr/testify/require"
)

// scriptedChunk is one thing a peer does: go quiet for after, then either hand
// over data or hang up.
type scriptedChunk struct {
	after time.Duration
	data  []byte
	eof   bool
}

// scriptedStream is a peer that answers on a schedule and honours whatever read
// deadline the reader set for the current read. Only Read and SetReadDeadline
// are reachable from readAll; the embedded interface satisfies the rest.
type scriptedStream struct {
	network.Stream

	deadline time.Time
	script   []scriptedChunk
}

func (s *scriptedStream) SetReadDeadline(t time.Time) error {
	s.deadline = t
	return nil
}

func (s *scriptedStream) Read(p []byte) (int, error) {
	wait := time.Duration(1<<63 - 1) // a peer with nothing left to say never speaks again
	if len(s.script) > 0 {
		wait = s.script[0].after
	}

	if left := time.Until(s.deadline); wait > left {
		if left > 0 {
			time.Sleep(left)
		}
		return 0, os.ErrDeadlineExceeded
	}
	time.Sleep(wait)

	c := s.script[0]
	s.script = s.script[1:]
	if c.eof {
		return 0, io.EOF
	}

	n := copy(p, c.data)
	if n < len(c.data) { // reader's buffer was smaller; keep the rest for the next read
		s.script = append([]scriptedChunk{{data: c.data[n:]}}, s.script...)
	}
	return n, nil
}

func TestReadAllFirstByteGetsTheWholeResponseBudget(t *testing.T) {
	const idleTimeout = 20 * time.Millisecond
	payload := []byte("a block")

	t.Run("a peer slower than idleTimeout is not abandoned", func(t *testing.T) {
		// One round trip to a distant peer, well inside the response budget but
		// several times idleTimeout. Held to idleTimeout this peer is dropped
		// and the round trip is wasted.
		s := &scriptedStream{script: []scriptedChunk{
			{after: 5 * idleTimeout, data: payload},
			{eof: true},
		}}

		got, err := readAll(s, blkReadLimit, time.Now().Add(2*time.Second), idleTimeout)
		require.NoError(t, err)
		require.Equal(t, payload, got)
	})

	t.Run("a transfer that stalls mid-block still trips idleTimeout", func(t *testing.T) {
		// idleTimeout keeps the job it was named for: once bytes are flowing, a
		// gap this long means the peer stopped sending.
		s := &scriptedStream{script: []scriptedChunk{
			{data: payload},
			{after: 5 * idleTimeout, data: payload},
			{eof: true},
		}}

		_, err := readAll(s, blkReadLimit, time.Now().Add(2*time.Second), idleTimeout)
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	})

	t.Run("a peer that never answers still fails at the response deadline", func(t *testing.T) {
		// The first read is longer, not unbounded.
		s := &scriptedStream{} // says nothing, ever

		t0 := time.Now()
		_, err := readAll(s, blkReadLimit, t0.Add(200*time.Millisecond), idleTimeout)
		require.True(t, errors.Is(err, os.ErrDeadlineExceeded) || err.Error() == "timeout",
			"want a deadline error, got %v", err)
		require.WithinDuration(t, t0.Add(200*time.Millisecond), time.Now(), 150*time.Millisecond)
	})
}
