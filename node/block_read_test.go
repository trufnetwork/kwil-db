package node

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/trufnetwork/kwil-db/core/crypto"

	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
)

func TestReadAllStopsAtOverallDeadlineWhileChunksArrive(t *testing.T) {
	mn := mock.New()
	defer mn.Close()

	_, h1 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	_, h2 := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	if err := mn.LinkAll(); err != nil {
		t.Fatal(err)
	}
	if err := mn.ConnectAllButSelf(); err != nil {
		t.Fatal(err)
	}

	const proto protocol.ID = "/test/readall-deadline/1"
	stop := make(chan struct{})
	defer close(stop)
	h2.SetStreamHandler(proto, func(s network.Stream) {
		defer s.Close()
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			if _, err := s.Write([]byte{1}); err != nil {
				return
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := h1.NewStream(ctx, h2.ID(), proto)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	const (
		overall = 200 * time.Millisecond
		idle    = 5 * time.Second
	)
	start := time.Now()
	_, err = readAll(s, 1_000_000, start.Add(overall), idle)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout")
	}
	// A chunk every 20ms must not keep the read open for the idle timeout.
	if elapsed > time.Second {
		t.Fatalf("read ran %s with overall deadline %s", elapsed, overall)
	}
}
