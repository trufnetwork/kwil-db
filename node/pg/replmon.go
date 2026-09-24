package pg

// This file defines a simple "replication monitor" for:
//  - listening for end-of-commit WAL data messages from a logical replication slot
//  - publishing updates with the message to a subscriber of a sequenced tx number
//
// It is designed for the DB type and is not intended to be used more generally.
// As such, none of this is exported.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/trufnetwork/kwil-db/core/utils/random"
)

// publicationName is the name of the publication required for logical
// replication.
const publicationName = "kwild_repl"

// decodeCommitPayload extracts the seq value and commit hash from the data
// received from the logical replication message stream (see captureRepl).
func decodeCommitPayload(cid []byte) (int64, []byte, error) {
	if len(cid) <= 8 {
		return 0, nil, errors.New("invalid commit ID length")
	}
	seq := int64(binary.BigEndian.Uint64(cid))
	commitID := make([]byte, len(cid)-8)
	copy(commitID, cid[8:])
	return seq, commitID, nil
}

// replMon is the "replication monitor" that sits between the DB type and the
// receiver goroutine listening on a postgres replication slot. This is not
// exported for general use, but a consumer will use the recvID method, the
// errChan, and the done chan to interact.
type replMon struct {
	conn *pgconn.PgConn
	quit context.CancelFunc
	done chan struct{} // termination broadcast channel
	err  error         // specific error, safe to read after done is closed

	received *atomic.Uint64 // WAL data messages taken off the stream, see awaitCommitID

	mtx      sync.Mutex
	promises map[int64]chan []byte
	// The promise map supports multiple concurrent sentry sequences,
	// which is required for per-transaction 2PC where each kwil tx gets
	// its own PG transaction with a unique sentry sequence number.

	// changesetWriters map[int64]io.Writer // maps the sequence number to the changeset writer
	changesetWriter *changesetIoWriter
}

// newReplMon creates a new connection and logical replication data monitor, and
// immediately starts receiving messages from the host. A consumer should
// request a commit ID promise using the recvID method prior to committing a
// transaction.
func newReplMon(ctx context.Context, host, port, user, pass, dbName string, schemaFilter func(string) bool,
	oidToTypes map[uint32]*datatype) (*replMon, error) {
	conn, err := replConn(ctx, host, port, user, pass, dbName)
	if err != nil {
		return nil, err
	}

	// we set the changeset io.Writer to nil, as the changesetIoWriter will skip all writes
	// until enabled by setting the atomic.Bool to true.
	cs := &changesetIoWriter{
		metadata: &changesetMetadata{
			relationIdx: map[[2]string]int{},
		},
		oidToType: oidToTypes,
		// writer is nil, set in caller prior to preparing txns, ignored if left nil
	}

	var slotName = publicationName + random.String(8) // arbitrary, so just avoid collisions
	received := new(atomic.Uint64)
	commitChan, errChan, quit, err := startRepl(ctx, conn, publicationName, slotName, schemaFilter, cs, received)
	if err != nil {
		conn.Close(context.Background())
		return nil, err
	}

	rm := &replMon{
		conn:            conn,
		quit:            quit,
		done:            make(chan struct{}),
		received:        received,
		promises:        make(map[int64]chan []byte),
		changesetWriter: cs,
	}

	go func() {
		defer close(rm.done)
		defer quit()
		defer conn.Close(context.Background())

		for cid := range commitChan { // until commitChan is closed
			// decode seq,chash
			seq, cHash, err := decodeCommitPayload(cid)
			if err != nil {
				rm.err = fmt.Errorf("invalid commit payload encoding: %w", err)
				return // quit() will terminate startRepl
			}
			// if promise exists, send it, otherwise put it in the results map
			rm.mtx.Lock()
			if p, ok := rm.promises[seq]; ok {
				p <- cHash
				delete(rm.promises, seq)
			} else {
				// This is unexpected since pg.DB will call recvID first. If we are
				// in this `else`, it is to be discarded, from another connection.
				logger.Warnf("Received commit ID for seq %d BEFORE recvID", seq)
			}
			rm.mtx.Unlock()
		}

		// commitChan was closed by the replication stream goroutine, so we
		// expect a cause from its errChan. It could just be context.Canceled
		// from a clean shutdown, or it could be something pathological.
		rm.err = <-errChan // send guaranteed before commitChan closed
	}()

	return rm, nil
}

// this channel-based approach is so that the commit ID is guaranteed to pertain
// to the requested sequence number.
func (rm *replMon) recvID(seq int64, changes chan<- any) (chan []byte, bool) {
	// Ensure a commit ID can be promised before we give one.
	select {
	case <-rm.done:
		return nil, false
	default:
	}

	c := make(chan []byte, 1)

	rm.mtx.Lock()
	defer rm.mtx.Unlock()
	if _, have := rm.promises[seq]; have {
		panic(fmt.Sprintf("Commit ID promise for sequence %d ALREADY EXISTS", seq))
	}
	rm.promises[seq] = c

	// TODO: bind the changeset writer to seq. If a precommit gives up before
	// its PREPARE is decoded, and the next transaction calls recvID first, the
	// old transaction's changes go to the new changes channel, and its PREPARE
	// closes that channel.
	rm.changesetWriter.setChangesetWriter(changes) // set the changeset writer to the changes channel

	return c, true
}

// commitIDStall is how long a prepared transaction waits for its commit ID
// while the replication stream delivers nothing. Tests shorten it.
var commitIDStall = 30 * time.Second

// commitIDMaxWait bounds the whole wait. Postgres is silent for about 1.2 s per
// million rows after PREPARE, so the stall already fails a block past about 25
// million changed rows, some 13 minutes of hashing. This only ends a wait
// that the stream's other traffic keeps alive after the commit ID was lost.
const commitIDMaxWait = 30 * time.Minute

// awaitCommitID waits for the commit ID promised on resChan. Postgres sends a
// prepared transaction's changes only once it is prepared, and a large one can
// take minutes to arrive and hash, so the wait lasts while the stream keeps
// delivering data. It gives up once stall passes with nothing received: if the
// stream dies between PREPARE TRANSACTION and done closing, no other case
// fires, and the wait would otherwise freeze consensus. It also gives up after
// maxWait, since data from other transactions counts as delivery too.
func awaitCommitID(ctx context.Context, resChan <-chan []byte, done <-chan struct{},
	received *atomic.Uint64, stall, maxWait time.Duration) ([]byte, error) {
	tick := time.NewTicker(stall / 30)
	defer tick.Stop()
	limit := time.NewTimer(maxWait)
	defer limit.Stop()
	seen, since := received.Load(), time.Now()
	for {
		select {
		case commitID, ok := <-resChan:
			if !ok {
				return nil, errors.New("resChan unexpectedly closed")
			}
			return commitID, nil
		case <-done: // the replMon has died after we executed PREPARE TRANSACTION
			return nil, errors.New("replication stream interrupted")
		case now := <-tick.C:
			if n := received.Load(); n != seen {
				seen, since = n, now
			} else if now.Sub(since) >= stall {
				return nil, errors.New("precommit timed out waiting for commit ID from replication monitor")
			}
		case <-limit.C:
			return nil, fmt.Errorf("precommit gave up waiting for commit ID after %v", maxWait)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (rm *replMon) stop() {
	rm.quit()
	<-rm.done
	// rm.conn.Close(context.Background())
}
