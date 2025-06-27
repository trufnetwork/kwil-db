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

	mtx      sync.Mutex
	promises map[int64]chan []byte
	// the map above was used to support multiple concurrent write txns, but
	// this is never the case where one replMon is only used by one pg.DB since
	// pg.DB disallows multiple outer write transactions. consider just making
	// this a chan field

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
	commitChan, errChan, quit, err := startRepl(ctx, conn, publicationName, slotName, schemaFilter, cs)
	if err != nil {
		conn.Close(context.Background())
		return nil, err
	}

	rm := &replMon{
		conn:            conn,
		quit:            quit,
		done:            make(chan struct{}),
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

	// TODO: fix rollback so changesetWriter.fail() is not in a race with this.
	// This means having the rollback method wait on the fail call (the rollback repl mesg)
	rm.changesetWriter.setChangesetWriter(changes) // set the changeset writer to the changes channel

	return c, true
}

func (rm *replMon) stop() {
	rm.quit()
	<-rm.done
	// rm.conn.Close(context.Background())
}
