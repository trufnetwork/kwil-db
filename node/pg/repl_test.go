//go:build pglive

package pg

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/utils/random"
)

// This not-a-unit-test isolates the unexported internal logical replication
// monitor and ensures it always returns the same expected result for a basic
// set of modifications. The functions used here are otherwise only used by the
// pg.DB type, which tests it in a more realistic way.
func Test_repl(t *testing.T) {
	UseLogger(log.New(log.WithWriter(os.Stdout), log.WithLevel(log.LevelDebug)))
	host, port, user, pass, dbName := "127.0.0.1", "5432", "kwild", "kwild", "kwil_test_db"

	ctx := context.Background()
	conn, err := replConn(ctx, host, port, user, pass, dbName)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	sysident, err := pglogrepl.IdentifySystem(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("SystemID:", sysident.SystemID, "Timeline:", sysident.Timeline,
		"XLogPos:", sysident.XLogPos, "DBName:", sysident.DBName)

	deadline, exists := t.Deadline()
	if !exists {
		deadline = time.Now().Add(2 * time.Minute)
	}

	ctx, cancel := context.WithDeadline(ctx, deadline.Add(-time.Second*5))
	defer cancel()
	connQ, err := pgx.Connect(ctx, connString(host, port, user, pass, dbName, false))
	if err != nil {
		t.Fatal(err)
	}
	if err = ensureFullReplicaIdentityTrigger(ctx, connQ); err != nil {
		t.Fatalf("failed to create full replication identity trigger: %v", err)
	}
	if err = ensureSentryTable(ctx, connQ); err != nil {
		t.Fatalf("failed to create transaction sequencing table: %v", err)
	}
	if _, err = connQ.Exec(ctx, "ALTER TABLE "+sentryTableNameFull+" REPLICA IDENTITY FULL"); err != nil {
		t.Fatalf("failed to alter table: %v", err)
	}
	if err = ensurePublication(ctx, connQ); err != nil {
		t.Fatalf("failed to create publication: %v", err)
	}

	// Reset sentry table and sequence to a known state.
	_, err = connQ.Exec(ctx, `DELETE FROM `+sentryTableNameFull)
	if err != nil {
		t.Fatal(err)
	}
	_, err = connQ.Exec(ctx, `ALTER SEQUENCE `+sentrySeqName+` RESTART WITH 1`)
	if err != nil {
		t.Fatal(err)
	}

	schemaFilter := func(string) bool { return true } // capture changes from all namespaces

	const publicationName = "kwild_repl"
	var slotName = publicationName + random.String(8)
	commitChan, errChan, quit, err := startRepl(ctx, conn, publicationName, slotName, schemaFilter, &changesetIoWriter{}, new(atomic.Uint64))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("replication slot started and listening")

	_, err = connQ.Exec(ctx, `DROP TABLE IF EXISTS blah`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = connQ.Exec(ctx, `CREATE TABLE IF NOT EXISTS blah (id BYTEA PRIMARY KEY, stuff TEXT NOT NULL, val INT8)`)
	if err != nil {
		t.Fatal(err)
	}

	var gotSeq int64
	var gotHash []byte

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer quit()

		if cid, ok := <-commitChan; ok {
			seq, commitHash, err := decodeCommitPayload(cid)
			if err != nil {
				t.Errorf("invalid commit payload encoding: %v", err)
				return
			}
			gotSeq = seq
			gotHash = commitHash
			return // receive only once in this test
		}

		// commitChan was closed before receive (not expected in this test)
		t.Error(<-errChan)
	}()

	tx, err := connQ.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tx.Exec(ctx, `insert INTO blah values ( '{11}', 'woot' , 42);`)
	tx.Exec(ctx, `update blah SET stuff = 6, id = '{13}', val=41 where id = '{10}';`)
	tx.Exec(ctx, `update blah SET stuff = 33;`)
	tx.Exec(ctx, `delete FROM blah where id = '{11}';`)
	// sends on commitChan are only expected from sequenced transactions.
	// Use the real sequence generator to obtain the next seq.
	wantSeq, err := incrementSeq(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}

	err = tx.Commit(ctx) // this triggers the send
	if err != nil {
		t.Fatal(err)
	}

	wg.Wait() // to receive the commit id or an error

	if gotSeq != wantSeq {
		t.Errorf("WAL seq mismatch: got %d, want %d", gotSeq, wantSeq)
	}
	if len(gotHash) == 0 {
		t.Error("commit hash is empty")
	}

	connQ.Close(ctx)
}

// Test_replHashesALargeTransactionWhole checks that a transaction too large for
// Postgres to decode in memory gets one commit hash, whatever happens while it
// runs. With streaming on, Postgres sent such a transaction in pieces before it
// ended. captureRepl then hashed away everything before a rolled-back
// savepoint, started over when another transaction committed in between, and
// after an aborted one stopped with "sequence already set".
func Test_replHashesALargeTransactionWhole(t *testing.T) {
	host, port, user, pass, dbName := "127.0.0.1", "5432", "kwild", "kwild", "kwil_test_db"

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	connQ, err := pgx.Connect(ctx, connString(host, port, user, pass, dbName, false))
	if err != nil {
		t.Fatal(err)
	}
	defer connQ.Close(context.Background())
	// A second writer, as the event store is on a node.
	other, err := pgx.Connect(ctx, connString(host, port, user, pass, dbName, false))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(context.Background())

	if err = ensureFullReplicaIdentityTrigger(ctx, connQ); err != nil {
		t.Fatal(err)
	}
	if err = ensureSentryTable(ctx, connQ); err != nil {
		t.Fatal(err)
	}
	if err = ensurePublication(ctx, connQ); err != nil {
		t.Fatal(err)
	}

	exec := func(q interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	}, stmt string) {
		t.Helper()
		if _, err := q.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	exec(connQ, `DROP TABLE IF EXISTS big_txn, other_writes`)
	exec(connQ, `CREATE TABLE big_txn (id INT8 PRIMARY KEY, stuff TEXT NOT NULL)`)
	exec(connQ, `CREATE TABLE other_writes (id INT8 PRIMARY KEY)`)

	// Postgres may hold 64 kB of a transaction in memory while decoding it,
	// and each transaction below writes about 500 kB.
	conn, err := pgconn.Connect(ctx, connString(host, port, user, pass, dbName, true)+
		" options='-c logical_decoding_work_mem=64kB'")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	// The sentry table's sequence differs in every transaction. Leave it out
	// of the hash so the transactions' own changes can be compared.
	schemaFilter := func(schema string) bool { return schema != InternalSchemaName }
	slotName := "kwild_repl" + random.String(8)
	received := new(atomic.Uint64)
	commitChan, errChan, quit, err := startRepl(ctx, conn, "kwild_repl", slotName, schemaFilter, &changesetIoWriter{}, received)
	if err != nil {
		t.Fatal(err)
	}
	defer quit()

	// run writes 5,000 rows, calls during, writes 10 more, and prepares. It
	// returns the commit hash replication sends for the transaction.
	run := func(during func(tx pgx.Tx)) []byte {
		t.Helper()
		tx, err := connQ.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wantSeq, err := incrementSeq(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		exec(tx, `INSERT INTO big_txn SELECT g, repeat('a', 80) FROM generate_series(1, 5000) g`)
		during(tx)
		exec(tx, `INSERT INTO big_txn SELECT g, repeat('c', 80) FROM generate_series(20001, 20010) g`)
		gid := random.String(10)
		exec(tx, `PREPARE TRANSACTION '`+gid+`'`)
		_ = tx.Commit(ctx) // only clears pgx's state; PREPARE ended the transaction
		defer exec(connQ, `ROLLBACK PREPARED '`+gid+`'`)

		select {
		case cid, ok := <-commitChan:
			if !ok {
				t.Fatalf("replication stopped: %v", <-errChan)
			}
			seq, hash, err := decodeCommitPayload(cid)
			if err != nil {
				t.Fatal(err)
			}
			if seq != wantSeq {
				t.Fatalf("commit ID for seq %d, want %d", seq, wantSeq)
			}
			return hash
		case <-ctx.Done():
			t.Fatal("no commit ID")
		}
		return nil
	}

	want := run(func(pgx.Tx) {})

	got := run(func(tx pgx.Tx) { // a failed kwil tx rolls back to its savepoint
		exec(tx, `SAVEPOINT failed_tx`)
		exec(tx, `INSERT INTO big_txn SELECT g, repeat('b', 80) FROM generate_series(5001, 10000) g`)
		exec(tx, `ROLLBACK TO SAVEPOINT failed_tx`)
	})
	if !bytes.Equal(got, want) {
		t.Errorf("a rolled-back savepoint changed the commit hash: %x, want %x", got, want)
	}

	got = run(func(pgx.Tx) {
		exec(other, `INSERT INTO other_writes VALUES (1)`)
		exec(other, `DELETE FROM other_writes`)
	})
	if !bytes.Equal(got, want) {
		t.Errorf("another writer's commits changed the commit hash: %x, want %x", got, want)
	}

	tx, err := connQ.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = incrementSeq(ctx, tx); err != nil {
		t.Fatal(err)
	}
	exec(tx, `INSERT INTO big_txn SELECT g, repeat('d', 80) FROM generate_series(1, 5000) g`)
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	got = run(func(pgx.Tx) {})
	if !bytes.Equal(got, want) {
		t.Errorf("an aborted transaction changed the next commit hash: %x, want %x", got, want)
	}

	// Postgres should have run out of decoding memory on these. If it did
	// not, nothing above would have been streamed with streaming on either.
	var spilled int64
	for range 50 {
		err = connQ.QueryRow(ctx, `SELECT spill_txns FROM pg_stat_replication_slots WHERE slot_name = lower($1)`,
			slotName).Scan(&spilled)
		if err == nil && spilled > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if spilled == 0 {
		t.Errorf("no transaction outgrew logical_decoding_work_mem (err %v)", err)
	}

	// Precommit waits while this count moves. Each prepared transaction above
	// sent over 5,000 rows.
	if n := received.Load(); n < 4*5000 {
		t.Errorf("counted %d WAL data messages, want at least %d", n, 4*5000)
	}
}
