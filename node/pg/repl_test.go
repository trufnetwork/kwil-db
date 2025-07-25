//go:build pglive

package pg

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5"

	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/utils/random"
	"github.com/trufnetwork/kwil-db/node/utils/muhash"
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

	_, err = connQ.Exec(ctx, sqlUpdateSentrySeq, 0)
	if err != nil {
		t.Fatal(err)
	}

	schemaFilter := func(string) bool { return true } // capture changes from all namespaces

	const publicationName = "kwild_repl"
	var slotName = publicationName + random.String(8)
	commitChan, errChan, quit, err := startRepl(ctx, conn, publicationName, slotName, schemaFilter, &changesetIoWriter{})
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

	wantCommitHash, _ := hex.DecodeString("d42916cd1980b7370b9adca989af0a4c5ad7e31544fd795cbfa8c2e11556d85a")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer quit()

		if cid, ok := <-commitChan; ok {
			_, commitHash, err := decodeCommitPayload(cid)
			if err != nil {
				t.Errorf("invalid commit payload encoding: %v", err)
				return
			}
			// t.Logf("Commit HASH: %x\n", commitHash)
			if !bytes.Equal(commitHash, wantCommitHash) {
				t.Errorf("commit hash mismatch, got %x, wanted %x", commitHash, wantCommitHash)
			}

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
	// Bump seq in the sentry table!
	_, err = tx.Exec(ctx, sqlUpdateSentrySeq, 1)
	if err != nil {
		t.Fatal(err)
	}

	err = tx.Commit(ctx) // this triggers the send
	if err != nil {
		t.Fatal(err)
	}

	wg.Wait() // to receive the commit id or an error
	connQ.Close(ctx)
}

// TestResetTransactionState tests that resetTransactionState properly cleans up all state
func TestResetTransactionState(t *testing.T) {
	// Setup hasher with some data
	hasher := muhash.New()
	hasher.Add([]byte("test data"))

	// Setup stats with some counts
	stats := &walStats{
		inserts: 5,
		updates: 3,
		deletes: 2,
		truncs:  1,
	}

	// Setup changeset writer with mock channel
	changesetChan := make(chan any, 10)
	changesetWriter := &changesetIoWriter{
		csChan: changesetChan,
		metadata: &changesetMetadata{
			relationIdx: map[[2]string]int{
				{"test", "table"}: 0,
			},
			Relations: []*Relation{{Schema: "test", Table: "table"}},
		},
	}

	// Setup sequence with non-default value
	seq := int64(42)

	// Verify initial state is dirty
	if hasher.DigestHash() == [32]byte{} {
		t.Error("hasher should have data before reset")
	}
	if stats.inserts == 0 && stats.updates == 0 && stats.deletes == 0 && stats.truncs == 0 {
		t.Error("stats should have counts before reset")
	}
	if seq == -1 {
		t.Error("seq should not be -1 before reset")
	}

	// Call resetTransactionState
	resetTransactionState(hasher, stats, changesetWriter, &seq)

	// Verify hasher is reset
	emptyHash := muhash.New().DigestHash()
	if hasher.DigestHash() != emptyHash {
		t.Error("hasher should be reset to empty state")
	}

	// Verify stats are reset
	if stats.inserts != 0 || stats.updates != 0 || stats.deletes != 0 || stats.truncs != 0 {
		t.Error("stats should be reset to zero")
	}

	// Verify sequence is reset
	if seq != -1 {
		t.Errorf("seq should be reset to -1, got %d", seq)
	}

	// Verify changeset writer finalize was called (channel should be closed)
	select {
	case _, ok := <-changesetChan:
		if ok {
			t.Error("changeset channel should be closed after finalize")
		}
	default:
		t.Error("changeset channel should be closed after finalize")
	}
}

// TestStreamAbortMessageV2StateReset tests that StreamAbortMessageV2 triggers proper state reset
func TestStreamAbortMessageV2StateReset(t *testing.T) {
	// Setup dirty state
	hasher := muhash.New()
	hasher.Add([]byte("dirty data"))

	stats := &walStats{inserts: 1, updates: 2}
	seq := int64(100)

	changesetChan := make(chan any, 1)
	changesetWriter := &changesetIoWriter{
		csChan: changesetChan,
		metadata: &changesetMetadata{
			relationIdx: make(map[[2]string]int),
		},
	}

	// Test the reset function directly (simulating StreamAbortMessageV2 handling)
	resetTransactionState(hasher, stats, changesetWriter, &seq)

	// Verify state was reset
	emptyHash := muhash.New().DigestHash()
	if hasher.DigestHash() != emptyHash {
		t.Error("hasher should be reset after StreamAbortMessageV2")
	}
	if stats.inserts != 0 || stats.updates != 0 {
		t.Error("stats should be reset after StreamAbortMessageV2")
	}
	if seq != -1 {
		t.Error("seq should be reset to -1 after StreamAbortMessageV2")
	}
}

// TestRollbackPreparedMessageV3StateReset tests that RollbackPreparedMessageV3 triggers proper state reset
func TestRollbackPreparedMessageV3StateReset(t *testing.T) {
	// Setup dirty state
	hasher := muhash.New()
	hasher.Add([]byte("prepared transaction data"))

	stats := &walStats{
		inserts: 10,
		updates: 5,
		deletes: 3,
		truncs:  1,
	}

	seq := int64(200)

	changesetChan := make(chan any, 1)
	changesetWriter := &changesetIoWriter{
		csChan: changesetChan,
		metadata: &changesetMetadata{
			relationIdx: make(map[[2]string]int),
		},
	}

	// Test the reset function directly (simulating RollbackPreparedMessageV3 handling)
	resetTransactionState(hasher, stats, changesetWriter, &seq)

	// Verify state was reset
	emptyHash := muhash.New().DigestHash()
	if hasher.DigestHash() != emptyHash {
		t.Error("hasher should be reset after RollbackPreparedMessageV3")
	}
	if stats.inserts != 0 || stats.updates != 0 || stats.deletes != 0 || stats.truncs != 0 {
		t.Error("stats should be reset after RollbackPreparedMessageV3")
	}
	if seq != -1 {
		t.Error("seq should be reset to -1 after RollbackPreparedMessageV3")
	}
}

// TestAppHashConsistencyAfterAbort tests that AppHash remains consistent after transaction abort
func TestAppHashConsistencyAfterAbort(t *testing.T) {
	// Create two identical hashers
	hasher1 := muhash.New()
	hasher2 := muhash.New()

	// Both hashers process same initial data
	testData := []byte("some transaction data")
	hasher1.Add(testData)
	hasher2.Add(testData)

	// Verify they have same hash
	hash1 := hasher1.DigestHash()
	hash2 := hasher2.DigestHash()
	if hash1 != hash2 {
		t.Error("initial hashes should be identical")
	}

	// Simulate abort scenario: hasher1 gets aborted and reset, hasher2 continues
	stats1 := &walStats{}
	seq1 := int64(50)
	changesetWriter1 := &changesetIoWriter{
		metadata: &changesetMetadata{relationIdx: make(map[[2]string]int)},
	}

	// hasher1 experiences abort and gets reset
	resetTransactionState(hasher1, stats1, changesetWriter1, &seq1)

	// hasher2 continues without abort (simulating validator with sufficient disk space)
	// Both now process the same next transaction
	nextData := []byte("next successful transaction")
	hasher1.Add(nextData)
	hasher2.Reset() // hasher2 also resets because it commits successfully
	hasher2.Add(nextData)

	// Final hashes should be identical
	finalHash1 := hasher1.DigestHash()
	finalHash2 := hasher2.DigestHash()
	if finalHash1 != finalHash2 {
		t.Errorf("final hashes should be identical after proper reset, got %x vs %x",
			finalHash1, finalHash2)
	}
}
