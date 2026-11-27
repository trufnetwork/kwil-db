package blockprocessor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// snapEvents records the order of snapshot tx and dump calls.
type snapEvents struct {
	mtx    sync.Mutex
	events []string
}

func (e *snapEvents) add(event string) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	e.events = append(e.events, event)
}

func (e *snapEvents) list() []string {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	return append([]string(nil), e.events...)
}

type snapDB struct {
	mockDB
	ev *snapEvents
}

func (d *snapDB) BeginSnapshotTx(ctx context.Context) (sql.Tx, string, error) {
	d.ev.add("export")
	return &snapTx{ev: d.ev}, "snapshot-id", nil
}

type snapTx struct {
	mockTx
	ev *snapEvents
}

func (tx *snapTx) Rollback(ctx context.Context) error {
	tx.ev.add("rollback")
	return nil
}

// fakeSnapshots starts dumps whose finish waits for release or for the dump
// ctx, and then sends its result on finished.
type fakeSnapshots struct {
	SnapshotModule
	ev        *snapEvents
	startErr  error
	finishErr error
	release   chan struct{}
	finished  chan error
}

func (f *fakeSnapshots) Enabled() bool { return true }

func (f *fakeSnapshots) IsSnapshotDue(height uint64) bool { return true }

func (f *fakeSnapshots) StartSnapshot(ctx context.Context, height uint64, snapshotID string, schemas, excludedTables []string, excludeTableData []string) (func() error, error) {
	f.ev.add(fmt.Sprintf("start %d", height))
	if f.startErr != nil {
		return nil, f.startErr
	}
	return func() error {
		err := f.finishErr
		select {
		case <-f.release:
		case <-ctx.Done():
			err = ctx.Err()
		}
		f.finished <- err
		return err
	}, nil
}

func newSnapshotTestProcessor() (*BlockProcessor, *fakeSnapshots) {
	ev := &snapEvents{}
	snaps := &fakeSnapshots{ev: ev, release: make(chan struct{}), finished: make(chan error, 1)}
	return &BlockProcessor{db: &snapDB{ev: ev}, snapshotter: snaps, log: log.DiscardLogger}, snaps
}

// snapshot calls snapshotDB the way Commit does, with mtx held, and returns
// the done channel of the dump that is running after it.
func snapshot(t *testing.T, bp *BlockProcessor, height int64) (<-chan struct{}, error) {
	t.Helper()
	bp.mtx.Lock()
	defer bp.mtx.Unlock()
	err := bp.snapshotDB(context.Background(), height)
	return bp.snapDone, err
}

func TestSnapshotDBReturnsWhileDumpRuns(t *testing.T) {
	bp, snaps := newSnapshotTestProcessor()

	done, err := snapshot(t, bp, 10)
	require.NoError(t, err)
	require.Equal(t, []string{"export", "start 10", "rollback"}, snaps.ev.list())
	select {
	case <-done:
		t.Fatal("the dump ended before it was released")
	default:
	}

	close(snaps.release)
	require.NoError(t, <-snaps.finished)
	<-done
}

func TestOneSnapshotDumpAtATime(t *testing.T) {
	bp, snaps := newSnapshotTestProcessor()

	done, err := snapshot(t, bp, 10)
	require.NoError(t, err)
	for _, height := range []int64{11, 12} {
		_, err := snapshot(t, bp, height)
		require.NoError(t, err)
	}
	require.Equal(t, []string{"export", "start 10", "rollback"}, snaps.ev.list())

	close(snaps.release)
	require.NoError(t, <-snaps.finished)
	<-done

	_, err = snapshot(t, bp, 13)
	require.NoError(t, err)
	require.NoError(t, <-snaps.finished)
	require.Equal(t, []string{"export", "start 10", "rollback", "export", "start 13", "rollback"}, snaps.ev.list())
}

func TestSnapshotRetriedAfterFailedDump(t *testing.T) {
	bp, snaps := newSnapshotTestProcessor()
	close(snaps.release)

	// A failed dump frees the slot for the next due height.
	snaps.finishErr = errors.New("disk full")
	done, err := snapshot(t, bp, 10)
	require.NoError(t, err)
	require.ErrorContains(t, <-snaps.finished, "disk full")
	<-done
	snaps.finishErr = nil

	// A dump that fails to start returns the error and rolls back the export.
	snaps.startErr = errors.New("pg_dump wrote no output")
	_, err = snapshot(t, bp, 11)
	require.ErrorIs(t, err, snaps.startErr)
	snaps.startErr = nil

	_, err = snapshot(t, bp, 12)
	require.NoError(t, err)
	require.NoError(t, <-snaps.finished)
	require.Equal(t, []string{
		"export", "start 10", "rollback",
		"export", "start 11", "rollback",
		"export", "start 12", "rollback",
	}, snaps.ev.list())
}

func TestCloseStopsBackgroundSnapshot(t *testing.T) {
	bp, snaps := newSnapshotTestProcessor() // the dump is never released

	_, err := snapshot(t, bp, 10)
	require.NoError(t, err)

	closed := make(chan error, 1)
	go func() { closed <- bp.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return while a dump was running")
	}

	select {
	case err := <-snaps.finished:
		require.ErrorIs(t, err, context.Canceled)
	default:
		t.Fatal("Close returned before the dump ended")
	}
	require.Equal(t, []string{"export", "start 10", "rollback"}, snaps.ev.list())
}

// commitDB, commitTx and commitMigrator let Commit write the chain state.
type commitDB struct {
	snapDB
}

func (d *commitDB) BeginTx(ctx context.Context) (sql.Tx, error) {
	return &commitTx{}, nil
}

type commitTx struct {
	mockTx
}

func (tx *commitTx) BeginTx(ctx context.Context) (sql.Tx, error) {
	return &commitTx{}, nil
}

func (tx *commitTx) Execute(ctx context.Context, stmt string, args ...any) (*sql.ResultSet, error) {
	return &sql.ResultSet{Status: sql.CommandTag{RowsAffected: 1}}, nil
}

type commitMigrator struct {
	MigratorModule
}

func (commitMigrator) PersistLastChangesetHeight(ctx context.Context, tx sql.Executor, height int64) error {
	return nil
}

// TestCommitReturnsWhileSnapshotDumpRuns checks that Commit, and with it the
// block processor's lock, does not wait for the dump it started.
func TestCommitReturnsWhileSnapshotDumpRuns(t *testing.T) {
	bp, snaps := newSnapshotTestProcessor()
	bp.db = &commitDB{snapDB{ev: snaps.ev}}
	bp.txapp = &mockTxApp{}
	bp.migrator = commitMigrator{}
	bp.chainCtx = &common.ChainContext{NetworkParameters: &types.NetworkParameters{}}

	committed := make(chan error, 1)
	go func() {
		committed <- bp.Commit(context.Background(), &types.CommitRequest{Height: 10})
	}()
	select {
	case err := <-committed:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Commit did not return while the dump was running")
	}
	require.Equal(t, []string{"export", "start 10", "rollback"}, snaps.ev.list())
	select {
	case <-snaps.finished:
		t.Fatal("the dump ended before it was released")
	default:
	}

	close(snaps.release)
	require.NoError(t, <-snaps.finished)
}
