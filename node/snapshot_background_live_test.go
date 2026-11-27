//go:build pglive

package node

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
)

type noNamespaces struct{}

func (noNamespaces) ListPostgresSchemasToDump() []string { return nil }

// snapshotText returns the sanitized dump of the snapshot at height, without
// the \restrict lines, whose key pg_dump picks at random.
func snapshotText(t *testing.T, store *snapshotter.SnapshotStore, height uint64) string {
	t.Helper()
	snap := store.GetSnapshot(height, 0)
	require.NotNil(t, snap)
	var compressed bytes.Buffer
	for i := range snap.ChunkCount {
		chunk, err := store.LoadSnapshotChunk(height, 0, i)
		require.NoError(t, err)
		compressed.Write(chunk)
	}
	gzReader, err := gzip.NewReader(&compressed)
	require.NoError(t, err)
	dump, err := io.ReadAll(gzReader)
	require.NoError(t, err)

	var kept []string
	for _, line := range strings.SplitAfter(string(dump), "\n") {
		if !strings.HasPrefix(line, `\restrict `) && !strings.HasPrefix(line, `\unrestrict `) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "")
}

// TestBackgroundSnapshotHoldsLocksAndState checks, with a real pg_dump 16, what
// a background snapshot rests on: by its first byte pg_dump has imported the
// exported snapshot, locked every table it dumps and read the sequences, so
// the export may then end and later writes, DDL and nextval do not reach the
// dump.
func TestBackgroundSnapshotHoldsLocksAndState(t *testing.T) {
	// CI puts pg_dump 16 on PATH (.github/workflows/pr.yaml), so the test must
	// run there; elsewhere it skips without one.
	skip := t.Skipf
	if os.Getenv("CI") != "" {
		skip = t.Fatalf
	}
	version, err := exec.Command("pg_dump", "--version").Output()
	if err != nil {
		skip("pg_dump not found: %v", err)
	}
	if !strings.Contains(string(version), "(PostgreSQL) 16.") {
		skip("pg_dump 16 required, found %s", version)
	}
	t.Logf("%s", bytes.TrimSpace(version))

	ctx := context.Background()
	db := restoreTestDB(t, "kwil_test_snapshot_background")
	conn := dbConn(t, db)
	// t is large enough that pg_dump is still writing it, and so still holds
	// its locks, while nobody reads the dump.
	_, err = conn.Exec(ctx, `CREATE SCHEMA ds_bg;
		CREATE TABLE ds_bg.t (id int8 PRIMARY KEY, v text);
		CREATE TABLE ds_bg.u (id int8 PRIMARY KEY);
		CREATE SEQUENCE ds_bg.s;
		INSERT INTO ds_bg.t SELECT i, md5(i::text) FROM generate_series(1, 500000) i;
		INSERT INTO ds_bg.u VALUES (1);
		SELECT nextval('ds_bg.s') FROM generate_series(1, 5);`)
	require.NoError(t, err)

	// The export, as BeginSnapshotTx makes it.
	export, err := dbConn(t, db).BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	var snapshotID string
	require.NoError(t, export.QueryRow(ctx, `SELECT pg_export_snapshot()`).Scan(&snapshotID))

	store, err := snapshotter.NewSnapshotStore(&snapshotter.SnapshotConfig{
		Enable:          true,
		SnapshotDir:     t.TempDir(),
		MaxSnapshots:    3,
		RecurringHeight: 1,
		DBConfig:        &db,
	}, nil, noNamespaces{}, log.DiscardLogger)
	require.NoError(t, err)
	dumpSchemas := []string{"ds_bg"}

	// Height 1 is dumped the synchronous way, with the export open throughout.
	require.NoError(t, store.CreateSnapshot(ctx, 1, snapshotID, dumpSchemas, nil, nil))

	activity := func() string {
		var state string
		if err := conn.QueryRow(ctx, `SELECT coalesce(state, '') || ' wait=' || coalesce(wait_event_type, '') || ' query=' || left(query, 60)
			FROM pg_stat_activity WHERE application_name = 'pg_dump'`).Scan(&state); err != nil {
			return err.Error() // pg_dump has not connected yet
		}
		return state
	}

	// Height 2 is dumped the background way. While another session holds u,
	// pg_dump cannot lock it, so StartSnapshot must not return.
	blocker, err := dbConn(t, db).Begin(ctx)
	require.NoError(t, err)
	_, err = blocker.Exec(ctx, `LOCK TABLE ds_bg.u IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)

	var finish func() error
	started := make(chan error, 1)
	go func() {
		var err error
		finish, err = store.StartSnapshot(ctx, 2, snapshotID, dumpSchemas, nil, nil)
		started <- err
	}()
	require.Eventually(t, func() bool { return strings.Contains(activity(), "wait=Lock") }, 10*time.Second, 10*time.Millisecond)
	t.Logf("pg_dump while u is held: %s", activity())
	select {
	case <-started:
		t.Fatal("StartSnapshot returned while pg_dump waited for a table lock")
	case <-time.After(500 * time.Millisecond):
	}
	require.NoError(t, blocker.Rollback(ctx))
	require.NoError(t, <-started)

	rows, err := conn.Query(ctx, `SELECT c.relname || ' ' || l.mode || ' granted=' || l.granted
		FROM pg_locks l
		JOIN pg_stat_activity a ON a.pid = l.pid
		JOIN pg_class c ON c.oid = l.relation
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE a.application_name = 'pg_dump' AND n.nspname = 'ds_bg'
		ORDER BY 1`)
	require.NoError(t, err)
	locks, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	t.Logf("pg_dump when StartSnapshot returned: %s", activity())
	t.Logf("pg_dump locks in ds_bg when StartSnapshot returned: %q", locks)
	for _, rel := range []string{"s", "t", "u"} {
		require.Contains(t, locks, rel+" AccessShareLock granted=true")
	}

	require.NoError(t, export.Rollback(ctx))

	for _, stmt := range []string{
		`INSERT INTO ds_bg.t SELECT i, 'late' FROM generate_series(500001, 501000) i`,
		`SELECT nextval('ds_bg.s') FROM generate_series(1, 100)`,
		`CREATE TABLE ds_bg.newt (id int8)`,
	} {
		stmtCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := conn.Exec(stmtCtx, stmt)
		cancel()
		require.NoError(t, err, stmt)
	}

	require.NoError(t, finish())

	synchronous, background := snapshotText(t, store, 1), snapshotText(t, store, 2)
	require.Contains(t, background, "SELECT pg_catalog.setval('ds_bg.s', 5, true);")
	require.NotContains(t, background, "late")
	require.NotContains(t, background, "newt")
	require.Equal(t, synchronous, background)
	t.Logf("background dump: %d bytes, equal to the synchronous dump", len(background))
}
