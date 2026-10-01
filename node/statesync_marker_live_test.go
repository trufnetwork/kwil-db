//go:build pglive

package node

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
)

const restoreHeight = 100

// goodDump and badDump are what a snapshot restore feeds psql. badDump fails
// part way, after it has created two of kwild's schemas.
const goodDump = "CREATE SCHEMA kwild_voting;\n" +
	"CREATE SCHEMA main;\n" +
	"CREATE TABLE main.records (v int8);\n" +
	"COPY main.records (v) FROM stdin;\n" +
	"1\n" +
	"\\.\n"

const badDump = "CREATE SCHEMA kwild_voting;\n" +
	"CREATE SCHEMA main;\n" +
	"CREATE TABLE main.records (v int8);\n" +
	"COPY main.records (v) FROM stdin;\n" +
	"not a number\n" +
	"\\.\n"

// restoreService returns a state sync service restoring into a scratch
// database that already holds an operator's schema with one row.
func restoreService(t *testing.T, dbName, dump string) (*StateSyncService, *snapshotMetadata, *restoreBlockStore) {
	t.Helper()
	db := restoreTestDB(t, dbName)
	conn := dbConn(t, db)
	_, err := conn.Exec(context.Background(), `CREATE SCHEMA operator_data;
		CREATE TABLE operator_data.notes (v text);
		INSERT INTO operator_data.notes VALUES ('keep me');`)
	require.NoError(t, err)

	dir := t.TempDir()
	var chunk bytes.Buffer
	gz := gzip.NewWriter(&chunk)
	_, err = gz.Write([]byte(dump))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	require.NoError(t, os.WriteFile(filepath.Join(dir, "chunk-0.sql.gz"), chunk.Bytes(), 0o644))

	sum := sha256.Sum256([]byte(dump))
	bs := &restoreBlockStore{}
	ss := &StateSyncService{
		dbConfig:      db,
		snapshotDir:   dir,
		restoreMarker: config.StatesyncRestoreMarkerPath(t.TempDir()),
		blockStore:    bs,
		log:           log.DiscardLogger,
	}
	snap := &snapshotMetadata{Height: restoreHeight, Chunks: 1, Hash: sum[:], Size: uint64(len(dump))}
	return ss, snap, bs
}

func dbConn(t *testing.T, db config.DBConfig) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%s user=%s password=%s database=%s sslmode=disable",
		db.Host, db.Port, db.User, db.Pass, db.DBName))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close(ctx) })
	return conn
}

func schemas(t *testing.T, ss *StateSyncService) []string {
	t.Helper()
	conn := dbConn(t, ss.dbConfig)
	rows, _ := conn.Query(context.Background(), sqlUserSchemas)
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return names
}

const sqlUserSchemas = `SELECT nspname FROM pg_namespace
	WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema' ORDER BY 1`

func operatorRowKept(t *testing.T, ss *StateSyncService) {
	t.Helper()
	var v string
	require.NoError(t, dbConn(t, ss.dbConfig).QueryRow(context.Background(),
		`SELECT v FROM operator_data.notes`).Scan(&v))
	require.Equal(t, "keep me", v)
}

func TestFailedRestoreIsUndoneAtNextStart(t *testing.T) {
	ss, snap, _ := restoreService(t, "kwil_test_restore_undo_failed", badDump)
	before := schemas(t, ss)

	require.Error(t, ss.restoreDB(context.Background(), snap))
	require.Contains(t, schemas(t, ss), "kwild_voting", "the failed restore should have left schemas behind")
	interrupted, err := RestoreInterrupted(ss.restoreMarker)
	require.NoError(t, err)
	require.True(t, interrupted)

	// The next start.
	require.NoError(t, ss.ClearInterruptedRestore(context.Background()))

	require.Equal(t, before, schemas(t, ss))
	operatorRowKept(t, ss)
	interrupted, err = RestoreInterrupted(ss.restoreMarker)
	require.NoError(t, err)
	require.False(t, interrupted)

	// And the start after that has nothing to undo.
	require.NoError(t, ss.ClearInterruptedRestore(context.Background()))
	require.Equal(t, before, schemas(t, ss))
}

func TestRestoreStoppedBeforeItsBlockIsStoredIsUndone(t *testing.T) {
	ss, snap, _ := restoreService(t, "kwil_test_restore_undo_stopped", goodDump)
	before := schemas(t, ss)

	// The restore finished, but the node stopped before storing block 100.
	require.NoError(t, ss.restoreDB(context.Background(), snap))

	require.NoError(t, ss.ClearInterruptedRestore(context.Background()))

	require.Equal(t, before, schemas(t, ss))
	operatorRowKept(t, ss)
	interrupted, err := RestoreInterrupted(ss.restoreMarker)
	require.NoError(t, err)
	require.False(t, interrupted)
}

func TestFinishedRestoreIsKept(t *testing.T) {
	ss, snap, bs := restoreService(t, "kwil_test_restore_finished", goodDump)

	require.NoError(t, ss.restoreDB(context.Background(), snap))
	after := schemas(t, ss)
	// Block 100 was stored, and the node stopped before removing the marker.
	bs.height = restoreHeight

	require.NoError(t, ss.ClearInterruptedRestore(context.Background()))

	require.Equal(t, after, schemas(t, ss))
	interrupted, err := RestoreInterrupted(ss.restoreMarker)
	require.NoError(t, err)
	require.False(t, interrupted)
}

func TestInterruptedRestoreWithAnotherBlockStoreHeightIsRefused(t *testing.T) {
	ss, snap, bs := restoreService(t, "kwil_test_restore_mismatch", goodDump)

	require.NoError(t, ss.restoreDB(context.Background(), snap))
	after := schemas(t, ss)
	bs.height = restoreHeight + 7

	err := ss.ClearInterruptedRestore(context.Background())
	require.ErrorContains(t, err, "reset the node")

	require.Equal(t, after, schemas(t, ss), "nothing may be dropped")
	interrupted, err := RestoreInterrupted(ss.restoreMarker)
	require.NoError(t, err)
	require.True(t, interrupted)
}
