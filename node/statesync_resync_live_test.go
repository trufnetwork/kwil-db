//go:build pglive

package node

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/pg"
)

const (
	resyncFrom   = 100  // the node's height
	resyncSnap   = 1000 // the height of the trusted provider's snapshot
	resyncBehind = 500  // resync_when_behind
)

// nodeSchemas seeds what a node's database holds: kwild's schemas, the ones
// node extensions and pg_repack create, and one an operator created.
const nodeSchemas = `
	CREATE SCHEMA kwild_chain;
	CREATE TABLE kwild_chain.chain (height INT8, app_hash BYTEA, dirty BOOLEAN DEFAULT FALSE);
	CREATE SCHEMA kwild_voting;
	CREATE TABLE kwild_voting.voters (name BYTEA, power INT8);
	CREATE SCHEMA kwild_engine;
	CREATE TABLE kwild_engine.namespaces (name TEXT);
	INSERT INTO kwild_engine.namespaces VALUES ('main'), ('info');
	CREATE SCHEMA info;
	CREATE SCHEMA main;
	CREATE TABLE main.records (id INT8 PRIMARY KEY, v TEXT);
	INSERT INTO main.records VALUES (1, 'old');
	CREATE SCHEMA kwild_internal;
	CREATE SCHEMA kwild_accts;
	CREATE SCHEMA kwild_migrations;
	CREATE SCHEMA kwild_events;
	CREATE SCHEMA ds_test;
	CREATE SCHEMA ext_tn_local;
	CREATE TABLE ext_tn_local.streams (id INT8);
	INSERT INTO ext_tn_local.streams VALUES (1), (2), (3);
	CREATE SCHEMA repack;
	CREATE SCHEMA operator_data;
	CREATE TABLE operator_data.notes (v TEXT);
	INSERT INTO operator_data.notes VALUES ('keep me');`

// keptSchemas are the schemas a resync leaves alone.
var keptSchemas = []string{"ext_tn_local", "operator_data", "public", "repack"}

// lockedBuffer collects log output written from more than one goroutine.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type resyncNode struct {
	ss     *StateSyncService
	bs     *restoreBlockStore
	db     config.DBConfig
	height int64 // the height the node starts at
	self   crypto.PublicKey
	logs   *lockedBuffer
}

// newResyncNode returns a node at height resyncFrom whose trusted provider
// offers a snapshot at resyncSnap.
func newResyncNode(t *testing.T, dbName string) *resyncNode {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	net := newFindTestNet(ctx, t)
	net.trusted.addSnapshot(findTestSnapshot(resyncSnap))

	db := restoreTestDB(t, dbName)
	conn := dbConn(t, db)
	_, err := conn.Exec(ctx, nodeSchemas)
	require.NoError(t, err)
	setChainState(t, db, resyncFrom, blockAppHash(resyncFrom), false)

	pool, err := pg.NewPool(ctx, &pg.PoolConfig{ConnConfig: *pgConnConfig(db), MaxConns: 3})
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	n := &resyncNode{
		ss:     net.me,
		bs:     &restoreBlockStore{height: resyncFrom},
		db:     db,
		height: resyncFrom,
		self:   newPublicKey(t),
		logs:   &lockedBuffer{},
	}
	n.ss.db = pool
	n.ss.dbConfig = db
	n.ss.blockStore = n.bs
	n.ss.restoreMarker = config.StatesyncRestoreMarkerPath(t.TempDir())
	n.ss.cfg.ResyncWhenBehind = resyncBehind
	n.ss.log = log.New(log.WithWriter(n.logs))
	return n
}

func setChainState(t *testing.T, db config.DBConfig, height int64, appHash ktypes.Hash, dirty bool) {
	t.Helper()
	conn := dbConn(t, db)
	_, err := conn.Exec(context.Background(), `DELETE FROM kwild_chain.chain`)
	require.NoError(t, err)
	_, err = conn.Exec(context.Background(), `INSERT INTO kwild_chain.chain VALUES ($1, $2, $3)`, height, appHash[:], dirty)
	require.NoError(t, err)
}

func (n *resyncNode) resync(t *testing.T) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cleared, err := n.ss.ResyncIfFarBehind(ctx, n.self, nil)
	require.NoError(t, err)
	return cleared
}

// untouched checks that the node still has everything it started with.
func (n *resyncNode) untouched(t *testing.T, before []string) {
	t.Helper()
	require.Equal(t, before, schemas(t, n.ss))
	require.Empty(t, n.bs.calls)
	require.Equal(t, n.height, n.bs.height)
	interrupted, err := RestoreInterrupted(n.ss.restoreMarker)
	require.NoError(t, err)
	require.False(t, interrupted)
}

func (n *resyncNode) operatorDataKept(t *testing.T) {
	t.Helper()
	operatorRowKept(t, n.ss)
	var streams int
	require.NoError(t, dbConn(t, n.db).QueryRow(context.Background(),
		`SELECT count(*) FROM ext_tn_local.streams`).Scan(&streams))
	require.Equal(t, 3, streams)
}

// resyncDump is the snapshot at resyncSnap: the state a new node restores.
func resyncDump(appHash ktypes.Hash) string {
	return fmt.Sprintf(`CREATE SCHEMA kwild_chain;
CREATE TABLE kwild_chain.chain (height INT8, app_hash BYTEA, dirty BOOLEAN DEFAULT FALSE);
COPY kwild_chain.chain (height, app_hash, dirty) FROM stdin;
%d	\\x%x	f
\.
CREATE SCHEMA kwild_voting;
CREATE TABLE kwild_voting.voters (name BYTEA, power INT8);
CREATE SCHEMA main;
CREATE TABLE main.records (id INT8 PRIMARY KEY, v TEXT);
COPY main.records (id, v) FROM stdin;
1	new
2	new
\.
`, resyncSnap, appHash[:])
}

// restoreSnapshot runs the rest of a new node's state sync on the cleared
// node: restore the snapshot, check its app hash, store its block.
func (n *resyncNode) restoreSnapshot(t *testing.T, dump string, appHash ktypes.Hash) {
	t.Helper()
	require.NoError(t, n.restoreDump(t, dump, appHash))
	snap := &snapshotMetadata{Height: resyncSnap, AppHash: appHash[:]}
	require.NoError(t, n.ss.verifyState(context.Background(), snap))
	require.NoError(t, n.ss.storeRestoredBlock(&ktypes.Block{Header: &ktypes.BlockHeader{Height: resyncSnap}}, &ktypes.CommitInfo{}))
}

// restoreDump restores dump as the snapshot at resyncSnap.
func (n *resyncNode) restoreDump(t *testing.T, dump string, appHash ktypes.Hash) error {
	t.Helper()
	var chunk bytes.Buffer
	gz := gzip.NewWriter(&chunk)
	_, err := gz.Write([]byte(dump))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	require.NoError(t, os.WriteFile(filepath.Join(n.ss.snapshotDir, "chunk-0.sql.gz"), chunk.Bytes(), 0o644))

	sum := sha256.Sum256([]byte(dump))
	snap := &snapshotMetadata{Height: resyncSnap, Chunks: 1, Hash: sum[:], Size: uint64(len(dump)), AppHash: appHash[:]}
	return n.ss.restoreDB(context.Background(), snap)
}

func records(t *testing.T, db config.DBConfig) []string {
	t.Helper()
	rows, _ := dbConn(t, db).Query(context.Background(), `SELECT id || ' ' || v FROM main.records ORDER BY id`)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return got
}

func TestResyncRestoresANodeFarBehind(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_far_behind")

	require.True(t, n.resync(t))

	require.Equal(t, keptSchemas, schemas(t, n.ss))
	n.operatorDataKept(t)
	require.Equal(t, []string{"reset"}, n.bs.calls)
	require.Zero(t, n.bs.height)
	m, err := readRestoreMarker(n.ss.restoreMarker)
	require.NoError(t, err)
	require.Equal(t, &restoreMarker{Height: resyncSnap, SchemasBefore: keptSchemas, ResyncFrom: resyncFrom}, m)
	require.Contains(t, n.logs.String(), "Resync decision")

	appHash := blockAppHash(resyncSnap)
	dump := resyncDump(appHash)
	n.restoreSnapshot(t, dump, appHash)

	// The database is the snapshot's state beside the schemas the resync kept,
	// and holds nothing of the old state.
	require.Equal(t, []string{"ext_tn_local", "kwild_chain", "kwild_voting", "main", "operator_data", "public", "repack"},
		schemas(t, n.ss))
	require.Equal(t, []string{"1 new", "2 new"}, records(t, n.db))
	n.operatorDataKept(t)
	require.Equal(t, int64(resyncSnap), n.bs.height)
	interrupted, err := RestoreInterrupted(n.ss.restoreMarker)
	require.NoError(t, err)
	require.False(t, interrupted)

	// A new node restoring the same snapshot ends with the same state.
	fresh := restoreTestDB(t, "kwil_test_resync_fresh")
	require.NoError(t, restore(t, fresh, dump))
	require.Equal(t, records(t, fresh), records(t, n.db))
}

func TestResyncReplaysANodeNotFarBehind(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_near")
	n.height = resyncSnap - resyncBehind // exactly resync_when_behind blocks behind
	setChainState(t, n.db, n.height, blockAppHash(n.height), false)
	n.bs.height = n.height
	before := schemas(t, n.ss)

	require.False(t, n.resync(t))

	n.untouched(t, before)
	require.Contains(t, n.logs.String(), "resync=false")
}

func TestResyncNeverClearsAValidator(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_validator")
	_, err := dbConn(t, n.db).Exec(context.Background(), `INSERT INTO kwild_voting.voters VALUES ($1, 1)`,
		append(crypto.WireEncodeKeyType(n.self.Type()), n.self.Bytes()...))
	require.NoError(t, err)
	before := schemas(t, n.ss)

	require.False(t, n.resync(t))

	n.untouched(t, before)
	require.Contains(t, n.logs.String(), "this node is a validator")

	// The genesis leader is a validator too.
	_, err = dbConn(t, n.db).Exec(context.Background(), `DELETE FROM kwild_voting.voters`)
	require.NoError(t, err)
	cleared, err := n.ss.ResyncIfFarBehind(context.Background(), n.self, n.self)
	require.NoError(t, err)
	require.False(t, cleared)
	n.untouched(t, before)
}

func TestResyncRefusesWhenSomethingDependsOnKwild(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_dependent")
	_, err := dbConn(t, n.db).Exec(context.Background(),
		`CREATE VIEW operator_data.recent AS SELECT id FROM main.records`)
	require.NoError(t, err)
	before := schemas(t, n.ss)

	require.False(t, n.resync(t))

	n.untouched(t, before)
	require.Contains(t, n.logs.String(), "operator_data.recent")
}

func TestResyncRefusesADatabaseThatIsNotThisNodes(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_foreign")
	before := schemas(t, n.ss)

	// Another app hash at the same height.
	setChainState(t, n.db, resyncFrom, ktypes.HashBytes([]byte("another chain")), false)
	require.False(t, n.resync(t))
	n.untouched(t, before)

	// A database ahead of the block store.
	setChainState(t, n.db, resyncFrom+1, blockAppHash(resyncFrom+1), false)
	require.False(t, n.resync(t))
	n.untouched(t, before)

	require.Contains(t, n.logs.String(), "does not match this node's block store")
}

func TestResyncFromADirtyChainState(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_dirty")
	// Stopped while committing block resyncFrom: the database still holds the
	// app hash of the block before.
	setChainState(t, n.db, resyncFrom, blockAppHash(resyncFrom-1), true)

	require.True(t, n.resync(t))
	require.Equal(t, keptSchemas, schemas(t, n.ss))
}

func TestResyncRollsBackAnOrphanedPreparedTransaction(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_prepared")
	ctx := context.Background()
	stopped := dbConn(t, n.db)
	_, err := stopped.Exec(ctx, `BEGIN; INSERT INTO main.records VALUES (9, 'mid-block'); PREPARE TRANSACTION 'resync_orphan'`)
	require.NoError(t, err)
	// So the test database can be dropped even if the resync leaves it.
	t.Cleanup(func() { dbConn(t, n.db).Exec(ctx, `ROLLBACK PREPARED 'resync_orphan'`) })

	require.True(t, n.resync(t))

	require.Equal(t, keptSchemas, schemas(t, n.ss))
	var prepared int
	require.NoError(t, dbConn(t, n.db).QueryRow(ctx,
		`SELECT count(*) FROM pg_prepared_xacts WHERE database = current_database()`).Scan(&prepared))
	require.Zero(t, prepared)
}

func TestResyncStoppedBeforeTheBlockStoreIsClearedFinishesAtNextStart(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_stop_reset")
	n.bs.resetErr = errors.New("stopped")

	cleared, err := n.ss.ResyncIfFarBehind(context.Background(), n.self, nil)
	require.ErrorContains(t, err, "stopped")
	require.True(t, cleared)
	require.Equal(t, int64(resyncFrom), n.bs.height)
	require.Contains(t, schemas(t, n.ss), "main")

	// The next start.
	n.bs.resetErr = nil
	require.True(t, nextStart(t, n.ss))

	require.Zero(t, n.bs.height)
	require.Equal(t, keptSchemas, schemas(t, n.ss))
	n.operatorDataKept(t)
	n.stillResyncing(t)

	n.restoreSnapshot(t, resyncDump(blockAppHash(resyncSnap)), blockAppHash(resyncSnap))
	n.doneResyncing(t)
}

func TestResyncStoppedBeforeTheSchemasAreDroppedFinishesAtNextStart(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_stop_drop")
	ctx, stop := context.WithCancel(context.Background())
	n.bs.onReset = stop // the node stops right after its block store is cleared

	_, err := n.ss.ResyncIfFarBehind(ctx, n.self, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, n.bs.height)
	require.Contains(t, schemas(t, n.ss), "main")

	// The next start.
	n.bs.onReset = nil
	require.True(t, nextStart(t, n.ss))

	require.Equal(t, keptSchemas, schemas(t, n.ss))
	n.operatorDataKept(t)
	n.stillResyncing(t)

	n.restoreSnapshot(t, resyncDump(blockAppHash(resyncSnap)), blockAppHash(resyncSnap))
	n.doneResyncing(t)
}

func TestResyncStaysAResyncUntilARestoreFinishes(t *testing.T) {
	n := newResyncNode(t, "kwil_test_resync_restarts")
	require.True(t, n.resync(t))

	// The restore fails part way, after creating some of kwild's schemas.
	appHash := blockAppHash(resyncSnap)
	err := n.restoreDump(t, badDump, appHash)
	require.Error(t, err)
	require.Contains(t, schemas(t, n.ss), "kwild_voting")
	n.stillResyncing(t)

	// Each later start undoes what is left and is still resyncing, however
	// many times state sync fails, so the node never replays from genesis.
	for range 2 {
		require.True(t, nextStart(t, n.ss))
		require.Equal(t, keptSchemas, schemas(t, n.ss))
		n.stillResyncing(t)
	}

	n.restoreSnapshot(t, resyncDump(appHash), appHash)
	n.doneResyncing(t)
	require.False(t, nextStart(t, n.ss))
}

// stillResyncing checks that the restore marker says the node was cleared to
// resync from its old height.
func (n *resyncNode) stillResyncing(t *testing.T) {
	t.Helper()
	m, err := readRestoreMarker(n.ss.restoreMarker)
	require.NoError(t, err)
	require.Equal(t, uint64(resyncFrom), m.ResyncFrom)
}

// doneResyncing checks that the node restored the snapshot and holds no
// restore marker.
func (n *resyncNode) doneResyncing(t *testing.T) {
	t.Helper()
	require.Equal(t, int64(resyncSnap), n.bs.height)
	require.Equal(t, []string{"1 new", "2 new"}, records(t, n.db))
	n.operatorDataKept(t)
	interrupted, err := RestoreInterrupted(n.ss.restoreMarker)
	require.NoError(t, err)
	require.False(t, interrupted)
}
