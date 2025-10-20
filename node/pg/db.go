package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/trufnetwork/kwil-db/core/utils/random"
	"github.com/trufnetwork/kwil-db/node/metrics"
	"github.com/trufnetwork/kwil-db/node/types/sql"

	"github.com/jackc/pgx/v5"
)

var mets metrics.DBMetrics = metrics.DB

// DB is a session-aware wrapper that creates and stores a write Tx on request,
// and provides top level Exec/Set methods that error if no Tx exists. This
// design prevents any out-of-session write statements from executing, and makes
// uncommitted reads explicit (and impossible in the absence of an active
// transaction).
//
// This type is tailored to use in kwild in the following ways:
//
//  1. Controlled transactional interaction that requires beginning a
//     transaction before using the Exec method, unless put in "autocommit" mode
//     using the AutoCommit method. Use of the write connection when not
//     executing a block's transactions is prevented.
//
//  2. Using an underlying connection pool, with multiple readers and a single
//     write connection to ensure all uses of Execute operate on the active
//     transaction.
//
//  3. Emulating SQLite changesets by collecting WAL data for updates from a
//     dedicated logical replication connection and slot. The Precommit method
//     is used to retrieve the commit ID prior to Commit.
//
// DB requires a superuser connection to a Postgres database that can perform
// administrative actions on the database.
type DB struct {
	pool *Pool    // raw connection pool
	repl *replMon // logical replication monitor for collecting commit IDs

	// This context is not passed anywhere. It is just used as a convenient way
	// to implements Done and Err methods for the DB consumer.
	cancel context.CancelCauseFunc
	ctx    context.Context

	// Guarantee that we are in-session by tracking and using a Tx for the write methods.
	mtx        sync.Mutex
	autoCommit bool   // skip the explicit transaction (begin/commit automatically)
	tx         pgx.Tx // interface
	txid       string // uid of the prepared transaction
	seq        int64

	// NOTE: this was initially designed for a single ongoing write transaction,
	// held in the tx field, and the (*DB).Execute method using it *implicitly*.
	// We have moved toward using the Execute method of the transaction returned
	// by BeginTx/BeginPreparedTx/BeginReadTx, and we can potentially allow
	// multiple uncommitted write transactions to support a 2 phase commit of
	// different stores using the same pg.DB instance. This will take refactoring
	// of the DB and concrete transaction type methods.
}

func isConnClosed(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, pgx.ErrTxClosed) || strings.Contains(err.Error(), "conn closed")
}

func (db *DB) failConn(err error) error {
	// Any write-path "conn closed" means the in-progress block transaction vanished.
	// To preserve deterministic replay we surface a fatal ErrDBFailure so the node
	// restarts and replays the block from the last committed height.
	logger.Errorf("writer transaction connection lost: %v", err)
	if db.tx != nil {
		if rel, ok := db.tx.(releaser); ok {
			rel.Release()
		}
	}
	db.tx = nil
	db.txid = ""
	db.seq = -1
	return errors.Join(sql.ErrDBFailure, err)
}

// DBConfig is the configuration for the Kwil DB backend, which includes the
// connection parameters and a schema filter used to selectively include WAL
// data for certain PostgreSQL schemas in commit ID calculation.
type DBConfig struct {
	PoolConfig

	// SchemaFilter is used to include WAL data for certain *postgres* schema
	// (not Kwil schema). If nil, the default is to include updates to tables in
	// any schema prefixed by "ds_".
	// DEPRECATED: This has become baked into Kwil's DB conventions in many places.
	SchemaFilter func(string) bool
}

const DefaultSchemaFilterPrefix = "ds_"

var defaultSchemaFilter = func(schema string) bool {
	return strings.HasPrefix(schema, DefaultSchemaFilterPrefix)
}

// [dev note] Transaction sequencing flow:
// - when ready to commit a tx, increment (UPDATE) the seq int8 in kwild_internal.sentry table
// - request from the repl monitor a promise for the commit ID for that seq
// - commit the tx
// - repl captures the ordered updates for the transaction
// - in repl receiver, decode and record the seq row update from WAL data (the final update before the commit message)
// - send complete commit digest back to the consumer via the promise channel for that seq value
// - ensure it matches the seq in the exec just prior
//
// To prepare for the above, initialize as follows:
// - create kwild_internal.sentry table if not exists
// - insert row with seq=0, if no rows

// NewDB creates a new Kwil DB instance. On creation, it will connect to the
// configured postgres process, creating as many connections as specified by the
// PoolConfig plus a special connection for a logical replication slot receiver.
// The database user (postgresql "role") must be a super user for several
// reasons: creating triggers, collations, and the replication publication.
//
// WARNING: There must only be ONE instance of a DB for a given postgres
// database. Transactions that use the Precommit method update an internal table
// used to sequence transactions.
func NewDB(ctx context.Context, cfg *DBConfig) (*DB, error) {
	// Create the connection pool.
	pool, err := NewPool(ctx, &cfg.PoolConfig)
	if err != nil {
		return nil, err
	}

	writer, err := pool.writer.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer writer.Release()
	conn := writer.Conn()

	// Ensure that the postgres host is running with an acceptable version.
	pgVer, pgVerNum, err := pgVersion(ctx, conn)
	if err != nil {
		return nil, err
	}
	logger.Infof("Connected to %v", pgVer) // Connected to PostgreSQL 16.1 (Ubuntu 16.1-1.pgdg22.04+1) on ...

	major, minor, okVer := validateVersion(pgVerNum, verMajorRequired, verMinorRequired)
	if !okVer {
		return nil, fmt.Errorf("required PostgreSQL version not satisfied. Required %d.%d but connected to %d.%d",
			verMajorRequired, verMinorRequired, major, minor)
	}

	// Now check system settings, including logical replication and prepared transactions.
	if err = verifySettings(ctx, conn); err != nil {
		return nil, err
	}

	// Verify that the db user/role is superuser with replication privileges.
	if err = checkSuperuser(ctx, conn); err != nil {
		return nil, err
	}

	if err = setTimezoneUTC(ctx, conn); err != nil {
		return nil, err
	}

	// Clean up orphaned prepared transaction that may have been left over from
	// an unclean shutdown. If we don't, postgres will hang on query.
	if _, err = rollbackPreparedTxns(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create publication: %w", err)
	}

	// Create the NOCASE collation to emulate SQLite's collation.
	if err = ensureCollation(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create custom collations: %w", err)
	}

	// Ensure all tables that are created with no primary key or unique index
	// are altered to have "full replication identity" for UPDATE and DELETES.
	if err = ensureFullReplicaIdentityTrigger(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create full replication identity trigger: %w", err)
	}

	// Create the publication that is required for logical replication.
	if err = ensurePublication(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create publication: %w", err)
	}

	if err = ensureUUIDExtension(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create UUID extension: %w", err)
	}

	if err = ensurePgCryptoExtension(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create pgcrypto extension: %w", err)
	}

	okSchema := cfg.SchemaFilter
	if okSchema == nil {
		okSchema = defaultSchemaFilter
	}

	repl, err := newReplMon(ctx, cfg.Host, cfg.Port, cfg.User, cfg.Pass, cfg.DBName, okSchema, pool.idTypes)
	if err != nil {
		return nil, err
	}

	// Create the tx sequence table with single row if it doesn't exists.
	if err = ensureSentryTable(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create transaction sequencing table: %w", err)
	}

	// Register the error function so a statement like `SELECT error('boom');`
	// will raise an exception and cause the query to error.
	if err = ensureErrorPLFunc(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create ERROR function: %w", err)
	}

	// Register the notice function so a statement like `SELECT notice('boom');`
	// will raise a notice that can be captured by a subscriber
	if err = ensureNoticePLFuncs(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create NOTICE function: %w", err)
	}

	if err = ensureUnixTimestampFuncs(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create parse_unix_timestamp function: %w", err)
	}

	runCtx, cancel := context.WithCancelCause(context.Background())

	db := &DB{
		pool:   pool,
		repl:   repl,
		cancel: cancel,
		ctx:    runCtx,
		seq:    -1,
	}

	// Supervise the replication stream monitor. If it dies (repl.done chan
	// closed), we should close the DB connections, signal the failure to
	// consumers, and offer the cause.
	go func() {
		<-db.repl.done      // wait for capture goroutine to end (broadcast channel)
		cancel(db.repl.err) // set the cause

		if db.repl.err != nil && !errors.Is(db.repl.err, context.Canceled) {
			logger.Errorf("replication monitor failed: %v", db.repl.err)
		}

		// db.pool.Close()

		// If the DB has shut down, there will be no more notices, which may be
		// needed to unblock a receiver e.g. FinalizeBlock, so we close the
		// channels to unblock them and allow the application to return.
		db.pool.subscribers.Exclusive(func(m map[int64]chan<- string) {
			for txid, sub := range m {
				// We won't be sending any more message with the 'pgtx:' prefix,
				// so we send an empty string PRIOR to closing the channel to
				// signal premature completion.
				sub <- ""
				close(sub)
				delete(m, txid)
			}
		})

		// Potentially we can have a newReplMon restart loop here instead of
		// shutdown. However, this proved complex and unlikely to succeed.
	}()

	return db, nil
}

// EnsureFullReplicaIdentityDatasets should be used after the first time opening
// a database that was restored from a snapshot, which may have been created
// with an older version of kwild that did not set this on all tables.
func (db *DB) EnsureFullReplicaIdentityDatasets(ctx context.Context) error {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = db.Execute(ctx, sqlAlterAllWithReplicaIdentFull)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Close shuts down the Kwil DB. This stops all connections and the WAL data
// receiver.
func (db *DB) Close() error {
	db.cancel(nil)
	db.repl.stop()
	if db.tx == nil {
		return db.pool.Close()
	}

	// This is a bug, so we are going to panic so the issue is not easily
	// ignored, but we will rollback the tx so we don't hang or leak
	// postgresql resources.

	if db.txid != "" {
		logger.Warnln("Rolling back PREPARED transaction", db.txid)
		// With PREPARE TRANSACTION already done, rollback the prepared transaction.
		sqlRollback := fmt.Sprintf(`ROLLBACK PREPARED '%s'`, db.txid)
		if _, err := db.tx.Exec(context.Background(), sqlRollback); err != nil {
			return fmt.Errorf("ROLLBACK PREPARED failed: %w", err)
		}
		// We don't use Rollback, which normally releases automatically.
		if rel, ok := db.tx.(releaser); ok {
			rel.Release()
		}
		db.txid = ""
	} else { // otherwise regular rollback
		logger.Warnln("Rolling back regular transaction")
		db.tx.Rollback(context.Background())
	}

	db.tx = nil
	db.pool.Close()
	panic("Closed the DB with an active transaction, probably forgot to rollback the tx somewhere!")
}

// Done allows higher level systems to monitor the state of the DB backend
// connection and shutdown (or restart) the application if necessary. Without
// this, the application hits an error the next time it uses the DB, which may
// be confusing and inopportune.
func (db *DB) Done() <-chan struct{} {
	return db.ctx.Done()
}

// Err provides any error that caused the DB to shutdown. This will return
// context.Canceled after Close has been called.
func (db *DB) Err() error {
	return context.Cause(db.ctx)
}

// AutoCommit toggles auto-commit mode, in which the Execute method may be used
// without having to begin/commit. This is to support startup and initialization
// tasks that occur prior to the start of the atomic commit process used while
// executing blocks.
func (db *DB) AutoCommit(auto bool) {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	if db.tx != nil {
		panic("already in a tx")
	}
	db.autoCommit = auto
}

// For {accounts,validators}.Datasets / registry.DB
var _ sql.Executor = (*DB)(nil)

var _ sql.PreparedTxMaker = (*DB)(nil) // for dataset Registry

// beginTx starts a read-write transaction, returning a dbTx. It will be for a
// prepared transaction if sequenced is true, incrementing the seq value of the
// internal sentry table to allow obtaining a commit ID with Precommit. If
// sequenced is false, the precommit method will hang (use commit only). If
// sequenced is true and the precommit method is not used (straight to commit),
// it will work as intended, but the replication monitor will warn about an
// unexpected sequence update in the transaction.
func (db *DB) beginTx(ctx context.Context, sequenced bool) (*dbTx, error) {
	tx, err := db.beginWriterTx(ctx, sequenced)
	if err != nil {
		return nil, err
	}

	ntx := &nestedTx{
		Tx:         tx,
		accessMode: sql.ReadWrite,
		oidTypes:   db.pool.idTypes,
	}
	return &dbTx{
		nestedTx:   ntx,
		db:         db,
		accessMode: sql.ReadWrite,
	}, nil
}

// BeginPreparedTx makes the DB's singular transaction, which is used automatically
// by consumers of the Query and Execute methods. This is the mode of operation
// used by Kwil to have one system coordinating transaction lifetime, with one
// or more other systems implicitly using the transaction for their queries.
//
// This method creates a sequenced transaction, and it should be committed with
// a prepared transaction (two-phase commit) using Precommit. Use BeginTx for a
// regular outer transaction without sequencing or a prepared transaction.
//
// The returned transaction is also capable of creating nested transactions.
// This functionality is used to prevent user dataset query errors from rolling
// back the outermost transaction.
func (db *DB) BeginPreparedTx(ctx context.Context) (sql.PreparedTx, error) {
	return db.beginTx(ctx, true) // sequenced, expose Precommit
}

var _ sql.TxMaker = (*DB)(nil)
var _ sql.DB = (*DB)(nil)

// BeginTx starts a regular read-write transaction. For a sequenced two-phase
// transaction, use BeginPreparedTx.
func (db *DB) BeginTx(ctx context.Context) (sql.Tx, error) {
	return db.beginTx(ctx, false) // slice off the Precommit method from sql.PreparedTx
}

// ReadTx creates a read-only transaction for the database.
// It obtains a read connection from the pool, which will be returned
// to the pool when the transaction is closed.
func (db *DB) BeginReadTx(ctx context.Context) (sql.OuterReadTx, error) {
	return db.beginReadTx(ctx, pgx.RepeatableRead)
}

// BeginSnapshotTx creates a read-only transaction with serializable isolation
// level. This is used for taking a snapshot of the database.
func (db *DB) BeginSnapshotTx(ctx context.Context) (sql.Tx, string, error) {
	tx, err := db.beginReadTx(ctx, pgx.Serializable)
	if err != nil {
		return nil, "", err
	}

	// export snpashot id
	res, err := tx.Execute(ctx, "SELECT pg_export_snapshot();")
	if err != nil {
		return nil, "", err
	}

	// Expected to have 1 row and 1 column
	if len(res.Columns) != 1 || len(res.Rows) != 1 {
		return nil, "", fmt.Errorf("unexpected result from pg_export_snapshot: %v", res)
	}

	snapshotID := res.Rows[0][0].(string)
	return tx, snapshotID, err
}

func (db *DB) beginReadTx(ctx context.Context, iso pgx.TxIsoLevel) (sql.OuterReadTx, error) {
	// stat := db.pool.readers.Stat()
	// fmt.Printf("total / max cons: %d / %d\n", stat.TotalConns(), stat.MaxConns())
	conn, err := db.pool.readers.Acquire(ctx) // ensure we have a connection
	if err != nil {
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
		IsoLevel:   iso, // only for read-only as repeatable ready can fail a write tx commit
	})
	if err != nil {
		conn.Release()
		return nil, err
	}

	ntx := &nestedTx{
		Tx:         tx,
		accessMode: sql.ReadOnly,
		oidTypes:   db.pool.idTypes,
	}

	return &readTx{
		nestedTx:    ntx,
		release:     sync.OnceFunc(conn.Release),
		subscribers: db.pool.subscribers,
	}, nil
}

// BeginReservedReadTx starts a read-only transaction using a reserved reader
// connection. This is to allow read-only consensus operations that operate
// outside of the write transaction's lifetime, such as proposal preparation and
// approval, to function without contention on the reader pool that services
// user requests.
func (db *DB) BeginReservedReadTx(ctx context.Context) (sql.Tx, error) {
	tx, err := db.pool.reserved.BeginTx(ctx, pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
		IsoLevel:   pgx.RepeatableRead,
	})
	if err != nil {
		return nil, err
	}

	return &nestedTx{
		Tx:         tx,
		accessMode: sql.ReadOnly,
		oidTypes:   db.pool.idTypes,
	}, nil
}

// BeginDelayedReadTx returns a valid SQL transaction, but will only
// start the transaction once the first query is executed. This is useful
// for when a calling module is expected to control the lifetime of a read
// transaction, but the implementation might not need to use the transaction.
func (db *DB) BeginDelayedReadTx() sql.OuterReadTx {
	return &delayedReadTx{db: db}
}

type writeTxWrapper struct {
	pgx.Tx
	release func()
}

func (txw *writeTxWrapper) Release() {
	txw.release()
}

func (txw *writeTxWrapper) Commit(ctx context.Context) error {
	defer txw.release()
	return txw.Tx.Commit(ctx)
}

func (txw *writeTxWrapper) Rollback(ctx context.Context) error {
	defer txw.release()
	return txw.Tx.Rollback(ctx)
}

// beginWriterTx is the critical section of BeginTx.
// It creates a new transaction on the write connection, and stores it in the
// DB's tx field. It is not exported, and is only called from BeginTx.
func (db *DB) beginWriterTx(ctx context.Context, sequenced bool) (pgx.Tx, error) {
	db.mtx.Lock()
	defer db.mtx.Unlock()

	if db.tx != nil {
		return nil, errors.New("writer tx exists")
	}

	writer, err := db.pool.writer.Acquire(ctx)
	if err != nil {
		return nil, err
	}

	tx, err := writer.BeginTx(ctx, pgx.TxOptions{
		AccessMode: pgx.ReadWrite,
		IsoLevel:   pgx.ReadUncommitted, // consider if ReadCommitted would be fine. uncommitted refers to other transactions, not needed
	})
	if err != nil {
		writer.Release()
		return nil, err
	}

	// Make the tx available to Execute and QueryPending.
	db.tx = &writeTxWrapper{
		Tx:      tx,
		release: writer.Release,
	}

	if !sequenced {
		db.seq = -1 // should already be
		return db.tx, nil
	}

	// Do the seq update in sentry table. This ensures a replication message
	// sequence is emitted from this transaction, and that the data returned
	// from it includes the expected seq value.
	seq, err := incrementSeq(ctx, tx)
	if err != nil {
		// writeTxWrapper.Rollback will release the connection
		if err2 := db.tx.Rollback(context.Background()); err2 != nil {
			db.tx = nil // clear the tx regardless of error
			return nil, fmt.Errorf("failed to rollback: %w", errors.Join(err, err2))
		}
		db.tx = nil
		return nil, err
	}
	logger.Debugf("updated seq to %d", seq)
	db.seq = seq

	return db.tx, nil
}

// precommit finalizes the transaction with a prepared transaction and returns
// the ID of the commit. The transaction is not yet committed. It takes an io.Writer
// to write the changeset to, and returns the commit ID. If the io.Writer is nil,
// it won't write the changeset anywhere.
func (db *DB) precommit(ctx context.Context, changes chan<- any) ([]byte, error) {
	db.mtx.Lock()
	defer db.mtx.Unlock()

	if db.tx == nil || db.seq == -1 {
		return nil, errors.New("no tx exists")
	}

	// track the changes, and set the changeset writer
	resChan, ok := db.repl.recvID(db.seq, changes)
	if !ok { // commitID will not be available, error. There is no recovery presently.
		return nil, errors.New("replication connection is down")
	}

	txid := random.String(10)
	sqlPrepareTx := fmt.Sprintf(`PREPARE TRANSACTION '%s'`, txid)
	if _, err := db.tx.Exec(ctx, sqlPrepareTx); err != nil {
		if isConnClosed(err) {
			return nil, db.failConn(err)
		}
		return nil, err
	}
	db.txid = txid

	logger.Debugf("prepared transaction %q", db.txid)

	// Wait for the "commit id" from the replication monitor.
	select {
	case commitID, ok := <-resChan:
		if !ok {
			return nil, errors.New("resChan unexpectedly closed")
		}
		logger.Debugf("received commit ID %x", commitID)
		// The transaction is ready to commit, stored in a file with postgres in
		// the pg_twophase folder of the pg cluster data_directory.
		return commitID, nil
	case <-db.repl.done: // the replMon has died after we executed PREPARE TRANSACTION
		return nil, errors.New("replication stream interrupted")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// commit is called from the Commit method of the sql.Tx
// returned from BeginTx (or Begin). See tx.go.
func (db *DB) commit(ctx context.Context) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()

	if db.tx == nil {
		return errors.New("no tx exists")
	}
	if db.txid == "" {
		// Allow commit without two-phase prepare
		err := db.tx.Commit(ctx)
		db.tx = nil
		db.seq = -1
		if err != nil {
			if isConnClosed(err) {
				return db.failConn(err)
			}
			return err
		}
		return nil
	}

	defer func() {
		if db.tx == nil {
			return
		}
		sqlRollback := fmt.Sprintf(`ROLLBACK PREPARED '%s'`, db.txid)
		db.txid = ""
		db.seq = -1
		if _, err := db.tx.Exec(ctx, sqlRollback); err != nil {
			logger.Warnf("ROLLBACK PREPARED failed: %v", err)
		}
		// We don't use Commit, which normally releases automatically.
		if rel, ok := db.tx.(releaser); ok {
			rel.Release()
		}
		db.tx = nil
	}()

	sqlCommit := fmt.Sprintf(`COMMIT PREPARED '%s'`, db.txid)
	if _, err := db.tx.Exec(ctx, sqlCommit); err != nil {
		if isConnClosed(err) {
			return db.failConn(fmt.Errorf("commit prepared: %w", err))
		}
		return fmt.Errorf("COMMIT PREPARED failed: %w", err)
	}

	// Success, the defer should not try to rollback, and we should forget about
	// this prepared transaction's name, otherwise a future tx rollback prior to
	// prepare will try to rollback this old prepared txn.
	db.tx = nil
	db.txid = ""
	db.seq = -1

	return nil
}

// rollback is called from the Rollback method of the sql.Tx
// returned from BeginTx (or Begin). See tx.go.
func (db *DB) rollback(ctx context.Context) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()

	if db.tx == nil {
		return errors.New("no tx exists")
	}

	defer func() {
		db.tx = nil
		db.txid = ""
		db.seq = -1
	}()

	// If precommit not yet done, do a regular rollback.
	if db.txid == "" {
		err := db.tx.Rollback(ctx)
		if err == nil {
			return nil
		}
		if isConnClosed(err) {
			return db.failConn(err)
		}
		return err
	}

	defer func() {
		// We don't use Rollback, which normally releases automatically.
		if rel, ok := db.tx.(releaser); ok {
			rel.Release()
		}
	}()

	// With precommit already done, rollback the prepared transaction, and do
	// not do the regular rollback, which is a no-op that emits a warning
	// notice: "WARNING:  there is no transaction in progress".
	sqlRollback := fmt.Sprintf(`ROLLBACK PREPARED '%s'`, db.txid)
	if _, err := db.tx.Exec(ctx, sqlRollback); err != nil {
		if isConnClosed(err) {
			return db.failConn(fmt.Errorf("rollback prepared: %w", err))
		}
		return fmt.Errorf("ROLLBACK PREPARED failed: %w", err)
	}

	return nil
}

// Query performs a read-only query on a read connection.
func (db *DB) Query(ctx context.Context, stmt string, args ...any) (*sql.ResultSet, error) {
	// Pass through to the read pool, isolated from any active transactions on
	// the write connection.
	return db.pool.Query(ctx, stmt, args...)
}

// discardCommitID is for Execute when in auto-commit mode.
func (db *DB) discardCommitID(ctx context.Context, resChan chan []byte) {
	select {
	case cid := <-resChan:
		logger.Debugf("discarding commit ID %x", cid)
	case <-db.repl.done:
	case <-ctx.Done():
	}
}

// Pool is a trapdoor to get the connection pool. Probably not for normal Kwil
// DB operation, but test setup/teardown.
func (db *DB) Pool() *Pool {
	return db.pool
}

// Execute runs a statement on an existing transaction, or on a short lived
// transaction from the write connection if in auto-commit mode.
func (db *DB) Execute(ctx context.Context, stmt string, args ...any) (*sql.ResultSet, error) {
	db.mtx.Lock()
	defer db.mtx.Unlock()

	// NOTE: if we remove the db.tx field, we'd have this top level method
	// always function in "autoCommit" mode, with an ephemeral transaction.
	if db.tx != nil {
		if db.autoCommit {
			return nil, errors.New("tx already created, cannot use auto commit")
		}
		res, err := query(ctx, db.pool.idTypes, db.tx, stmt, args...)
		if err != nil && isConnClosed(err) {
			return nil, db.failConn(err)
		}
		return res, err
	}
	if !db.autoCommit {
		return nil, sql.ErrNoTransaction
	}

	// We do manual autocommit since postgresql will skip it for some
	// statements, plus we are also injecting the seq update query.
	var resChan chan []byte
	var res *sql.ResultSet
	err := pgx.BeginTxFunc(ctx, db.pool.writer,
		pgx.TxOptions{
			AccessMode: pgx.ReadWrite,
			IsoLevel:   pgx.ReadCommitted,
		},
		func(tx pgx.Tx) error {
			seq, err := incrementSeq(ctx, tx)
			if err != nil {
				return err
			}
			var ok bool
			resChan, ok = db.repl.recvID(seq, nil) // nil changeset writer since we are in auto-commit mode
			if !ok {
				return errors.New("replication connection is down")
			}
			res, err = query(ctx, db.pool.idTypes, tx, stmt, args...)
			return err
		},
	)
	if err != nil {
		return nil, err
	}
	db.discardCommitID(ctx, resChan)
	return res, nil
}

// TODO: require rw with target_session_attrs=read-write ?

// Exec executes a Postgres SQL statement against the database. Unlike the Execute method,
// this function does not use `query` internally, which allows for many statements delimited by
// semicolons to be executed in one call.
func Exec(ctx context.Context, tx sql.Executor, stmt string) error {
	var conn *pgx.Conn
	switch tx := tx.(type) {
	case *DB:
		tx.mtx.Lock()
		defer tx.mtx.Unlock()
		if tx.tx == nil {
			return sql.ErrNoTransaction
		}

		conn = tx.tx.(conner).Conn()
	case conner:
		conn = tx.Conn()
	default:
		return fmt.Errorf("unsupported type %T", tx)
	}

	_, err := conn.Exec(ctx, stmt)
	return err
}
