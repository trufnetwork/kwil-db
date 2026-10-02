package pg

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	// Tables with no PRIMARY KEY or UNIQUE index will fail to update or delete
	// when there is an active publication and replication slot unless the
	// table's "replication identity" is explicitly set to "full". We ensure
	// that is the case by creating an event trigger to perform the ALTER TABLE
	// command whenever a DDL command with the "CREATE TABLE" tag is processed
	// for a table with neither a primary key or unique index. We also do this
	// for all tables that even have a primary key or unique index so that we
	// can get a full changeset with the old values that are updated or deleted,
	// not just the primary keys.

	sqlCreateEvtTriggerReplIdent = `CREATE EVENT TRIGGER set_replica_identity_on_create
		ON ddl_command_end
		WHEN TAG IN ('CREATE TABLE')
		EXECUTE FUNCTION set_replica_identity();`

	sqlDropEvtTriggerReplIdent = `DROP EVENT TRIGGER IF EXISTS set_replica_identity_on_create;`

	sqlCreatePublicationINE = `DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_publication WHERE pubname = '%[1]s'
	) THEN
		EXECUTE 'CREATE PUBLICATION %[1]s FOR ALL TABLES';
		RAISE NOTICE 'Publication %[1]s created.';
	ELSE
		RAISE NOTICE 'Publication %[1]s already exists.';
	END IF;
END$$;`

	// on startup, check for any prepared transactions and roll them back. The
	// selected columns and their order in this query is explicit so it matches
	// the preparedTxn struct.
	sqlListPreparedTxns = `SELECT transaction, gid, prepared, owner, database FROM pg_prepared_xacts;`

	sqlCreateCollationNOCASE = `CREATE COLLATION IF NOT EXISTS nocase (
		provider = icu, locale = 'und-u-ks-level2', deterministic = false
	);`

	sqlCreateUUIDExtension = `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`

	// postgres returns EXTRACT as a double precision, but will only at most have 6
	// decimal places of precision (to measure microseconds). We cast to numeric(16, 6)
	// which should allow for up to 6 decimal places of precision.
	// Since max unix timestamp is 2147483648, we can cast to numeric(16, 6) to allow 10 digits
	// before the decimal and 6 after.
	sqlCreateParseUnixTimestampFunc = `CREATE OR REPLACE FUNCTION parse_unix_timestamp(timestamp_string text, format_string text)
	RETURNS NUMERIC(16, 6) AS $$
	BEGIN
		RETURN EXTRACT(EPOCH FROM TO_TIMESTAMP(timestamp_string, format_string))::numeric(16, 6);
	END;
	$$ LANGUAGE plpgsql;`

	// this is the inverse of parse_unix_timestamp
	sqlCreateFormatUnixTimestampFunc = `CREATE OR REPLACE FUNCTION format_unix_timestamp(unix_timestamp NUMERIC(16, 6), format_string text)
	RETURNS TEXT AS $$
	BEGIN
		RETURN TO_CHAR(TO_TIMESTAMP(unix_timestamp), format_string);
	END;
	$$ LANGUAGE plpgsql;`

	sqlCreateOrReplaceReplicaIdentity = `CREATE OR REPLACE FUNCTION set_replica_identity()
RETURNS event_trigger
LANGUAGE plpgsql
AS $$
DECLARE
    obj record;
BEGIN
    FOR obj IN
        SELECT * FROM pg_event_trigger_ddl_commands() WHERE command_tag = 'CREATE TABLE'
    LOOP
        EXECUTE 'ALTER TABLE ' || obj.object_identity || ' REPLICA IDENTITY FULL';
    END LOOP;
END;
$$;`

	sqlAlterAllWithReplicaIdentFull = `DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (
        SELECT schemaname, tablename
        FROM pg_tables
        WHERE schemaname LIKE 'ds_%'
    )
    LOOP
        EXECUTE 'ALTER TABLE ' || quote_ident(r.schemaname) || '.' || quote_ident(r.tablename) || ' REPLICA IDENTITY FULL;';
    END LOOP;
END $$;`
)

func checkSuperuser(ctx context.Context, conn *pgx.Conn) error {
	user := conn.Config().User
	// Verify that the db user/role is superuser with replication privileges.
	var isSuper, isReplicator bool
	err := conn.QueryRow(ctx, `SELECT rolsuper, rolreplication FROM pg_roles WHERE rolname = $1;`, user).
		Scan(&isSuper, &isReplicator)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("postgres role does not exists: %v", user)
		}
		return fmt.Errorf("unable to verify superuser status of postgres role %v: %w", user, err)
	}
	if !isSuper || !isReplicator {
		return fmt.Errorf("postgres role is not a superuser with replication: %v", user)
	}
	return nil
}

func ensureCollation(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, sqlCreateCollationNOCASE)
	return err
}

func ensurePublication(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, fmt.Sprintf(sqlCreatePublicationINE, publicationName))
	return err
}

func ensureUUIDExtension(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, sqlCreateUUIDExtension)
	return err
}

func ensurePgCryptoExtension(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto;`)
	return err
}

func ensureUnixTimestampFuncs(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, sqlCreateParseUnixTimestampFunc)
	if err != nil {
		return err
	}

	_, err = conn.Exec(ctx, sqlCreateFormatUnixTimestampFunc)
	return err
}

// ErrDatabaseInUse means another session is connected to the database.
var ErrDatabaseInUse = errors.New("database is in use")

// sqlCountOtherSessions counts the clients connected to the current database
// besides the caller. A running node holds client connections and a
// replication walsender. Autovacuum workers are left out, since Postgres stops
// them itself before a DROP DATABASE.
const sqlCountOtherSessions = `SELECT count(*) FROM pg_stat_activity
	WHERE datname = current_database() AND pid <> pg_backend_pid()
	AND backend_type IN ('client backend', 'walsender')`

// RollbackOrphanedPreparedTxns rolls back the prepared transactions that a node
// left in its database when it stopped between PREPARE TRANSACTION and COMMIT
// PREPARED, and returns how many it rolled back. Postgres refuses to drop a
// database that holds any. It returns ErrDatabaseInUse, and rolls back nothing,
// while another session is connected, because a running node's prepared
// transactions are not orphaned.
func RollbackOrphanedPreparedTxns(ctx context.Context, cfg *ConnConfig) (int, error) {
	conn, err := pgx.Connect(ctx, connString(cfg.Host, cfg.Port, cfg.User, cfg.Pass, cfg.DBName, false))
	if err != nil {
		return 0, err
	}
	defer conn.Close(ctx)

	var others int64
	if err := conn.QueryRow(ctx, sqlCountOtherSessions).Scan(&others); err != nil {
		return 0, err
	}
	if others > 0 {
		return 0, fmt.Errorf("%w: %d other connections to %q", ErrDatabaseInUse, others, cfg.DBName)
	}

	return rollbackPreparedTxns(ctx, conn)
}

// sqlListSchemas lists the schemas in the current database, leaving out the
// ones Postgres owns.
const sqlListSchemas = `SELECT nspname FROM pg_namespace
	WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'
	ORDER BY nspname`

// ListSchemas returns the schemas in the configured database, leaving out the
// ones Postgres owns.
func ListSchemas(ctx context.Context, cfg *ConnConfig) ([]string, error) {
	conn, err := pgx.Connect(ctx, connString(cfg.Host, cfg.Port, cfg.User, cfg.Pass, cfg.DBName, false))
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	rows, _ := conn.Query(ctx, sqlListSchemas)
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// DropSchemasExcept drops, in one transaction, every schema in the configured
// database that is not in keep, leaving out the ones Postgres owns. It
// returns the schemas it dropped. It is for a node that is starting, so it
// first rolls back the prepared transactions a stopped node left behind,
// whose locks would otherwise hold the drop forever. Like the rollback when a
// node opens its database, it assumes no other node uses the database.
func DropSchemasExcept(ctx context.Context, cfg *ConnConfig, keep []string) ([]string, error) {
	conn, err := pgx.Connect(ctx, connString(cfg.Host, cfg.Port, cfg.User, cfg.Pass, cfg.DBName, false))
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	if _, err := rollbackPreparedTxns(ctx, conn); err != nil {
		return nil, err
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, _ := tx.Query(ctx, sqlListSchemas)
	schemas, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}

	var dropped []string
	for _, schema := range schemas {
		if slices.Contains(keep, schema) {
			continue
		}
		if _, err := tx.Exec(ctx, `DROP SCHEMA `+pgx.Identifier{schema}.Sanitize()+` CASCADE`); err != nil {
			return nil, fmt.Errorf("drop schema %s: %w", schema, err)
		}
		dropped = append(dropped, schema)
	}

	return dropped, tx.Commit(ctx)
}

// sqlOutsideDependents finds the objects outside the schemas in $1 that
// depend on objects inside them: the ones DROP SCHEMA ... CASCADE would take
// with it. pg_depend names an object by its catalog and oid, so objns maps
// each catalog that can hold one to the schema it lives in. A rule, trigger,
// default or policy lives in its table's schema. An object with no schema,
// such as a publication's table entry, counts as outside.
const sqlOutsideDependents = `WITH inside AS (
		SELECT oid FROM pg_namespace WHERE nspname = ANY($1)
	), objns (classid, objid, nsp) AS (
		SELECT 'pg_namespace'::regclass::oid, oid, oid FROM pg_namespace
		UNION ALL SELECT 'pg_class'::regclass::oid, oid, relnamespace FROM pg_class
		UNION ALL SELECT 'pg_proc'::regclass::oid, oid, pronamespace FROM pg_proc
		UNION ALL SELECT 'pg_type'::regclass::oid, oid, typnamespace FROM pg_type
		UNION ALL SELECT 'pg_constraint'::regclass::oid, oid, connamespace FROM pg_constraint
		UNION ALL SELECT 'pg_statistic_ext'::regclass::oid, oid, stxnamespace FROM pg_statistic_ext
		UNION ALL SELECT 'pg_rewrite'::regclass::oid, r.oid, c.relnamespace
			FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class
		UNION ALL SELECT 'pg_trigger'::regclass::oid, t.oid, c.relnamespace
			FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		UNION ALL SELECT 'pg_attrdef'::regclass::oid, a.oid, c.relnamespace
			FROM pg_attrdef a JOIN pg_class c ON c.oid = a.adrelid
		UNION ALL SELECT 'pg_policy'::regclass::oid, p.oid, c.relnamespace
			FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
	)
	SELECT DISTINCT pg_describe_object(d.classid, d.objid, 0) || ' depends on ' ||
		pg_describe_object(d.refclassid, d.refobjid, 0)
	FROM pg_depend d
	JOIN objns ref ON ref.classid = d.refclassid AND ref.objid = d.refobjid
	LEFT JOIN objns dep ON dep.classid = d.classid AND dep.objid = d.objid
	WHERE d.deptype IN ('n', 'a')
		AND ref.nsp IN (SELECT oid FROM inside)
		AND (dep.nsp IS NULL OR dep.nsp NOT IN (SELECT oid FROM inside))
	ORDER BY 1`

// OutsideDependents returns the objects outside the given schemas that depend
// on objects inside them, such as a view in another schema over one of their
// tables, or a foreign key that references one. Dropping the schemas with
// CASCADE would drop these too. Each is described as "<object> depends on
// <object>".
func OutsideDependents(ctx context.Context, cfg *ConnConfig, schemas []string) ([]string, error) {
	conn, err := pgx.Connect(ctx, connString(cfg.Host, cfg.Port, cfg.User, cfg.Pass, cfg.DBName, false))
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	rows, _ := conn.Query(ctx, sqlOutsideDependents, schemas)
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

type preparedTxn struct {
	XID      uint32    `db:"transaction"` // type xid is a 32-bit integer
	GID      string    `db:"gid"`
	Time     time.Time `db:"prepared"`
	Owner    string    `db:"owner"`
	Database string    `db:"database"`
}

func rollbackPreparedTxns(ctx context.Context, conn *pgx.Conn) (int, error) {
	rows, _ := conn.Query(ctx, sqlListPreparedTxns) // pgx ensures rows is readable and rows.Err contains any error
	preparedTxns, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[preparedTxn])
	if err != nil {
		return 0, err
	}
	var closed int
	connectedDB := conn.Config().Database
	if len(preparedTxns) > 0 {
		logger.Warnf("Found %d orphaned prepared transactions", len(preparedTxns))
	}
	for _, ptx := range preparedTxns {
		if connectedDB != ptx.Database {
			logger.Infof(`Not rolling back prepared transaction %v on foreign database %v. `+
				`A manual rollback may be required to avoid the DB hanging.`,
				ptx.GID, ptx.Database)
			continue
		}
		logger.Infof("Rolling back prepared transaction %v (xid %d) created by %v at %v",
			ptx.GID, ptx.XID, ptx.Owner, ptx.Time)
		sqlRollback := fmt.Sprintf(`ROLLBACK PREPARED '%s'`, ptx.GID)
		if _, err := conn.Exec(ctx, sqlRollback); err != nil {
			return 0, fmt.Errorf("ROLLBACK PREPARED failed: %v", err)
		}
		closed++
	}
	return closed, nil
}

const (
	InternalSchemaName = "kwild_internal"

	sentryTableName     = `sentry`
	sentryTableNameFull = InternalSchemaName + "." + sentryTableName
	sentrySeqName       = InternalSchemaName + "." + "sentry_seq"

	sqlCreateSentryTable = `CREATE TABLE IF NOT EXISTS ` + sentryTableNameFull + ` (seq INT8);`
	sqlCreateSentrySeq   = `CREATE SEQUENCE IF NOT EXISTS ` + sentrySeqName

	// incrementSeq uses INSERT (not UPDATE) so that each prepared transaction
	// gets its own row, avoiding row-level lock contention between concurrent
	// prepared transactions that would deadlock on a single-row UPDATE.
	sqlInsertSentrySeq = `INSERT INTO ` + sentryTableNameFull + ` (seq) VALUES (nextval('` + sentrySeqName + `')) RETURNING seq;`

	sqlCreateSchemaTemplate = `CREATE SCHEMA IF NOT EXISTS %s;`
	sqlSchemaExists         = `SELECT schema_name
		FROM information_schema.schemata
		WHERE schema_name = $1;`

	sqlSchemaTableExists = `SELECT EXISTS (
		SELECT FROM information_schema.tables 
		WHERE  table_schema = $1
		AND    table_name   = $2
	);`
	sqlTableExists = `SELECT to_regclass($1);`
)

func tableExists(ctx context.Context, schema, table string, conn *pgx.Conn) (bool, error) {
	rows, _ := conn.Query(ctx, sqlSchemaTableExists, schema, table)
	return pgx.CollectExactlyOneRow(rows, pgx.RowTo[bool])
}

// ensureFullReplicaIdentityTrigger creates an event trigger to set the replica
// identity to "full" for all tables that are created.
func ensureFullReplicaIdentityTrigger(ctx context.Context, conn *pgx.Conn) error {
	// Create the function for the even trigger
	_, err := conn.Exec(ctx, sqlCreateOrReplaceReplicaIdentity)
	if err != nil {
		return err
	}

	// Create the event trigger that calls the function.
	// Drop it always in case we update the logic, new nodes will automatically get the new logic
	_, err = conn.Exec(ctx, sqlDropEvtTriggerReplIdent)
	if err != nil {
		return err
	}

	_, err = conn.Exec(ctx, sqlCreateEvtTriggerReplIdent)
	return err
}

func ensureSentryTable(ctx context.Context, conn *pgx.Conn) error {
	exists, err := tableExists(ctx, InternalSchemaName, sentryTableName, conn)
	if err != nil {
		return err
	}

	if !exists {
		createStmt := fmt.Sprintf(sqlCreateSchemaTemplate, InternalSchemaName)
		if _, err = conn.Exec(ctx, createStmt); err != nil {
			return err
		}
		if _, err = conn.Exec(ctx, sqlCreateSentryTable); err != nil {
			return err
		}
	}

	// Create the sequence if it doesn't exist yet. This is the one-time
	// migration from UPDATE-based sentry to INSERT-based sentry.
	// Seed from existing rows so nextval picks up where the old approach left off.
	// Use GREATEST to never lower the sequence below 1 (PG minimum).
	if _, err = conn.Exec(ctx, sqlCreateSentrySeq); err != nil {
		return err
	}
	var maxSeq int64
	if err = conn.QueryRow(ctx, `SELECT COALESCE(MAX(seq), 0) FROM `+sentryTableNameFull).Scan(&maxSeq); err != nil {
		return err
	}
	if maxSeq > 0 {
		// Advance the sequence if table rows are ahead (migration path).
		// Use GREATEST to never lower the sequence — it may be ahead due to
		// rolled-back transactions whose nextval calls are not reversed.
		if _, err = conn.Exec(ctx,
			`SELECT setval('`+sentrySeqName+`', GREATEST((SELECT last_value FROM `+sentrySeqName+`), $1))`, maxSeq); err != nil {
			return err
		}
	}

	// Clean up old sentry rows. At startup there are no active prepared
	// transactions (rollbackPreparedTxns already ran), so all rows are
	// stale. This prevents unbounded table growth from INSERT-based sequencing.
	_, err = conn.Exec(ctx, `DELETE FROM `+sentryTableNameFull)
	return err
}

func incrementSeq(ctx context.Context, tx pgx.Tx) (int64, error) {
	var seq int64
	if err := tx.QueryRow(ctx, sqlInsertSentrySeq).Scan(&seq); err != nil {
		return 0, fmt.Errorf("sentry seq insert failed: %w", err)
	}
	return seq, nil
}
