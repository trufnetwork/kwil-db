package pg

import (
	"context"
	"errors"
	"fmt"
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

	sqlInsertSentryRow = `INSERT INTO ` + sentryTableNameFull + ` (seq) VALUES ($1);`
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
