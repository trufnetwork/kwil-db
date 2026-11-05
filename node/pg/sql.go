package pg

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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

	// sqlForeignPreparedTxns lists the prepared transactions in the current
	// database that another role prepared, each with that role. Postgres lets
	// only the role that prepared a transaction, or a superuser, roll it back,
	// and being a member of that role is not enough. The role is NULL when it
	// has since been dropped.
	sqlForeignPreparedTxns = `SELECT format('%L (prepared by %s)', gid, COALESCE(owner::text, 'a dropped role'))
	FROM pg_prepared_xacts
	WHERE database = current_database() AND owner IS DISTINCT FROM current_user
	ORDER BY prepared, gid;`

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
	RETURNS NUMERIC(16, 6) AS $$` + sqlParseUnixTimestampBody + `$$ LANGUAGE plpgsql;`

	// sqlParseUnixTimestampBody, and sqlFormatUnixTimestampBody below, are the
	// bodies of the functions, as Postgres keeps them in pg_proc.prosrc.
	sqlParseUnixTimestampBody = `
	BEGIN
		RETURN EXTRACT(EPOCH FROM TO_TIMESTAMP(timestamp_string, format_string))::numeric(16, 6);
	END;
	`

	// this is the inverse of parse_unix_timestamp
	sqlCreateFormatUnixTimestampFunc = `CREATE OR REPLACE FUNCTION format_unix_timestamp(unix_timestamp NUMERIC(16, 6), format_string text)
	RETURNS TEXT AS $$` + sqlFormatUnixTimestampBody + `$$ LANGUAGE plpgsql;`

	sqlFormatUnixTimestampBody = `
	BEGIN
		RETURN TO_CHAR(TO_TIMESTAMP(unix_timestamp), format_string);
	END;
	`

	// sqlReplicaIdentityFuncBody is the body of set_replica_identity(), as
	// Postgres keeps it in pg_proc.prosrc.
	sqlReplicaIdentityFuncBody = `
DECLARE
    obj record;
BEGIN
    FOR obj IN
        SELECT * FROM pg_event_trigger_ddl_commands() WHERE command_tag = 'CREATE TABLE'
    LOOP
        EXECUTE 'ALTER TABLE ' || obj.object_identity || ' REPLICA IDENTITY FULL';
    END LOOP;
END;
`

	sqlCreateOrReplaceReplicaIdentity = `CREATE OR REPLACE FUNCTION set_replica_identity()
RETURNS event_trigger
LANGUAGE plpgsql
AS $$` + sqlReplicaIdentityFuncBody + `$$;`

	// sqlCheckReplicaIdentityTrigger reads whether the event trigger that
	// ensureFullReplicaIdentityTrigger creates is enabled, fires on CREATE
	// TABLE alone, and runs set_replica_identity() with the body given as $1.
	// It also reads whether the current role is a member of none of the roles
	// that own the trigger, its function and the function's schema, since an
	// owner may drop or change them.
	sqlCheckReplicaIdentityTrigger = `SELECT e.evtenabled = 'O',
		e.evtevent = 'ddl_command_end' AND e.evttags IS NOT DISTINCT FROM ARRAY['CREATE TABLE'],
		p.proname = 'set_replica_identity' AND l.lanname = 'plpgsql' AND p.prosrc = $1,
		NOT (pg_has_role(e.evtowner, 'MEMBER') OR pg_has_role(p.proowner, 'MEMBER') OR pg_has_role(n.nspowner, 'MEMBER'))
	FROM pg_event_trigger e
	JOIN pg_proc p ON p.oid = e.evtfoid
	JOIN pg_namespace n ON n.oid = p.pronamespace
	JOIN pg_language l ON l.oid = p.prolang
	WHERE e.evtname = 'set_replica_identity_on_create';`

	// sqlCheckPublication reads whether the publication named $1 is for all
	// tables and publishes every change as CREATE PUBLICATION does by default,
	// and whether the current role is not a member of the role that owns it,
	// since an owner may drop or change it.
	sqlCheckPublication = `SELECT puballtables AND pubinsert AND pubupdate AND pubdelete AND pubtruncate AND NOT pubviaroot,
		NOT pg_has_role(pubowner, 'MEMBER')
	FROM pg_publication WHERE pubname = $1;`

	// sqlServerRoleMemberships lists the superuser roles, and the roles that
	// may run programs on the database server or read and write its files,
	// that the current role is a member of.
	sqlServerRoleMemberships = `SELECT CASE WHEN rolsuper THEN rolname::text || ' (a superuser)' ELSE rolname::text END
	FROM pg_roles
	WHERE (rolsuper OR rolname IN ('pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files'))
		AND pg_has_role(oid, 'MEMBER')
	ORDER BY rolname;`

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

// checkRole verifies that the db user/role has the REPLICATION attribute, and
// reports whether it is a superuser. A role that is not a superuser must not
// be a member of a superuser role, or of a role that may run programs on the
// database server or read and write its files. It must also be allowed to set
// session_replication_role, which a snapshot restore sets.
func checkRole(ctx context.Context, conn *pgx.Conn) (superuser bool, err error) {
	user := conn.Config().User
	var isReplicator bool
	err = conn.QueryRow(ctx, `SELECT rolsuper, rolreplication FROM pg_roles WHERE rolname = $1;`, user).
		Scan(&superuser, &isReplicator)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("postgres role does not exists: %v", user)
		}
		return false, fmt.Errorf("unable to verify superuser status of postgres role %v: %w", user, err)
	}
	if !isReplicator {
		return false, fmt.Errorf("postgres role does not have the REPLICATION attribute: %v", user)
	}
	if superuser {
		return true, nil
	}

	rows, _ := conn.Query(ctx, sqlServerRoleMemberships)
	memberOf, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return false, fmt.Errorf("unable to read the role memberships of postgres role %v: %w", user, err)
	}
	if len(memberOf) > 0 {
		revoke := "that membership"
		if len(memberOf) > 1 {
			revoke = "those memberships"
		}
		return false, fmt.Errorf("postgres role %s is not a superuser but is a member of %s, and a role that is not "+
			"a superuser must not be able to act as one, run programs on the database server, or read and write its "+
			"files; revoke %s, then start kwild again", user, strings.Join(memberOf, ", "), revoke)
	}

	var maySetReplicationRole bool
	err = conn.QueryRow(ctx, `SELECT has_parameter_privilege('session_replication_role', 'SET');`).
		Scan(&maySetReplicationRole)
	if err != nil {
		return false, fmt.Errorf("unable to verify whether postgres role %v may set session_replication_role: %w", user, err)
	}
	if !maySetReplicationRole {
		return false, errSuperuserSetup(conn.Config(),
			"postgres role "+user+" may not set session_replication_role, which a snapshot restore sets")
	}
	return false, nil
}

// errSuperuserSetup is the error for a role that is not a superuser when
// something only a superuser may set up is missing or not as kwild needs it.
// It names all of that, so that one pass by a superuser sets up everything.
func errSuperuserSetup(cfg *pgx.ConnConfig, problem string) error {
	return fmt.Errorf("%s; postgres role %s is not a superuser, so a superuser must first run "+
		"GRANT SET ON PARAMETER session_replication_role TO %[2]s, and create in database %[3]s, owned by "+
		"the superuser: the publication %[4]s FOR ALL TABLES, the function set_replica_identity() as kwild "+
		"defines it in a schema the superuser owns, and the event trigger set_replica_identity_on_create that "+
		"runs it ON ddl_command_end WHEN TAG IN ('CREATE TABLE') (NewDB in kwil-db's node/pg package describes "+
		"each); then start kwild again",
		problem, cfg.User, cfg.Database, publicationName)
}

func ensureCollation(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, sqlCreateCollationNOCASE)
	return err
}

func ensurePublication(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, fmt.Sprintf(sqlCreatePublicationINE, publicationName))
	return err
}

// checkPublication is ensurePublication for a role that is not a superuser,
// which may not create a publication for all tables. It verifies that the
// publication is as ensurePublication creates it, and that the role is not a
// member of the role that owns it.
func checkPublication(ctx context.Context, conn *pgx.Conn) error {
	var asCreated, notOwned bool
	err := conn.QueryRow(ctx, sqlCheckPublication, publicationName).Scan(&asCreated, &notOwned)
	var problem string
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		problem = "does not exist"
	case err != nil:
		return fmt.Errorf("failed to read publication: %w", err)
	case !asCreated:
		problem = "is not for all tables with every change published, as kwild creates it"
	case !notOwned:
		problem = "can be dropped or changed by postgres role " + conn.Config().User + ", which owns it or is a member of its owner"
	default:
		return nil
	}
	cfg := conn.Config()
	return errSuperuserSetup(cfg, fmt.Sprintf("publication %s in database %s %s", publicationName, cfg.Database, problem))
}

func ensureUUIDExtension(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, sqlCreateUUIDExtension)
	return err
}

func ensurePgCryptoExtension(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto;`)
	return err
}

var (
	funcParseUnixTimestamp = &helperFunc{sqlCreateParseUnixTimestampFunc, "parse_unix_timestamp(text, text)",
		"timestamp_string text, format_string text", "numeric", sqlParseUnixTimestampBody}
	funcFormatUnixTimestamp = &helperFunc{sqlCreateFormatUnixTimestampFunc, "format_unix_timestamp(numeric, text)",
		"unix_timestamp numeric, format_string text", "text", sqlFormatUnixTimestampBody}
)

func ensureUnixTimestampFuncs(ctx context.Context, conn *pgx.Conn, superuser bool) error {
	err := ensureHelperFunc(ctx, conn, superuser, funcParseUnixTimestamp)
	if err != nil {
		return err
	}

	return ensureHelperFunc(ctx, conn, superuser, funcFormatUnixTimestamp)
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

// MayCreateDatabase reports whether the configured role may create a database
// owned by the role named owner, as CREATE DATABASE ... OWNER requires: whether
// it is a superuser, or has the CREATEDB attribute and may SET ROLE to owner.
func MayCreateDatabase(ctx context.Context, cfg *ConnConfig, owner string) (bool, error) {
	conn, err := pgx.Connect(ctx, connString(cfg.Host, cfg.Port, cfg.User, cfg.Pass, cfg.DBName, false))
	if err != nil {
		return false, err
	}
	defer conn.Close(ctx)

	var may bool
	err = conn.QueryRow(ctx, `SELECT u.rolsuper OR (u.rolcreatedb AND EXISTS (
			SELECT FROM pg_roles o WHERE o.rolname = $1 AND pg_has_role(o.oid, 'SET')))
		FROM pg_roles u WHERE u.rolname = current_user`, owner).Scan(&may)
	return may, err
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

// checkPreparedTxnOwners is for a role that is not a superuser, which may roll
// back only the prepared transactions that it prepared. It returns an error
// that names each prepared transaction in the database that another role
// prepared, so that rollbackPreparedTxns does not stop part way through.
func checkPreparedTxnOwners(ctx context.Context, conn *pgx.Conn) error {
	rows, _ := conn.Query(ctx, sqlForeignPreparedTxns)
	foreign, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("failed to read prepared transactions: %w", err)
	}
	if len(foreign) == 0 {
		return nil
	}
	cfg := conn.Config()
	return fmt.Errorf("postgres role %s is not a superuser, so it may roll back only the prepared transactions it "+
		"prepared, but database %s holds prepared transactions that other roles prepared: %s; a superuser must "+
		"first run ROLLBACK PREPARED for each in database %[2]s, then start kwild again",
		cfg.User, cfg.Database, strings.Join(foreign, ", "))
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

// checkFullReplicaIdentityTrigger is ensureFullReplicaIdentityTrigger for a
// role that is not a superuser, which may not create an event trigger. It
// verifies that the trigger and its function are as
// ensureFullReplicaIdentityTrigger creates them. It compares the function's
// name, language and body, so the function may be in another schema or fix its
// own search_path. It also verifies that the role is not a member of the roles
// that own the trigger, the function and the function's schema, so that the
// role may neither drop nor change them.
func checkFullReplicaIdentityTrigger(ctx context.Context, conn *pgx.Conn) error {
	var enabled, onCreateTable, runsFunc, notOwned bool
	err := conn.QueryRow(ctx, sqlCheckReplicaIdentityTrigger, sqlReplicaIdentityFuncBody).
		Scan(&enabled, &onCreateTable, &runsFunc, &notOwned)
	var problem string
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		problem = "does not exist"
	case err != nil:
		return fmt.Errorf("failed to read full replication identity trigger: %w", err)
	case !enabled:
		problem = "is not enabled as kwild creates it"
	case !onCreateTable:
		problem = "does not fire on CREATE TABLE alone"
	case !runsFunc:
		problem = "does not run set_replica_identity() as kwild defines it"
	case !notOwned:
		problem = "can be dropped or changed by postgres role " + conn.Config().User +
			", which owns, or is a member of the owner of, the trigger, its function or the function's schema"
	default:
		return nil
	}
	cfg := conn.Config()
	return errSuperuserSetup(cfg, fmt.Sprintf("event trigger set_replica_identity_on_create in database %s %s",
		cfg.Database, problem))
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
