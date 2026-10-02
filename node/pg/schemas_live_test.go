//go:build pglive

package pg

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// schemasTestDB creates an empty database for one test and drops it
// afterwards, rolling back anything the test left prepared in it first.
func schemasTestDB(t *testing.T, name string) *ConnConfig {
	t.Helper()
	ctx := context.Background()
	conf := &ConnConfig{Host: cfg.Host, Port: cfg.Port, User: cfg.User, Pass: cfg.Pass, DBName: name}
	admin := schemasTestConn(t, &ConnConfig{Host: conf.Host, Port: conf.Port, User: conf.User, Pass: conf.Pass, DBName: "postgres"})
	drop := func() {
		if conn, err := pgx.Connect(ctx, connString(conf.Host, conf.Port, conf.User, conf.Pass, name, false)); err == nil {
			rows, _ := conn.Query(ctx, `SELECT gid FROM pg_prepared_xacts WHERE database = current_database()`)
			gids, _ := pgx.CollectRows(rows, pgx.RowTo[string])
			for _, gid := range gids {
				_, _ = conn.Exec(ctx, fmt.Sprintf(`ROLLBACK PREPARED '%s'`, gid))
			}
			conn.Close(ctx)
		}
		_, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		require.NoError(t, err)
	}
	drop()
	_, err := admin.Exec(ctx, `CREATE DATABASE `+name+` OWNER kwild`)
	require.NoError(t, err)
	t.Cleanup(drop)
	return conf
}

func schemasTestConn(t *testing.T, conf *ConnConfig) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connString(conf.Host, conf.Port, conf.User, conf.Pass, conf.DBName, false))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close(ctx) })
	return conn
}

func TestOutsideDependents(t *testing.T) {
	ctx := context.Background()
	conf := schemasTestDB(t, "kwil_test_outside_dependents")
	conn := schemasTestConn(t, conf)
	exec := func(stmt string) {
		t.Helper()
		_, err := conn.Exec(ctx, stmt)
		require.NoError(t, err)
	}
	owned := []string{"main", "kwild_x"}

	// Objects inside the owned schemas, among them the kinds that pg_depend
	// files under their table rather than a schema, a trigger on an owned
	// table that calls a function outside them, as pg_repack's do, and a
	// publication of every table: nothing outside depends on what is inside.
	exec(`CREATE SCHEMA main; CREATE SCHEMA kwild_x; CREATE SCHEMA op; CREATE SCHEMA repack`)
	exec(`CREATE TYPE kwild_x.kind AS ENUM ('a', 'b')`)
	exec(`CREATE TABLE main.records (id INT8 PRIMARY KEY, v TEXT DEFAULT 'none', k kwild_x.kind)`)
	exec(`CREATE VIEW main.all_records AS SELECT * FROM main.records`)
	exec(`CREATE POLICY readers ON main.records USING (true)`)
	exec(`CREATE STATISTICS main.records_stats ON id, v FROM main.records`)
	exec(`CREATE FUNCTION repack.log() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$`)
	exec(`CREATE TRIGGER repack_log AFTER INSERT ON main.records FOR EACH ROW EXECUTE FUNCTION repack.log()`)
	exec(`CREATE PUBLICATION all_tables FOR ALL TABLES`)
	exec(`CREATE TABLE op.notes (v TEXT)`)

	dependents, err := OutsideDependents(ctx, conf, owned)
	require.NoError(t, err)
	require.Empty(t, dependents)

	// Objects outside that a DROP SCHEMA ... CASCADE of the owned schemas
	// would take with it.
	exec(`CREATE VIEW op.recent AS SELECT id FROM main.records`)
	exec(`CREATE TABLE op.child (record INT8 REFERENCES main.records (id))`)
	exec(`CREATE TABLE op.typed (k kwild_x.kind)`)
	exec(`CREATE FUNCTION kwild_x.audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$`)
	exec(`CREATE TRIGGER audit AFTER INSERT ON op.notes FOR EACH ROW EXECUTE FUNCTION kwild_x.audit()`)
	exec(`CREATE PUBLICATION records FOR TABLE main.records`)

	dependents, err = OutsideDependents(ctx, conf, owned)
	require.NoError(t, err)
	require.Equal(t, []string{
		"constraint child_record_fkey on table op.child depends on index main.records_pkey",
		"constraint child_record_fkey on table op.child depends on table main.records",
		"publication of table main.records in publication records depends on table main.records",
		"rule _RETURN on view op.recent depends on table main.records",
		"table op.typed depends on type kwild_x.kind",
		"trigger audit on table op.notes depends on function kwild_x.audit()",
	}, dependents)
}

func TestDropSchemasExceptRollsBackOrphanedPreparedTxns(t *testing.T) {
	ctx := context.Background()
	conf := schemasTestDB(t, "kwil_test_drop_prepared")
	conn := schemasTestConn(t, conf)
	_, err := conn.Exec(ctx, `CREATE SCHEMA main; CREATE TABLE main.records (id INT8); CREATE SCHEMA keep_me`)
	require.NoError(t, err)

	// A node stopped between PREPARE TRANSACTION and COMMIT PREPARED leaves a
	// transaction that holds a lock on main.records.
	stopped := schemasTestConn(t, conf)
	tx, err := stopped.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO main.records VALUES (1)`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `PREPARE TRANSACTION 'stopped_node'`)
	require.NoError(t, err)
	require.NoError(t, stopped.Close(ctx))

	// Without the rollback, the drop waits on that lock until this times out.
	dropCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	dropped, err := DropSchemasExcept(dropCtx, conf, []string{"public", "keep_me"})
	require.NoError(t, err)
	require.Equal(t, []string{"main"}, dropped)

	var prepared int
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM pg_prepared_xacts WHERE database = current_database()`).Scan(&prepared))
	require.Zero(t, prepared)
	schemas, err := ListSchemas(ctx, conf)
	require.NoError(t, err)
	require.Equal(t, []string{"keep_me", "public"}, schemas)
}
