//go:build pglive

package setup

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/node/pg"
)

// scratchDB creates an empty database for one test and drops it afterwards,
// rolling back anything a test left prepared in it first.
func scratchDB(t *testing.T, name string) *pg.ConnConfig {
	t.Helper()
	ctx := context.Background()
	conf := &pg.ConnConfig{Host: "127.0.0.1", Port: "5432", User: "kwild", Pass: "kwild", DBName: name}

	drop := func() {
		if conn, err := connect(ctx, conf); err == nil {
			rows, _ := conn.Query(ctx, `SELECT gid FROM pg_prepared_xacts WHERE database = current_database()`)
			gids, _ := pgx.CollectRows(rows, pgx.RowTo[string])
			for _, gid := range gids {
				_, _ = conn.Exec(ctx, fmt.Sprintf(`ROLLBACK PREPARED '%s'`, gid))
			}
			conn.Close(ctx)
		}
		admin, err := connect(ctx, &pg.ConnConfig{Host: conf.Host, Port: conf.Port, User: conf.User, Pass: conf.Pass, DBName: "postgres"})
		require.NoError(t, err)
		defer admin.Close(ctx)
		_, err = admin.Exec(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		require.NoError(t, err)
	}

	drop()
	admin, err := connect(ctx, &pg.ConnConfig{Host: conf.Host, Port: conf.Port, User: conf.User, Pass: conf.Pass, DBName: "postgres"})
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `CREATE DATABASE `+name+` OWNER kwild`)
	admin.Close(ctx)
	require.NoError(t, err)
	t.Cleanup(drop)

	return conf
}

func connect(ctx context.Context, conf *pg.ConnConfig) (*pgx.Conn, error) {
	return pgx.Connect(ctx, fmt.Sprintf("host=%s port=%s user=%s password=%s database=%s sslmode=disable",
		conf.Host, conf.Port, conf.User, conf.Pass, conf.DBName))
}

// leavePreparedTxn does what a node stopped between PREPARE TRANSACTION and
// COMMIT PREPARED does: it prepares a write and disconnects.
func leavePreparedTxn(t *testing.T, conf *pg.ConnConfig, gid string) {
	t.Helper()
	ctx := context.Background()
	conn, err := connect(ctx, conf)
	require.NoError(t, err)
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS blocks (height INT8)`)
	require.NoError(t, err)
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO blocks VALUES (1)`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, fmt.Sprintf(`PREPARE TRANSACTION '%s'`, gid))
	require.NoError(t, err)
}

func countPrepared(t *testing.T, conf *pg.ConnConfig) int {
	t.Helper()
	ctx := context.Background()
	conn, err := connect(ctx, conf)
	require.NoError(t, err)
	defer conn.Close(ctx)
	var n int
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM pg_prepared_xacts WHERE database = current_database()`).Scan(&n))
	return n
}

func tableExists(t *testing.T, conf *pg.ConnConfig) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := connect(ctx, conf)
	require.NoError(t, err)
	defer conn.Close(ctx)
	var exists bool
	require.NoError(t, conn.QueryRow(ctx, `SELECT to_regclass('public.blocks') IS NOT NULL`).Scan(&exists))
	return exists
}

func TestResetPGStateClearsPreparedTxns(t *testing.T) {
	conf := scratchDB(t, "kwil_test_reset_prepared")
	leavePreparedTxn(t, conf, "left_by_stopped_node")
	require.Equal(t, 1, countPrepared(t, conf))

	require.NoError(t, resetPGState(context.Background(), conf))

	require.Equal(t, 0, countPrepared(t, conf))
	require.False(t, tableExists(t, conf), "the database was not recreated empty")
}

func TestResetPGStateWithoutPreparedTxns(t *testing.T) {
	conf := scratchDB(t, "kwil_test_reset_clean")
	leavePreparedTxn(t, conf, "committed_later")
	ctx := context.Background()
	conn, err := connect(ctx, conf)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `COMMIT PREPARED 'committed_later'`)
	require.NoError(t, err)
	require.NoError(t, conn.Close(ctx))

	require.NoError(t, resetPGState(ctx, conf))

	require.False(t, tableExists(t, conf), "the database was not recreated empty")
}

func TestResetPGStateRefusesWhileConnected(t *testing.T) {
	conf := scratchDB(t, "kwil_test_reset_in_use")
	leavePreparedTxn(t, conf, "held_by_running_node")
	ctx := context.Background()
	running, err := connect(ctx, conf) // a node that is still running
	require.NoError(t, err)
	defer running.Close(ctx)

	err = resetPGState(ctx, conf)
	require.ErrorIs(t, err, pg.ErrDatabaseInUse)

	// Nothing was touched: the running node's transaction and data remain.
	require.Equal(t, 1, countPrepared(t, conf))
	require.True(t, tableExists(t, conf))
}

// TestResetPGStateAsDatabaseOwner resets as a role that owns the database but
// is not a superuser. Postgres lets such a role drop the database, but it may
// create it again owned by kwild only with CREATEDB and the right to SET ROLE
// kwild. Without both, the reset refuses before it changes anything.
func TestResetPGStateAsDatabaseOwner(t *testing.T) {
	const role, name = "kwil_test_reset_owner", "kwil_test_reset_owned"
	ctx := context.Background()
	admin, err := connect(ctx, &pg.ConnConfig{Host: "127.0.0.1", Port: "5432", User: "kwild", Pass: "kwild", DBName: "postgres"})
	require.NoError(t, err)
	t.Cleanup(func() { admin.Close(ctx) })
	dropRole := func(t *testing.T) {
		_, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		require.NoError(t, err)
		_, err = admin.Exec(ctx, `DROP ROLE IF EXISTS `+role)
		require.NoError(t, err)
	}

	for _, tc := range []struct {
		name  string
		stmts []string // that give the role its attributes and memberships
		reset bool     // or refuse
	}{
		{"without CREATEDB", []string{`ALTER ROLE ` + role + ` NOCREATEDB`}, false},
		{"with CREATEDB but without SET ROLE kwild", []string{`ALTER ROLE ` + role + ` CREATEDB`}, false},
		{"with CREATEDB and SET ROLE kwild", []string{`ALTER ROLE ` + role + ` CREATEDB`,
			`GRANT kwild TO ` + role + ` WITH SET TRUE`}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dropRole(t) // left by an interrupted run
			_, err := admin.Exec(ctx, `CREATE ROLE `+role+` LOGIN NOSUPERUSER PASSWORD 'kwild'`)
			require.NoError(t, err)
			t.Cleanup(func() { dropRole(t) }) // after scratchDB drops the database
			for _, stmt := range tc.stmts {
				_, err = admin.Exec(ctx, stmt)
				require.NoError(t, err)
			}

			conf := scratchDB(t, name)
			_, err = admin.Exec(ctx, `ALTER DATABASE `+name+` OWNER TO `+role)
			require.NoError(t, err)
			conn, err := connect(ctx, conf)
			require.NoError(t, err)
			_, err = conn.Exec(ctx, `CREATE TABLE blocks (height INT8)`)
			require.NoError(t, err)
			require.NoError(t, conn.Close(ctx))

			ownerConf := *conf
			ownerConf.User = role
			err = resetPGState(ctx, &ownerConf)
			if tc.reset {
				require.NoError(t, err)
				require.False(t, tableExists(t, conf), "the database was not recreated empty")
				return
			}
			require.ErrorContains(t, err, "postgres role "+role+" is not a superuser and does not have both "+
				"CREATEDB and the right to SET ROLE kwild")
			require.True(t, tableExists(t, conf), "the database was dropped")
		})
	}
}
