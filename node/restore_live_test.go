//go:build pglive

package node

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
)

// restoreTestDB creates an empty database for one test and drops it after.
func restoreTestDB(t *testing.T, name string) config.DBConfig {
	t.Helper()
	ctx := context.Background()
	db := config.DBConfig{Host: "127.0.0.1", Port: "5432", User: "kwild", Pass: "kwild", DBName: name}

	admin, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%s user=%s password=%s database=postgres sslmode=disable",
		db.Host, db.Port, db.User, db.Pass))
	require.NoError(t, err)
	drop := func() {
		_, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		require.NoError(t, err)
	}
	drop()
	_, err = admin.Exec(ctx, `CREATE DATABASE `+name+` OWNER kwild`)
	require.NoError(t, err)
	t.Cleanup(func() {
		drop()
		admin.Close(ctx)
	})
	return db
}

func tablesIn(t *testing.T, db config.DBConfig) []string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%s user=%s password=%s database=%s sslmode=disable",
		db.Host, db.Port, db.User, db.Pass, db.DBName))
	require.NoError(t, err)
	defer conn.Close(ctx)
	rows, _ := conn.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'restored' ORDER BY 1`)
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return names
}

func restore(t *testing.T, db config.DBConfig, dump string) error {
	sum := sha256.Sum256([]byte(dump))
	return RestoreDB(context.Background(), strings.NewReader(dump), db, sum[:], log.DiscardLogger)
}

func TestRestoreDBStopsAtTheFirstFailedStatement(t *testing.T) {
	db := restoreTestDB(t, "kwil_test_restore_error")
	dump := "CREATE SCHEMA restored;\n" +
		"CREATE TABLE restored.before (v int8);\n" +
		"COPY restored.before (v) FROM stdin;\n" +
		"1\n" +
		"not a number\n" +
		"\\.\n" +
		"CREATE TABLE restored.after (v int8);\n" +
		// More than a pipe buffer after the failure, so psql exits while the
		// dump is still being written and the write sees a broken pipe.
		strings.Repeat("SELECT 1;\n", 200_000)

	err := restore(t, db, dump)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid input syntax for type bigint")
	require.Equal(t, []string{"before"}, tablesIn(t, db), "psql kept going after the failed COPY")
}

func TestRestoreDBAcceptsRestrictLines(t *testing.T) {
	db := restoreTestDB(t, "kwil_test_restore_restrict")
	// The shape pg_dump 16.10 and later give a sanitized snapshot.
	dump := "\\restrict key1\n" +
		"\\unrestrict key1\n" +
		"\\restrict key1\n" +
		"CREATE SCHEMA restored;\n" +
		"CREATE TABLE restored.blocks (v int8);\n" +
		"COPY restored.blocks (v) FROM stdin;\n" +
		"1\n" +
		"\\.\n" +
		"\\unrestrict key1\n"

	require.NoError(t, restore(t, db, dump))
	require.Equal(t, []string{"blocks"}, tablesIn(t, db))
}

func TestRestoreDBRejectsAWrongHash(t *testing.T) {
	db := restoreTestDB(t, "kwil_test_restore_hash")
	dump := "CREATE SCHEMA restored;\n"
	wrong := sha256.Sum256([]byte("something else"))

	err := RestoreDB(context.Background(), strings.NewReader(dump), db, wrong[:], log.DiscardLogger)
	require.ErrorContains(t, err, "invalid snapshot hash")
}
