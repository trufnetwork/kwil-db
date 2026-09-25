package node

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
)

func TestRestoreDBRestrictsPsqlMetaCommands(t *testing.T) {
	tempDir := t.TempDir()
	argsFile := filepath.Join(tempDir, "args")
	stdinFile := filepath.Join(tempDir, "stdin")
	psqlPath := filepath.Join(tempDir, "psql")
	require.NoError(t, os.WriteFile(psqlPath, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PSQL_ARGS_FILE\"\ncat > \"$PSQL_STDIN_FILE\"\n"), 0o755))
	t.Setenv("PSQL_ARGS_FILE", argsFile)
	t.Setenv("PSQL_STDIN_FILE", stdinFile)

	dump := []byte("SELECT 1;\n\\! touch /tmp/kwil-statesync-pwned\n")
	hash := sha256.Sum256(dump)
	err := restoreDB(context.Background(), bytes.NewReader(dump), config.DBConfig{
		Host: "localhost", Port: "5432", User: "kwild", DBName: "kwild",
	}, hash[:], psqlPath, true, log.DiscardLogger)
	require.NoError(t, err)

	stdin, err := os.ReadFile(stdinFile)
	require.NoError(t, err)
	parts := strings.SplitN(string(stdin), "\n", 2)
	require.Len(t, parts, 2)
	require.Regexp(t, regexp.MustCompile(`^\\restrict [0-9a-f]{64}$`), parts[0])
	require.Equal(t, string(dump), parts[1])

	args, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	require.Contains(t, string(args), "--no-psqlrc\n")
	require.Contains(t, string(args), "--set\nON_ERROR_STOP=1\n")
}

func TestRestoreDBDoesNotNestRestrictionForTrustedSnapshot(t *testing.T) {
	tempDir := t.TempDir()
	stdinFile := filepath.Join(tempDir, "stdin")
	psqlPath := filepath.Join(tempDir, "psql")
	require.NoError(t, os.WriteFile(psqlPath, []byte("#!/bin/sh\ncat > \"$PSQL_STDIN_FILE\"\n"), 0o755))
	t.Setenv("PSQL_STDIN_FILE", stdinFile)

	dump := []byte("\\restrict DumpKey\nSELECT 1;\n\\unrestrict DumpKey\n")
	hash := sha256.Sum256(dump)
	require.NoError(t, restoreDB(context.Background(), bytes.NewReader(dump), config.DBConfig{},
		hash[:], psqlPath, false, log.DiscardLogger))

	stdin, err := os.ReadFile(stdinFile)
	require.NoError(t, err)
	require.Equal(t, dump, stdin)
}

func TestStateSyncRejectsSnapshotBeforeStartingPsql(t *testing.T) {
	tempDir := t.TempDir()
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, err := zw.Write([]byte("SELECT 1;\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "chunk-0.sql.gz"), compressed.Bytes(), 0o600))

	psqlPath := filepath.Join(tempDir, "psql")
	startedFile := filepath.Join(tempDir, "started")
	require.NoError(t, os.WriteFile(psqlPath, []byte("#!/bin/sh\ntouch \"$PSQL_STARTED_FILE\"\n"), 0o755))
	t.Setenv("PSQL_STARTED_FILE", startedFile)

	service := &StateSyncService{
		cfg:         &config.StateSyncConfig{PsqlPath: psqlPath},
		snapshotDir: tempDir,
		log:         log.DiscardLogger,
	}
	err = service.restoreDB(context.Background(), &snapshotMetadata{
		Chunks: 1,
		Hash:   bytes.Repeat([]byte{0xff}, sha256.Size),
	})
	require.ErrorContains(t, err, "invalid snapshot hash")
	require.NoFileExists(t, startedFile)
}
