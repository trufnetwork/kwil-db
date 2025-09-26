package snapshotter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
)

const (
	dump1File = "test_data/dump1.sql"
	dump2File = "test_data/dump2.sql"
)

type MockNamespaceManager struct {
}

func (m *MockNamespaceManager) ListPostgresSchemasToDump() []string {
	return nil
}

func TestSanitizeLogicalDump(t *testing.T) {
	dir := t.TempDir()
	logger := log.DiscardLogger
	// Create a snapshotter
	ns := &MockNamespaceManager{}

	snapshotter := NewSnapshotter(nil, dir, ns, logger)

	// Create snapshot directory
	height := uint64(1)
	formatDir := snapshotFormatDir(dir, height, 0)
	err := os.MkdirAll(formatDir, 0755)
	require.NoError(t, err)

	data1, err := os.ReadFile(dump1File)
	require.NoError(t, err)
	data2, err := os.ReadFile(dump2File)
	require.NoError(t, err)

	var buf1 bytes.Buffer
	hash1, err := snapshotter.sanitizeDumpStream(context.Background(), height, 0, formatDir, bytes.NewReader(data1), &buf1)
	require.NoError(t, err)

	var buf2 bytes.Buffer
	hash2, err := snapshotter.sanitizeDumpStream(context.Background(), height, 0, formatDir, bytes.NewReader(data2), &buf2)
	require.NoError(t, err)

	require.Equal(t, hash1, hash2)
	require.Equal(t, buf1.Bytes(), buf2.Bytes())

	scanner := bufio.NewScanner(bytes.NewReader(buf1.Bytes()))
	for scanner.Scan() {
		line := scanner.Text()
		// Ensure that the line does not begin with SET, SELECT or white spaces
		require.NotRegexp(t, `^\s*SET|SELECT`, line)
	}

	err = scanner.Err()
	require.NoError(t, err)
}

func TestCompressStreamDeterministic(t *testing.T) {
	data := []byte("deterministic data\n")

	var first bytes.Buffer
	require.NoError(t, compressStream(context.Background(), bytes.NewReader(data), &first))

	var second bytes.Buffer
	require.NoError(t, compressStream(context.Background(), bytes.NewReader(data), &second))

	require.Equal(t, first.Bytes(), second.Bytes())
}

func TestSplitDumpIntoChunksExactMultiple(t *testing.T) {
	dir := t.TempDir()
	logger := log.DiscardLogger
	snapshotter := NewSnapshotter(nil, dir, &MockNamespaceManager{}, logger)

	height := uint64(11)
	require.NoError(t, os.MkdirAll(snapshotChunkDir(dir, height, 0), 0o755))

	data := bytes.Repeat([]byte{0x42}, int(chunkSize))
	channel := make(chan []byte, 1)
	channel <- []byte{1, 2, 3}
	close(channel)

	snapshot, err := snapshotter.splitStreamIntoChunks(context.Background(), height, 0, bytes.NewReader(data), channel)
	require.NoError(t, err)
	require.Equal(t, uint32(1), snapshot.ChunkCount)

	entries, err := os.ReadDir(snapshotChunkDir(dir, height, 0))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	chunkPath := snapshotChunkFile(dir, height, 0, 0)
	fi, err := os.Stat(chunkPath)
	require.NoError(t, err)
	require.EqualValues(t, len(data), fi.Size())
}

func TestCopyBlockSorterSpillAndMerge(t *testing.T) {
	tmpDir := t.TempDir()
	sorter := newCopyBlockSorter(tmpDir, 32)

	lines := []string{
		"row-c\n",
		"row-a\n",
		"row-b\n",
		"row-d\n",
	}

	for _, line := range lines {
		require.NoError(t, sorter.AddLine([]byte(line)))
	}

	buf := &bytes.Buffer{}
	require.NoError(t, sorter.Flush(buf))

	expectedLines := make([]string, len(lines))
	copy(expectedLines, lines)
	sort.SliceStable(expectedLines, func(i, j int) bool {
		iHash := sha256.Sum256([]byte(expectedLines[i]))
		jHash := sha256.Sum256([]byte(expectedLines[j]))
		if cmp := bytes.Compare(iHash[:], jHash[:]); cmp != 0 {
			return cmp < 0
		}
		return expectedLines[i] < expectedLines[j]
	})

	require.Equal(t, []byte(strings.Join(expectedLines, "")), buf.Bytes())

	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)
	require.Len(t, entries, 0, "spill files should be cleaned up")
}

func TestCreateSnapshotStreaming(t *testing.T) {
	cfg := &config.DBConfig{DBName: "ignored", User: "ignored", Host: "localhost", Port: "5432"}
	dir := t.TempDir()
	logger := log.DiscardLogger
	snapshotter := NewSnapshotter(cfg, dir, &MockNamespaceManager{}, logger)

	dumpBytes, err := os.ReadFile(filepath.Join("test_data", "dump1.sql"))
	require.NoError(t, err)

	scriptPath := filepath.Join(dir, "pg_dump")
	script := "#!/bin/sh\ncat <<'EOF'\n" + string(dumpBytes) + "\nEOF\n"
	require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o755))

	originalPath := os.Getenv("PATH")
	newPath := dir
	if originalPath != "" {
		newPath = dir + string(os.PathListSeparator) + originalPath
	}
	t.Setenv("PATH", newPath)

	height := uint64(42)
	var expected bytes.Buffer
	expectedHash, err := snapshotter.sanitizeDumpStream(context.Background(), height, 0, t.TempDir(), bytes.NewReader(dumpBytes), &expected)
	require.NoError(t, err)

	snapshot, err := snapshotter.CreateSnapshot(context.Background(), height, "snapshot-stream-test", nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, expectedHash, snapshot.SnapshotHash)
	require.Equal(t, uint32(1), snapshot.ChunkCount)

	chunkPath := snapshotChunkFile(dir, height, 0, 0)
	chunkFile, err := os.Open(chunkPath)
	require.NoError(t, err)
	defer chunkFile.Close()

	gzReader, err := gzip.NewReader(chunkFile)
	require.NoError(t, err)
	defer gzReader.Close()

	chunkContent, err := io.ReadAll(gzReader)
	require.NoError(t, err)
	require.Equal(t, expected.Bytes(), chunkContent)

	headerPath := snapshotHeaderFile(dir, height, 0)
	headerInfo, err := os.Stat(headerPath)
	require.NoError(t, err)
	require.False(t, headerInfo.IsDir())

	formatEntries, err := os.ReadDir(snapshotFormatDir(dir, height, 0))
	require.NoError(t, err)
	require.Len(t, formatEntries, 2)

	chunkDirEntries, err := os.ReadDir(snapshotChunkDir(dir, height, 0))
	require.NoError(t, err)
	require.Len(t, chunkDirEntries, 1)
}
