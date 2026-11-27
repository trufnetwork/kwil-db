package snapshotter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

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

// fakePgDump puts a pg_dump that runs body first on PATH and returns a
// Snapshotter that writes into a new directory.
func fakePgDump(t *testing.T, body string) (*Snapshotter, string) {
	t.Helper()
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "pg_dump"), []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	dir := t.TempDir()
	cfg := &config.DBConfig{DBName: "ignored", User: "ignored", Host: "localhost", Port: "5432"}
	return NewSnapshotter(cfg, dir, &MockNamespaceManager{}, log.DiscardLogger), dir
}

// within fails the test if fn does not return within d.
func within(t *testing.T, d time.Duration, fn func() error) error {
	t.Helper()
	ch := make(chan error, 1)
	go func() { ch <- fn() }()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		t.Fatalf("did not return within %v", d)
		return nil
	}
}

// readChunks returns the uncompressed content of a snapshot's chunks.
func readChunks(t *testing.T, dir string, snapshot *Snapshot) []byte {
	t.Helper()
	var compressed bytes.Buffer
	for i := range snapshot.ChunkCount {
		chunk, err := os.ReadFile(snapshotChunkFile(dir, snapshot.Height, 0, i))
		require.NoError(t, err)
		compressed.Write(chunk)
	}
	gzReader, err := gzip.NewReader(&compressed)
	require.NoError(t, err)
	content, err := io.ReadAll(gzReader)
	require.NoError(t, err)
	return content
}

func TestStartSnapshotReturnsAtFirstByte(t *testing.T) {
	dump, err := filepath.Abs(dump1File)
	require.NoError(t, err)
	marks := t.TempDir()
	first, rest := filepath.Join(marks, "first"), filepath.Join(marks, "rest")
	// pg_dump writes its first byte once first exists, and the rest once rest
	// exists.
	s, dir := fakePgDump(t, fmt.Sprintf("until [ -e %[1]q ]; do sleep 0.01; done\n"+
		"head -c 1 %[3]q\n"+
		"until [ -e %[2]q ]; do sleep 0.01; done\n"+
		"exec tail -c +2 %[3]q", first, rest, dump))

	var finish func() (*Snapshot, error)
	started := make(chan error, 1)
	go func() {
		var err error
		finish, err = s.StartSnapshot(context.Background(), 42, "snapshot-id", nil, nil, nil)
		started <- err
	}()

	select {
	case <-started:
		t.Fatal("StartSnapshot returned before pg_dump wrote anything")
	case <-time.After(200 * time.Millisecond):
	}

	require.NoError(t, os.WriteFile(first, nil, 0o644))
	select {
	case err := <-started:
		require.NoError(t, err) // pg_dump is still waiting to write the rest
	case <-time.After(5 * time.Second):
		t.Fatal("StartSnapshot did not return after pg_dump wrote its first byte")
	}

	require.NoError(t, os.WriteFile(rest, nil, 0o644))
	snapshot, err := finish()
	require.NoError(t, err)

	dumpBytes, err := os.ReadFile(dump)
	require.NoError(t, err)
	var expected bytes.Buffer
	expectedHash, err := s.sanitizeDumpStream(context.Background(), 42, 0, t.TempDir(), bytes.NewReader(dumpBytes), &expected)
	require.NoError(t, err)
	require.Equal(t, expectedHash, snapshot.SnapshotHash)
	require.Equal(t, expected.Bytes(), readChunks(t, dir, snapshot))
}

func TestStartSnapshotFailsWithoutOutput(t *testing.T) {
	s, dir := fakePgDump(t, "echo boom >&2\nexit 1")

	_, err := s.StartSnapshot(context.Background(), 3, "snapshot-id", nil, nil, nil)
	require.ErrorContains(t, err, "boom")
	require.NoDirExists(t, snapshotHeightDir(dir, 3))
}

func TestStartSnapshotCancelledInGate(t *testing.T) {
	s, dir := fakePgDump(t, "exec sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := within(t, 2*time.Second, func() error {
		_, err := s.StartSnapshot(ctx, 3, "snapshot-id", nil, nil, nil)
		return err
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoDirExists(t, snapshotHeightDir(dir, 3))
}

// Each stage closes only its own writer. These two cases hang if a stage that
// stops leaves the stage writing into it blocked on its pipe.

func TestCreateSnapshotReturnsWhenCancelled(t *testing.T) {
	s, dir := fakePgDump(t, "exec od -An -tx1 -v /dev/urandom") // never ends
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(300*time.Millisecond, cancel)

	err := within(t, 5*time.Second, func() error {
		_, err := s.CreateSnapshot(ctx, 5, "snapshot-id", nil, nil, nil)
		return err
	})
	require.Error(t, err)
	require.NoDirExists(t, snapshotHeightDir(dir, 5))
}

func TestCreateSnapshotReturnsOnStageError(t *testing.T) {
	dump, err := filepath.Abs(dump1File)
	require.NoError(t, err)
	s, dir := fakePgDump(t, fmt.Sprintf("exec cat %q", dump))
	// A directory where the first chunk file goes makes the chunk stage fail.
	require.NoError(t, os.MkdirAll(snapshotChunkFile(dir, 6, 0, 0), 0o755))

	err = within(t, 5*time.Second, func() error {
		_, err := s.CreateSnapshot(context.Background(), 6, "snapshot-id", nil, nil, nil)
		return err
	})
	require.ErrorContains(t, err, "failed to create chunk file")
	require.NoDirExists(t, snapshotHeightDir(dir, 6))
}
