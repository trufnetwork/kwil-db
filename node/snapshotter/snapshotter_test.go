package snapshotter

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/utils"
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

	// copy the logical dump file1
	stage1File := filepath.Join(formatDir, stage1output)
	err = utils.CopyFile(dump1File, stage1File)
	require.NoError(t, err)

	hash1, err := snapshotter.sanitizeDump(height, 0)
	require.NoError(t, err)

	// Sanitize the second dump file
	err = utils.CopyFile(dump2File, stage1File)
	require.NoError(t, err)

	hash2, err := snapshotter.sanitizeDump(height, 0)
	require.NoError(t, err)

	// Ensure that both the sanitized dumps are same
	require.Equal(t, hash1, hash2)

	// Check the sanitized file
	stage2File := filepath.Join(formatDir, stage2output)
	sanitizedFile, err := os.Open(stage2File)
	require.NoError(t, err)

	scanner := bufio.NewScanner(sanitizedFile)
	for scanner.Scan() {
		line := scanner.Text()
		// Ensure that the line does not begin with SET, SELECT or white spaces
		require.NotRegexp(t, `^\s*SET|SELECT`, line)
	}

	err = scanner.Err()
	require.NoError(t, err)
}
