package snapshotter

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/log"
)

type MockSnapshotter struct {
	snapshotDir string
}

func NewMockSnapshotter(dir string) *MockSnapshotter {
	return &MockSnapshotter{snapshotDir: dir}
}

func (m *MockSnapshotter) CreateSnapshot(ctx context.Context, height uint64, snapshotID string, schemas, excludeTables []string, excludeTableData []string) (*Snapshot, error) {
	data := sha256.Sum256([]byte(snapshotID))

	snapshot := &Snapshot{
		Height:       height,
		Format:       0,
		ChunkCount:   1,
		ChunkHashes:  [][HashLen]byte{data},
		SnapshotHash: data[:],
		SnapshotSize: uint64(len(data)),
	}

	// create the snapshot directory
	chunkDir := snapshotChunkDir(m.snapshotDir, height, 0)
	err := os.MkdirAll(chunkDir, 0755)
	if err != nil {
		return nil, err
	}

	headerFile := snapshotHeaderFile(m.snapshotDir, height, 0)
	err = snapshot.SaveAs(headerFile)
	if err != nil {
		return nil, err
	}

	chunkFile := snapshotChunkFile(m.snapshotDir, height, 0, 0)
	file, err := os.Create(chunkFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	_, err = file.Write(data[:])
	if err != nil {
		return nil, err
	}

	return snapshot, nil
}

func NewMockSnapshotStore(dir string, cfg *SnapshotConfig, logger log.Logger) (*SnapshotStore, error) {
	snapshotter := NewMockSnapshotter(dir)
	store := &SnapshotStore{
		cfg:             cfg,
		snapshots:       make(map[uint64]*Snapshot),
		snapshotHeights: make([]uint64, 0),
		snapshotter:     snapshotter,
		log:             logger,
	}

	return store, nil
}

func TestCreateSnapshots(t *testing.T) {
	dir := t.TempDir()
	logger := log.DiscardLogger

	cfg := &SnapshotConfig{
		Enable:          true,
		RecurringHeight: 1,
		SnapshotDir:     dir,
		MaxSnapshots:    2,
	}
	store, err := NewMockSnapshotStore(dir, cfg, logger)
	require.NoError(t, err)

	ctx := context.Background()

	height := uint64(1)

	// Check if the snapshot is due
	require.True(t, store.IsSnapshotDue(height))

	// Create a snapshot
	err = store.CreateSnapshot(ctx, height, "snapshot1", nil, nil, nil)
	require.NoError(t, err)

	// List snapshots
	snaps := store.ListSnapshots()
	require.Len(t, snaps, 1)
	require.Equal(t, height, snaps[0].Height)
	require.Equal(t, uint32(1), snaps[0].ChunkCount)

	// Create 2nd snapshot
	height = 2
	err = store.CreateSnapshot(ctx, height, "snapshot2", nil, nil, nil)
	require.NoError(t, err)

	// List snapshots
	snaps = store.ListSnapshots()
	require.Len(t, snaps, 2)

	// Create 3rd snapshot, should purge the snapshot with height 1
	height = 3
	err = store.CreateSnapshot(ctx, height, "snapshot3", nil, nil, nil)
	require.NoError(t, err)

	// List snapshots
	snaps = store.ListSnapshots()
	require.Len(t, snaps, 2)
	for _, snap := range snaps {
		require.NotEqual(t, uint64(1), snap.Height)
	}
}

func TestRegisterSnapshot(t *testing.T) {
	dir := t.TempDir()
	logger := log.DiscardLogger

	cfg := &SnapshotConfig{
		Enable:          true,
		RecurringHeight: 1,
		SnapshotDir:     dir,
		MaxSnapshots:    2,
	}
	store, err := NewMockSnapshotStore(dir, cfg, logger)
	require.NoError(t, err)

	ctx := context.Background()

	var snapshot *Snapshot
	// register a snapshot that doesn't exist or nil
	err = store.RegisterSnapshot(snapshot)
	require.NoError(t, err)

	// List snapshots
	snaps := store.ListSnapshots()
	require.Len(t, snaps, 0)

	// Create a snapshot at height 1 through the snapshotter
	height := uint64(1)
	snapshot, err = store.snapshotter.CreateSnapshot(ctx, height, "snapshot1", nil, nil, nil)
	require.NoError(t, err)

	// Register the snapshot
	err = store.RegisterSnapshot(snapshot)
	require.NoError(t, err)

	// Create another snapshot at height 1
	snapshot2, err := store.snapshotter.CreateSnapshot(ctx, height, "snapshot1-2", nil, nil, nil)
	require.NoError(t, err)

	// Register the snapshot, as snapshot already exists at the height, its a no-op
	err = store.RegisterSnapshot(snapshot2)
	require.NoError(t, err)

	snapHash := sha256.Sum256([]byte("snapshot1"))
	// List snapshots
	snaps = store.ListSnapshots()
	require.Len(t, snaps, 1)
	require.Equal(t, height, snaps[0].Height)
	require.Equal(t, snapHash[:], snaps[0].SnapshotHash)

	// Create a snapshot at height 2
	height = 2
	snapshot, err = store.snapshotter.CreateSnapshot(ctx, height, "snapshot2", nil, nil, nil)
	require.NoError(t, err)

	// Register the snapshot
	err = store.RegisterSnapshot(snapshot)
	require.NoError(t, err)

	// List snapshots
	snaps = store.ListSnapshots()
	require.Len(t, snaps, 2)

	// Create a snapshot at height 3
	height = 3
	snapshot, err = store.snapshotter.CreateSnapshot(ctx, height, "snapshot3", nil, nil, nil)
	require.NoError(t, err)

	// Register the snapshot
	err = store.RegisterSnapshot(snapshot)
	require.NoError(t, err)

	// List snapshots
	snaps = store.ListSnapshots()
	require.Len(t, snaps, 2)
	for _, snap := range snaps {
		require.NotEqual(t, uint64(1), snap.Height)
	}
}

func TestLoadSnapshotChunk(t *testing.T) {
	dir := t.TempDir()
	snapshotter := NewMockSnapshotter(dir)
	logger := log.DiscardLogger

	cfg := &SnapshotConfig{
		RecurringHeight: 1,
		SnapshotDir:     dir,
		MaxSnapshots:    2,
	}
	store, err := NewMockSnapshotStore(dir, cfg, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Create a snapshot at height 1
	height := uint64(1)
	snapshot, err := snapshotter.CreateSnapshot(ctx, height, "snapshot1", nil, nil, nil)
	require.NoError(t, err)

	// Register the snapshot
	err = store.RegisterSnapshot(snapshot)
	require.NoError(t, err)
	snapHash := sha256.Sum256([]byte("snapshot1"))
	// Load the snapshot chunk
	data, err := store.LoadSnapshotChunk(height, 0, 0)
	require.NoError(t, err)
	require.Equal(t, snapHash[:], data)

	// Load the snapshot chunk that doesn't exist
	data, err = store.LoadSnapshotChunk(height, 0, 1)
	require.Error(t, err)
	require.Nil(t, data)

	// Load the snapshot chunk of unsupported format
	data, err = store.LoadSnapshotChunk(height, 1, 0)
	require.Error(t, err)
	require.Nil(t, data)

	// Load the snapshot chunk that doesn't exist at a given height
	height = 2
	data, err = store.LoadSnapshotChunk(height, 0, 0)
	require.Error(t, err)
	require.Nil(t, data)

}
