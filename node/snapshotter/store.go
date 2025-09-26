package snapshotter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

/*
	SnapshotStore is responsible for creating, managing and serving the snapshots used for statesync process.
	The snapshots stored in the snapshot store cannot and should not be used for network migrations. As they
	don't always provide the latest state of the network and contains the state which shouldn't be available
	at the genesis of a new network.

	SnapshotStore Layout on disk:
	SnapshotsDir:
		snapshot-<height1>:
			snapshot-format-0
				header.json
				chunks:
					chunk-0.sql.gz
					chunk-1.sql.gz
					...
					chunk-n.sql.gz

		snapshot-<height2>:
			snapshot-format-0
				header.json
				chunks:
					chunk-0.sql.gz
					...
					chunk-n.sql.gz

	Currently we only support snapshots of format plain sql dump compressed with gzip.
	This can be extended to support other formats in the future.
*/

type SnapshotConfig struct {
	// Snapshot store configuration
	Enable           bool
	SnapshotDir      string
	MaxSnapshots     int
	RecurringHeight  uint64
	DBConfig         *config.DBConfig
	ChunkSendTimeout time.Duration
}

type BlockStore interface {
	GetByHeight(height int64) (types.Hash, *ktypes.Block, *ktypes.CommitInfo, error)
	Best() (height int64, blkHash, appHash types.Hash, stamp time.Time)
}

type SnapshotStore struct {
	// Snapshot Config
	cfg *SnapshotConfig

	// Snapshot Store
	snapshots       map[uint64]*Snapshot // Map of snapshot height to snapshot header
	snapshotHeights []uint64             // List of snapshot heights
	snapshotsMtx    sync.RWMutex         // Protects access to snapshots and snapshotHeights

	// Snapshotter
	snapshotter DBSnapshotter

	// blockStore
	blockStore BlockStore

	// Logger
	log log.Logger
}

type DBSnapshotter interface {
	CreateSnapshot(ctx context.Context, height uint64, snapshotID string, schemas, excludeTables []string, excludeTableData []string) (*Snapshot, error)
}

func NewSnapshotStore(cfg *SnapshotConfig, bs BlockStore, ns NamespaceManager, logger log.Logger) (*SnapshotStore, error) {
	snapshotter := NewSnapshotter(cfg.DBConfig, cfg.SnapshotDir, ns, logger)
	ss := &SnapshotStore{
		cfg:         cfg,
		snapshots:   make(map[uint64]*Snapshot),
		snapshotter: snapshotter,
		log:         logger,
		blockStore:  bs,
	}

	err := ss.loadSnapshots()
	if err != nil {
		return nil, fmt.Errorf("failed to load snapshots from disk: %w", err)
	}

	return ss, nil
}

func (s *SnapshotStore) Enabled() bool {
	return s.cfg.Enable
}

// IsSnapshotDue checks if a snapshot is due at the given height.
func (s *SnapshotStore) IsSnapshotDue(height uint64) bool {
	if s.cfg.RecurringHeight == 0 || !s.cfg.Enable {
		return false
	}

	s.snapshotsMtx.RLock()
	defer s.snapshotsMtx.RUnlock()

	if len(s.snapshotHeights) == 0 {
		return true
	}

	lastHeight := s.snapshotHeights[len(s.snapshotHeights)-1]
	if height <= lastHeight {
		return false
	}

	return height-lastHeight >= s.cfg.RecurringHeight
}

// List snapshots lists all the registered snapshots in the snapshot store.
func (s *SnapshotStore) ListSnapshots() []*Snapshot {
	s.snapshotsMtx.RLock()
	defer s.snapshotsMtx.RUnlock()

	snaps := make([]*Snapshot, 0, len(s.snapshots))
	for _, snap := range s.snapshots {
		snaps = append(snaps, snap)
	}

	return snaps
}

func (s *SnapshotStore) GetSnapshot(height uint64, _ uint32) *Snapshot {
	s.snapshotsMtx.RLock()
	defer s.snapshotsMtx.RUnlock()

	return s.snapshots[height]
}

// CreateSnapshot creates a new snapshot at the given height and snapshot ID.
// SnapshotStore ensures that the number of snapshots does not exceed the maximum configured snapshots.
// If exceeds, it deletes the oldest snapshot.
// It takes a list of schemas, excludedTables and excludeTableData args to specify the contents of the snapshot.
// schemas: list of schemas to include in the snapshot
// excludedTables: list of tables to exclude from the snapshot
// excludeTableData: list of tables to include schema but exclude data from the snapshot
func (s *SnapshotStore) CreateSnapshot(ctx context.Context, height uint64, snapshotID string, schemas, excludedTables []string, excludeTableData []string) error {
	// Create a snapshot of the database at the given height
	snapshot, err := s.snapshotter.CreateSnapshot(ctx, height, snapshotID, schemas, excludedTables, excludeTableData)
	if err != nil {
		os.RemoveAll(snapshotHeightDir(s.cfg.SnapshotDir, height))
		return fmt.Errorf("failed to create snapshot at height %d: %w", height, err)
	}

	// Register the snapshot
	err = s.RegisterSnapshot(snapshot)
	if err != nil {
		os.RemoveAll(snapshotHeightDir(s.cfg.SnapshotDir, height))
		return fmt.Errorf("failed to register snapshot at height %d: %w", height, err)
	}

	return nil
}

// RegisterSnapshot registers the existing snapshot in the snapshot store.
// It ensures that the number of snapshots does not exceed the maximum configured snapshots.
// If exceeds, it deletes the oldest snapshot.
func (s *SnapshotStore) RegisterSnapshot(snapshot *Snapshot) error {
	s.snapshotsMtx.Lock()
	defer s.snapshotsMtx.Unlock()

	if snapshot == nil {
		return nil // no snapshot to register
	}

	if _, ok := s.snapshots[snapshot.Height]; ok { // snapshot already exists at the given height
		return nil
	}

	// Register the snapshot
	s.snapshots[snapshot.Height] = snapshot
	s.snapshotHeights = append(s.snapshotHeights, snapshot.Height)

	// Sort the snapshot heights in ascending order
	slices.Sort(s.snapshotHeights)

	// Check if the number of snapshots exceeds the maximum number of snapshots
	for len(s.snapshotHeights) > s.cfg.MaxSnapshots {
		// Delete the oldest snapshot
		s.deleteOldestSnapshot()
	}
	return nil
}

// DeleteOldestSnapshot deletes the oldest snapshot.
// Deletes the internal and fs snapshot files and references corresponding to the oldest snapshot.
func (s *SnapshotStore) deleteOldestSnapshot() error {
	if len(s.snapshotHeights) == 0 {
		return nil
	}

	oldHeight := s.snapshotHeights[0]
	snapshot := s.snapshots[oldHeight]
	snapshotDir := snapshotHeightDir(s.cfg.SnapshotDir, snapshot.Height)

	os.RemoveAll(snapshotDir) // Delete the oldest snapshot directory

	delete(s.snapshots, oldHeight)            // delete the snapshot reference
	s.snapshotHeights = s.snapshotHeights[1:] // remove the oldest snapshot height
	return nil
}

// LoadSnapshotChunk loads a snapshot chunk at the given height and chunk index of given format.
// It returns the snapshot chunk as a byte slice of max size 16MB.
// errors if the chunk of chunkIndex corresponding to snapshot at given height and format does not exist.
func (s *SnapshotStore) LoadSnapshotChunk(height uint64, format uint32, chunkIdx uint32) ([]byte, error) {
	s.snapshotsMtx.RLock()
	defer s.snapshotsMtx.RUnlock()

	// Check if snapshot format is supported
	if format != DefaultSnapshotFormat {
		return nil, fmt.Errorf("unsupported snapshot format %d", format)
	}

	// Check if snapshot exists
	snapshot, ok := s.snapshots[height]
	if !ok {
		return nil, fmt.Errorf("snapshot at height %d does not exist", height)
	}

	// Check if chunk exists
	if chunkIdx >= snapshot.ChunkCount {
		return nil, fmt.Errorf("chunk %d does not exist in snapshot at height %d", chunkIdx, height)
	}

	// Read the chunk file
	chunkFile := snapshotChunkFile(s.cfg.SnapshotDir, height, format, chunkIdx)
	bts, err := os.ReadFile(chunkFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("chunk %d does not exist in snapshot at height %d", chunkIdx, height)
		}
		return nil, fmt.Errorf("failed to read chunk %d at height %d: %w", chunkIdx, height, err)
	}
	// TODO: cache chunk bytes by file name (with last used vacuum timer) so
	// many peers don't force us to load the same chunk into memory many times.

	return bts, nil
}

// GetSnapshotChunkFile returns the file path for a snapshot chunk for streaming.
func (s *SnapshotStore) GetSnapshotChunkFile(height uint64, format uint32, chunkIdx uint32) (string, error) {
	s.snapshotsMtx.RLock()
	defer s.snapshotsMtx.RUnlock()

	// Check if snapshot format is supported
	if format != DefaultSnapshotFormat {
		return "", fmt.Errorf("unsupported snapshot format %d", format)
	}

	// Check if snapshot exists
	snapshot, ok := s.snapshots[height]
	if !ok {
		return "", fmt.Errorf("snapshot at height %d does not exist", height)
	}

	// Check if chunk exists
	if chunkIdx >= snapshot.ChunkCount {
		return "", fmt.Errorf("chunk %d does not exist in snapshot at height %d", chunkIdx, height)
	}

	// Get the chunk file path
	chunkFile := snapshotChunkFile(s.cfg.SnapshotDir, height, format, chunkIdx)

	// Verify file exists
	if _, err := os.Stat(chunkFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("chunk %d does not exist in snapshot at height %d", chunkIdx, height)
		}
		return "", fmt.Errorf("failed to access chunk %d at height %d: %w", chunkIdx, height, err)
	}

	return chunkFile, nil
}

// LoadSnapshotHeader loads the snapshots from the snapshotDir
// and registers them in the snapshot store.
func (s *SnapshotStore) loadSnapshots() error {
	// Scan the snapshot directory and load all the snapshots
	files, err := os.ReadDir(s.cfg.SnapshotDir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(s.cfg.SnapshotDir, 0755)
		}
		return err
	}

	for _, file := range files {
		if !file.IsDir() {
			continue
		}
		fileName := file.Name() // format: block-<height>
		names := strings.Split(fileName, "-")
		if len(names) != 2 {
			s.log.Warn("invalid snapshot directory name, ignoring the snapshot", "dir", fileName)
			continue
		}
		height := names[1]
		heightInt, err := strconv.ParseUint(height, 10, 64)
		if err != nil {
			s.log.Warn("invalid snapshot height, ignoring the snapshot", "height", height, "err", err)
			continue
		}

		// Load snapshot header
		headerFile := snapshotHeaderFile(s.cfg.SnapshotDir, heightInt, DefaultSnapshotFormat)
		header, err := loadSnapshot(headerFile)
		if err != nil {
			s.log.Warn("Invalid snapshot header file, ignoring the snapshot", "height", height, "err", err)
			continue
		}

		// Ensure that the chunk files exist
		for i := uint32(0); i < header.ChunkCount; i++ {
			chunkFile := snapshotChunkFile(s.cfg.SnapshotDir, heightInt, DefaultSnapshotFormat, i)
			if _, err := os.Stat(chunkFile); err != nil { // chunk file doesn't exist
				s.log.Warn("Invalid snapshot chunk file, ignoring the snapshot", "chunk_file", chunkFile, "err", err)
				continue
			}
		}

		s.snapshots[heightInt] = header
		s.snapshotHeights = append(s.snapshotHeights, heightInt)
	}

	sort.Slice(s.snapshotHeights, func(i, j int) bool {
		return s.snapshotHeights[i] < s.snapshotHeights[j]
	})

	// Check if the number of snapshots exceeds the maximum number of snapshots
	for len(s.snapshotHeights) > s.cfg.MaxSnapshots {
		// Delete the oldest snapshot
		if err := s.deleteOldestSnapshot(); err != nil {
			return fmt.Errorf("failed to delete oldest snapshot: %w", err)
		}
	}

	return nil
}

// utility functions
func snapshotHeightDir(snapshotDir string, height uint64) string {
	return filepath.Join(snapshotDir, fmt.Sprintf("block-%d", height))
}

func snapshotFormatDir(snapshotDir string, height uint64, format uint32) string {
	return filepath.Join(snapshotHeightDir(snapshotDir, height), fmt.Sprintf("format-%d", format))
}

func snapshotChunkDir(snapshotDir string, height uint64, format uint32) string {
	return filepath.Join(snapshotFormatDir(snapshotDir, height, format), "chunks")
}

func snapshotChunkFile(snapshotDir string, height uint64, format uint32, chunkIdx uint32) string {
	return filepath.Join(snapshotChunkDir(snapshotDir, height, format), fmt.Sprintf("chunk-%d.sql.gz", chunkIdx))
}

func snapshotHeaderFile(snapshotDir string, height uint64, format uint32) string {
	return filepath.Join(snapshotFormatDir(snapshotDir, height, format), "header.json")
}
