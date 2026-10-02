package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

// restoreBlockStore stands in for the block store. It records the order of
// Store, Sync and Reset. It holds every block up to height, block h with the
// app hash blockAppHash(h). Sync fails when syncErr is set, and Reset fails
// when resetErr is set, after calling onReset.
type restoreBlockStore struct {
	height   int64
	calls    []string
	syncErr  error
	resetErr error
	onReset  func()
}

func blockAppHash(height int64) types.Hash {
	return types.HashBytes(fmt.Appendf(nil, "app hash %d", height))
}

func (f *restoreBlockStore) Best() (int64, types.Hash, types.Hash, time.Time) {
	return f.height, types.Hash{}, types.Hash{}, time.Time{}
}

func (f *restoreBlockStore) GetRawByHeight(height int64) (types.Hash, []byte, *ktypes.CommitInfo, error) {
	if height < 1 || height > f.height {
		return types.Hash{}, nil, nil, types.ErrNotFound
	}
	return types.Hash{}, nil, &ktypes.CommitInfo{AppHash: blockAppHash(height)}, nil
}

func (f *restoreBlockStore) Store(blk *ktypes.Block, _ *ktypes.CommitInfo) error {
	f.height = blk.Header.Height
	f.calls = append(f.calls, "store")
	return nil
}

func (f *restoreBlockStore) Sync() error {
	f.calls = append(f.calls, "sync")
	return f.syncErr
}

func (f *restoreBlockStore) Reset() error {
	f.calls = append(f.calls, "reset")
	if f.onReset != nil {
		f.onReset()
	}
	if f.resetErr != nil {
		return f.resetErr
	}
	f.height = 0
	return nil
}

func TestRestoreMarkerRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "statesync-restore.json")

	interrupted, err := RestoreInterrupted(path)
	require.NoError(t, err)
	require.False(t, interrupted)

	want := &restoreMarker{Height: 42, SnapshotHash: "ab", SchemasBefore: []string{"public", "operator_data"}}
	require.NoError(t, writeRestoreMarker(path, want))
	got, err := readRestoreMarker(path)
	require.NoError(t, err)
	require.Equal(t, want, got)

	interrupted, err = RestoreInterrupted(path)
	require.NoError(t, err)
	require.True(t, interrupted)

	require.NoError(t, clearRestoreMarker(path))
	require.NoError(t, clearRestoreMarker(path), "clearing twice is fine")
	interrupted, err = RestoreInterrupted(path)
	require.NoError(t, err)
	require.False(t, interrupted)
}

func TestUnreadableRestoreMarkerIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "statesync-restore.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o644))

	_, err := RestoreInterrupted(path)
	require.Error(t, err)
}

func markedService(t *testing.T) (*StateSyncService, *restoreBlockStore) {
	t.Helper()
	bs := &restoreBlockStore{}
	ss := &StateSyncService{
		restoreMarker: filepath.Join(t.TempDir(), "statesync-restore.json"),
		blockStore:    bs,
		log:           log.DiscardLogger,
	}
	require.NoError(t, writeRestoreMarker(ss.restoreMarker, &restoreMarker{Height: 100}))
	return ss, bs
}

var restoredBlock = &ktypes.Block{Header: &ktypes.BlockHeader{Height: 100}}

func TestStoreRestoredBlockSyncsBeforeRemovingTheMarker(t *testing.T) {
	ss, bs := markedService(t)

	require.NoError(t, ss.storeRestoredBlock(restoredBlock, &ktypes.CommitInfo{}))

	require.Equal(t, []string{"store", "sync"}, bs.calls)
	interrupted, err := RestoreInterrupted(ss.restoreMarker)
	require.NoError(t, err)
	require.False(t, interrupted)
}

func TestStoreRestoredBlockKeepsTheMarkerWhenSyncFails(t *testing.T) {
	ss, bs := markedService(t)
	bs.syncErr = errors.New("disk gone")

	err := ss.storeRestoredBlock(restoredBlock, &ktypes.CommitInfo{})
	require.ErrorContains(t, err, "disk gone")

	interrupted, err := RestoreInterrupted(ss.restoreMarker)
	require.NoError(t, err)
	require.True(t, interrupted)
}

func TestStoreRestoredBlockStopsWhenTheMarkerCannotBeRemoved(t *testing.T) {
	ss, _ := markedService(t)
	// A non-empty directory in the marker's place cannot be removed.
	require.NoError(t, os.Remove(ss.restoreMarker))
	require.NoError(t, os.MkdirAll(filepath.Join(ss.restoreMarker, "x"), 0o755))

	err := ss.storeRestoredBlock(restoredBlock, &ktypes.CommitInfo{})
	require.ErrorContains(t, err, "remove the state sync restore marker")
}

func TestInterruptedResyncAtAnotherHeightIsRefused(t *testing.T) {
	ss, bs := markedService(t)
	require.NoError(t, writeRestoreMarker(ss.restoreMarker, &restoreMarker{Height: 1000, ResyncFrom: 100}))
	bs.height = 250 // neither where the resync started nor where it was going

	// No database is configured, so reaching the drop would fail differently.
	_, err := ss.ClearInterruptedRestore(context.Background())
	require.ErrorContains(t, err, "reset the node")

	require.Empty(t, bs.calls)
	interrupted, err := RestoreInterrupted(ss.restoreMarker)
	require.NoError(t, err)
	require.True(t, interrupted)
}
