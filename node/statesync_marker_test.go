package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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
