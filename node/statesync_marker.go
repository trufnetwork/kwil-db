package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// restoreMarker records a state sync restore that has started and not yet
// finished. It is written before the restore touches the database and removed
// once the block at the snapshot height is stored, which is the last step. A
// node that finds it at startup was stopped, or failed, part way through.
type restoreMarker struct {
	Height       uint64 `json:"height"`
	SnapshotHash string `json:"snapshot_hash"`
	// SchemasBefore lists the schemas the database held before the restore,
	// so that undoing the restore drops only what it created.
	SchemasBefore []string `json:"schemas_before"`
}

func writeRestoreMarker(path string, m *restoreMarker) error {
	dir := filepath.Dir(path)
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal restore marker: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".statesync-restore-*")
	if err != nil {
		return fmt.Errorf("create restore marker: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write restore marker: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync restore marker: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close restore marker: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename restore marker: %w", err)
	}
	return syncDir(dir)
}

// readRestoreMarker returns fs.ErrNotExist when no restore is in progress.
func readRestoreMarker(path string) (*restoreMarker, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("read restore marker: %w", err)
	}
	m := &restoreMarker{}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("unmarshal restore marker %s: %w", path, err)
	}
	return m, nil
}

func clearRestoreMarker(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("remove restore marker: %w", err)
	}
	return syncDir(filepath.Dir(path))
}

// RestoreInterrupted reports whether a state sync restore started in this root
// directory and did not finish.
func RestoreInterrupted(path string) (bool, error) {
	_, err := readRestoreMarker(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func syncDir(dir string) error {
	df, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for sync: %w", err)
	}
	defer df.Close()
	if err := df.Sync(); err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	return nil
}
