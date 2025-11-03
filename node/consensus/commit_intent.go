package consensus

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	ktypes "github.com/trufnetwork/kwil-db/core/types"
)

type commitIntent struct {
	Height    int64  `json:"height"`
	BlockHash string `json:"block_hash"`
}

func (ci *commitIntent) hash() (ktypes.Hash, error) {
	if ci.BlockHash == "" {
		return ktypes.Hash{}, nil
	}
	return ktypes.NewHashFromString(ci.BlockHash)
}

type commitIntentLog struct {
	path string
	dir  string
}

func newCommitIntentLog(path string) *commitIntentLog {
	return &commitIntentLog{
		path: path,
		dir:  filepath.Dir(path),
	}
}

func (cil *commitIntentLog) Record(height int64, hash ktypes.Hash) error {
	if err := os.MkdirAll(cil.dir, 0o755); err != nil {
		return fmt.Errorf("create commit intent directory: %w", err)
	}

	payload := commitIntent{
		Height:    height,
		BlockHash: hash.String(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal commit intent: %w", err)
	}

	tmp, err := os.CreateTemp(cil.dir, ".commit-intent-*")
	if err != nil {
		return fmt.Errorf("create temp commit intent file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write commit intent: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync commit intent: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close commit intent temp file: %w", err)
	}

	if err := os.Rename(tmp.Name(), cil.path); err != nil {
		return fmt.Errorf("rename commit intent: %w", err)
	}

	return syncDir(cil.dir)
}

func (cil *commitIntentLog) Load() (*commitIntent, error) {
	data, err := os.ReadFile(cil.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("read commit intent: %w", err)
	}

	intent := &commitIntent{}
	if err := json.Unmarshal(data, intent); err != nil {
		return nil, fmt.Errorf("unmarshal commit intent: %w", err)
	}

	return intent, nil
}

func (cil *commitIntentLog) Clear() error {
	if err := os.Remove(cil.path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("remove commit intent: %w", err)
	}

	return syncDir(cil.dir)
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
