// Package memstore provides a memory-backed block store, which is only suitable
// for testing where a disk-based store or third party dependencies are not desired.
package memstore

import (
	"fmt"
	"sync"
	"time"

	"github.com/trufnetwork/kwil-db/core/types"
	ntypes "github.com/trufnetwork/kwil-db/node/types"
)

type blockHashes struct { // meta
	hash    types.Hash
	appHash types.Hash
	stamp   time.Time
}

type MemBS struct {
	mtx        sync.RWMutex
	idx        map[types.Hash]int64
	hashes     map[int64]blockHashes
	blocks     map[types.Hash]*types.Block
	commitInfo map[types.Hash]*types.CommitInfo
	txResults  map[types.Hash][]types.TxResult
	txIds      map[types.Hash]types.Hash // tx hash -> block hash
	fetching   map[types.Hash]bool       // TODO: remove, app concern
}

func NewMemBS() *MemBS {
	return &MemBS{
		idx:        make(map[types.Hash]int64),
		hashes:     make(map[int64]blockHashes),
		blocks:     make(map[types.Hash]*types.Block),
		txResults:  make(map[types.Hash][]types.TxResult),
		txIds:      make(map[types.Hash]types.Hash),
		fetching:   make(map[types.Hash]bool),
		commitInfo: make(map[types.Hash]*types.CommitInfo),
	}
}

var _ ntypes.BlockStore = &MemBS{}

func (bs *MemBS) GetRaw(hash types.Hash) ([]byte, *types.CommitInfo, error) {
	blk, ci, err := bs.Get(hash)
	if err != nil {
		return nil, nil, err
	}
	return blk.Bytes(), ci, nil
}

func (bs *MemBS) Get(hash types.Hash) (*types.Block, *types.CommitInfo, error) {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	blk, have := bs.blocks[hash]
	if !have {
		return nil, nil, types.ErrNotFound
	}
	ci, have := bs.commitInfo[hash]
	if !have {
		return nil, nil, types.ErrNotFound
	}
	return blk, ci, nil
}

func (bs *MemBS) GetRawByHeight(height int64) (types.Hash, []byte, *types.CommitInfo, error) {
	hash, blk, ci, err := bs.GetByHeight(height)
	if err != nil {
		return types.Hash{}, nil, nil, err
	}
	return hash, blk.Bytes(), ci, nil
}

func (bs *MemBS) GetByHeight(height int64) (types.Hash, *types.Block, *types.CommitInfo, error) {
	// time.Sleep(100 * time.Millisecond) // wtf where is there a logic race in CE?
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	blkHash, have := bs.hashes[height]
	if !have {
		return types.Hash{}, nil, nil, types.ErrNotFound
	}
	blk, have := bs.blocks[blkHash.hash]
	if !have {
		return types.Hash{}, nil, nil, types.ErrNotFound
	}
	ci, have := bs.commitInfo[blkHash.hash]
	if !have {
		return types.Hash{}, nil, nil, types.ErrNotFound
	}
	return blkHash.hash, blk, ci, nil
}

func (bs *MemBS) GetBlockHeader(hash types.Hash) (*types.BlockHeader, error) {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	blk, have := bs.blocks[hash]
	if !have {
		return nil, types.ErrNotFound
	}
	return blk.Header, nil
}

func (bs *MemBS) GetBlockHeaderByHeight(height int64) (*types.BlockHeader, error) {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	blkHash, have := bs.hashes[height]
	if !have {
		return nil, types.ErrNotFound
	}
	blk, have := bs.blocks[blkHash.hash]
	if !have {
		return nil, types.ErrNotFound
	}
	return blk.Header, nil
}

func (bs *MemBS) Have(blkid types.Hash) bool {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	_, have := bs.idx[blkid]
	return have
}

func (bs *MemBS) Store(block *types.Block, ci *types.CommitInfo) error {
	if ci == nil {
		return fmt.Errorf("commit info is nil")
	}

	bs.mtx.Lock()
	defer bs.mtx.Unlock()
	blkHash := block.Hash()
	bs.blocks[blkHash] = block
	bs.idx[blkHash] = block.Header.Height
	bs.commitInfo[blkHash] = ci
	bs.hashes[block.Header.Height] = blockHashes{
		hash:    blkHash,
		appHash: ci.AppHash,
	}
	for _, tx := range block.Txns {
		txHash := tx.Hash()
		bs.txIds[txHash] = blkHash
	}
	return nil
}

func (bs *MemBS) StoreResults(hash types.Hash, results []types.TxResult) error {
	bs.mtx.Lock()
	defer bs.mtx.Unlock()
	bs.txResults[hash] = results
	return nil
}

func (bs *MemBS) Results(hash types.Hash) ([]types.TxResult, error) {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	res, have := bs.txResults[hash]
	if !have {
		return nil, types.ErrNotFound
	}
	return res, nil
}

func (bs *MemBS) Result(hash types.Hash, idx uint32) (*types.TxResult, error) {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	res, have := bs.txResults[hash]
	if !have {
		return nil, types.ErrNotFound
	}
	if int(idx) >= len(res) {
		return nil, fmt.Errorf("%w: invalid block index", types.ErrNotFound)
	}
	r := res[idx]
	return &r, nil
}

func (bs *MemBS) Best() (height int64, blkHash, appHash types.Hash, stamp time.Time) {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	for heighti, hashes := range bs.hashes {
		if heighti >= height {
			height = heighti
			blkHash = hashes.hash
			appHash = hashes.appHash
			stamp = hashes.stamp
		}
	}
	return height, blkHash, appHash, stamp
}

func (bs *MemBS) PreFetch(blkid types.Hash) (bool, func()) {
	bs.mtx.Lock()
	defer bs.mtx.Unlock()
	if _, have := bs.idx[blkid]; have {
		return false, func() {} // don't need it
	}

	if fetching := bs.fetching[blkid]; fetching {
		return false, func() {} // already getting it
	}
	bs.fetching[blkid] = true

	return true, func() {
		bs.mtx.Lock()
		delete(bs.fetching, blkid)
		bs.mtx.Unlock()
	} // go get it
}

func (bs *MemBS) Close() error { return nil }

// Sync is a no-op for the in-memory block store.
func (bs *MemBS) Sync() error { return nil }

func (bs *MemBS) GetTx(txHash types.Hash) (tx *types.Transaction, height int64, hash types.Hash, idx uint32, err error) {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	// check the tx index, pull the block and then search for the tx with the expected hash
	blkHash, have := bs.txIds[txHash]
	if !have {
		return nil, 0, types.Hash{}, 0, types.ErrNotFound
	}
	blk, have := bs.blocks[blkHash]
	if !have {
		return nil, 0, types.Hash{}, 0, types.ErrNotFound
	}
	for idx, tx := range blk.Txns {
		txHashi := tx.Hash()
		if txHashi == txHash {
			return tx, blk.Header.Height, blk.Hash(), uint32(idx), nil
		}
	}
	return nil, 0, types.Hash{}, 0, types.ErrNotFound
}

func (bs *MemBS) HaveTx(txHash types.Hash) bool {
	bs.mtx.RLock()
	defer bs.mtx.RUnlock()
	_, have := bs.txIds[txHash]
	return have
}
