package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"

	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/types"

	"github.com/dgraph-io/badger/v4"
)

type BlockStore struct {
	mtx      sync.RWMutex
	idx      map[types.Hash]int64
	hashes   map[int64]types.Hash // []types.Hash, also could store pointer
	fetching map[types.Hash]bool  // TODO: remove, app concern

	db  *badger.DB
	tdb *badger.DB
}

var (
	nsHeight = []byte("h:")
	nsBlock  = []byte("b:")
	nsTxn    = []byte("t:")
)

func NewBlockStore(dir string, opts ...Option) (*BlockStore, error) {
	options := &options{
		logger: log.DiscardLogger,
	}

	for _, opt := range opts {
		opt(options)
	}
	logger := options.logger

	bOpts := badger.DefaultOptions(filepath.Join(dir, "bstore"))
	bOpts.WithLogger(&badgerLogger{logger})
	bOpts = bOpts.WithLoggingLevel(badger.WARNING)
	db, err := badger.Open(bOpts)
	if err != nil {
		return nil, err
	}
	bOpts = badger.DefaultOptions(filepath.Join(dir, "txi"))
	bOpts = bOpts.WithLoggingLevel(badger.WARNING)
	tdb, err := badger.Open(bOpts)
	if err != nil {
		return nil, err
	}
	bs := &BlockStore{
		idx:      make(map[types.Hash]int64),
		hashes:   make(map[int64]types.Hash),
		fetching: make(map[types.Hash]bool),
		db:       db,
		tdb:      tdb,
	}

	itOpts := badger.DefaultIteratorOptions
	itOpts.Prefix = nsHeight // the heights only, not block content
	pfxLen := len(nsHeight)

	var hash types.Hash // reuse in loop

	err = db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(itOpts)
		defer it.Close()

		var count int
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			var height int64
			err := item.Value(func(val []byte) error {
				if len(val) < 8 {
					return errors.New("invalid height in block index")
				}
				height = int64(binary.LittleEndian.Uint64(val))
				return nil
			})
			if err != nil {
				return err
			}

			key := item.Key()
			if len(key) < types.HashLen+pfxLen {
				return errors.New("block hash in block index")
			}

			copy(hash[:], key[pfxLen:])
			bs.idx[hash] = height
			bs.hashes[height] = hash
			count++
		}

		// logger.Infof("loaded %d blocks from the block store", count)
		logger.Info("block index loaded", "blocks", count)

		return nil
	})

	return bs, err
}

func (bki *BlockStore) Close() error {
	return errors.Join(bki.db.Close(), bki.tdb.Close())
}

func (bki *BlockStore) Have(hash types.Hash) bool {
	bki.mtx.RLock()
	defer bki.mtx.RUnlock()
	_, have := bki.idx[hash]
	return have
}

func (bki *BlockStore) Store(blk *types.Block) error {
	blkHash := blk.Hash()
	// blkid := blkHash.String()
	height := blk.Header.Height

	raw := types.EncodeBlock(blk)

	bki.mtx.Lock()
	defer bki.mtx.Unlock()
	delete(bki.fetching, blkHash)
	bki.idx[blkHash] = height
	bki.hashes[height] = blkHash
	heightBts := binary.LittleEndian.AppendUint64(nil, uint64(height))
	err := bki.db.Update(func(txn *badger.Txn) error {
		// store its height
		key := slices.Concat(nsHeight, blkHash[:])
		err := txn.Set(key, heightBts)
		if err != nil {
			return err
		}
		// store the contents
		key = slices.Concat(nsBlock, blkHash[:])
		return txn.Set(key, raw)
	})
	if err != nil {
		return err
	}

	blkInfo := append(heightBts, blkHash[:]...)
	for i, tx := range blk.Txns {
		hash := types.HashBytes(tx)

		err := bki.tdb.Update(func(txn *badger.Txn) error {
			// store its block info
			blkInfoIdx := binary.LittleEndian.AppendUint32(blkInfo, uint32(i))
			key := slices.Concat(nsBlock, hash[:]) // tdb["b:txHash"] = block info
			if err := txn.Set(key, blkInfoIdx); err != nil {
				return err
			}
			// store its own content (todo: seek in block data to get one tx)
			key = slices.Concat(nsTxn, hash[:]) // tdb["t:txHash"] = raw block
			return txn.Set(key, tx)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (bki *BlockStore) PreFetch(blkid types.Hash) (bool, func()) { // TODO: remove
	bki.mtx.Lock()
	defer bki.mtx.Unlock()
	if _, have := bki.idx[blkid]; have {
		return false, func() {} // don't need it
	}

	if fetching := bki.fetching[blkid]; fetching {
		return false, func() {} // already getting it
	}
	bki.fetching[blkid] = true

	return true, func() {
		bki.mtx.Lock()
		delete(bki.fetching, blkid)
		bki.mtx.Unlock()
	} // go get it
}

func (bki *BlockStore) size() int {
	bki.mtx.RLock()
	defer bki.mtx.RUnlock()
	return len(bki.idx)
}

func (bki *BlockStore) Best() (int64, types.Hash) {
	bki.mtx.RLock()
	defer bki.mtx.RUnlock()
	var bestHeight int64
	var bestHash types.Hash
	for height, hash := range bki.hashes {
		if height >= bestHeight {
			bestHeight = height
			bestHash = hash
		}
	}
	return bestHeight, bestHash
}
func (bki *BlockStore) Get(blkHash types.Hash) (int64, []byte, error) {
	bki.mtx.RLock()
	defer bki.mtx.RUnlock()
	height, have := bki.idx[blkHash]
	if !have {
		return -1, nil, nil
	}

	var raw []byte
	err := bki.db.View(func(txn *badger.Txn) error {
		key := slices.Concat(nsBlock, blkHash[:]) // bdb["b:hash"] => raw block
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		raw, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return height, raw, nil
}

func (bki *BlockStore) GetByHeight(height int64) (types.Hash, []byte, error) {
	bki.mtx.RLock()
	defer bki.mtx.RUnlock()
	hash, have := bki.hashes[height]
	if !have {
		return hash, nil, types.ErrNotFound
	}
	storedHeight, raw, err := bki.Get(hash)
	if storedHeight != height {
		panic(fmt.Sprintf("internal inconsistency: %d != %d", storedHeight, height))
	}
	return hash, raw, err
}

func (bki *BlockStore) HaveTx(txHash types.Hash) bool {
	var have bool
	err := bki.tdb.View(func(txn *badger.Txn) error {
		// get the block info
		key := slices.Concat(nsBlock, txHash[:]) // tdb["b:txHash"] => blk info
		if _, err := txn.Get(key); err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil
			}
			return err
		}
		have = true
		return nil
	})
	if err != nil {
		panic(err)
	}
	return have
}

func (bki *BlockStore) GetTx(txHash types.Hash) (int64, []byte, error) {
	var raw []byte
	var height int64
	var blkHash types.Hash
	// var blkIdx uint32
	err := bki.tdb.View(func(txn *badger.Txn) error {
		// get the block info
		key := slices.Concat(nsBlock, txHash[:]) // tdb["b:txHash"] => blk info
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			if len(val) < 8+types.HashLen+4 {
				return errors.New("invalid block info for tx")
			}
			height = int64(binary.LittleEndian.Uint64(val))
			copy(blkHash[:], val[8:])
			// blkIdx = binary.LittleEndian.Uint32(val[8+types.HashLen:])
			return nil
		})
		if err != nil {
			return err
		}

		// get the transaction content
		key = slices.Concat(nsTxn, txHash[:]) // tdb["t:txHash"] => raw tx
		item, err = txn.Get(key)
		if err != nil {
			return err
		}
		raw, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return 0, nil, types.ErrNotFound
		}
		return 0, nil, err
	}

	// NOTE: we could now pull the block and seek to the tx location

	return height, raw, nil
}
