package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/kwilteam/kwil-db/core/log"
	ktypes "github.com/kwilteam/kwil-db/core/types"
	"github.com/kwilteam/kwil-db/node/metrics"
	"github.com/kwilteam/kwil-db/node/types"

	"github.com/dgraph-io/badger/v4"
	boptions "github.com/dgraph-io/badger/v4/options"
)

var mets metrics.StoreMetrics = metrics.Store

// This version of BlockStore has one badger DB. The block is one value.
// Transaction gets seek into block.

type blockHashes struct {
	hash    types.Hash
	appHash types.Hash
	stamp   time.Time
}

type BlockStore struct {
	mtx        sync.RWMutex
	bestHeight int64
	bestHash   types.Hash
	idx        map[types.Hash]int64
	hashes     map[int64]blockHashes
	fetching   map[types.Hash]bool // TODO: remove, app concern

	// TODO: LRU cache for recent txns

	log log.Logger
	db  *badger.DB
}

var (
	nsHeader     = []byte("h:") // block metadata (header + signature)
	nsBlock      = []byte("b:") // full block
	nsTxn        = []byte("t:") // transaction index by tx hash
	nsResults    = []byte("r:") // block execution results by block hash
	nsCommitInfo = []byte("c:") // commit info by block hash
)

var _ types.BlockStore = &BlockStore{}

func NewBlockStore(dir string, opts ...Option) (*BlockStore, error) {
	options := &options{
		logger: log.DiscardLogger,
	}

	for _, opt := range opts {
		opt(options)
	}
	logger := options.logger

	bOpts := badger.DefaultOptions(filepath.Join(dir, "bstore"))
	bOpts.Logger = &badgerLogger{logger.NewWithLevel(log.LevelWarn, "BADGER")}
	// NOTE: do NOT use WithLoggingLevel since that overwrites our logger!
	// bOpts.SyncWrites = true // write survive process crash without this by virtue of mmap
	// Compression and caching are closely related. See comments in else case below:
	if options.compress {
		const bs = 1 << 16 // 65536, default is 4096
		bOpts.BlockSize = bs
		bOpts.Compression = boptions.ZSTD // not snappy
		bOpts.ZSTDCompressionLevel = 1
		bOpts.BlockCacheSize = 256 << 20 // 256 MiB is the default already
	} else {
		bOpts.Compression = boptions.None
		bOpts.BlockCacheSize = 0
		// badger docs say:
		//
		//   It is recommended to use a cache if you're using compression or
		//   encryption. If compression and encryption both are disabled, adding a
		//   cache will lead to unnecessary overhead which will affect the read
		//   performance. Setting size to zero disables the cache altogether.
		//
		// As such, with compression disabled, we set to zero to disable the cache.
	}
	// bOpts.CompactL0OnClose = true

	db, err := badger.Open(bOpts)
	if err != nil {
		return nil, err
	}

	bs := &BlockStore{
		idx:      make(map[types.Hash]int64),
		hashes:   make(map[int64]blockHashes),
		fetching: make(map[types.Hash]bool),
		db:       db,
		log:      logger,
	}

	// Initialize block index from the db
	itOpts := badger.DefaultIteratorOptions
	itOpts.Prefix = nsHeader
	pfxLen := len(nsHeader)

	var hash types.Hash // reuse in loop
	var ci ktypes.CommitInfo

	err = db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(itOpts)
		defer it.Close()

		var count int
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			var height int64
			var stamp time.Time
			err := item.Value(func(val []byte) error {
				r := bytes.NewReader(val)
				blockHeader, err := ktypes.DecodeBlockHeader(r)
				if err != nil {
					return err
				}
				height = blockHeader.Height
				stamp = blockHeader.Timestamp
				// sig, err = io.ReadAll(r)
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

			// get the app hash from nsCommitInfo
			commitInfoKey := slices.Concat(nsCommitInfo, key[pfxLen:])
			item, err = txn.Get(commitInfoKey)
			if err != nil {
				return err
			}

			err = item.Value(func(val []byte) error {
				err = ci.UnmarshalBinary(val)
				return err
			})
			if err != nil {
				return err
			}

			bs.idx[hash] = height
			bs.hashes[height] = blockHashes{
				hash:    hash,
				appHash: ci.AppHash,
				stamp:   stamp,
			}
			if bs.bestHeight < height {
				bs.bestHeight = height
				bs.bestHash = hash
			}
			count++
		}

		logger.Infof("indexed %d blocks", count)

		return nil
	})

	return bs, err
}

func (bki *BlockStore) Close() error {
	// bki.db.RunValueLogGC(0.5)
	return bki.db.Close()
}

func (bki *BlockStore) Have(hash types.Hash) bool {
	bki.mtx.RLock()
	defer bki.mtx.RUnlock()
	_, have := bki.idx[hash]
	return have
}

const blkInfoLen = 8 + types.HashLen + 4

func makeTxVal(height int64, blkHash types.Hash, idx uint32) []byte {
	val := make([]byte, blkInfoLen)
	binary.LittleEndian.PutUint64(val, uint64(height))
	copy(val[8:], blkHash[:])
	binary.LittleEndian.PutUint32(val[8+types.HashLen:], idx)
	return val
}

func (bki *BlockStore) mayReplaceTx(txn *badger.Txn, err error) (*badger.Txn, error) {
	if err == nil {
		return txn, nil
	}
	if !errors.Is(err, badger.ErrTxnTooBig) {
		return nil, err
	}
	bki.log.Warn("block store: replacing large txn")
	if err = txn.Commit(); err != nil {
		txn.Discard()
		return nil, err
	}
	return bki.db.NewTransaction(true), nil
}

func (bki *BlockStore) StoreResults(hash types.Hash, results []ktypes.TxResult) error {
	txn := bki.db.NewTransaction(true)
	defer txn.Discard()

	// The key prefix will be nsResults + tx index
	for i, res := range results {
		key := slices.Concat(nsResults, hash[:], binary.LittleEndian.AppendUint32(nil, uint32(i)))
		resBts, err := res.MarshalBinary()
		if err != nil {
			return err
		}
		err = txn.Set(key, resBts)
		if err != nil {
			txn, err = bki.mayReplaceTx(txn, err)
			if err != nil {
				return err
			} // else we recovered
			defer txn.Discard()
		}
	}

	return txn.Commit()
}

func (bki *BlockStore) Results(hash types.Hash) ([]ktypes.TxResult, error) {
	prefixLen := len(nsResults) + types.HashLen

	// Get block header to determine number of transactions
	var txCount uint32
	err := bki.db.View(func(txn *badger.Txn) error {
		key := slices.Concat(nsHeader, hash[:])
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			header, err := ktypes.DecodeBlockHeader(bytes.NewReader(val))
			if err != nil {
				return err
			}
			txCount = header.NumTxns
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	results := make([]ktypes.TxResult, txCount)

	err = bki.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = slices.Concat(nsResults, hash[:])

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			idx := binary.LittleEndian.Uint32(key[prefixLen:])
			if idx >= txCount {
				return fmt.Errorf("invalid tx index %d", idx)
			}

			err := item.Value(func(val []byte) error {
				var result ktypes.TxResult
				if err := result.UnmarshalBinary(val); err != nil {
					return err
				}
				results[idx] = result
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return results, err
}

func (bki *BlockStore) Result(hash types.Hash, idx uint32) (*ktypes.TxResult, error) {
	var res ktypes.TxResult
	err := bki.db.View(func(txn *badger.Txn) error {
		key := slices.Concat(nsResults, hash[:], binary.LittleEndian.AppendUint32(nil, idx))
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return res.UnmarshalBinary(val)
		})
	})
	return &res, err
}

func (bki *BlockStore) Store(blk *ktypes.Block, commitInfo *ktypes.CommitInfo) error {
	blkHash := blk.Hash()
	height := blk.Header.Height

	rawBlk := ktypes.EncodeBlock(blk)

	txHashes := make([]ktypes.Hash, blk.Header.NumTxns)
	for i, tx := range blk.Txns {
		txHashes[i] = tx.HashCache()
	}

	txn := bki.db.NewTransaction(true)
	defer txn.Discard()

	// Store block metadata (header + signature)
	key := slices.Concat(nsHeader, blkHash[:])
	err := txn.Set(key, append(ktypes.EncodeBlockHeader(blk.Header), blk.Signature...))
	if err != nil {
		return err
	}

	// Store the block contents with the nsBlock prefix
	key = slices.Concat(nsBlock, blkHash[:])
	err = txn.Set(key, rawBlk)
	if err != nil {
		return err
	}

	// Store commitInfo.
	bytes, err := commitInfo.MarshalBinary()
	if err != nil {
		return err
	}

	key = slices.Concat(nsCommitInfo, blkHash[:])
	err = txn.Set(key, bytes)
	if err != nil {
		return err
	}
	// NOTE: we are going to store this again in the next block's header, so
	// this is possibly a suboptimal design.

	// Store the txn index
	for idx, txHash := range txHashes {
		key = slices.Concat(nsTxn, txHash[:]) // "t:txHash" => height + blkHash + blkIdx
		val := makeTxVal(height, blkHash, uint32(idx))
		err := txn.Set(key, val)
		txn, err = bki.mayReplaceTx(txn, err)
		if err != nil {
			return err
		}
	}

	bki.mtx.Lock()
	defer bki.mtx.Unlock()

	if err = txn.Commit(); err != nil {
		return err
	}

	mets.BlockStored(context.Background(), height, int64(len(rawBlk)))

	delete(bki.fetching, blkHash)
	bki.idx[blkHash] = height
	bki.hashes[height] = blockHashes{
		hash:    blkHash,
		appHash: commitInfo.AppHash,
		stamp:   blk.Header.Timestamp,
	}
	if bki.bestHeight < height {
		bki.bestHeight = height
		bki.bestHash = blkHash
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

// Best returns the best block's height, hash, appHash, and time stamp. The
// appHash is a result of executing the block, not the appHash stored in the
// header, which is from the execution of the previous block. The time stamp is
// what is in the header.
func (bki *BlockStore) Best() (height int64, blkHash, appHash types.Hash, stamp time.Time) {
	bki.mtx.RLock()
	defer bki.mtx.RUnlock()
	height, blkHash = bki.bestHeight, bki.bestHash
	appHash, stamp = bki.hashes[height].appHash, bki.hashes[height].stamp
	return
}

func (bki *BlockStore) GetRaw(blkHash types.Hash) ([]byte, *ktypes.CommitInfo, error) {
	if !bki.Have(blkHash) {
		return nil, nil, types.ErrNotFound
	}

	var rawBlock []byte
	var ci ktypes.CommitInfo
	err := bki.db.View(func(txn *badger.Txn) error {
		// Load the block and get the tx
		blockKey := slices.Concat(nsBlock, blkHash[:])
		item, err := txn.Get(blockKey)
		if err != nil {
			return err
		}

		rawBlock, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}

		// Load the commit info
		commitInfoKey := slices.Concat(nsCommitInfo, blkHash[:])
		item, err = txn.Get(commitInfoKey)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			err = ci.UnmarshalBinary(val)
			return err
		})
	})

	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil, types.ErrNotFound
	}

	mets.BlockRetrieved(context.Background(), -1, int64(len(rawBlock)))

	return rawBlock, &ci, nil
}

func (bki *BlockStore) Get(blkHash types.Hash) (*ktypes.Block, *ktypes.CommitInfo, error) {
	if !bki.Have(blkHash) {
		return nil, nil, types.ErrNotFound
	}

	var blkSize int

	var block *ktypes.Block
	var ci ktypes.CommitInfo
	err := bki.db.View(func(txn *badger.Txn) error {
		// Load the block and get the tx
		blockKey := slices.Concat(nsBlock, blkHash[:])
		item, err := txn.Get(blockKey)
		if err != nil {
			return err
		}

		err = item.Value(func(val []byte) error {
			blkSize = len(val)
			block, err = ktypes.DecodeBlock(val)
			return err
		})
		if err != nil {
			return err
		}

		// Load the apphash
		appHashKey := slices.Concat(nsCommitInfo, blkHash[:])
		item, err = txn.Get(appHashKey)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			err = ci.UnmarshalBinary(val)
			return err
		})
	})

	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil, types.ErrNotFound
	}

	mets.BlockRetrieved(context.Background(), block.Header.Height, int64(blkSize))

	return block, &ci, err
}

func (bki *BlockStore) GetRawByHeight(height int64) (types.Hash, []byte, *ktypes.CommitInfo, error) {
	bki.mtx.RLock()
	hashes, have := bki.hashes[height]
	bki.mtx.RUnlock()
	if !have {
		return types.Hash{}, nil, nil, types.ErrNotFound
	}
	blk, ci, err := bki.GetRaw(hashes.hash)
	if err != nil {
		return types.Hash{}, nil, nil, err
	}
	// NOTE: appHash should match hashes.appHash, so check it here.
	if ci.AppHash != hashes.appHash {
		return types.Hash{}, nil, nil, fmt.Errorf("appHash mismatch: %s != %s", ci.AppHash, hashes.appHash)
	}

	return hashes.hash, blk, ci, err
}

// GetByHeight retrieves the full block based on the block height. The returned
// hash is a convenience for the caller to spare computing it. The app hash,
// which is encoded in the next block header, is also returned.
func (bki *BlockStore) GetByHeight(height int64) (types.Hash, *ktypes.Block, *ktypes.CommitInfo, error) {
	bki.mtx.RLock()
	hashes, have := bki.hashes[height]
	bki.mtx.RUnlock()
	if !have {
		return types.Hash{}, nil, nil, types.ErrNotFound
	}
	blk, ci, err := bki.Get(hashes.hash)
	if err != nil {
		return types.Hash{}, nil, nil, err
	}
	// NOTE: appHash should match hashes.appHash, so check it here.
	if ci.AppHash != hashes.appHash {
		return types.Hash{}, nil, nil, fmt.Errorf("appHash mismatch: %s != %s", ci.AppHash, hashes.appHash)
	}

	return hashes.hash, blk, ci, err
}

// GetBlockHeader retrieves the block header for the given block hash. If the
// block is not found, it returns types.ErrNotFound. The header is the decoded
// header, not the raw bytes. This is useful for getting the header without
// loading the entire block, which can be large.
func (bki *BlockStore) GetBlockHeader(blkHash types.Hash) (*ktypes.BlockHeader, error) {
	if !bki.Have(blkHash) {
		return nil, types.ErrNotFound
	}

	var block *ktypes.Block
	err := bki.db.View(func(txn *badger.Txn) error {
		blockKey := slices.Concat(nsBlock, blkHash[:])
		item, err := txn.Get(blockKey)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			block, err = ktypes.DecodeBlock(val)
			return err
		})
	})

	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, types.ErrNotFound
	}

	return block.Header, nil
}

// GetBlockHeaderByHeight retrieves the block header for the given block height.
// If the block is not found, it returns types.ErrNotFound. The header is the
// decoded header, not the raw bytes. This is useful for getting the header
// without loading the entire block, which can be large.
func (bki *BlockStore) GetBlockHeaderByHeight(height int64) (*ktypes.BlockHeader, error) {
	bki.mtx.RLock()
	hashes, have := bki.hashes[height]
	bki.mtx.RUnlock()
	if !have {
		return nil, types.ErrNotFound
	}
	// NOTE: Could just use bki.GetBlockHeader here but it seems the appHash
	// check below is important when fetching data by height.
	blk, ci, err := bki.Get(hashes.hash)
	if err != nil {
		return nil, err
	}
	// NOTE: appHash should match hashes.appHash, so check it here.
	if ci.AppHash != hashes.appHash {
		return nil, fmt.Errorf("appHash mismatch: %s != %s", ci.AppHash, hashes.appHash)
	}
	return blk.Header, err
}

func (bki *BlockStore) HaveTx(txHash types.Hash) bool {
	var have bool
	err := bki.db.View(func(txn *badger.Txn) error {
		key := slices.Concat(nsTxn, txHash[:]) // tdb["t:txHash"]
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
		if errors.Is(err, badger.ErrDBClosed) {
			return false
		}
		panic(err)
	}
	return have
}

// GetTx returns the raw bytes of the transaction, and information on the block
// containing the transaction.
func (bki *BlockStore) GetTx(txHash types.Hash) (tx *ktypes.Transaction, height int64, blkHash types.Hash, blkIdx uint32, err error) {
	var raw []byte
	err = bki.db.View(func(txn *badger.Txn) error {
		// Get block info from the tx index
		key := slices.Concat(nsTxn, txHash[:]) // tdb["t:txHash"] => blk info
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			if len(val) < blkInfoLen {
				return errors.New("invalid block info for tx")
			}
			height = int64(binary.LittleEndian.Uint64(val))
			copy(blkHash[:], val[8:])
			blkIdx = binary.LittleEndian.Uint32(val[8+types.HashLen:])
			return nil
		})
		if err != nil {
			return err
		}

		// Load the block and get the tx
		blockKey := slices.Concat(nsBlock, blkHash[:])
		item, err = txn.Get(blockKey)
		if err != nil {
			return err // bug
		}

		return item.Value(func(val []byte) error {
			raw, err = ktypes.GetRawBlockTx(val, blkIdx)
			return err
			// block, err := types.DecodeBlock(val)
			// if err != nil {
			// 	return err
			// }
			// if len(block.Txns) <= int(blkIdx) {
			// 	return types.ErrNotFound // bug
			// }
			// raw = block.Txns[blkIdx]
			// return nil
		})
	})

	if errors.Is(err, badger.ErrKeyNotFound) {
		err = types.ErrNotFound
	}

	if len(raw) == 0 {
		return
	}

	mets.TransactionRetrieved(context.Background())

	tx = new(ktypes.Transaction)
	err = tx.UnmarshalBinary(raw)

	return
}
