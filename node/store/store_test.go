package store

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/kwilteam/kwil-db/core/crypto/auth"
	"github.com/kwilteam/kwil-db/core/log"
	ktypes "github.com/kwilteam/kwil-db/core/types"
	"github.com/kwilteam/kwil-db/node/types"
	"github.com/stretchr/testify/require"
)

func getFileSizes(dirPath string) ([][2]string, error) {
	var filesInfo [][2]string

	// Walk through the directory
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Only get files, not directories
		if !info.IsDir() {
			// Store file name and size in KB
			filesInfo = append(filesInfo, [2]string{info.Name(), fmt.Sprintf("%.2f KiB", float64(info.Size())/1024)})
		}
		return nil
	})
	return filesInfo, err
}

// Pretty print function
func prettyPrintFileSizes(filesInfo [][2]string) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.TabIndent)
	fmt.Fprintln(writer, "File Name\tSize")
	fmt.Fprintln(writer, "---------\t----")

	for _, fileInfo := range filesInfo {
		fmt.Fprintf(writer, "%s\t%s\n", fileInfo[0], fileInfo[1])
	}
	writer.Flush()
}

func setupTestBlockStore(t *testing.T, compress ...bool) (*BlockStore, string) {
	comp := len(compress) > 0 && compress[0]
	tmpDir := t.TempDir()
	bs, err := NewBlockStore(tmpDir, WithCompression(comp))
	if err != nil {
		t.Fatalf("Failed to create block store: %v", err)
	}

	t.Cleanup(func() {
		bs.Close()
	})

	return bs, tmpDir
}

func fakeAppHash(height int64) types.Hash {
	return types.HashBytes(binary.LittleEndian.AppendUint64(nil, uint64(height)))
}

func createTestBlock(_ *testing.T, height int64, numTxns int) (*ktypes.Block, types.Hash, [][]byte) {
	txs := make([]*ktypes.Transaction, numTxns)
	txns := make([][]byte, numTxns)
	for i := range numTxns {
		tx := newTx(uint64(i)+uint64(height), "sender")
		tx.Body.Payload = []byte(strings.Repeat("data", 1000))
		rawTx, err := tx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		txs[i] = tx
		txns[i] = rawTx
	}
	blk := ktypes.NewBlock(height, types.Hash{2, 3, 4}, types.Hash{6, 7, 8}, types.Hash{5, 5, 5},
		types.Hash{5, 5, 5}, time.Unix(1729723553+height, 0), txs)
	return blk, fakeAppHash(height), txns
}

func TestBlockStore_StoreAndGet(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 2)
	err := bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(appHash)

	hash := block.Hash()
	blk, ci, err := bs.Get(hash)
	if err != nil {
		t.Fatal(err)
	}
	height := blk.Header.Height
	data := ktypes.EncodeBlock(blk)

	if height != block.Header.Height {
		t.Errorf("Expected height %d, got %d", block.Header.Height, height)
	}

	if data == nil {
		t.Fatal("Expected block data, got nil")
	}

	if appHash != ci.AppHash {
		t.Errorf("Expected app hash %v, got %v", appHash, ci.AppHash)
	}

	retrievedBlock, err := ktypes.DecodeBlock(data)
	if err != nil {
		t.Fatal(err)
	}
	if retrievedBlock.Header.Height != block.Header.Height {
		t.Errorf("Expected retrieved block height %d, got %d", block.Header.Height, retrievedBlock.Header.Height)
	}
	if retrievedBlock.Hash() != hash {
		t.Fatal("hash mismatch")
	}
}

func TestBlockStore_GetByHeight(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 2)
	bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})

	gotHash, blk, ci, err := bs.GetByHeight(1)
	if err != nil {
		t.Fatal(err)
	}
	hash := blk.Hash()
	if hash != block.Hash() {
		t.Errorf("Expected hash %v, got %v", block.Hash(), hash)
	}
	if hash != gotHash {
		t.Errorf("Expected hash %v, got %v", hash, gotHash)
	}

	if appHash != ci.AppHash {
		t.Errorf("Expected app hash %x, got %x", appHash, ci.AppHash)
	}

	// if data == nil {
	// 	t.Fatal("Expected block data, got nil")
	// }
}

func TestBlockStore_GetBlockHeader(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 2)
	bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})

	blkHeader, err := bs.GetBlockHeader(block.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if blkHeader.Hash() != block.Hash() {
		t.Errorf("Expected hash %v, got %v", block.Hash(), blkHeader.Hash())
	}

	// Test invalid hash
	_, err = bs.GetBlockHeader(types.Hash{1, 2, 3})
	if err == nil {
		t.Error("Expected error for non-existent block hash")
	}
	if !errors.Is(err, types.ErrNotFound) {
		t.Errorf("Expected %v, got %v", types.ErrNotFound, err)
	}
}

func TestBlockStore_GetBlockHeaderByHeight(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 2)
	bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})

	blkHeader, err := bs.GetBlockHeaderByHeight(block.Header.Height)
	if err != nil {
		t.Fatal(err)
	}
	if blkHeader.Hash() != block.Hash() {
		t.Errorf("Expected hash %v, got %v", block.Hash(), blkHeader.Hash())
	}

	// Test invalid hash
	_, err = bs.GetBlockHeaderByHeight(467)
	if err == nil {
		t.Error("Expected error for non-existent block height")
	}
	if !errors.Is(err, types.ErrNotFound) {
		t.Errorf("Expected %v, got %v", types.ErrNotFound, err)
	}
}

func TestBlockStore_Have(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 2)
	hash := block.Hash()

	if bs.Have(hash) {
		t.Error("Block should not exist before storing")
	}

	bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})

	if !bs.Have(hash) {
		t.Error("Block should exist after storing")
	}

	bs.Close()
}

func TestBlockStore_GetTx(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 3)
	bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})

	for _, tx := range block.Txns {
		txHash := tx.Hash()
		tx, height, _, _, err := bs.GetTx(txHash)
		if err != nil {
			t.Fatal(err)
		}
		rawTx, err := tx.MarshalBinary()
		require.NoError(t, err)

		if height != block.Header.Height {
			t.Errorf("Expected tx height %d, got %d", block.Header.Height, height)
		}

		txData, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(txData, rawTx) {
			t.Error("Retrieved transaction data doesn't match original")
		}
	}
}

func TestBlockStore_HaveTx(t *testing.T) {
	bs, dir := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 6)
	txHash := block.Txns[0].Hash()

	if bs.HaveTx(txHash) {
		t.Error("Transaction should not exist before storing block")
	}

	bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})

	if !bs.HaveTx(txHash) {
		t.Error("Transaction should exist after storing block")
	}

	bs.Close()

	bs, err := NewBlockStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if !bs.HaveTx(txHash) {
		t.Error("Transaction should exist after reloading store")
	}

	if !bs.Have(block.Hash()) {
		t.Error("block should exist after reloading store")
	}
}

func TestBlockStore_StoreWithNoTransactions(t *testing.T) {
	bs, _ := setupTestBlockStore(t)
	block := ktypes.NewBlock(1, types.Hash{2, 3, 4}, types.Hash{6, 7, 8}, types.Hash{},
		types.Hash{5, 5, 5}, time.Unix(1729723553, 0), []*ktypes.Transaction{})
	appHash := fakeAppHash(1)

	err := bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}

	blk, ci, err := bs.Get(block.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if len(blk.Txns) != 0 {
		t.Error("Expected empty transactions")
	}
	if ci.AppHash != appHash {
		t.Errorf("Expected app hash %x, got %x", appHash, ci.AppHash)
	}
}

func TestBlockStore_StoreConcurrent(t *testing.T) {
	bs, _ := setupTestBlockStore(t)
	done := make(chan bool)
	blockCount := 100

	for i := range 3 {
		go func(start int) {
			for j := range blockCount {
				block, appHash, _ := createTestBlock(t, int64(start*blockCount+j), 2)
				err := bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
				if err != nil {
					t.Error(err)
				}
			}
			done <- true
		}(i)
	}

	for range 3 {
		<-done
	}

	for i := range 3 {
		for j := range blockCount {
			height := int64(i*blockCount + j)
			_, blk, ci, err := bs.GetByHeight(height)
			if err != nil {
				t.Errorf("Failed to get block at height %d: %v", height, err)
			}
			if blk.Header.Height != height {
				t.Errorf("Expected height %d, got %d", height, blk.Header.Height)
			}
			if ci.AppHash != fakeAppHash(height) {
				t.Errorf("Expected app hash %x, got %x", fakeAppHash(height), ci.AppHash)
			}
		}
	}
}

func TestBlockStore_StoreDuplicateBlock(t *testing.T) {
	bs, _ := setupTestBlockStore(t)
	block, appHash, _ := createTestBlock(t, 1, 2)

	err := bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}

	err = bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}

	height, hash, gotAppHash, _ := bs.Best()
	if height != block.Header.Height {
		t.Errorf("Expected height %d, got %d", block.Header.Height, height)
	}
	if hash != block.Hash() {
		t.Errorf("Expected hash %x, got %x", block.Hash(), hash)
	}
	if appHash != gotAppHash {
		t.Errorf("Expected app hash %x, got %x", appHash, gotAppHash)
	}
}

func TestBlockStore_StoreWithLargeTransactions(t *testing.T) {
	bs, _ := setupTestBlockStore(t, true)
	largeTxPayload := make([]byte, 1<<20) // 1MB transaction
	for i := range largeTxPayload {
		largeTxPayload[i] = byte(i % 256)
	}

	largeTx := newTx(2, "moo")
	largeTx.Body.Payload = largeTxPayload
	otherTx := newTx(1, "Adsf")
	otherTx.Body.Payload = []byte{1, 2, 3}

	largeTxRaw, err := largeTx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	otherTxRaw, err := otherTx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	block := ktypes.NewBlock(1, types.Hash{2, 3, 4}, types.Hash{6, 7, 8}, types.Hash{},
		types.Hash{5, 5, 5}, time.Unix(1729723553, 0), []*ktypes.Transaction{largeTx, otherTx})
	appHash := fakeAppHash(1)

	err = bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}

	blkHash := block.Hash()
	bk, ci, err := bs.Get(blkHash)
	if err != nil {
		t.Fatal(err)
	}
	if bk.Hash() != blkHash {
		t.Fatal("hash mismatch")
	}
	if ci.AppHash != appHash {
		t.Fatal("apphash mismatch")
	}

	for _, rawTx := range [][]byte{largeTxRaw, otherTxRaw} {
		txHash := types.HashBytes(rawTx)
		tx, _, _, _, err := bs.GetTx(txHash)
		if err != nil {
			t.Fatal(err)
		}
		txData, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(txData, rawTx) {
			t.Error("Retrieved transaction data doesn't match original")
		}
	}

	// bs.Close()
	// filesInfo, err := getFileSizes(tmpDir)
	// if err != nil {
	// 	t.Logf("Error: %v", err)
	// } else {
	// 	prettyPrintFileSizes(filesInfo)
	// }
}

func newTx(nonce uint64, sender string, optPayload ...string) *ktypes.Transaction {
	payload := `random payload`
	if len(optPayload) > 0 {
		payload = optPayload[0]
	}
	return &ktypes.Transaction{
		Signature: &auth.Signature{},
		Body: &ktypes.TransactionBody{
			Description: "test",
			Payload:     []byte(payload),
			Fee:         big.NewInt(0),
			Nonce:       nonce,
		},
		Sender: []byte(sender),
	}
}

func TestLargeBlockStore(t *testing.T) {
	// This test demonstrates that zstd level 1 compression is no slower than no
	// compression for reasonably compressible data.
	t.Run("no compression", func(t *testing.T) {
		testLargeBlockStore(t, false)
	})

	t.Run("compression", func(t *testing.T) {
		testLargeBlockStore(t, true)
	})
}

func testLargeBlockStore(t *testing.T, compress bool) {
	// Create block store
	dir := t.TempDir()
	logger := log.NewStdoutLogger()
	bs, err := NewBlockStore(dir, WithCompression(compress), WithLogger(logger))
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()

	// Generate large number of blocks with many txs
	const numBlocks = 100
	const txsPerBlock = 1000
	const txSize = 1024 // 1KB per tx, small enough not to use vlog for the block

	var prevHash types.Hash
	var prevAppHash types.Hash

	rngSrc := rand.NewChaCha8(prevHash)
	rng := rand.New(rngSrc)

	// Patterned tx body to make it compressible
	txPayload := make([]byte, txSize-8)
	for i := range txPayload {
		txPayload[i] = byte(i % 16)
	}

	// Create blocks with random transactions
	for height := int64(1); height <= numBlocks; height++ {
		// Generate random transactions
		rawTxns := make([][]byte, txsPerBlock)
		txns := make([]*ktypes.Transaction, txsPerBlock)
		for i := range rawTxns {
			tx := newTx(uint64(i), "sendername")
			tx.Body.Payload = make([]byte, txSize)
			copy(tx.Body.Payload, txPayload)
			txns[i] = tx
			rawTxns[i], err = tx.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
		}

		// Create and store block
		block := ktypes.NewBlock(height, prevHash, prevAppHash, types.Hash{}, types.Hash{}, time.Now(), txns)
		appHash := types.HashBytes([]byte(fmt.Sprintf("app-%d", height)))
		err = bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
		if err != nil {
			t.Fatal(err)
		}

		prevHash = block.Hash()

		// Verify block retrieval
		if height%100 == 0 {
			retrieved, ci, err := bs.Get(prevHash)
			if err != nil {
				t.Errorf("Failed to get block at height %d: %v", height, err)
			}
			if retrieved.Hash() != prevHash {
				t.Errorf("Retrieved block hash mismatch at height %d", height)
			}
			if ci.AppHash != appHash {
				t.Errorf("Retrieved app hash mismatch at height %d", height)
			}
			if retrieved.Header.PrevAppHash != prevAppHash {
				t.Errorf("Retrieved prev app hash mismatch at height %d", height)
			}

			// Verify random transaction retrieval

			txIdx := rng.IntN(len(txns))
			txHash := types.HashBytes(rawTxns[txIdx])
			tx, gotHeight, _, _, err := bs.GetTx(txHash)
			if err != nil {
				t.Errorf("Failed to get tx at height %d, idx %d: %v", height, txIdx, err)
			}
			txData, err := tx.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if gotHeight != height {
				t.Errorf("Wrong tx height. Got %d, want %d", gotHeight, height)
			}
			if !bytes.Equal(txData, rawTxns[txIdx]) {
				t.Error("Retrieved tx data mismatch")
			}
		}

		prevAppHash = appHash // types.HashBytes([]byte(fmt.Sprintf("app-%d", height)))
	}

	// Verify final database size
	bs.Close() // else we are checking size of huge sparse allocated files
	dbSize := getDirSize(dir)
	t.Logf("Final database size: %d MB", dbSize/1024/1024)
	filesInfo, err := getFileSizes(dir)
	if err != nil {
		t.Logf("Error: %v", err)
	} else {
		prettyPrintFileSizes(filesInfo)
	}
}

func getDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}
func TestBlockStore_StoreAndGetResults(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 3)
	err := bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}

	results := []ktypes.TxResult{
		{Code: 0, Log: "result1", Events: []ktypes.Event{}},
		{Code: 1, Log: "result2", Events: []ktypes.Event{{}}},
		{Code: 2, Log: "result3", Events: []ktypes.Event{{}, {}}},
	}

	err = bs.StoreResults(block.Hash(), results)
	if err != nil {
		t.Fatal(err)
	}

	gotResults, err := bs.Results(block.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if len(gotResults) != len(results) {
		t.Fatalf("Expected %d results, got %d", len(results), len(gotResults))
	}

	for i, res := range results {
		if res.Code != gotResults[i].Code {
			t.Errorf("Result %d: expected code %d, got %d", i, res.Code, gotResults[i].Code)
		}
		if res.Log != gotResults[i].Log {
			t.Errorf("Result %d: expected data %s, got %s", i, res.Log, gotResults[i].Log)
		}
	}
}

func TestBlockStore_StoreResultsEmptyBlock(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block := ktypes.NewBlock(1, types.Hash{2, 3, 4}, types.Hash{6, 7, 8}, types.Hash{},
		types.Hash{5, 5, 5}, time.Unix(1729723553, 0), []*ktypes.Transaction{})
	appHash := fakeAppHash(1)

	err := bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}

	results := []ktypes.TxResult{}
	err = bs.StoreResults(block.Hash(), results)
	if err != nil {
		t.Fatal(err)
	}

	gotResults, err := bs.Results(block.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if len(gotResults) != 0 {
		t.Errorf("Expected empty results, got %d results", len(gotResults))
	}
}

func TestBlockStore_ResultsNonExistentBlock(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	nonExistentHash := types.Hash{1, 2, 3}
	_, err := bs.Results(nonExistentHash)
	if err == nil {
		t.Error("Expected error when getting results for non-existent block")
	}
}

func TestBlockStore_StoreResultsLargeData(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 2)
	err := bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}

	largeData := make([]byte, 1<<20) // 1MB
	// rngSrc := rand.NewChaCha8([32]byte{}) // deterministic random data
	crand.Read(largeData)

	results := []ktypes.TxResult{
		{Code: 0, Log: string(largeData)},
		{Code: 1, Log: "small result"},
	}

	err = bs.StoreResults(block.Hash(), results)
	if err != nil {
		t.Fatal(err)
	}

	gotResults, err := bs.Results(block.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if gotResults[0].Log != string(largeData) {
		t.Error("Large result data mismatch")
	}
	if gotResults[1].Log != "small result" {
		t.Error("Small result data mismatch")
	}
}

func TestBlockStore_StoreResultsMismatchedCount(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 2)
	err := bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}

	results := []ktypes.TxResult{
		{Code: 0, Log: "result1"},
		{Code: 1, Log: "result2"},
		{Code: 2, Log: "result3"}, // Extra result
	}

	err = bs.StoreResults(block.Hash(), results)
	if err != nil {
		t.Fatal(err)
	}

	_, err = bs.Results(block.Hash())
	if err == nil {
		t.Error("expected error when getting results for mismatched count")
	}

}

func TestBlockStore_Result(t *testing.T) {
	bs, _ := setupTestBlockStore(t)

	block, appHash, _ := createTestBlock(t, 1, 3)
	err := bs.Store(block, &ktypes.CommitInfo{AppHash: appHash})
	if err != nil {
		t.Fatal(err)
	}

	results := []ktypes.TxResult{
		{Code: 0, Log: "success", Events: []ktypes.Event{}},
		{Code: 1, Log: "failure", Events: []ktypes.Event{}},
		{Code: 2, Log: "pending", Events: []ktypes.Event{}},
	}

	err = bs.StoreResults(block.Hash(), results)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		idx     uint32
		want    *ktypes.TxResult
		wantErr bool
	}{
		{
			name: "valid first result",
			idx:  0,
			want: &results[0],
		},
		{
			name: "valid middle result",
			idx:  1,
			want: &results[1],
		},
		{
			name: "valid last result",
			idx:  2,
			want: &results[2],
		},
		{
			name:    "invalid index",
			idx:     3,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bs.Result(block.Hash(), tt.idx)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if got.Code != tt.want.Code {
				t.Errorf("Code = %v, want %v", got.Code, tt.want.Code)
			}
			if got.Log != tt.want.Log {
				t.Errorf("Log = %v, want %v", got.Log, tt.want.Log)
			}
			if len(got.Events) != len(tt.want.Events) {
				t.Errorf("Events length = %v, want %v", len(got.Events), len(tt.want.Events))
			}
		})
	}

	// Test with non-existent block hash
	nonExistentHash := types.Hash{0xFF, 0xFF, 0xFF}
	_, err = bs.Result(nonExistentHash, 0)
	if err == nil {
		t.Error("expected error for non-existent block hash, got nil")
	}

	// Test after closing store
	bs.Close()
	_, err = bs.Result(block.Hash(), 0)
	if err == nil {
		t.Error("expected error after store closure, got nil")
	}
}
