package mempool

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

const (
	mempoolSz = 200_000_000 // 200MB
	maxTxSz   = 4_000_000   // 4MB
)

func newTx(nonce uint64, sender string) *types.Tx {
	return types.NewTx(&ktypes.Transaction{
		Signature: &auth.Signature{},
		Body: &ktypes.TransactionBody{
			Description: "test",
			Payload:     []byte(`random payload`),
			Fee:         big.NewInt(0),
			Nonce:       nonce,
		},
		Sender: []byte(sender),
	})
}

func Test_MempoolRemove(t *testing.T) {
	m := New(mempoolSz, maxTxSz)

	// Setup test transactions
	tx1 := newTx(1, "A")
	tx2 := newTx(2, "B")

	// Add transactions to mempool
	m.Store(tx1)
	m.Store(tx2)

	// Test removing existing transaction
	m.Remove(tx1.Hash())
	require.Len(t, m.txQ, 1)
	require.Len(t, m.txns, 1)
	assert.Equal(t, m.txQ[0].Hash(), tx2.Hash())
	_, exists := m.txns[tx1.Hash()]
	assert.False(t, exists)

	// Test removing non-existent transaction
	nonExistentHash := types.Hash{9}
	m.Remove(nonExistentHash)
	require.Len(t, m.txQ, 1)
	require.Len(t, m.txns, 1)
	assert.Equal(t, m.txQ[0].Hash(), tx2.Hash())

	// Test removing last transaction
	m.Remove(tx2.Hash())
	assert.Empty(t, m.txQ)
	assert.Empty(t, m.txns)
}

func Test_MempoolReapN(t *testing.T) {
	m := New(mempoolSz, maxTxSz)

	// Setup test transactions
	tx1 := newTx(1, "A")
	tx2 := newTx(2, "B")
	tx3 := newTx(3, "C")

	// Test reaping from empty mempool
	emptyReap := m.ReapN(1)
	assert.Empty(t, emptyReap)

	// Add transactions to mempool
	m.Store(tx1)
	m.Store(tx2)
	m.Store(tx3)

	// Test reaping more transactions than available
	overReap := m.ReapN(5)
	require.Len(t, overReap, 3)
	assert.Equal(t, overReap[0].Hash(), tx1.Hash())
	assert.Equal(t, overReap[1].Hash(), tx2.Hash())
	assert.Equal(t, overReap[2].Hash(), tx3.Hash())
	assert.Empty(t, m.txQ)
	assert.Empty(t, m.txns)

	// Refill mempool
	m.Store(tx1)
	m.Store(tx2)
	m.Store(tx3)

	// Test partial reaping
	partialReap := m.ReapN(2)
	require.Len(t, partialReap, 2)
	assert.Equal(t, partialReap[0].Hash(), tx1.Hash())
	assert.Equal(t, partialReap[1].Hash(), tx2.Hash())
	assert.Len(t, m.txQ, 1)
	assert.Len(t, m.txns, 1)

	// Test reaping remaining transaction
	finalReap := m.ReapN(1)
	require.Len(t, finalReap, 1)
	assert.Equal(t, finalReap[0].Hash(), tx3.Hash())
	assert.Empty(t, m.txQ)
	assert.Empty(t, m.txns)

	// Test reaping with zero count
	zeroReap := m.ReapN(0)
	assert.Empty(t, zeroReap)
}

func TestMempool_Size(t *testing.T) {
	t.Run("size tracking with stored transactions", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)

		// Create a test transaction
		tx := newTx(1, "A")

		err := mp.Store(tx)
		if err != nil {
			t.Fatal("transaction should be neither found nor rejected")
		}

		byteSize, count := mp.Size()
		expectedByteSize := tx.SerializeSize()

		if count != 1 {
			t.Errorf("tx count = %d, want 1", count)
		}
		if byteSize != int(expectedByteSize) {
			t.Errorf("byte size = %d, want %d", byteSize, expectedByteSize)
		}
	})

	t.Run("size tracking with multiple transactions", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)

		tx1 := newTx(1, "A")
		tx2 := newTx(2, "B")

		mp.Store(tx1)
		mp.Store(tx2)

		byteSize, count := mp.Size()
		expectedByteSize1 := tx1.SerializeSize()
		expectedByteSize2 := tx2.SerializeSize()

		if count != 2 {
			t.Errorf("tx count = %d, want 2", count)
		}
		if byteSize != int(expectedByteSize1+expectedByteSize2) {
			t.Errorf("byte size = %d, want %d", byteSize, expectedByteSize1+expectedByteSize2)
		}
	})

	// Test store same txid again, already found
	t.Run("size tracking with duplicate txid", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		err := mp.Store(tx1)
		require.NoError(t, err)
		err = mp.Store(tx1)
		require.True(t, errors.Is(err, ktypes.ErrTxAlreadyExists))
	})

	// Test Store with a low SetMaxSize
	t.Run("size tracking with SetMaxSize", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		mp.SetMaxSize(20)
		tx1 := newTx(1, "abcdefghijklmnopqrstuvwxyz")
		err := mp.Store(tx1)
		require.True(t, errors.Is(err, ktypes.ErrMempoolFull))
	})

	t.Run("tx too big", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		mp.SetMaxSize(20)
		tx1 := newTx(1, "abcdefghijklmnopqrstuvwxyz")
		err := mp.Store(tx1)
		require.True(t, errors.Is(err, ktypes.ErrMempoolFull))
	})
}

func TestMempool_SizeWithRemove(t *testing.T) {
	mp := New(mempoolSz, maxTxSz)

	// Create and store two transactions
	tx1 := newTx(1, "A")
	tx2 := newTx(2, "B")

	hash1 := tx1.Hash()

	err := mp.Store(tx1)
	require.NoError(t, err, "transaction should be neither found nor rejected")

	err = mp.Store(tx2)
	require.NoError(t, err, "transaction should be neither found nor rejected")

	// Verify initial size
	byteSize, count := mp.Size()
	if count != 2 {
		t.Errorf("initial tx count = %d, want 2", count)
	}

	// Remove one transaction
	mp.Remove(hash1)

	// Verify updated size
	newByteSize, newCount := mp.Size()
	if newCount != 1 {
		t.Errorf("tx count after remove = %d, want 1", newCount)
	}

	size1 := tx1.SerializeSize()
	expectedByteSize := byteSize - int(size1)
	if newByteSize != expectedByteSize {
		t.Errorf("byte size after remove = %d, want %d", newByteSize, expectedByteSize)
	}
}

func TestMempool_RecheckTxs(t *testing.T) {
	t.Run("recheck with all valid transactions", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		tx2 := newTx(2, "B")

		mp.Store(tx1)
		mp.Store(tx2)

		initialSize, initialCount := mp.Size()

		checkFn := func(ctx context.Context, tx *types.Tx) error {
			return nil
		}

		mp.RecheckTxs(context.Background(), checkFn)

		finalSize, finalCount := mp.Size()
		assert.Equal(t, initialSize, finalSize)
		assert.Equal(t, initialCount, finalCount)
	})

	t.Run("recheck with all invalid transactions", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		tx2 := newTx(2, "B")

		mp.Store(tx1)
		mp.Store(tx2)

		checkFn := func(ctx context.Context, tx *types.Tx) error {
			return errors.New("invalid transaction")
		}

		mp.RecheckTxs(context.Background(), checkFn)

		size, count := mp.Size()
		assert.Equal(t, 0, size)
		assert.Equal(t, 0, count)
		assert.Empty(t, mp.txQ)
		assert.Empty(t, mp.txns)
	})

	t.Run("recheck with mixed valid/invalid transactions", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		tx2 := newTx(2, "B")
		tx3 := newTx(3, "C")

		mp.Store(tx1)
		mp.Store(tx2)
		mp.Store(tx3)

		checkFn := func(ctx context.Context, tx *types.Tx) error {
			if string(tx.Sender) == "B" {
				return errors.New("invalid transaction")
			}
			return nil
		}

		mp.RecheckTxs(context.Background(), checkFn)

		_, count := mp.Size()
		assert.Equal(t, 2, count)
		assert.Len(t, mp.txQ, 2)
		assert.Len(t, mp.txns, 2)

		// Verify specific transactions
		_, exists := mp.txns[tx2.Hash()]
		assert.False(t, exists)
		_, exists = mp.txns[tx1.Hash()]
		assert.True(t, exists)
		_, exists = mp.txns[tx3.Hash()]
		assert.True(t, exists)
	})

	t.Run("with a lot more transactions mixed invalid", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		tx2 := newTx(2, "B")
		tx3 := newTx(3, "C")
		tx4 := newTx(4, "D")
		tx5 := newTx(5, "E")
		tx6 := newTx(6, "F")
		tx7 := newTx(7, "G")
		tx8 := newTx(8, "H")
		tx9 := newTx(9, "I")
		tx10 := newTx(10, "J")

		mp.Store(tx1)
		mp.Store(tx2)
		mp.Store(tx3)
		mp.Store(tx4)
		mp.Store(tx5)
		mp.Store(tx6)
		mp.Store(tx7)
		mp.Store(tx8)
		mp.Store(tx9)
		mp.Store(tx10)

		checkFn := func(ctx context.Context, tx *types.Tx) error {
			switch string(tx.Sender) {
			case "B", "D", "F", "H", "J": // 2, 4, 6, 8, 10
				return errors.New("invalid transaction")
			default:
				return nil
			}
		}

		mp.RecheckTxs(context.Background(), checkFn)
		_, count := mp.Size()
		assert.Equal(t, 5, count)
		assert.Len(t, mp.txQ, 5)
		assert.Len(t, mp.txns, 5)

		// Verify specific transactions
		_, exists := mp.txns[tx2.Hash()]
		assert.False(t, exists)
		_, exists = mp.txns[tx4.Hash()]
		assert.False(t, exists)
		_, exists = mp.txns[tx6.Hash()]
		assert.False(t, exists)
		_, exists = mp.txns[tx8.Hash()]
		assert.False(t, exists)
		_, exists = mp.txns[tx10.Hash()]
		assert.False(t, exists)

		_, exists = mp.txns[tx1.Hash()]
		assert.True(t, exists)
		_, exists = mp.txns[tx3.Hash()]
		assert.True(t, exists)
		_, exists = mp.txns[tx5.Hash()]
		assert.True(t, exists)
		_, exists = mp.txns[tx7.Hash()]
		assert.True(t, exists)
		_, exists = mp.txns[tx9.Hash()]
		assert.True(t, exists)
	})

	t.Run("recheck with canceled context", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		mp.Store(tx1)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		checkFn := func(ctx context.Context, tx *types.Tx) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		}

		mp.RecheckTxs(ctx, checkFn)

		size, count := mp.Size()
		assert.Equal(t, 0, size)
		assert.Equal(t, 0, count)
	})
}

func TestMempool_PeekN(t *testing.T) {
	t.Run("peek with size limit", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")                       // small tx
		tx2 := newTx(2, strings.Repeat("B", 1000)) // large tx
		tx3 := newTx(3, "C")                       // small tx

		mp.Store(tx1)
		mp.Store(tx2)
		mp.Store(tx3)

		// Set size limit to allow only first two transactions
		txns := mp.PeekN(3, int(tx1.SerializeSize()+tx2.SerializeSize()))
		require.Len(t, txns, 2)
		assert.Equal(t, tx1.Hash(), txns[0].Hash())
		assert.Equal(t, tx2.Hash(), txns[1].Hash())

		// Verify original mempool is unchanged
		size, count := mp.Size()
		assert.Equal(t, 3, count)
		assert.True(t, size > 0)
	})

	t.Run("peek with zero size limit", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		tx2 := newTx(2, "B")

		mp.Store(tx1)
		mp.Store(tx2)

		txns := mp.PeekN(2, 0)
		require.Len(t, txns, 2)
		assert.Equal(t, tx1.Hash(), txns[0].Hash())
		assert.Equal(t, tx2.Hash(), txns[1].Hash())
	})

	t.Run("peek with n greater than available txs", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		mp.Store(tx1)

		txns := mp.PeekN(5, 1000)
		require.Len(t, txns, 1)
		assert.Equal(t, tx1.Hash(), txns[0].Hash())
	})

	t.Run("peek with empty mempool", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		txns := mp.PeekN(1, 1000)
		assert.Empty(t, txns)
	})

	t.Run("peek with negative size limit", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		tx2 := newTx(2, "B")

		mp.Store(tx1)
		mp.Store(tx2)

		txns := mp.PeekN(2, -1)
		require.Len(t, txns, 2)
		assert.Equal(t, tx1.Hash(), txns[0].Hash())
		assert.Equal(t, tx2.Hash(), txns[1].Hash())
	})

	t.Run("peek with zero n", func(t *testing.T) {
		mp := New(mempoolSz, maxTxSz)
		tx1 := newTx(1, "A")
		mp.Store(tx1)

		txns := mp.PeekN(0, 1000)
		assert.Empty(t, txns)
	})
}
