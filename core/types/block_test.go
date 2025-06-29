package types

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"

	"github.com/stretchr/testify/require"
)

func newTx(nonce uint64, sender, payload string) *Transaction {
	return &Transaction{
		Signature: &auth.Signature{},
		Body: &TransactionBody{
			Description: "test",
			Payload:     []byte(payload),
			Fee:         big.NewInt(0),
			Nonce:       nonce,
		},
		Sender: []byte(sender),
	}
}

func TestDecodeBlockHeader_invalid(t *testing.T) {
	data := strings.NewReader("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001")
	_, err := DecodeBlockHeader(data)
	require.Error(t, err)
	require.ErrorContains(t, err, "encoded length is negative")
}

func TestGetRawBlockTx(t *testing.T) {
	privKey, pubKey, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)

	makeRawBlock := func(txnPayloads [][]byte) ([]byte, *Block) {
		txns := make([]*Transaction, len(txnPayloads))
		for i, pl := range txnPayloads {
			txns[i] = newTx(uint64(i), "bob", string(pl))
		}
		blk := NewBlock(1, Hash{1, 2, 3}, Hash{6, 7, 8}, Hash{}, Hash{}, time.Unix(1729890593, 0), txns)
		err := blk.Sign(privKey)
		require.NoError(t, err)
		return EncodeBlock(blk), blk
	}

	t.Run("valid block signature", func(t *testing.T) {
		txns := [][]byte{[]byte("tx1")}
		rawBlock, _ := makeRawBlock(txns)
		blk, err := DecodeBlock(rawBlock)
		require.NoError(t, err)

		valid, err := blk.VerifySignature(pubKey)
		require.NoError(t, err)
		require.True(t, valid)
	})

	t.Run("valid transaction index", func(t *testing.T) {
		txns := [][]byte{
			[]byte("tx1"),
			[]byte("transaction2"),
			[]byte("tx3"),
		}
		rawBlock, blk := makeRawBlock(txns)
		const idx = 1
		rawTx, err := GetRawBlockTx(rawBlock, idx)
		if err != nil {
			t.Fatal(err)
		}
		txOut1 := blk.Txns[idx]
		rawTxOut1, err := txOut1.MarshalBinary()
		require.NoError(t, err)
		if !bytes.Equal(rawTx, rawTxOut1) {
			t.Errorf("got tx %x, want %x", rawTx, rawTxOut1)
		}
	})

	t.Run("invalid transaction length", func(t *testing.T) {
		buf := new(bytes.Buffer)
		header := &BlockHeader{Height: 1, NumTxns: 1}
		buf.Write(EncodeBlockHeader(header))
		buf.Write(binary.AppendUvarint(nil, 0))             // empty sig
		buf.Write(binary.AppendUvarint(nil, uint64(1<<30))) // Very large tx length

		_, err := GetRawBlockTx(buf.Bytes(), 0)
		if err == nil {
			t.Error("expected error for invalid transaction length")
		}
	})

	t.Run("index out of range", func(t *testing.T) {
		txns := [][]byte{[]byte("tx1")}
		rawBlock, _ := makeRawBlock(txns)

		_, err := GetRawBlockTx(rawBlock, 1)
		if err != ErrNotFound {
			t.Errorf("got err %v, want ErrNotFound", err)
		}
	})

	t.Run("corrupted block data", func(t *testing.T) {
		txns := [][]byte{[]byte("tx1")}
		rawBlock, _ := makeRawBlock(txns)
		blk, err := DecodeBlock(rawBlock)
		require.NoError(t, err)

		sigLen := len(blk.Signature) + 4
		corrupted := rawBlock[:len(rawBlock)-1-sigLen]

		_, err = GetRawBlockTx(corrupted, 0)
		if err == nil {
			t.Error("expected error for corrupted block data")
		}
	})

	t.Run("empty block", func(t *testing.T) {
		rawBlock, _ := makeRawBlock([][]byte{})

		_, err := GetRawBlockTx(rawBlock, 0)
		if err != ErrNotFound {
			t.Errorf("got err %v, want ErrNotFound", err)
		}
	})
}

func TestCalcMerkleRoot(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		root := CalcMerkleRoot([]Hash{})
		if root != (Hash{}) {
			t.Errorf("empty slice should return zero hash, got %x", root)
		}
	})

	t.Run("single leaf", func(t *testing.T) {
		leaf := Hash{1, 2, 3, 4}
		root := CalcMerkleRoot([]Hash{leaf})
		if root != leaf {
			t.Errorf("single leaf should return same hash, got %x, want %x", root, leaf)
		}
	})

	t.Run("two leaves", func(t *testing.T) {
		leaf1 := Hash{1, 2, 3, 4}
		leaf2 := Hash{5, 6, 7, 8}
		root := CalcMerkleRoot([]Hash{leaf1, leaf2})

		var buf [HashLen * 2]byte
		copy(buf[:HashLen], leaf1[:])
		copy(buf[HashLen:], leaf2[:])
		expected := HashBytes(buf[:])

		if root != expected {
			t.Errorf("got root %x, want %x", root, expected)
		}
	})

	t.Run("three leaves", func(t *testing.T) {
		leaves := []Hash{
			{1, 1, 1, 1},
			{2, 2, 2, 2},
			{3, 3, 3, 3},
		}
		CalcMerkleRoot(leaves)

		// Verify original slice not modified
		if leaves[2] != (Hash{3, 3, 3, 3}) {
			t.Error("original slice was modified")
		}
	})

	t.Run("four leaves", func(t *testing.T) {
		leaves := []Hash{
			{1, 1, 1, 1},
			{2, 2, 2, 2},
			{3, 3, 3, 3},
			{4, 4, 4, 4},
		}
		root1 := CalcMerkleRoot(leaves)

		// Calculate same root with modified order
		leaves[0], leaves[1] = leaves[1], leaves[0]
		root2 := CalcMerkleRoot(leaves)

		if root1 == root2 {
			t.Error("roots should differ when leaf order changes")
		}
	})

	t.Run("preserve input", func(t *testing.T) {
		original := []Hash{
			{1, 1, 1, 1},
			{2, 2, 2, 2},
		}
		originalCopy := make([]Hash, len(original))
		copy(originalCopy, original)

		CalcMerkleRoot(original)

		for i := range original {
			if original[i] != originalCopy[i] {
				t.Errorf("input slice was modified at index %d", i)
			}
		}
	})
}

func TestBlock_EncodeDecode(t *testing.T) {
	t.Run("encode and decode empty block", func(t *testing.T) {
		original := &Block{
			Header: &BlockHeader{
				Version:          1,
				Height:           100,
				NumTxns:          0,
				PrevHash:         Hash{1, 2, 3},
				PrevAppHash:      Hash{4, 5, 6},
				ValidatorSetHash: Hash{7, 8, 9},
				Timestamp:        time.Now().UTC().Truncate(time.Millisecond),
				MerkleRoot:       Hash{10, 11, 12},
			},
			Txns:      []*Transaction{},
			Signature: []byte("test-signature"),
		}

		encoded := EncodeBlock(original)
		decoded, err := DecodeBlock(encoded)
		require.NoError(t, err)
		require.Equal(t, original.Header, decoded.Header)
		require.Equal(t, original.Signature, decoded.Signature)
		require.Empty(t, decoded.Txns)
	})

	t.Run("encode and decode block with multiple transactions", func(t *testing.T) {
		txns := []*Transaction{
			newTx(0, "bob", "tx1"),
			newTx(1, "bob", "transaction 2"),
			newTx(0, "alice", string(make([]byte, 1000))),
		}
		original := &Block{
			Header: &BlockHeader{
				Version:          1,
				Height:           100,
				NumTxns:          uint32(len(txns)),
				PrevHash:         Hash{1, 2, 3},
				PrevAppHash:      Hash{4, 5, 6},
				ValidatorSetHash: Hash{7, 8, 9},
				Timestamp:        time.Now().UTC().Truncate(time.Millisecond),
				MerkleRoot:       Hash{10, 11, 12},
			},
			Txns:      txns,
			Signature: []byte("test-signature-long"),
		}

		encoded := EncodeBlock(original)
		decoded, err := DecodeBlock(encoded)
		require.NoError(t, err)
		require.Equal(t, original.Header, decoded.Header)
		require.Equal(t, original.Signature, decoded.Signature)
		require.EqualExportedValues(t, original.Txns, decoded.Txns)
	})

	t.Run("decode with invalid signature length", func(t *testing.T) {
		buf := new(bytes.Buffer)
		header := &BlockHeader{Height: 1, NumTxns: 0}
		buf.Write(EncodeBlockHeader(header))
		buf.Write(binary.AppendUvarint(nil, 1<<31)) // too big signature

		_, err := DecodeBlock(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature length")
	})

	t.Run("decode with invalid transaction count", func(t *testing.T) {
		buf := new(bytes.Buffer)
		header := &BlockHeader{Height: 1, NumTxns: 1}
		buf.Write(EncodeBlockHeader(header))
		// sigLen and sig
		buf.Write(binary.AppendUvarint(nil, 3))
		buf.Write([]byte("sig"))

		// lx len, but no tx data
		buf.Write(binary.AppendUvarint(nil, uint64(20)))

		_, err := DecodeBlock(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid number of transactions")
	})

	t.Run("decode with invalid transaction length", func(t *testing.T) {
		buf := new(bytes.Buffer)
		header := &BlockHeader{Height: 1, NumTxns: 1}
		buf.Write(EncodeBlockHeader(header))
		// sigLen and sig
		buf.Write(binary.AppendUvarint(nil, 3))
		buf.Write([]byte("sig"))

		// first txLen -- too big (but pass tx count check)
		buf.Write(binary.AppendUvarint(nil, uint64(1<<31)))
		buf.Write([]byte("txdata"))

		_, err := DecodeBlock(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid transaction length")
	})

	t.Run("decode with truncated data", func(t *testing.T) {
		original := &Block{
			Header: &BlockHeader{
				Version:   1,
				Height:    100,
				NumTxns:   1,
				Timestamp: time.Now(),
			},
			Txns:      []*Transaction{newTx(0, "bob", "a")},
			Signature: []byte("sig"),
		}
		encoded := EncodeBlock(original)
		truncated := encoded[:len(encoded)-10]

		_, err := DecodeBlock(truncated)
		require.Error(t, err)
	})

	t.Run("block header with leader update", func(t *testing.T) {
		_, pub, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)

		original := &Block{
			Header: &BlockHeader{
				Version:          1,
				Height:           100,
				NumTxns:          0,
				PrevHash:         Hash{1, 2, 3},
				PrevAppHash:      Hash{4, 5, 6},
				ValidatorSetHash: Hash{7, 8, 9},
				Timestamp:        time.Now().UTC().Truncate(time.Millisecond),
				MerkleRoot:       Hash{10, 11, 12},
				NewLeader:        pub,
			},
			Txns:      []*Transaction{},
			Signature: []byte("test-signature"),
		}

		encoded := EncodeBlock(original)
		decoded, err := DecodeBlock(encoded)
		require.NoError(t, err)
		require.Equal(t, original.Header, decoded.Header)
		require.Equal(t, original.Signature, decoded.Signature)
		require.Empty(t, decoded.Txns)
	})
}

func TestCalcMerkleRoot_Extended(t *testing.T) {
	t.Run("five leaves", func(t *testing.T) {
		leaves := []Hash{
			{1, 1, 1, 1},
			{2, 2, 2, 2},
			{3, 3, 3, 3},
			{4, 4, 4, 4},
			{5, 5, 5, 5},
		}
		root := CalcMerkleRoot(leaves)
		require.NotEqual(t, Hash{}, root)

		// Verify the tree structure by calculating intermediate nodes
		var buf [HashLen * 2]byte
		copy(buf[:HashLen], leaves[0][:])
		copy(buf[HashLen:], leaves[1][:])
		h01 := HashBytes(buf[:])

		copy(buf[:HashLen], leaves[2][:])
		copy(buf[HashLen:], leaves[3][:])
		h23 := HashBytes(buf[:])

		copy(buf[:HashLen], leaves[4][:])
		copy(buf[HashLen:], leaves[4][:])
		h44 := HashBytes(buf[:])

		copy(buf[:HashLen], h01[:])
		copy(buf[HashLen:], h23[:])
		h0123 := HashBytes(buf[:])

		copy(buf[:HashLen], h44[:])
		copy(buf[HashLen:], h44[:])
		h4444 := HashBytes(buf[:])

		copy(buf[:HashLen], h0123[:])
		copy(buf[HashLen:], h4444[:])
		expected := HashBytes(buf[:])

		require.Equal(t, expected, root)
	})

	t.Run("seven leaves", func(t *testing.T) {
		leaves := []Hash{
			{1, 1, 1, 1},
			{2, 2, 2, 2},
			{3, 3, 3, 3},
			{4, 4, 4, 4},
			{5, 5, 5, 5},
			{6, 6, 6, 6},
			{7, 7, 7, 7},
		}
		root1 := CalcMerkleRoot(leaves)

		// Calculate with different ordering
		reversed := make([]Hash, len(leaves))
		copy(reversed, leaves)
		for i := range len(reversed) / 2 {
			reversed[i], reversed[len(reversed)-1-i] = reversed[len(reversed)-1-i], reversed[i]
		}
		root2 := CalcMerkleRoot(reversed)

		require.NotEqual(t, root1, root2)
	})

	t.Run("one leaf", func(t *testing.T) {
		leaves := []Hash{{1, 1, 1, 1}}
		root := CalcMerkleRoot(leaves)

		require.Equal(t, root, leaves[0])
	})

	t.Run("nil slice", func(t *testing.T) {
		root := CalcMerkleRoot(nil)
		require.Equal(t, Hash{}, root)
	})

	t.Run("large number of leaves", func(t *testing.T) {
		leaves := make([]Hash, 1000)
		for i := range leaves {
			for j := range leaves[i] {
				leaves[i][j] = byte(i % 256)
			}
		}
		root := CalcMerkleRoot(leaves)
		require.NotEqual(t, Hash{}, root)

		// Verify deterministic output
		root2 := CalcMerkleRoot(leaves)
		require.Equal(t, root, root2)
	})
}

func TestBlock_Size(t *testing.T) {
	t.Run("empty block", func(t *testing.T) {
		blk := &Block{
			Header:    &BlockHeader{Height: 1},
			Signature: []byte{},
			Txns:      []*Transaction{},
		}
		blockSize, txnsSize := blk.Size()
		require.Greater(t, blockSize, int64(0))
		require.Equal(t, int64(0), txnsSize)
	})

	t.Run("block with signature only", func(t *testing.T) {
		blk := &Block{
			Header:    &BlockHeader{Height: 1},
			Signature: []byte("test-signature-123"),
			Txns:      []*Transaction{},
		}
		blockSize, txnsSize := blk.Size()
		expectedSigSize := len(blk.Signature)
		require.Greater(t, blockSize, int64(expectedSigSize))
		require.Equal(t, int64(0), txnsSize)
	})

	t.Run("block with varying transaction sizes", func(t *testing.T) {
		txns := []*Transaction{
			newTx(0, "sender1", "small"),
			newTx(1, "sender2", string(make([]byte, 1000))),
			newTx(2, "sender3", string(make([]byte, 5000))),
		}
		blk := &Block{
			Header:    &BlockHeader{Height: 1, NumTxns: uint32(len(txns))},
			Signature: []byte("sig"),
			Txns:      txns,
		}
		blockSize, txnsSize := blk.Size()

		var expectedTxnsSize int64
		for _, tx := range txns {
			expectedTxnsSize += tx.SerializeSize()
		}

		require.Greater(t, blockSize, txnsSize)
		require.Equal(t, expectedTxnsSize, txnsSize)

		txnsSize = blk.TxnsSize()
		require.Equal(t, expectedTxnsSize, txnsSize)
	})

	t.Run("block with large header fields", func(t *testing.T) {
		blk := &Block{
			Header: &BlockHeader{
				Height:           999999,
				NumTxns:          1000,
				PrevHash:         Hash{1, 2, 3},
				PrevAppHash:      Hash{4, 5, 6},
				ValidatorSetHash: Hash{7, 8, 9},
				Timestamp:        time.Now(),
				MerkleRoot:       Hash{10, 11, 12},
			},
			Signature: []byte("signature"),
			Txns:      []*Transaction{newTx(0, "sender", "payload")},
		}
		blockSize, txnsSize := blk.Size()
		require.Greater(t, blockSize, txnsSize)
		require.Greater(t, blockSize, int64(len(blk.Signature)))
	})

	t.Run("block with many small transactions", func(t *testing.T) {
		txns := make([]*Transaction, 100)
		for i := range txns {
			txns[i] = newTx(uint64(i), "sender", "small")
		}
		blk := &Block{
			Header:    &BlockHeader{Height: 1, NumTxns: uint32(len(txns))},
			Signature: []byte("sig"),
			Txns:      txns,
		}
		blockSize, txnsSize := blk.Size()

		var expectedTxnsSize int64
		for _, tx := range txns {
			expectedTxnsSize += tx.SerializeSize()
		}

		require.Greater(t, blockSize, txnsSize)
		require.Equal(t, expectedTxnsSize, txnsSize)

		txnsSize = blk.TxnsSize()
		require.Equal(t, expectedTxnsSize, txnsSize)
	})

	// agrees with EncodeBlock
	t.Run("match", func(t *testing.T) {
		txns := []*Transaction{
			newTx(0, "bob", "tx1"),
			newTx(1, "bob", "transaction 2"),
			newTx(0, "alice", string(make([]byte, 1000))),
		}
		blk := &Block{
			Header: &BlockHeader{
				Version:          1,
				Height:           100,
				NumTxns:          uint32(len(txns)),
				PrevHash:         Hash{1, 2, 3},
				PrevAppHash:      Hash{4, 5, 6},
				ValidatorSetHash: Hash{7, 8, 9},
				Timestamp:        time.Now().UTC().Truncate(time.Millisecond),
				MerkleRoot:       Hash{10, 11, 12},
			},
			Txns:      txns,
			Signature: []byte("test-signature"),
		}
		encoded := EncodeBlock(blk)
		encSize := len(encoded)

		blockSize, _ := blk.Size()
		require.EqualValues(t, encSize, blockSize)
	})
}

func TestBlockHeader_JSON(t *testing.T) {
	t.Run("marshal and unmarshal with all fields", func(t *testing.T) {
		_, pubKey, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)

		original := &BlockHeader{
			Version:           2,
			Height:            12345,
			NumTxns:           67,
			PrevHash:          Hash{1, 2, 3, 4},
			PrevAppHash:       Hash{5, 6, 7, 8},
			Timestamp:         time.Now().UTC().Truncate(time.Millisecond),
			MerkleRoot:        Hash{9, 10, 11, 12},
			ValidatorSetHash:  Hash{13, 14, 15, 16},
			NetworkParamsHash: Hash{17, 18, 19, 20},
			NewLeader:         pubKey,
		}

		data, err := original.MarshalJSON()
		require.NoError(t, err)

		var decoded BlockHeader
		err = decoded.UnmarshalJSON(data)
		require.NoError(t, err)
		require.Equal(t, original, &decoded)
	})

	t.Run("marshal and unmarshal with zero values", func(t *testing.T) {
		original := &BlockHeader{}

		data, err := original.MarshalJSON()
		require.NoError(t, err)

		var decoded BlockHeader
		err = decoded.UnmarshalJSON(data)
		require.NoError(t, err)
		require.Equal(t, original, &decoded)
	})

	t.Run("unmarshal invalid json", func(t *testing.T) {
		invalidJSON := []byte(`{"height": "not a number"}`)
		var bh BlockHeader
		err := bh.UnmarshalJSON(invalidJSON)
		require.Error(t, err)
	})

	t.Run("timestamp precision", func(t *testing.T) {
		original := &BlockHeader{
			Timestamp: time.Now().UTC().Add(time.Microsecond * 123),
		}

		data, err := original.MarshalJSON()
		require.NoError(t, err)

		var decoded BlockHeader
		err = decoded.UnmarshalJSON(data)
		require.NoError(t, err)

		// Should only preserve millisecond precision
		require.Equal(t, original.Timestamp.UnixMilli(), decoded.Timestamp.UnixMilli())
	})

	t.Run("negative timestamp", func(t *testing.T) {
		original := &BlockHeader{
			Timestamp: time.Unix(-1000, 0),
		}

		data, err := original.MarshalJSON()
		require.NoError(t, err)

		var decoded BlockHeader
		err = decoded.UnmarshalJSON(data)
		require.NoError(t, err)
		require.Equal(t, original.Timestamp.UnixMilli(), decoded.Timestamp.UnixMilli())
	})
}
