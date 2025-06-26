package types

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto"
)

const (
	BlockVersion = 0
)

var ErrNotFound = errors.New("not found")

// BlockHeader is the header of a block.
type BlockHeader struct {
	Version  uint16
	Height   int64
	NumTxns  uint32
	PrevHash Hash // PrevHash is previous block's hash
	// PrevAppHash is the app hash from the execution of the previous block,
	// which corresponds to the app hash in CommitInfo for the previous block.
	PrevAppHash Hash
	Timestamp   time.Time
	MerkleRoot  Hash // Merkle tree reference to hash of all transactions for the block

	// Hash of the current validator set for the block
	ValidatorSetHash Hash

	// Hash of the network params for the block
	NetworkParamsHash Hash

	// New leader for this block if changed through some kind of offline consensus.
	// NOTE: leader updates currently can occur two ways:
	// 1. By creating the param_updates resolutions with the leader change and
	//    letting the validators vote on it. This is the preferred method but requires
	//    the leader to be online to propose a block containing the resolution related
	//    transactions.
	// 2. By using the "validators replace-leader" command. This is a temporary solution.
	//    In scenarios where the leader is offline and unrecoverable, the validators
	//    can offline agree on a new leader and issue `kwild validators promote` command
	//    to promote the new leader. It's important that the leader candidate also issues
	//    this command and become a leader and propose a block with the leader update.
	//    If enough validators agree to the change, they can accept the proposals and
	//    commit the block with the leader update. Once the block is committed, the other
	//    validators that didn't participate in the offline agreement will update their
	//    leader to the new candidate.
	NewLeader crypto.PublicKey
}

// JSON marshalling is customized:
// - Timestamp is (un)marshalled as a unix millisecond timestamp.
// - NewLeader may be nil when marshalling, and null or omitted when unmarshalling.

type jsonBlockHeader struct {
	Version     uint16 `json:"version"`
	Height      int64  `json:"height"`
	NumTxns     uint32 `json:"num_txns"`
	PrevHash    Hash   `json:"prev_hash"`
	PrevAppHash Hash   `json:"prev_app_hash"`
	// Timestamp is the unix millisecond timestamp
	Timestamp         int64           `json:"stamp_ms"`
	MerkleRoot        Hash            `json:"merkle_root"`
	ValidatorSetHash  Hash            `json:"vals_hash"`
	NetworkParamsHash Hash            `json:"params_hash"`
	NewLeader         json.RawMessage `json:"new_leader,omitempty"`
}

func (bh BlockHeader) MarshalJSON() ([]byte, error) {
	//  In other contexts core/types.PublicKey will error if marshalling nil (or
	//  unmarshalling from JSON null). In this context, we allow it.
	var newLeader json.RawMessage // default: null => omitted
	if bh.NewLeader != nil {
		var err error
		newLeader, err = json.Marshal(PublicKey{bh.NewLeader})
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(&jsonBlockHeader{
		Version:           bh.Version,
		Height:            bh.Height,
		NumTxns:           bh.NumTxns,
		PrevHash:          bh.PrevHash,
		PrevAppHash:       bh.PrevAppHash,
		Timestamp:         bh.Timestamp.UnixMilli(),
		MerkleRoot:        bh.MerkleRoot,
		ValidatorSetHash:  bh.ValidatorSetHash,
		NetworkParamsHash: bh.NetworkParamsHash,
		NewLeader:         newLeader,
	})
}

func (bh *BlockHeader) UnmarshalJSON(b []byte) error {
	var jbh jsonBlockHeader
	if err := json.Unmarshal(b, &jbh); err != nil {
		return err
	}
	var newLeader crypto.PublicKey // default: omitted or null => nil
	if len(jbh.NewLeader) > 0 && string(jbh.NewLeader) != ` null` {
		var pk PublicKey
		if err := json.Unmarshal(jbh.NewLeader, &pk); err != nil {
			return err
		}
		newLeader = pk.PublicKey
	}
	*bh = BlockHeader{
		Version:           jbh.Version,
		Height:            jbh.Height,
		NumTxns:           jbh.NumTxns,
		PrevHash:          jbh.PrevHash,
		PrevAppHash:       jbh.PrevAppHash,
		Timestamp:         time.UnixMilli(jbh.Timestamp).UTC(),
		MerkleRoot:        jbh.MerkleRoot,
		ValidatorSetHash:  jbh.ValidatorSetHash,
		NetworkParamsHash: jbh.NetworkParamsHash,
		NewLeader:         newLeader,
	}
	return nil
}

type Block struct {
	Header    *BlockHeader   `json:"header"`
	Txns      []*Transaction `json:"txns"`
	Signature []byte         `json:"sig"` // Signature is the block producer's signature (leader in our model)
}

func NewBlock(height int64, prevHash, appHash, valSetHash, paramsHash Hash, stamp time.Time, txns []*Transaction) *Block {
	numTxns := len(txns)
	txHashes := make([]Hash, numTxns)
	for i, tx := range txns {
		txHashes[i] = tx.HashCache()
	}
	merkelRoot := CalcMerkleRoot(txHashes)
	hdr := &BlockHeader{
		Version:     BlockVersion,
		Height:      height,
		PrevHash:    prevHash,
		PrevAppHash: appHash,
		NumTxns:     uint32(numTxns),
		Timestamp:   stamp.Truncate(time.Millisecond).UTC(),
		MerkleRoot:  merkelRoot,

		ValidatorSetHash:  valSetHash,
		NetworkParamsHash: paramsHash,
	}
	return &Block{
		Header: hdr,
		Txns:   txns,
	}
}

func (b *Block) Hash() Hash {
	return b.Header.Hash()
}

func (b *Block) CalcMerkleRoot() Hash {
	txHashes := make([]Hash, len(b.Txns))
	for i, tx := range b.Txns {
		txHashes[i] = tx.HashCache()
	}
	return CalcMerkleRoot(txHashes)
}

func (b *Block) Sign(signer crypto.PrivateKey) error {
	hash := b.Hash()
	sig, err := signer.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign block: %w", err)
	}
	b.Signature = sig
	return nil
}

func (b *Block) VerifySignature(pubKey crypto.PublicKey) (bool, error) {
	hash := b.Hash()
	return pubKey.Verify(hash[:], b.Signature)
}

func DecodeBlockHeader(r io.Reader) (*BlockHeader, error) {
	hdr := new(BlockHeader)

	if err := binary.Read(r, SerializationByteOrder, &hdr.Version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}

	if err := binary.Read(r, SerializationByteOrder, &hdr.Height); err != nil {
		return nil, fmt.Errorf("failed to read height: %w", err)
	}

	if err := binary.Read(r, SerializationByteOrder, &hdr.NumTxns); err != nil {
		return nil, fmt.Errorf("failed to read number of transactions: %w", err)
	}

	_, err := io.ReadFull(r, hdr.PrevHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read previous block hash: %w", err)
	}

	_, err = io.ReadFull(r, hdr.PrevAppHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read previous block hash: %w", err)
	}

	_, err = io.ReadFull(r, hdr.ValidatorSetHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read validator hash: %w", err)
	}

	_, err = io.ReadFull(r, hdr.NetworkParamsHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read network params hash: %w", err)
	}

	var timeStamp uint64
	if err := binary.Read(r, SerializationByteOrder, &timeStamp); err != nil {
		return nil, fmt.Errorf("failed to read number of transactions: %w", err)
	}
	hdr.Timestamp = time.UnixMilli(int64(timeStamp)).UTC()

	_, err = io.ReadFull(r, hdr.MerkleRoot[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read merkel root: %w", err)
	}

	// Read leader updates if any
	var leaderUpdate bool
	if err := binary.Read(r, SerializationByteOrder, &leaderUpdate); err != nil {
		return nil, fmt.Errorf("failed to read leader update flag: %w", err)
	}
	if leaderUpdate {
		keyBts, err := ReadCompactBytes(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read leader update key: %w", err)
		}

		key, err := crypto.WireDecodePubKey(keyBts)
		if err != nil {
			return nil, fmt.Errorf("failed to decode leader update key: %w", err)
		}

		hdr.NewLeader = key
	}

	return hdr, nil
}

func (bh *BlockHeader) String() string {
	return fmt.Sprintf("BlockHeader{Version: %d, Height: %d, NumTxns: %d, PrevHash: %s, AppHash: %s, Timestamp: %s, MerkelRoot: %s}",
		bh.Version,
		bh.Height,
		bh.NumTxns,
		bh.PrevHash,
		bh.PrevAppHash,
		bh.Timestamp.Format(time.RFC3339),
		bh.MerkleRoot)
}

func (bh *BlockHeader) writeBlockHeader(w io.Writer) error {
	if err := binary.Write(w, SerializationByteOrder, bh.Version); err != nil {
		return fmt.Errorf("failed to write version: %w", err)
	}

	if err := binary.Write(w, SerializationByteOrder, bh.Height); err != nil {
		return fmt.Errorf("failed to write height: %w", err)
	}

	if err := binary.Write(w, SerializationByteOrder, bh.NumTxns); err != nil {
		return fmt.Errorf("failed to write number of transactions: %w", err)
	}

	if _, err := w.Write(bh.PrevHash[:]); err != nil {
		return fmt.Errorf("failed to write previous block hash: %w", err)
	}

	if _, err := w.Write(bh.PrevAppHash[:]); err != nil {
		return fmt.Errorf("failed to write app hash: %w", err)
	}

	if _, err := w.Write(bh.ValidatorSetHash[:]); err != nil {
		return fmt.Errorf("failed to write validator hash: %w", err)
	}

	if _, err := w.Write(bh.NetworkParamsHash[:]); err != nil {
		return fmt.Errorf("failed to write network params hash: %w", err)
	}

	if err := binary.Write(w, SerializationByteOrder, uint64(bh.Timestamp.UnixMilli())); err != nil {
		return fmt.Errorf("failed to write timestamp: %w", err)
	}

	if _, err := w.Write(bh.MerkleRoot[:]); err != nil {
		return fmt.Errorf("failed to write merkel root: %w", err)
	}

	// leader updates if any
	leaderUpdate := bh.NewLeader != nil
	if leaderUpdate {
		_, err := w.Write([]byte{1})
		if err != nil {
			return fmt.Errorf("failed to write leader update flag: %w", err)
		}
		if err := WriteCompactBytes(w, crypto.WireEncodeKey(bh.NewLeader)); err != nil {
			return fmt.Errorf("failed to write leader update key: %w", err)
		}
	} else {
		_, err := w.Write([]byte{0})
		if err != nil {
			return fmt.Errorf("failed to write leader update flag: %w", err)
		}
	}

	return nil
}

func EncodeBlockHeader(hdr *BlockHeader) []byte {
	var buf bytes.Buffer
	hdr.writeBlockHeader(&buf)
	return buf.Bytes()
}

func (bh *BlockHeader) Hash() Hash {
	hasher := NewHasher()
	bh.writeBlockHeader(hasher)
	return hasher.Sum(nil)
}

/*func encodeBlockHeaderOneAlloc(hdr *BlockHeader) []byte {
	// Preallocate buffer: 2 + 8 + 4 + 32 + 32 + 8 + 32 = 118 bytes
	buf := make([]byte, 0, 118)

	buf = SerializationByteOrder.AppendUint16(buf, hdr.Version)
	buf = SerializationByteOrder.AppendUint64(buf, uint64(hdr.Height))
	buf = SerializationByteOrder.AppendUint32(buf, hdr.NumTxns)
	buf = append(buf, hdr.PrevHash[:]...)
	buf = append(buf, hdr.AppHash[:]...)
	buf = SerializationByteOrder.AppendUint64(buf, uint64(hdr.Timestamp.UnixMilli()))
	buf = append(buf, hdr.MerkelRoot[:]...)

	return buf
}*/

func EncodeBlock(block *Block) []byte {
	headerBytes := EncodeBlockHeader(block.Header)

	buf := make([]byte, 0, len(headerBytes)+4+len(block.Signature)) // it's a lot more depending on txns, but we don't have size functions yet

	buf = append(buf, headerBytes...)

	buf = binary.AppendUvarint(buf, uint64(len(block.Signature)))
	buf = append(buf, block.Signature...)

	for _, tx := range block.Txns {
		rawTx := tx.Bytes()
		buf = binary.AppendUvarint(buf, uint64(len(rawTx)))
		buf = append(buf, rawTx...)
	}

	return buf
}

// Bytes returns the serialized block. This is equivalent to calling
// EncodeBlock with the block.
func (b *Block) Bytes() []byte {
	return EncodeBlock(b)
}

// SerializeSize returns the serialized size of the block. To get the total size
// of all transactions in the block, use the TxnsSize method. If both sizes are
// required, use the Size method to get both sizes in one call.
func (b *Block) SerializeSize() int64 {
	sz, _ := b.Size()
	return sz
}

// TxnsSize returns the total size of all serialized transactions in the block.
func (b *Block) TxnsSize() int64 {
	var sz int64
	for _, tx := range b.Txns {
		sz += tx.SerializeSize()
	}
	return sz
}

// Size returns both the total size of the serialized block, and the total size
// of all serialized transactions in the block.
func (b *Block) Size() (block, txns int64) {
	sigLen := len(b.Signature)
	block = int64(len(EncodeBlockHeader(b.Header)) + uvarintLen(uint64(sigLen)) + sigLen)
	for _, tx := range b.Txns {
		txSz := tx.SerializeSize()
		lenPrefixSize := len(binary.AppendUvarint(nil, uint64(txSz)))
		block += int64(lenPrefixSize) + tx.SerializeSize()
		txns += txSz
	}
	return block, txns
}

// CalcMerkleRoot computes the merkel root for a slice of hashes. This is based
// on the "inline" implementation from btcd / dcrd.
func CalcMerkleRoot(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return Hash{}
	case 1:
		return leaves[0]
	default:
	}

	// Do not modify the leaves slice from the caller.
	leaves = slices.Clone(leaves)

	// Create a buffer to reuse for hashing the branches and some long lived
	// slices into it to avoid reslicing.
	var buf [2 * HashLen]byte
	var left = buf[:HashLen]
	var right = buf[HashLen:]
	var both = buf[:]

	// The following algorithm works by replacing the leftmost entries in the
	// slice with the concatenations of each subsequent set of 2 hashes and
	// shrinking the slice by half to account for the fact that each level of
	// the tree is half the size of the previous one.  In the case a level is
	// unbalanced (there is no final right child), the final node is duplicated
	// so it ultimately is concatenated with itself.
	//
	// For example, the following illustrates calculating a tree with 5 leaves:
	//
	// [0 1 2 3 4]                              (5 entries)
	// 1st iteration: [h(0||1) h(2||3) h(4||4)] (3 entries)
	// 2nd iteration: [h(h01||h23) h(h44||h44)] (2 entries)
	// 3rd iteration: [h(h0123||h4444)]         (1 entry)
	for len(leaves) > 1 {
		// When there is no right child, the parent is generated by hashing the
		// concatenation of the left child with itself.
		if len(leaves)&1 != 0 {
			leaves = append(leaves, leaves[len(leaves)-1])
		}

		// Set the parent node to the hash of the concatenation of the left and
		// right children.
		for i := range len(leaves) / 2 {
			copy(left, leaves[i*2][:])
			copy(right, leaves[i*2+1][:])
			leaves[i] = HashBytes(both)
		}
		leaves = leaves[:len(leaves)/2]
	}
	return leaves[0]
}

func DecodeBlock(rawBlk []byte) (*Block, error) {
	r := bytes.NewReader(rawBlk)

	hdr, err := DecodeBlockHeader(r)
	if err != nil {
		return nil, err
	}

	sigLen, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature length: %w", err)
	}

	if sigLen > uint64(r.Len()) { // more than remaining
		return nil, fmt.Errorf("invalid signature length %d", sigLen)
	}

	sig := make([]byte, sigLen)
	if _, err := io.ReadFull(r, sig); err != nil {
		return nil, fmt.Errorf("failed to read signature: %w", err)
	}

	// Before allocating a large transaction slice, make sure it is possible
	// that the input slice can actually contain that number of transactions.
	// Alternatively, we could not allocate and just append.
	if int64(r.Len()) < int64(hdr.NumTxns)*int64(smallestTxSize) {
		return nil, fmt.Errorf("invalid number of transactions %d", hdr.NumTxns)
	}

	txns := make([]*Transaction, hdr.NumTxns)

	for i := range txns {
		txLen, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read tx length: %w", err)
		}

		if txLen > uint64(r.Len()) { // more than remaining
			return nil, fmt.Errorf("invalid transaction length %d", txLen)
		}
		if txLen == 0 {
			return nil, fmt.Errorf("invalid empty transaction idx %d", i)
		}

		rawTx := make([]byte, txLen)
		if _, err := io.ReadFull(r, rawTx); err != nil {
			return nil, fmt.Errorf("failed to read tx data: %w", err)
		}
		var tx Transaction
		if err = tx.UnmarshalBinary(rawTx); err != nil {
			return nil, fmt.Errorf("invalid transaction (%d): %w", i, err)
		}
		txns[i] = &tx
	}

	return &Block{
		Header:    hdr,
		Txns:      txns,
		Signature: sig,
	}, nil
}

// GetRawBlockTx extracts a transaction from a serialized block by its index in
// the block. This allows to more efficiently extract one transaction without
// copying all of the transactions in the block, and it avoids hashing all of
// the transactions, which would be required to match by txID.
func GetRawBlockTx(rawBlk []byte, idx uint32) ([]byte, error) {
	r := bytes.NewReader(rawBlk)

	hdr, err := DecodeBlockHeader(r)
	if err != nil {
		return nil, err
	}

	sigLen, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature length: %w", err)
	}

	if sigLen > uint64(len(rawBlk)) { // TODO: do better than this
		return nil, fmt.Errorf("invalid signature length %d", sigLen)
	}

	_, err = r.Seek(int64(sigLen), io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("failed to seek to txs: %w", err)
	}

	for i := range hdr.NumTxns {
		txLen, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read tx length: %w", err)
		}
		if txLen > uint64(len(rawBlk)) { // TODO: do better than this
			return nil, fmt.Errorf("invalid transaction length %d", txLen)
		}
		if txLen == 0 {
			return nil, fmt.Errorf("invalid empty transaction idx %d", i)
		}
		if idx == i {
			tx := make([]byte, txLen)
			if _, err := io.ReadFull(r, tx); err != nil {
				return nil, fmt.Errorf("failed to read tx data: %w", err)
			}
			return tx, nil
		}
		// seek to the start of the next tx
		if _, err := r.Seek(int64(txLen), io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to seek to next tx: %w", err)
		}
	}
	return nil, ErrNotFound
}
