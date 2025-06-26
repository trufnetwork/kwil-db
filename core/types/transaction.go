package types

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/utils"
)

var SerializationByteOrder = binary.LittleEndian

// TxQueryResponse is the response of a transaction query.
type TxQueryResponse struct {
	Hash   Hash         `json:"tx_hash,omitempty"`
	Height int64        `json:"height,omitempty"`
	Tx     *Transaction `json:"tx"`
	Result *TxResult    `json:"tx_result"`
}

// MsgDescriptionMaxLength is the max length of Description filed in
// TransactionBody and CallMessageBody
const MsgDescriptionMaxLength = 200

type Transaction struct {
	// Signature is the signature of the transaction.
	Signature *auth.Signature `json:"signature,omitempty"`

	// Body is the body of the transaction. It gets serialized and signed.
	Body *TransactionBody `json:"body,omitempty"`

	// Serialization is the serialization performed on `Body`
	// in order to generate the message that being signed.
	Serialization SignedMsgSerializationType `json:"serialization"`

	// Sender is the user identifier, which is generally an address but may be
	// a public key of the sender, hence bytes that encode as hexadecimal.
	Sender HexBytes `json:"sender"`

	strictUnmarshal bool
	cachedHash      *Hash // maybe maybe maybe... this would require a mutex or careful use
}

func (t *Transaction) StrictUnmarshal() {
	t.strictUnmarshal = true
}

// Hash gives the hash of the transaction that is the unique identifier for the
// transaction.
func (t *Transaction) Hash() Hash {
	raw := t.Bytes()
	return HashBytes(raw)
}

// HashCache is like Hash, but caches the hash of the transaction. If it is
// already cached, it is returned as is. Use this with caution:
//  1. it is not safe for concurrent use
//  2. the allocation and storage of the hash may potentially be undesirable
//  3. the hash is not guaranteed to be valid if the transaction is modified
func (t *Transaction) HashCache() Hash {
	if t.cachedHash == nil {
		hash := t.Hash()
		t.cachedHash = &hash
	}
	return *t.cachedHash
}

// TransactionBody is the body of a transaction that gets included in the
// signature. This type implements json.Marshaler and json.Unmarshaler to ensure
// that the Fee field is represented as a string in JSON rather than a number.
type TransactionBody struct {
	// Description is a human-readable description of the transaction.
	Description string `json:"desc"`

	// Payload is the raw bytes of the payload data.
	Payload []byte `json:"payload"`

	// PayloadType is the type of the payload, which may be used to determine
	// how to decode the payload.
	PayloadType PayloadType `json:"type"`

	// Fee is the fee the sender is willing to pay for the transaction.
	Fee *big.Int `json:"fee"` // MarshalJSON and UnmarshalJSON handle this field, but still tagged for reflection

	// Nonce should be the next nonce of the sender..
	Nonce uint64 `json:"nonce"`

	// ChainID identifies the Kwil chain for which the transaction is intended.
	// Alternatively, this could be withheld from the TransactionBody and passed
	// as an argument to SerializeMsg, as is seen in ethereum signers. However,
	// the full transaction serialization must include it anyway since it passes
	// through the consensus engine and p2p systems as an opaque blob that must
	// be unmarshaled with the chain ID in Kwil blockchain application.
	ChainID string `json:"chain_id"`

	strictUnmarshal bool
}

func (tb *TransactionBody) StrictUnmarshal() {
	tb.strictUnmarshal = true
}

// MarshalJSON marshals to JSON but with Fee as a string.
func (t TransactionBody) MarshalJSON() ([]byte, error) {
	// We could embed as "type txBodyAlias TransactionBody" instance in a struct
	// with a Fee string field, but the order of fields in marshalled json would
	// be different, so we clone the entire type with just Fee type changed.
	feeStr := t.Fee.String()
	if t.Fee == nil {
		feeStr = "0"
	}
	return json.Marshal(&struct {
		Description string      `json:"desc"`
		Payload     []byte      `json:"payload"`
		PayloadType PayloadType `json:"type"`
		Fee         string      `json:"fee"`
		Nonce       uint64      `json:"nonce"`
		ChainID     string      `json:"chain_id"`
	}{
		Description: t.Description,
		Payload:     t.Payload,
		PayloadType: t.PayloadType,
		Fee:         feeStr, // *big.Int => string
		Nonce:       t.Nonce,
		ChainID:     t.ChainID,
	})
}

// UnmarshalJSON unmarshals from JSON, handling a fee string.
func (t *TransactionBody) UnmarshalJSON(data []byte) error {
	// unmarshalling doesn't care about the order of the fields, so we can
	// unmarshal directly into t by embedding in an anonymous struct.
	type txBodyAlias TransactionBody // same json tags, lost methods, no recursion
	aux := &struct {
		Fee string `json:"fee"`
		*txBodyAlias
	}{
		txBodyAlias: (*txBodyAlias)(t),
	}
	// Unmarshal all fields except Fee directly into t.
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	// Grab the Fee from the anonymous struct, decode it, and set in t.Fee.
	if aux.Fee != "" {
		feeBigInt, ok := new(big.Int).SetString(aux.Fee, 10)
		if !ok {
			return fmt.Errorf("could not parse fee: %q", aux.Fee)
		}
		t.Fee = feeBigInt
	} else {
		t.Fee = big.NewInt(0)
	}
	return nil
}

const txMsgToSignTmplV0 = `%s

PayloadType: %s
PayloadDigest: %x
Fee: %s
Nonce: %d

Kwil Chain ID: %s
`

// SignedMsgSerializationType is the type of serialization performed on a
// transaction body(in signing and verification)
// The main reason we need this is that this type could also to used as the
// 'version' of the serialization.
// For now, i think it's a bit redundant. To sign a transaction, you need
// three types:
//  1. the type of payload
//  2. the type of serialization
//  3. the type of signature(e.g. signer)
//
// But in the future, take eth signing for example, we might change the
// `signedMsgTmpl` for personal_sign, or `domain` for eip712, this type could
// be used to distinguish the different versions.
//
// NOTE:
// The valid combination of 2.) and 3.) are:
//   - `SignedMsgConcat` + `PersonalSigner/CometBftSigner/NearSigner`, which is
//     the default for the `client` package
//   - `SignedMsgEip712` + `Eip712Signer`
type SignedMsgSerializationType string

func (s SignedMsgSerializationType) String() string {
	return string(s)
}

const (
	// SignedMsgConcat is a human-readable serialization of the transaction body
	// it needs a signer that signs
	SignedMsgConcat SignedMsgSerializationType = "concat"

	SignedMsgDirect SignedMsgSerializationType = "direct"

	// DefaultSignedMsgSerType is the default serialization type
	// It's `concat` for now, since it's the only one known works for every signer
	DefaultSignedMsgSerType = SignedMsgConcat
)

// CreateTransaction creates a new unsigned transaction.
func CreateTransaction(contents Payload, chainID string, nonce uint64) (*Transaction, error) {
	return createTransaction(contents, chainID, nonce, DefaultSignedMsgSerType)
}

// CreateNodeTransaction creates a new unsigned transaction with the "direct"
// serialization type.
func CreateNodeTransaction(contents Payload, chainID string, nonce uint64) (*Transaction, error) {
	return createTransaction(contents, chainID, nonce, SignedMsgDirect)
}

func createTransaction(contents Payload, chainID string, nonce uint64, sert SignedMsgSerializationType) (*Transaction, error) {
	data, err := contents.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Transaction{
		Body: &TransactionBody{
			Payload:     data,
			PayloadType: contents.Type(),
			Fee:         big.NewInt(0),
			Nonce:       nonce,
			ChainID:     chainID,
		},
		Serialization: sert,
	}, nil
}

// SerializeMsg produces the serialization of the transaction that is to be used
// in both signing and verification of transaction.
func (t *Transaction) SerializeMsg() ([]byte, error) {
	return t.Body.SerializeMsg(t.Serialization)
}

// Sign signs transaction body with given signer.
// It will serialize the transaction body first and sign it.
func (t *Transaction) Sign(signer auth.Signer) error {
	msg, err := t.SerializeMsg()
	if err != nil {
		return err
	}
	// The above serialized msg has to include the chainID rather than passing
	// it to the signer because it needs to be displayed in the friendly message
	// that the user signs.

	signature, err := signer.Sign(msg)
	if err != nil {
		return err
	}

	t.Signature = signature
	t.Sender = signer.CompactID()

	return nil
}

// SerializeMsg prepares a message for signing or verification using a certain
// message construction format. This is done since a Kwil transaction is foreign
// to wallets, and it is signed as a message, not a transaction that is native
// to the wallet. As such we define conventions for constructing user-friendly
// messages. The Kwil frontend SDKs must implement these serialization schemes.
func (t *TransactionBody) SerializeMsg(mst SignedMsgSerializationType) ([]byte, error) {
	if len(t.Description) > MsgDescriptionMaxLength {
		return nil, errors.New("description is too long")
	}

	switch mst {
	case SignedMsgDirect:
		msg := t.Bytes()
		sigHash := HashBytes(msg) // could just be msg
		return sigHash[:], nil
	case SignedMsgConcat:
		// Make a human-readable message using a template(txMsgToSignTmplV0).
		// In this message scheme, the displayed "token" is a hash of the
		// payload.
		// NOTE: 'payload` is still in binary form(RLP encoded),
		// we present its hash in the result message.
		payloadHash := HashBytes(t.Payload)
		payloadDigest := payloadHash[:20]
		msgStr := fmt.Sprintf(txMsgToSignTmplV0,
			t.Description,
			t.PayloadType.String(),
			payloadDigest,
			t.Fee.String(),
			t.Nonce,
			t.ChainID)
		return []byte(msgStr), nil
	}
	return nil, errors.New("invalid serialization type")
}

var smallestTxSize = 6 // (&Transaction{}).SerializeSize()

// SerializeSize gives the size of the serialized transaction.
func (t *Transaction) SerializeSize() int64 {
	totalLen := func(l int) int {
		return l + uvarintLen(uint64(l))
	}
	// NOTE: unit tests must have SerializeSize verified against MarshalBinary
	// and/or WriteTo to ensure this method does not become stale!
	var sigSize int64
	if t.Signature != nil {
		sigSize = t.Signature.SerializeSize()
	}
	var bodySize int64
	if t.Body != nil {
		bodySize = t.Body.SerializeSize()
	}
	return int64(2 +
		totalLen(int(sigSize)) +
		totalLen(int(bodySize)) +
		totalLen(len(t.Serialization)) +
		totalLen(len(t.Sender)))
}

var _ io.WriterTo = (*Transaction)(nil)

func (t *Transaction) WriteTo(w io.Writer) (int64, error) {
	cw := utils.NewCountingWriter(w)
	err := t.serialize(cw)
	return cw.Written(), err
}

var _ encoding.BinaryMarshaler = (*Transaction)(nil)

// Bytes returns the serialized transaction.
func (t *Transaction) Bytes() []byte {
	bts, _ := t.MarshalBinary() // guaranteed not to error
	return bts
}

// MarshalBinary produces the full binary serialization of the transaction,
// which is the form used in p2p messaging and blockchain storage.
func (t *Transaction) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	t.serialize(buf) // guaranteed not to error with bytes.Buffer
	return buf.Bytes(), nil
}

var _ io.ReaderFrom = (*Transaction)(nil)

func (t *Transaction) ReadFrom(r io.Reader) (int64, error) {
	n, err := t.deserialize(r)
	if err != nil {
		return n, err
	}
	return n, nil
}

var _ encoding.BinaryUnmarshaler = (*Transaction)(nil)

func (t *Transaction) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	n, err := t.deserialize(r)
	if err != nil {
		return err
	}
	if !t.strictUnmarshal {
		return nil
	}
	if n != int64(len(data)) {
		return errors.New("failed to read all")
	}
	if r.Len() != 0 {
		return errors.New("extra transaction data")
	}
	return nil
}

func (tb TransactionBody) Bytes() []byte {
	b, _ := tb.MarshalBinary() // does not error
	return b
}

var _ encoding.BinaryMarshaler = (*TransactionBody)(nil)

func (tb TransactionBody) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	tb.WriteTo(buf) // no error with bytes.Buffer
	return buf.Bytes(), nil
}

var _ io.WriterTo = TransactionBody{}

func (tb TransactionBody) WriteTo(w io.Writer) (int64, error) {
	cw := utils.NewCountingWriter(w)
	// Description Length + Description
	if err := WriteCompactString(cw, tb.Description); err != nil {
		return cw.Written(), fmt.Errorf("failed to write transaction body description: %w", err)
	}

	// serialized Payload
	if err := WriteCompactBytes(cw, EmptyIfNil(tb.Payload)); err != nil {
		return cw.Written(), fmt.Errorf("failed to write transaction body payload: %w", err)
	}

	// PayloadType
	payloadType := tb.PayloadType.String()
	if err := WriteCompactString(cw, payloadType); err != nil {
		return cw.Written(), fmt.Errorf("failed to write transaction body payload type: %w", err)
	}

	// Fee (big.Int)
	if err := WriteBigInt(cw, tb.Fee); err != nil {
		return cw.Written(), fmt.Errorf("failed to write transaction fee: %w", err)
	}

	// Nonce
	if err := binary.Write(cw, SerializationByteOrder, tb.Nonce); err != nil {
		return cw.Written(), fmt.Errorf("failed to write transaction body nonce: %w", err)
	}

	// ChainID
	if err := WriteCompactString(cw, tb.ChainID); err != nil {
		return cw.Written(), fmt.Errorf("failed to write transaction body chain ID: %w", err)
	}
	return cw.Written(), nil
}

// uvarintLen returns the number of bytes required to encode x as an unsigned
// varint. This is equivalent to len(binary.AppendUvarint(nil, x)), but computed
// without any allocations.
func uvarintLen(x uint64) int {
	var l int
	for x >= 0x80 {
		x >>= 7
		l++
	}
	return l + 1
}

// varintLen returns the number of bytes required to encode x as a signed
// varint. This is equivalent to len(binary.AppendVarint(nil, x)), but computed
// without any allocations.
func varintLen(x int64) int {
	ux := uint64(x) << 1
	if x < 0 {
		ux = ^ux
	}
	return uvarintLen(ux)
}

// SerializeSize gives the size of the serialized transaction body.
func (tb TransactionBody) SerializeSize() int64 {
	totalLen := func(l int) int {
		return l + uvarintLen(uint64(l))
	}
	// NOTE: unit tests must have SerializeSize verified against MarshalBinary!
	fw := utils.NewCountingWriter(io.Discard)
	WriteBigInt(fw, tb.Fee) // fee serialization involves the Fee strings, so this is not so trivial

	sz := totalLen(len(tb.Description)) +
		totalLen(len(tb.Payload)) +
		totalLen(len(tb.PayloadType)) +
		int(fw.Written()) +
		8 + // nonce
		totalLen(len(tb.ChainID))

	return int64(sz)
}

var _ io.ReaderFrom = (*TransactionBody)(nil)

func (tb *TransactionBody) ReadFrom(r io.Reader) (int64, error) {
	cr := utils.NewCountingReader(r)

	// Description Length + Description
	desc, err := ReadCompactString(cr)
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction body description: %w", err)
	}
	tb.Description = desc

	// serialized Payload
	payload, err := ReadCompactBytes(cr)
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction body payload: %w", err)
	}
	tb.Payload = payload

	// PayloadType
	payloadType, err := ReadCompactString(cr)
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction body payload type: %w", err)
	}
	tb.PayloadType = PayloadType(payloadType)

	// Fee (big.Int)
	b, err := ReadBigInt(cr)
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction body fee: %w", err)
	}
	tb.Fee = b // may be nil

	// Nonce
	if err := binary.Read(cr, SerializationByteOrder, &tb.Nonce); err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction body nonce: %w", err)
	}

	// ChainID
	chainID, err := ReadCompactString(cr)
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction body chain ID: %w", err)
	}
	tb.ChainID = chainID

	return cr.ReadCount(), nil
}

var _ encoding.BinaryUnmarshaler = (*TransactionBody)(nil)

func (tb *TransactionBody) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	n, err := tb.ReadFrom(buf)
	if err != nil {
		return err
	}

	if !tb.strictUnmarshal {
		return nil
	}

	if int(n) != len(data) {
		return errors.New("extra tx body data")
	}
	if buf.Len() != 0 {
		return errors.New("extra tx body data (buf)")
	}

	return nil
}

const txVersion uint16 = 0

func (t *Transaction) serialize(w io.Writer) (err error) {
	// version
	if err := binary.Write(w, SerializationByteOrder, txVersion); err != nil {
		return fmt.Errorf("failed to write transaction version: %w", err)
	}

	// Tx Signature
	var sigBytes []byte
	if t.Signature != nil {
		sigBytes = t.Signature.Bytes()
	}
	if err := WriteCompactBytes(w, EmptyIfNil(sigBytes)); err != nil {
		return fmt.Errorf("failed to write transaction signature: %w", err)
	}

	// Tx Body
	var bodyBytes []byte
	if t.Body != nil {
		bodyBytes = t.Body.Bytes()
	}
	if err := WriteCompactBytes(w, EmptyIfNil(bodyBytes)); err != nil {
		return fmt.Errorf("failed to write transaction body: %w", err)
	}

	// SerializationType
	if err := WriteCompactString(w, string(t.Serialization)); err != nil {
		return fmt.Errorf("failed to write transaction serialization type: %w", err)
	}

	// Sender
	if err := WriteCompactBytes(w, EmptyIfNil(t.Sender)); err != nil {
		return fmt.Errorf("failed to write transaction sender: %w", err)
	}

	return nil
}

func (t *Transaction) deserialize(r io.Reader) (int64, error) {
	cr := utils.NewCountingReader(r)

	// version
	var ver uint16
	err := binary.Read(cr, SerializationByteOrder, &ver)
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction version: %w", err)
	}
	if ver != txVersion { // in the future we can have different transaction (sub)structs, switch to different handling, etc.
		return cr.ReadCount(), fmt.Errorf("unsupported transaction version %d", ver)
	}

	// Signature
	sigBytes, err := ReadCompactBytes(cr)
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction signature: %w", err)
	}

	if len(sigBytes) != 0 {
		var signature auth.Signature
		if err = signature.UnmarshalBinary(sigBytes); err != nil {
			return cr.ReadCount(), fmt.Errorf("failed to unmarshal transaction signature: %w", err)
		}
		t.Signature = &signature
	}

	// TxBody
	bodyBytes, err := ReadCompactBytes(cr)
	if err != nil {
		return 0, fmt.Errorf("failed to read transaction body: %w", err)
	}
	if len(bodyBytes) != 0 {
		var body TransactionBody
		body.StrictUnmarshal() // not reading from a stream and we supposedly have the entire body here, so allow no trailing junk
		if err := body.UnmarshalBinary(bodyBytes); err != nil {
			return 0, fmt.Errorf("failed to unmarshal transaction body: %w", err)
		}
		t.Body = &body
	} else {
		t.Body = nil // in case Transaction is being reused
	}

	// SerializationType
	serType, err := ReadCompactString(cr)
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction serialization type: %w", err)
	}
	t.Serialization = SignedMsgSerializationType(serType)

	// Sender
	senderBytes, err := ReadCompactBytes(cr)
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read transaction sender: %w", err)
	}
	t.Sender = senderBytes

	return cr.ReadCount(), nil
}

func NilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func EmptyIfNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// WriteCompactBytes is like WriteBytes, but it uses a compact length (signed
// varint) prefix rather than a fixed 32-bit length prefix.
func WriteCompactBytes(w io.Writer, data []byte) error {
	if data == nil {
		_, err := w.Write(binary.AppendVarint(nil, -1)) // signed
		return err
	}
	_, err := w.Write(binary.AppendVarint(nil, int64(len(data)))) // signed
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// WriteBytes writes a byte slice to a writer. This uses a 32-bit length prefix
// to indicate how much data to read when deserializing.
func WriteBytes(w io.Writer, data []byte) error {
	if data == nil {
		return binary.Write(w, SerializationByteOrder, uint32(math.MaxUint32))
	}
	if err := binary.Write(w, SerializationByteOrder, uint32(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// WriteCompactString is like WriteString, but it uses a compact length
// (unsigned varint) prefix rather than a fixed 32-bit length prefix. Unlike
// WriteString, which passes through to WriteBytes, this does not pass through
// to WriteCompactBytes since there is no nil string, and there is no need to
// use a signed varint here.
func WriteCompactString(w io.Writer, s string) error {
	_, err := w.Write(binary.AppendUvarint(nil, uint64(len(s)))) // unsigned
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(s))
	return err
}

// WriteString writes a string to a writer. This uses a 32-bit length prefix.
func WriteString(w io.Writer, s string) error {
	return WriteBytes(w, []byte(s))
}

// byteReader is a wrapper around io.Reader that implements io.ByteReader.
// You could also do bufio.NewReader(r) but this is more direct.
type byteReader struct {
	r io.Reader
}

func newByteReader(r io.Reader) io.ByteReader {
	if br, ok := r.(io.ByteReader); ok {
		return br
	}
	return &byteReader{r: r}
}

var _ io.ByteReader = (*byteReader)(nil)

// ReadByte satisfies the io.ByteReader interface.
func (r *byteReader) ReadByte() (byte, error) {
	var b [1]byte
	_, err := r.r.Read(b[:])
	return b[0], err
}

func safeReadBytes(r io.Reader, length uint64) ([]byte, error) {
	var data []byte
	if rl, ok := r.(interface{ Len() int }); ok { // e.g. *bytes.Reader
		// This case allows us to preallocate somewhat safely since the reader
		// says it actually has that length of data. A bytes.Reader will do this.
		rLen := rl.Len()
		if rLen < 0 {
			return nil, fmt.Errorf("negative length from reader %d", rLen)
		}
		if length > uint64(rLen) {
			return nil, fmt.Errorf("encoded length %d is longer than data length %d", length, rl.Len())
		}
		data = make([]byte, length)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
	} else { // not preallocating here since we don't trust the source
		buf := &bytes.Buffer{}
		_, err := io.CopyN(buf, r, int64(length))
		if err != nil {
			return nil, fmt.Errorf("failed to read signature data: %w", err)
		}
		data = buf.Bytes()
	}

	return data, nil
}

// ReadCompactBytes reads a byte slice from a reader. This uses a compact
// length (signed varint) prefix rather than a fixed 32-bit length prefix.
func ReadCompactBytes(r io.Reader) ([]byte, error) {
	length, err := binary.ReadVarint(newByteReader(r)) // signed
	if err != nil {
		return nil, err
	}
	if length == -1 {
		return nil, nil
	}
	if length == 0 {
		return []byte{}, nil
	}
	if length < 0 {
		return nil, fmt.Errorf("encoded length is negative (%d)", length)
	}
	return safeReadBytes(r, uint64(length))
}

// ReadBytes reads a byte slice from a reader. This expects a 32-bit length
// prefix as written by WriteBytes.
func ReadBytes(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, SerializationByteOrder, &length); err != nil {
		return nil, err
	}

	switch length {
	case 0:
		return []byte{}, nil
	case math.MaxUint32:
		return nil, nil
	default:
	}

	return safeReadBytes(r, uint64(length))
}

// ReadString reads a string from a reader. This expects a 32-bit length prefix
// as written by WriteString.
func ReadString(r io.Reader) (string, error) {
	bts, err := ReadBytes(r)
	return string(bts), err
}

// ReadCompactString reads a string from a reader. This expects a compact length
// (unsigned varint) prefix as written by WriteCompactString. Unlike ReadString,
// this does not pass through to ReadBytes since there is no nil string, and
// there is no need to use a signed varint here.
func ReadCompactString(r io.Reader) (string, error) {
	length, err := binary.ReadUvarint(newByteReader(r)) // unsigned
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	bts, err := safeReadBytes(r, length)
	return string(bts), err
}

// WriteBigInt writes a serialized big.Int to a writer. Nil is kept distinct
// from 0. Currently non-nil values are written with their string representation
// from String(). This is not ideal but it's the best we can do for now given
// some major shortcomings fo the Bytes method of big.Int.
func WriteBigInt(w io.Writer, b *big.Int) error {
	if b == nil {
		_, err := w.Write([]byte{0})
		return err
	}

	_, err := w.Write([]byte{1})
	if err != nil {
		return err
	}

	// This is ridiculous, maybe we should just use String() and SetString()
	// var negByte byte
	// if b.Sign() < 0 {
	// 	negByte = 1
	// }
	// _, err = w.Write([]byte{negByte})
	// if err != nil {
	// 	return err
	// }
	// return WriteBytes(w, b.Bytes())

	return WriteCompactString(w, b.String())
}

// ReadBigInt reads a big.Int from a reader, as serialized by WriteBigInt.
func ReadBigInt(r io.Reader) (*big.Int, error) {
	var nilByte [1]byte
	_, err := r.Read(nilByte[:])
	if err != nil {
		return nil, err
	}

	switch nilByte[0] {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, errors.New("invalid nil int byte")
	}

	intStr, err := ReadCompactString(r)
	if err != nil {
		return nil, err
	}

	b := new(big.Int)
	b, ok := b.SetString(intStr, 10)
	if !ok {
		return nil, errors.New("bad big int string")
	}
	if b.String() != intStr {
		return nil, errors.New("non-canonical big int encoding")
	}

	// negByte := []byte{0}
	// _, err = io.ReadFull(r, negByte)
	// if err != nil {
	// 	return nil, err
	// }
	// b := new(big.Int).SetBytes(intBts)
	// if negByte[0] == 1 {
	// 	b.Neg(b)
	// }
	// if !bytes.Equal(b.Bytes(), intBts) {
	// 	return nil, errors.New("non-canonical big int encoding")
	// }
	return b, nil
}
