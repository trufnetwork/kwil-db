package snapshotter

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/trufnetwork/kwil-db/node/types"
)

// SnapshotChunkReq is for ProtocolIDSnapshotChunk "/kwil/snapchunk/1.0.0"
//
// This message type requests complete snapshot chunks. For resumable downloads
// and partial chunk fetching, see SnapshotChunkRangeReq which supports
// range-based requests with offset and length parameters.
type SnapshotChunkReq struct {
	Height uint64
	Format uint32
	Index  uint32
	Hash   types.Hash // TODO: Is this required? maybe providers serve the chunk only if the snapshot hash matches
}

var _ encoding.BinaryMarshaler = SnapshotChunkReq{}
var _ encoding.BinaryMarshaler = (*SnapshotChunkReq)(nil)

func (r SnapshotChunkReq) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8+4+4+types.HashLen)
	binary.LittleEndian.PutUint64(buf[:8], r.Height)
	binary.LittleEndian.PutUint32(buf[8:12], r.Format)
	binary.LittleEndian.PutUint32(buf[12:16], r.Index)
	copy(buf[16:], r.Hash[:])
	return buf, nil
}

func (r *SnapshotChunkReq) UnmarshalBinary(data []byte) error {
	if len(data) != 8+4+4+types.HashLen {
		return errors.New("unexpected data length")
	}
	r.Height = binary.LittleEndian.Uint64(data[:8])
	r.Format = binary.LittleEndian.Uint32(data[8:12])
	r.Index = binary.LittleEndian.Uint32(data[12:16])
	copy(r.Hash[:], data[16:])
	return nil
}

var _ io.WriterTo = (*SnapshotChunkReq)(nil)

func (r SnapshotChunkReq) WriteTo(w io.Writer) (int64, error) {
	bts, _ := r.MarshalBinary()
	n, err := w.Write(bts)
	return int64(n), err
}

var _ io.ReaderFrom = (*SnapshotChunkReq)(nil)

func (r *SnapshotChunkReq) ReadFrom(rd io.Reader) (int64, error) {
	var nr int = 0 // total bytes read
	if err := binary.Read(rd, binary.LittleEndian, &r.Height); err != nil {
		return 0, err
	}
	nr += 8

	if err := binary.Read(rd, binary.LittleEndian, &r.Format); err != nil {
		return int64(nr), err
	}
	nr += 4

	if err := binary.Read(rd, binary.LittleEndian, &r.Index); err != nil {
		return int64(nr), err
	}
	nr += 4

	n, err := io.ReadFull(rd, r.Hash[:])
	return int64(nr + n), err
}

// SnapshotReq is for ProtocolIDSnapshotMeta "/kwil/snapmeta/1.0.0"
type SnapshotReq struct {
	Height uint64
	Format uint32
}

var _ encoding.BinaryMarshaler = SnapshotReq{}
var _ encoding.BinaryMarshaler = (*SnapshotReq)(nil)

func (r SnapshotReq) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8+4)
	binary.LittleEndian.PutUint64(buf[:8], r.Height)
	binary.LittleEndian.PutUint32(buf[8:12], r.Format)
	return buf, nil
}

func (r *SnapshotReq) UnmarshalBinary(data []byte) error {
	if len(data) != 8+4 {
		return errors.New("unexpected data length")
	}
	r.Height = binary.LittleEndian.Uint64(data[:8])
	r.Format = binary.LittleEndian.Uint32(data[8:12])
	return nil
}

var _ io.WriterTo = (*SnapshotReq)(nil)

func (r SnapshotReq) WriteTo(w io.Writer) (int64, error) {
	bts, _ := r.MarshalBinary()
	n, err := w.Write(bts)
	return int64(n), err
}

var _ io.ReaderFrom = (*SnapshotReq)(nil)

func (r *SnapshotReq) ReadFrom(rd io.Reader) (int64, error) {
	var nr int = 0 // total bytes read
	if err := binary.Read(rd, binary.LittleEndian, &r.Height); err != nil {
		return 0, err
	}
	nr += 8

	if err := binary.Read(rd, binary.LittleEndian, &r.Format); err != nil {
		return int64(nr) + 4, err
	}
	nr += 4

	return int64(nr), nil
}

type SnapshotMetadata struct {
	Height      uint64     `json:"height"`
	Format      uint32     `json:"format"`
	Chunks      uint32     `json:"chunk_count"`
	Hash        []byte     `json:"hash"`
	Size        uint64     `json:"size"`
	ChunkHashes [][32]byte `json:"chunk_hashes"`

	AppHash []byte `json:"app_hash"`
}

func (sm *SnapshotMetadata) String() string {
	return fmt.Sprintf("SnapshotMetadata{Height: %d, Format: %d, Chunks: %d, Hash: %x, Size: %d, AppHash: %x}", sm.Height, sm.Format, sm.Chunks, sm.Hash, sm.Size, sm.AppHash)
}

// SnapshotKey is a snapshot key used for lookups.
type SnapshotKey [sha256.Size]byte

// Key generates a snapshot key, used for lookups. It takes into account not only the height and
// format, but also the chunks, snapshot hash and chunk hashes in case peers have generated snapshots in a
// non-deterministic manner. All fields must be equal for the snapshot to be considered the same.
func (s *SnapshotMetadata) Key() SnapshotKey {
	// Hash.Write() never returns an error.
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%v:%v:%v", s.Height, s.Format, s.Chunks)))
	hasher.Write(s.Hash)

	for _, chunkHash := range s.ChunkHashes {
		hasher.Write(chunkHash[:])
	}

	var key SnapshotKey
	copy(key[:], hasher.Sum(nil))
	return key
}

// SnapshotChunkRangeReq is a request for a range of bytes from a snapshot chunk.
// Enables resumable downloads by allowing clients to request partial chunks,
// critical for large chunks over unreliable networks where full re-download is expensive.
type SnapshotChunkRangeReq struct {
	Height uint64     `json:"height"`
	Format uint32     `json:"format"`
	Index  uint32     `json:"index"`
	Hash   types.Hash `json:"hash"`
	Offset uint64     `json:"offset"` // Starting byte offset for partial download
	Length uint64     `json:"length"` // Number of bytes to read (0 = read to end)
}

var _ encoding.BinaryMarshaler = SnapshotChunkRangeReq{}
var _ encoding.BinaryMarshaler = (*SnapshotChunkRangeReq)(nil)

func (r SnapshotChunkRangeReq) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8+4+4+types.HashLen+8+8)
	binary.LittleEndian.PutUint64(buf[:8], r.Height)
	binary.LittleEndian.PutUint32(buf[8:12], r.Format)
	binary.LittleEndian.PutUint32(buf[12:16], r.Index)
	copy(buf[16:16+types.HashLen], r.Hash[:])
	binary.LittleEndian.PutUint64(buf[16+types.HashLen:24+types.HashLen], r.Offset)
	binary.LittleEndian.PutUint64(buf[24+types.HashLen:32+types.HashLen], r.Length)
	return buf, nil
}

func (r *SnapshotChunkRangeReq) UnmarshalBinary(data []byte) error {
	expectedLen := 8 + 4 + 4 + types.HashLen + 8 + 8
	if len(data) != expectedLen {
		return fmt.Errorf("unexpected data length: got %d, expected %d", len(data), expectedLen)
	}
	r.Height = binary.LittleEndian.Uint64(data[:8])
	r.Format = binary.LittleEndian.Uint32(data[8:12])
	r.Index = binary.LittleEndian.Uint32(data[12:16])
	copy(r.Hash[:], data[16:16+types.HashLen])
	r.Offset = binary.LittleEndian.Uint64(data[16+types.HashLen : 24+types.HashLen])
	r.Length = binary.LittleEndian.Uint64(data[24+types.HashLen : 32+types.HashLen])
	return nil
}

var _ io.WriterTo = (*SnapshotChunkRangeReq)(nil)

func (r SnapshotChunkRangeReq) WriteTo(w io.Writer) (int64, error) {
	bts, err := r.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(bts)
	return int64(n), err
}

var _ io.ReaderFrom = (*SnapshotChunkRangeReq)(nil)

func (r *SnapshotChunkRangeReq) ReadFrom(rd io.Reader) (int64, error) {
	var nr int = 0
	if err := binary.Read(rd, binary.LittleEndian, &r.Height); err != nil {
		return 0, err
	}
	nr += 8

	if err := binary.Read(rd, binary.LittleEndian, &r.Format); err != nil {
		return int64(nr), err
	}
	nr += 4

	if err := binary.Read(rd, binary.LittleEndian, &r.Index); err != nil {
		return int64(nr), err
	}
	nr += 4

	n, err := io.ReadFull(rd, r.Hash[:])
	nr += n
	if err != nil {
		return int64(nr), err
	}

	if err := binary.Read(rd, binary.LittleEndian, &r.Offset); err != nil {
		return int64(nr), err
	}
	nr += 8

	if err := binary.Read(rd, binary.LittleEndian, &r.Length); err != nil {
		return int64(nr), err
	}
	nr += 8

	return int64(nr), nil
}

// SimpleProgress tracks basic download progress for resumable downloads
type SimpleProgress struct {
	ChunkIndex      uint32 `json:"chunk_index"`
	BytesDownloaded uint64 `json:"bytes_downloaded"`
	TotalSize       uint64 `json:"total_size,omitempty"`
}

// IsComplete returns true if the entire chunk has been downloaded
func (sp *SimpleProgress) IsComplete() bool {
	return sp.TotalSize > 0 && sp.BytesDownloaded >= sp.TotalSize
}

// RemainingBytes returns how many bytes are left to download
func (sp *SimpleProgress) RemainingBytes() uint64 {
	if sp.TotalSize == 0 || sp.BytesDownloaded >= sp.TotalSize {
		return 0
	}
	return sp.TotalSize - sp.BytesDownloaded
}
