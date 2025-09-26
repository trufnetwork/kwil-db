package snapshotter

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/trufnetwork/kwil-db/node/types"
)

func TestSnapshotChunkReqBinaryRoundTrip(t *testing.T) {
	original := SnapshotChunkReq{
		Height: 1234,
		Format: 42,
		Index:  3,
		Hash:   types.Hash{1, 2, 3, 4},
	}

	// marshal/unmarshal
	bts, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	var decoded SnapshotChunkReq
	if err := decoded.UnmarshalBinary(bts); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if decoded.Height != original.Height || decoded.Format != original.Format || decoded.Index != original.Index || decoded.Hash != original.Hash {
		t.Fatalf("decoded struct mismatch: %+v vs %+v", decoded, original)
	}

	// reader/writer interface
	buf := &bytes.Buffer{}
	if _, err := original.WriteTo(buf); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var readBack SnapshotChunkReq
	if _, err := readBack.ReadFrom(buf); err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if readBack.Height != original.Height || readBack.Format != original.Format || readBack.Index != original.Index || readBack.Hash != original.Hash {
		t.Fatalf("ReadFrom mismatch: %+v vs %+v", readBack, original)
	}

	// ensure size is exact
	expectedLen := 8 + 4 + 4 + types.HashLen
	if len(bts) != expectedLen {
		t.Fatalf("binary length mismatch: got %d want %d", len(bts), expectedLen)
	}

	// confirm byte layout (Height|Format|Index)
	if binary.LittleEndian.Uint32(bts[8:12]) != original.Format {
		t.Fatalf("format not encoded correctly")
	}
	if binary.LittleEndian.Uint32(bts[12:16]) != original.Index {
		t.Fatalf("index not encoded correctly")
	}
}
