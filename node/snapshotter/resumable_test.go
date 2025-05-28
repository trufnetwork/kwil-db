package snapshotter

import (
	"encoding/json"
	"testing"
)

func TestSimpleProgress(t *testing.T) {
	tests := []struct {
		name           string
		progress       *SimpleProgress
		isComplete     bool
		remainingBytes uint64
	}{
		{
			name: "empty progress",
			progress: &SimpleProgress{
				ChunkIndex:      0,
				BytesDownloaded: 0,
				TotalSize:       1000,
			},
			isComplete:     false,
			remainingBytes: 1000,
		},
		{
			name: "partial progress",
			progress: &SimpleProgress{
				ChunkIndex:      0,
				BytesDownloaded: 300,
				TotalSize:       1000,
			},
			isComplete:     false,
			remainingBytes: 700,
		},
		{
			name: "complete progress",
			progress: &SimpleProgress{
				ChunkIndex:      0,
				BytesDownloaded: 1000,
				TotalSize:       1000,
			},
			isComplete:     true,
			remainingBytes: 0,
		},
		{
			name: "over-downloaded (edge case)",
			progress: &SimpleProgress{
				ChunkIndex:      0,
				BytesDownloaded: 1200,
				TotalSize:       1000,
			},
			isComplete:     true,
			remainingBytes: 0,
		},
		{
			name: "unknown total size",
			progress: &SimpleProgress{
				ChunkIndex:      0,
				BytesDownloaded: 500,
				TotalSize:       0,
			},
			isComplete:     false,
			remainingBytes: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test IsComplete
			if got := tt.progress.IsComplete(); got != tt.isComplete {
				t.Errorf("IsComplete() = %v, want %v", got, tt.isComplete)
			}

			// Test RemainingBytes
			if got := tt.progress.RemainingBytes(); got != tt.remainingBytes {
				t.Errorf("RemainingBytes() = %v, want %v", got, tt.remainingBytes)
			}
		})
	}
}

func TestProgressSerialization(t *testing.T) {
	original := &SimpleProgress{
		ChunkIndex:      5,
		BytesDownloaded: 5000,
		TotalSize:       10000,
	}

	// Test JSON marshaling
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal progress: %v", err)
	}

	// Test JSON unmarshaling
	var restored SimpleProgress
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Failed to unmarshal progress: %v", err)
	}

	// Verify all fields
	if restored.ChunkIndex != original.ChunkIndex {
		t.Errorf("ChunkIndex: got %d, want %d", restored.ChunkIndex, original.ChunkIndex)
	}
	if restored.BytesDownloaded != original.BytesDownloaded {
		t.Errorf("BytesDownloaded: got %d, want %d", restored.BytesDownloaded, original.BytesDownloaded)
	}
	if restored.TotalSize != original.TotalSize {
		t.Errorf("TotalSize: got %d, want %d", restored.TotalSize, original.TotalSize)
	}
}

func TestSnapshotChunkRangeReq(t *testing.T) {
	original := SnapshotChunkRangeReq{
		Height: 12345,
		Format: 1,
		Index:  7,
		Hash:   [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Offset: 1024,
		Length: 2048,
	}

	// Test binary marshaling
	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal range request: %v", err)
	}

	// Test binary unmarshaling
	var restored SnapshotChunkRangeReq
	if err := restored.UnmarshalBinary(data); err != nil {
		t.Fatalf("Failed to unmarshal range request: %v", err)
	}

	// Verify all fields
	if restored.Height != original.Height {
		t.Errorf("Height: got %d, want %d", restored.Height, original.Height)
	}
	if restored.Format != original.Format {
		t.Errorf("Format: got %d, want %d", restored.Format, original.Format)
	}
	if restored.Index != original.Index {
		t.Errorf("Index: got %d, want %d", restored.Index, original.Index)
	}
	if restored.Hash != original.Hash {
		t.Errorf("Hash: got %x, want %x", restored.Hash, original.Hash)
	}
	if restored.Offset != original.Offset {
		t.Errorf("Offset: got %d, want %d", restored.Offset, original.Offset)
	}
	if restored.Length != original.Length {
		t.Errorf("Length: got %d, want %d", restored.Length, original.Length)
	}
}

func BenchmarkSimpleProgressOperations(b *testing.B) {
	progress := &SimpleProgress{
		ChunkIndex:      0,
		BytesDownloaded: 500000,
		TotalSize:       1000000,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = progress.IsComplete()
		_ = progress.RemainingBytes()
	}
}
