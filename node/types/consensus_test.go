package types

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
)

func TestConsensusReset_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		height  int64
		wantErr bool
	}{
		{
			name:    "positive height",
			height:  100,
			wantErr: false,
		},
		{
			name:    "zero height",
			height:  0,
			wantErr: false,
		},
		{
			name:    "negative height",
			height:  -1,
			wantErr: false,
		},
		{
			name:    "max height",
			height:  1<<63 - 1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := ConsensusReset{ToHeight: tt.height}

			data, err := cr.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			var decoded ConsensusReset
			err = decoded.UnmarshalBinary(data)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && decoded.ToHeight != tt.height {
				t.Errorf("Round trip failed: got %v, want %v", decoded.ToHeight, tt.height)
			}
		})
	}
}

func TestConsensusReset_UnmarshalInvalid(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "nil data",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "insufficient data",
			data:    []byte{1, 2, 3},
			wantErr: true,
		},
		{
			name:    "excess data",
			data:    bytes.Repeat([]byte{1}, 9),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cr ConsensusReset
			err := cr.UnmarshalBinary(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConsensusReset_Bytes(t *testing.T) {
	tests := []struct {
		name   string
		height int64
		want   int
	}{
		{
			name:   "standard height",
			height: 1000,
			want:   16,
		},
		{
			name:   "zero height",
			height: 0,
			want:   16,
		},
		{
			name:   "max height",
			height: 1<<63 - 1,
			want:   16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := ConsensusReset{ToHeight: tt.height}
			got := cr.Bytes()
			if len(got) != tt.want {
				t.Errorf("Bytes() length = %v, want %v", len(got), tt.want)
			}
		})
	}
}

func TestAckRes_MarshalUnmarshal(t *testing.T) {
	invalidBlock := NackStatusInvalidBlock
	OutOfSyncStatus := NackStatusOutOfSync
	signature := types.Signature{
		Data:       []byte{4, 5, 6},
		PubKeyType: crypto.KeyTypeSecp256k1,
		PubKey:     []byte{1, 2, 3},
	}

	tests := []struct {
		name    string
		ar      AckRes
		wantErr bool
	}{
		{
			name: "missing signature",
			ar: AckRes{
				ACK:     true,
				Height:  123,
				BlkHash: Hash{1, 2, 3},
				AppHash: &Hash{4, 5, 6},
			},
			wantErr: true,
		},
		{
			name: "valid ACK with all fields",
			ar: AckRes{
				ACK:       true,
				Height:    123,
				BlkHash:   Hash{1, 2, 3},
				AppHash:   &Hash{4, 5, 6},
				Signature: &signature,
			},
			wantErr: false,
		},
		{
			name: "valid nACK",
			ar: AckRes{
				ACK:        false,
				NackStatus: &invalidBlock,
				Height:     0,
				BlkHash:    Hash{},
				AppHash:    nil,
				Signature:  &signature,
			},
			wantErr: false,
		},
		{
			name: "valid nACK with OutOfSync status",
			ar: AckRes{
				ACK:        false,
				NackStatus: &OutOfSyncStatus,
				OutOfSyncProof: &OutOfSyncProof{
					Header: &types.BlockHeader{
						Version: 1,
					},
					Signature: []byte{1, 2, 3},
				},
				Height:    0,
				BlkHash:   Hash{},
				AppHash:   nil,
				Signature: &signature,
			},
			wantErr: false,
		},
		{
			name: "invalid nACK with OutOfSync status",
			ar: AckRes{
				ACK:            false,
				NackStatus:     &OutOfSyncStatus,
				OutOfSyncProof: nil,
				Height:         0,
				BlkHash:        Hash{},
				AppHash:        nil,
			},
			wantErr: true,
		},
		{
			name: "invalid ACK missing AppHash",
			ar: AckRes{
				ACK:       true,
				Height:    100,
				BlkHash:   Hash{1, 2, 3},
				AppHash:   nil,
				Signature: &signature,
			},
			wantErr: true,
		},
		{
			name: "max height value",
			ar: AckRes{
				ACK:       true,
				Height:    1<<63 - 1,
				BlkHash:   Hash{1},
				AppHash:   &Hash{2},
				Signature: &signature,
			},
			wantErr: false,
		},
		{
			name: "invalid nACK with AppHash",
			ar: AckRes{
				ACK:       false,
				Height:    0,
				BlkHash:   Hash{},
				AppHash:   &Hash{1, 2, 3},
				Signature: &signature,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.ar.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			var decoded AckRes
			err = decoded.UnmarshalBinary(data)
			if err != nil {
				t.Errorf("UnmarshalBinary() unexpected error = %v", err)
				return
			}

			if decoded.ACK != tt.ar.ACK {
				t.Errorf("ACK mismatch: got %v, want %v", decoded.ACK, tt.ar.ACK)
			}
			if decoded.Height != tt.ar.Height {
				t.Errorf("Height mismatch: got %v, want %v", decoded.Height, tt.ar.Height)
			}
			if decoded.BlkHash != tt.ar.BlkHash {
				t.Errorf("BlkHash mismatch: got %v, want %v", decoded.BlkHash, tt.ar.BlkHash)
			}
			if tt.ar.ACK {
				if decoded.AppHash == nil || *decoded.AppHash != *tt.ar.AppHash {
					t.Errorf("AppHash mismatch: got %v, want %v", decoded.AppHash, tt.ar.AppHash)
				}
			}
			if decoded.Signature.PubKeyType != tt.ar.Signature.PubKeyType {
				t.Errorf("Signature pubkey mismatch: got %v, want %v", decoded.Signature.PubKeyType, tt.ar.Signature.PubKeyType)
			}

			if !bytes.Equal(decoded.Signature.Data, tt.ar.Signature.Data) {
				t.Errorf("Signature data mismatch: got %v, want %v", decoded.Signature.Data, tt.ar.Signature.Data)
			}

			if !bytes.Equal(decoded.Signature.PubKey, tt.ar.Signature.PubKey) {
				t.Errorf("Signature pubkey mismatch: got %v, want %v", decoded.Signature.PubKey, tt.ar.Signature.PubKey)
			}
		})
	}
}

func TestAckRes_UnmarshalInvalid(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "invalid nACK with extra data",
			data:    []byte{0, 1, 2, 3},
			wantErr: true,
		},
		{
			name:    "incomplete ACK data",
			data:    []byte{1, 1, 2, 3},
			wantErr: true,
		},
		{
			name:    "partial hash data",
			data:    append([]byte{1}, bytes.Repeat([]byte{1}, HashLen+8)...),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ar AckRes
			err := ar.UnmarshalBinary(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestDiscoveryResponse_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name       string
		bestHeight int64
		wantErr    bool
	}{
		{
			name:       "positive height",
			bestHeight: 1234567,
			wantErr:    false,
		},
		{
			name:       "min height",
			bestHeight: -9223372036854775808,
			wantErr:    false,
		},
		{
			name:       "max height",
			bestHeight: 9223372036854775807,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dr := DiscoveryResponse{BestHeight: tt.bestHeight}

			data, err := dr.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			var decoded DiscoveryResponse
			err = decoded.UnmarshalBinary(data)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && decoded.BestHeight != tt.bestHeight {
				t.Errorf("Round trip failed: got %v, want %v", decoded.BestHeight, tt.bestHeight)
			}
		})
	}
}

func TestDiscoveryResponse_UnmarshalInvalid(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "nil data",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "short data",
			data:    []byte{1, 2, 3, 4, 5, 6, 7},
			wantErr: true,
		},
		{
			name:    "long data",
			data:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dr DiscoveryResponse
			err := dr.UnmarshalBinary(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDiscoveryResponse_Bytes(t *testing.T) {
	tests := []struct {
		name       string
		bestHeight int64
		wantLen    int
	}{
		{
			name:       "zero height",
			bestHeight: 0,
			wantLen:    8,
		},
		{
			name:       "large positive height",
			bestHeight: 1<<60 - 1,
			wantLen:    8,
		},
		{
			name:       "large negative height",
			bestHeight: -(1 << 60),
			wantLen:    8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dr := DiscoveryResponse{BestHeight: tt.bestHeight}
			got := dr.Bytes()
			if len(got) != tt.wantLen {
				t.Errorf("Bytes() length = %v, want %v", len(got), tt.wantLen)
			}

			// Verify the bytes can be decoded back
			decoded := int64(binary.LittleEndian.Uint64(got))
			if decoded != tt.bestHeight {
				t.Errorf("Bytes() decoded value = %v, want %v", decoded, tt.bestHeight)
			}
		})
	}
}
