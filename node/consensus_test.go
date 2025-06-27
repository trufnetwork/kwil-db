package node

import (
	"bytes"
	"testing"
	"time"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/node/types"
)

func TestBlockProp_MarshalUnmarshal(t *testing.T) {
	_, pub, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name    string
		bp      blockProp
		wantErr bool
	}{
		{
			name: "valid block proposal",
			bp: blockProp{
				Height:       100,
				Hash:         [32]byte{1, 2, 3},
				PrevHash:     [32]byte{4, 5, 6},
				Stamp:        time.Now().Unix(),
				LeaderSig:    []byte{7, 8, 9, 10},
				SenderPubKey: pub.Bytes(),
			},
			wantErr: false,
		},
		{
			name: "zero values",
			bp: blockProp{
				Height:    0,
				Hash:      [32]byte{},
				PrevHash:  [32]byte{},
				Stamp:     0,
				LeaderSig: []byte{1, 2, 3, 4},
			},
			wantErr: false,
		},
		{
			name: "large signature",
			bp: blockProp{
				Height:    1,
				Hash:      [32]byte{1},
				PrevHash:  [32]byte{2},
				Stamp:     1,
				LeaderSig: bytes.Repeat([]byte{1}, 100),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.bp.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Test both MarshalBinary and ReadFrom
			for _, unmarshalFn := range []func([]byte) (blockProp, error){
				func(data []byte) (blockProp, error) {
					var bp blockProp
					err := bp.UnmarshalBinary(data)
					return bp, err
				},
				func(data []byte) (blockProp, error) {
					var bp blockProp
					_, err := bp.ReadFrom(bytes.NewReader(data))
					return bp, err
				},
			} {
				newBp, err := unmarshalFn(data)
				if (err != nil) != tt.wantErr {
					t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
					return
				}

				if !tt.wantErr {
					if newBp.Height != tt.bp.Height {
						t.Errorf("Height mismatch: got %v, want %v", newBp.Height, tt.bp.Height)
					}
					if newBp.Hash != tt.bp.Hash {
						t.Errorf("Hash mismatch: got %v, want %v", newBp.Hash, tt.bp.Hash)
					}
					if newBp.PrevHash != tt.bp.PrevHash {
						t.Errorf("PrevHash mismatch: got %v, want %v", newBp.PrevHash, tt.bp.PrevHash)
					}
					if newBp.Stamp != tt.bp.Stamp {
						t.Errorf("Stamp mismatch: got %v, want %v", newBp.Stamp, tt.bp.Stamp)
					}
					if !bytes.Equal(newBp.LeaderSig, tt.bp.LeaderSig) {
						t.Errorf("LeaderSig mismatch: got %v, want %v", newBp.LeaderSig, tt.bp.LeaderSig)
					}
				}
			}
		})
	}
}

func TestBlockProp_UnmarshalInvalidData(t *testing.T) {
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
			data:    bytes.Repeat([]byte{1}, 8+2*types.HashLen+8+3),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bp := &blockProp{}
			err := bp.UnmarshalBinary(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
