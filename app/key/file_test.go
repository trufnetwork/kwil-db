package key

import (
	"testing"

	"github.com/trufnetwork/kwil-db/core/crypto"
)

func TestNodeKeyFileMarshalJSON(t *testing.T) {
	edKey, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	secKey, _, err := crypto.GenerateSecp256k1Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		key     crypto.PrivateKey
		wantErr bool
	}{
		{
			name:    "nil key",
			key:     nil,
			wantErr: true,
		},
		{
			name:    "valid ed25519 key",
			key:     edKey,
			wantErr: false,
		},
		{
			name:    "valid secp256k1 key",
			key:     secKey,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nk := NodeKeyFile{Key: tt.key}
			data, err := nk.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Log(string(data))
			if !tt.wantErr && len(data) == 0 {
				t.Error("MarshalJSON() returned empty data")
			}
		})
	}
}

func TestNodeKeyFileUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		wantKeyType crypto.KeyType
		wantErr     bool
	}{
		{
			name:        "valid ed25519 key",
			json:        `{"key":"cd96a460b7a9f49f3ea51af1da80505313a081cc58f3c9de73812ea72f19e5457e5880069c79450c30a95a025a0fdaa90b2cf99773df6d9f8609152cdd729ed1","type":"ed25519"}`,
			wantKeyType: crypto.KeyTypeEd25519,
			wantErr:     false,
		},
		{
			name:        "valid secp256k1 key",
			json:        `{"key":"18c739664360c732d2f2eecbfddc569dc522ebbbcbab64b995d8bff23b9befe7","type":"secp256k1"}`,
			wantKeyType: crypto.KeyTypeSecp256k1,
			wantErr:     false,
		},
		{
			name:    "invalid json",
			json:    `{"key": "invalid"}`,
			wantErr: true,
		},
		{
			name:    "missing type",
			json:    `{"key": "0102030405"}`,
			wantErr: true,
		},
		{
			name:    "invalid hex",
			json:    `{"key": "xyz", "type": "ed25519"}`,
			wantErr: true,
		},
		{
			name:    "invalid key type",
			json:    `{"key": "0102030405", "type": "invalid"}`,
			wantErr: true,
		},
		{
			name:    "empty key",
			json:    `{"key": "", "type": "ed25519"}`,
			wantErr: true,
		},
		{
			name:    "malformed json",
			json:    `{"key": "0102", "type":}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nk NodeKeyFile
			err := nk.UnmarshalJSON([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if nk.Key == nil {
				t.Error("UnmarshalJSON() did not set key")
			}
			if nk.Key.Type() != tt.wantKeyType {
				t.Errorf("UnmarshalJSON() key type = %v, want %v", nk.Key.Type(), tt.wantKeyType)
			}
		})
	}
}
