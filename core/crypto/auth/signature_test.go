package auth_test

import (
	"bytes"
	"testing"

	"github.com/trufnetwork/kwil-db/core/crypto/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignature_MarshalBinary(t *testing.T) {
	tests := []struct {
		name      string
		signature auth.Signature
		wantErr   bool
	}{
		{
			name: "valid signature",
			signature: auth.Signature{
				Data: []byte("test signature data"),
				Type: "test_type",
			},
			wantErr: false,
		},
		{
			name: "empty signature",
			signature: auth.Signature{
				Data: []byte{},
				Type: "",
			},
			wantErr: false,
		},
		{
			name: "large signature",
			signature: auth.Signature{
				Data: bytes.Repeat([]byte("a"), 1000),
				Type: "large_sig",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.signature.MarshalBinary()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			var unmarshaled auth.Signature
			err = unmarshaled.UnmarshalBinary(data)
			require.NoError(t, err)

			assert.Len(t, unmarshaled.Data, len(tt.signature.Data))
			if len(tt.signature.Data) > 0 {
				assert.Equal(t, tt.signature.Data, unmarshaled.Data)
			}
			assert.Equal(t, tt.signature.Type, unmarshaled.Type)
		})
	}
}

func TestSignature_UnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    auth.Signature
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "insufficient data length",
			data:    []byte{1, 2, 3},
			wantErr: true,
		},
		{
			name:    "invalid signature length",
			data:    []byte{255, 255, 255, 255, 0, 0, 0, 0},
			wantErr: true,
		},
		{
			name: "invalid type length",
			data: append(
				append([]byte{4, 0, 0, 0}, []byte("test")...),
				[]byte{255, 255, 255, 255}...,
			),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sig auth.Signature
			err := sig.UnmarshalBinary(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			if len(tt.data) < 8 {
				assert.NoError(t, err)
				return
			}
			assert.Equal(t, tt.want.Data, sig.Data)
			assert.Equal(t, tt.want.Type, sig.Type)
		})
	}
}

func TestSignature_SerializeSize(t *testing.T) {
	getSerializedSigLen := func(sig *auth.Signature) int64 {
		return int64(len(sig.Bytes()))
	}
	tests := []struct {
		name     string
		sig      auth.Signature
		expected int64
	}{
		{
			name: "Empty signature",
			sig: auth.Signature{
				Data: []byte{},
				Type: "",
			},
			expected: 2, // 1 byte for each uvarint(0)
		},
		{
			name: "Standard signature",
			sig: auth.Signature{
				Data: []byte{1, 2, 3, 4, 5},
				Type: "secp256k1",
			},
			expected: 16, // 1 + 5 + 1 + 9
		},
		{
			name: "Large signature",
			sig: auth.Signature{
				Data: make([]byte, 65),
				Type: "eth_personal_sign",
			},
			expected: 84, // 1 + 65 + 1 + 17
		},
		{
			name: "Only type",
			sig: auth.Signature{
				Data: nil,
				Type: "ed25519",
			},
			expected: 9, // 1 + 0 + 1 + 7
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualSigLen := getSerializedSigLen(&tt.sig)
			size := tt.sig.SerializeSize()
			assert.Equal(t, size, actualSigLen)
			assert.Equal(t, tt.expected, size)
		})
	}
}

func TestSignature_SerializeSizeMatchesWriteTo(t *testing.T) {
	tests := []struct {
		name string
		sig  auth.Signature
	}{
		{
			name: "Empty signature",
			sig: auth.Signature{
				Data: []byte{},
				Type: "",
			},
		},
		{
			name: "Standard signature",
			sig: auth.Signature{
				Data: []byte{1, 2, 3, 4, 5},
				Type: "secp256k1",
			},
		},
		{
			name: "Large signature",
			sig: auth.Signature{
				Data: make([]byte, 65),
				Type: "eth_personal_sign",
			},
		},
		{
			name: "Only type",
			sig: auth.Signature{
				Data: nil,
				Type: "ed25519",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedSize := tt.sig.SerializeSize()

			buf := new(bytes.Buffer)
			n, err := tt.sig.WriteTo(buf)

			require.NoError(t, err)
			assert.Equal(t, expectedSize, n, "SerializeSize should match WriteTo output size")
			assert.Equal(t, expectedSize, int64(buf.Len()), "SerializeSize should match actual bytes written")
		})
	}
}
