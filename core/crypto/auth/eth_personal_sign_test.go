package auth

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
)

func Test_eip55ChecksumAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    [20]byte
		expected string
	}{
		{
			name:     "Basic address",
			input:    [20]byte{0x5a, 0xAA, 0xfE, 0x6F, 0x8E, 0x4E, 0x44, 0xAA, 0x5d, 0x4c, 0xBd, 0x08, 0x7A, 0x63, 0x9B, 0x5E, 0x8A, 0x3E, 0xd3, 0x95},
			expected: "0x5aaaFe6F8e4E44aa5D4cBd087a639b5e8a3Ed395",
		},
		{
			name:     "All zeros",
			input:    [20]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: "0x0000000000000000000000000000000000000000",
		},
		{
			name:     "Mixed case address",
			input:    [20]byte{0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56},
			expected: "0x00123456789AbcdeF0123456789abCdef0123456",
		},
		{
			name:     "All F's",
			input:    [20]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			expected: "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eip55ChecksumAddr(tt.input)
			if result != tt.expected {
				t.Errorf("checksumHex() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestEthSecp256k1AuthenticatorVerifyPositive(t *testing.T) {
	privBts, _ := hex.DecodeString("a0505da852036821eb3df07e8f8ee1ebef5ce50034133ea038aee10c8b4c9111")
	priv, _ := crypto.UnmarshalSecp256k1PrivateKey(privBts)

	msg := []byte("test message")

	signer := GetUserSigner(priv)

	authnr := &EthSecp256k1Authenticator{}

	sig, err := signer.Sign(msg)
	require.NoError(t, err)

	err = authnr.Verify(signer.CompactID(), msg, sig.Data)
	require.NoError(t, err)

	// now pretend to be metamask
	sig.Data[crypto.RecoveryIDOffset] += 27

	err = authnr.Verify(signer.CompactID(), msg, sig.Data)
	require.NoError(t, err)

}

func TestEthSecp256k1AuthenticatorVerifyMetaMask(t *testing.T) {
	authnr := &EthSecp256k1Authenticator{}

	addrStr := "0x01ab2a7a29fdc3a3ad10e3ea07f2c7882b76b2e2"
	addr, _ := hex.DecodeString(addrStr[2:])
	msgBts, _ := hex.DecodeString("74657374206d657373616765") // "test message"
	mmSig, _ := hex.DecodeString("b98c74a03e9de2b99dac504eb0e63cfe464fa8b9cafc63c913efa6122815ad5a3560e90ce1367185b40fc58924a69a6ff975d62a73f3866b5ea003844ed113291b")

	err := authnr.Verify(addr, msgBts, mmSig)
	require.NoError(t, err)

	// https://etherscan.io/verifySig/265446
	msgBts2 := []byte("kwil was here")
	mmSig2, _ := hex.DecodeString("bc7acd4a00eec94ceed10bcf86d73f2c2b3b023f1d138b7c04248c724371fd39562c490be8431ed95ec1cebffc05bdb6e0d802c92fe8c8d6c6c7fb574fe321de1c")

	err = authnr.Verify(addr, msgBts2, mmSig2)
	require.NoError(t, err)
}

func TestEthSecp256k1AuthenticatorVerifyNegative(t *testing.T) {
	tests := []struct {
		name      string
		identity  []byte
		msg       []byte
		signature []byte
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "Invalid recovery ID",
			identity:  []byte{0x1, 0x2, 0x3, 0x4},
			msg:       []byte("test message"),
			signature: []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 29}, // recovery ID 29 is invalid
			wantErr:   true,
			errMsg:    "recovery",
		},
		{
			name:      "Empty message",
			identity:  []byte{0x1, 0x2, 0x3, 0x4},
			msg:       []byte{},
			signature: make([]byte, 65),
			wantErr:   true,
			errMsg:    "invalid signature",
		},
		{
			name:      "Short signature",
			identity:  []byte{0x1, 0x2, 0x3, 0x4},
			msg:       []byte("test message"),
			signature: []byte{0x1, 0x2, 0x3},
			wantErr:   true,
			errMsg:    "invalid signature length",
		},
		{
			name:      "Identity mismatch",
			identity:  make([]byte, 20),
			msg:       []byte("test message"),
			signature: make([]byte, 65),
			wantErr:   true,
			errMsg:    "invalid signature",
		},
		{
			name:      "Empty identity",
			identity:  []byte{},
			msg:       []byte("test message"),
			signature: make([]byte, 65),
			wantErr:   true,
			errMsg:    "invalid signature",
		},
	}

	auth := EthSecp256k1Authenticator{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.Verify(tt.identity, tt.msg, tt.signature)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
