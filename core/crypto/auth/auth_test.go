package auth_test

import (
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	secp256k1Key  = "f1aa5a7966c3863ccde3047f6a1e266cdc0c76b399e256b8fede92b1c69e4f4e"
	secp256k1Addr = "0xc89D42189f0450C2b2c3c61f58Ec5d628176A1E7"
	ed25519Key    = "7c67e60fce0c403ff40193a3128e5f3d8c2139aed36d76d7b5f1e70ec19c43f00aa611bf555596912bc6f9a9f169f8785918e7bab9924001895798ff13f05842"
	ed25519Addr   = "0aa611bf555596912bc6f9a9f169f8785918e7bab9924001895798ff13f05842"
)

var secp256k1PubKey string // from secp256k1Key

func init() {
	pk, err := hex.DecodeString(secp256k1Key)
	if err != nil {
		panic(err)
	}
	k, err := crypto.UnmarshalSecp256k1PrivateKey(pk)
	if err != nil {
		panic(err)
	}
	secp256k1PubKey = hex.EncodeToString(k.Public().Bytes())
}

func Test_AuthSignAndVerify(t *testing.T) {

	// testCase will take a signer
	// it will sign a message and verify the signature using
	// the proper authenticator.  It will then check that the
	// identifier is correct
	type testCase struct {
		name          string
		signer        auth.Signer
		authenticator auth.Authenticator
		ident         string
	}

	var msg = []byte("foo")

	testCases := []testCase{
		{
			name:          "Secp256k1 sha256",
			signer:        secp256k1PlainSigner(t, [32]byte{1, 2, 3}),
			authenticator: auth.Secp25k1Authenticator{},
			ident:         "03fdfb57fb936a3fccef973c99041317d0543a5f5c1d772ca60adca30c6c2606c6", // 33 byte compressed pubkey
		},
		{
			name:          "eth personal sign",
			signer:        secp256k1Signer(t, [32]byte{1, 2, 3}),
			authenticator: auth.EthSecp256k1Authenticator{},
			ident:         "0x1b7C6c9938cD93C10910dbC4d4aC8c9275e96925", // 0x prefixed 20 byte address
		},
		{
			name:          "ed25519",
			signer:        ed25519Signer(t, [32]byte{1, 2, 3}),
			authenticator: auth.Ed25519Authenticator{},
			ident:         "57b8983ac97d18aaa1eb428890d0abe673a843cf4a42e83ab875efd250c9dcb1", // 32 byte pubkey
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := tc.signer.Sign(msg)
			assert.NoError(t, err)

			// verify the signature
			err = tc.authenticator.Verify(tc.signer.CompactID(), msg, sig.Data)
			assert.NoError(t, err)

			// check the address
			identifier, err := tc.authenticator.Identifier(tc.signer.CompactID())
			assert.NoError(t, err)

			if tc.ident != identifier {
				t.Errorf("address mismatch, got %v want %v", identifier, tc.ident)
			}
		})
	}
}

func TestSecp256k1PlainIdentifier(t *testing.T) {
	pk, err := hex.DecodeString(secp256k1Key)
	require.NoError(t, err)

	k, err := crypto.UnmarshalSecp256k1PrivateKey(pk)
	require.NoError(t, err)

	signer := &auth.Secp256k1Signer{Secp256k1PrivateKey: *k}
	authenticator := auth.Secp25k1Authenticator{}

	identifier, err := authenticator.Identifier(signer.CompactID())
	require.NoError(t, err)

	assert.Equal(t, secp256k1PubKey, identifier)
}

func TestSecp256k1Identifier(t *testing.T) {
	pk, err := hex.DecodeString(secp256k1Key)
	require.NoError(t, err)

	k, err := crypto.UnmarshalSecp256k1PrivateKey(pk)
	require.NoError(t, err)

	signer := &auth.EthPersonalSigner{Key: *k}
	authenticator := auth.EthSecp256k1Authenticator{}

	address, err := authenticator.Identifier(signer.CompactID())
	require.NoError(t, err)

	assert.Equal(t, secp256k1Addr, address)
}

func TestEd25519Identifier(t *testing.T) {
	k, err := hex.DecodeString(ed25519Key)
	require.NoError(t, err)

	pk, err := crypto.UnmarshalEd25519PrivateKey(k)
	require.NoError(t, err)

	signer := &auth.Ed25519Signer{Ed25519PrivateKey: *pk}
	authenticator := auth.Ed25519Authenticator{}

	address, err := authenticator.Identifier(signer.CompactID())
	require.NoError(t, err)

	assert.Equal(t, ed25519Addr, address)
}

func secp256k1PlainSigner(t *testing.T, seed [32]byte) *auth.Secp256k1Signer {
	rngSrc := rand.NewChaCha8(seed)
	privKey, _, err := crypto.GenerateSecp256k1Key(rngSrc)
	require.NoError(t, err)

	fmt.Println("Private Key:", privKey)
	privKeyBytes := privKey.Bytes()
	k, err := crypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	return &auth.Secp256k1Signer{Secp256k1PrivateKey: *k}
}

func secp256k1Signer(t *testing.T, seed [32]byte) *auth.EthPersonalSigner {
	rngSrc := rand.NewChaCha8(seed)
	privKey, _, err := crypto.GenerateSecp256k1Key(rngSrc)
	require.NoError(t, err)

	fmt.Println("Private Key:", privKey)
	privKeyBytes := privKey.Bytes()
	k, err := crypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	return &auth.EthPersonalSigner{Key: *k}
}

func ed25519Signer(t *testing.T, seed [32]byte) *auth.Ed25519Signer {
	rngSrc := rand.NewChaCha8(seed)
	privKey, _, err := crypto.GenerateEd25519Key(rngSrc)
	require.NoError(t, err)

	pBytes := privKey.Bytes()
	k, err := crypto.UnmarshalEd25519PrivateKey(pBytes)
	require.NoError(t, err)

	return &auth.Ed25519Signer{Ed25519PrivateKey: *k}
}
