package node

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
)

// TestValidatorSigner_Sign tests the Sign method with different purposes
func TestValidatorSigner_Sign(t *testing.T) {
	// Create a test secp256k1 private key
	ecdsaKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privKeyBytes := crypto.FromECDSA(ecdsaKey)
	secp256k1Key, err := kwilcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	identity := secp256k1Key.Public().Bytes()
	logger := log.DiscardLogger

	signer := NewValidatorSigner(secp256k1Key, identity, logger)
	require.NotNil(t, signer)

	ctx := context.Background()
	messageHash := crypto.Keccak256([]byte("test message"))

	tests := []struct {
		name        string
		purpose     string
		expectError bool
	}{
		{
			name:        "valid epoch_voting purpose",
			purpose:     common.PurposeEpochVoting,
			expectError: false,
		},
		{
			name:        "valid withdrawal_signature purpose",
			purpose:     common.PurposeWithdrawalSig,
			expectError: false,
		},
		{
			name:        "valid gnosis_safe_signing purpose",
			purpose:     common.PurposeGnosisSafeSigning,
			expectError: false,
		},
		{
			name:        "invalid purpose should fail",
			purpose:     "malicious_purpose",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature, err := signer.Sign(ctx, messageHash, tt.purpose)

			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, signature)
				require.Contains(t, err.Error(), "unauthorized signing purpose")
			} else {
				require.NoError(t, err)
				require.NotNil(t, signature)
				require.Equal(t, 65, len(signature), "signature should be 65 bytes")

				// Verify V value is 31 or 32 (Gnosis Safe EIP-191 format)
				v := signature[64]
				require.True(t, v == 31 || v == 32, "V should be 31 or 32 for Gnosis Safe, got %d", v)
			}
		})
	}
}

// TestValidatorSigner_EthereumAddress tests Ethereum address derivation
func TestValidatorSigner_EthereumAddress(t *testing.T) {
	// Create a test secp256k1 private key
	ecdsaKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privKeyBytes := crypto.FromECDSA(ecdsaKey)
	secp256k1Key, err := kwilcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	identity := secp256k1Key.Public().Bytes()
	logger := log.DiscardLogger

	signer := NewValidatorSigner(secp256k1Key, identity, logger)
	require.NotNil(t, signer)

	// Get Ethereum address
	address, err := signer.EthereumAddress()
	require.NoError(t, err)
	require.Equal(t, 20, len(address), "Ethereum address should be 20 bytes")

	// Verify it matches the expected address
	expectedAddress := crypto.PubkeyToAddress(ecdsaKey.PublicKey)
	require.Equal(t, expectedAddress.Bytes(), address)
}

// TestValidatorSigner_CreateSecp256k1Signer tests transaction signer creation
func TestValidatorSigner_CreateSecp256k1Signer(t *testing.T) {
	// Create a test secp256k1 private key
	ecdsaKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privKeyBytes := crypto.FromECDSA(ecdsaKey)
	secp256k1Key, err := kwilcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	identity := secp256k1Key.Public().Bytes()
	logger := log.DiscardLogger

	valSigner := NewValidatorSigner(secp256k1Key, identity, logger)
	require.NotNil(t, valSigner)

	// Create transaction signer
	txSigner, err := valSigner.CreateSecp256k1Signer()
	require.NoError(t, err)
	require.NotNil(t, txSigner)

	// Verify the signer can sign a message
	testMsg := []byte("test transaction")
	signature, err := txSigner.Sign(testMsg)
	require.NoError(t, err)
	require.NotNil(t, signature)
}

// TestValidatorSigner_Identity tests identity retrieval
func TestValidatorSigner_Identity(t *testing.T) {
	// Create a test secp256k1 private key
	ecdsaKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privKeyBytes := crypto.FromECDSA(ecdsaKey)
	secp256k1Key, err := kwilcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	identity := secp256k1Key.Public().Bytes()
	logger := log.DiscardLogger

	signer := NewValidatorSigner(secp256k1Key, identity, logger)
	require.NotNil(t, signer)

	// Get identity
	retrievedIdentity := signer.Identity()
	require.Equal(t, identity, retrievedIdentity)
}

// TestValidatorSigner_NilPrivateKey tests that nil private key returns nil signer
func TestValidatorSigner_NilPrivateKey(t *testing.T) {
	signer := NewValidatorSigner(nil, []byte{}, log.DiscardLogger)
	require.Nil(t, signer, "should return nil for nil private key")
}

// TestValidatorSigner_SignatureVerification tests that signatures can be verified
func TestValidatorSigner_SignatureVerification(t *testing.T) {
	// Create a test secp256k1 private key
	ecdsaKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privKeyBytes := crypto.FromECDSA(ecdsaKey)
	secp256k1Key, err := kwilcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	identity := secp256k1Key.Public().Bytes()
	logger := log.DiscardLogger

	signer := NewValidatorSigner(secp256k1Key, identity, logger)
	require.NotNil(t, signer)

	ctx := context.Background()
	messageHash := crypto.Keccak256([]byte("test message"))

	// Sign the message
	signature, err := signer.Sign(ctx, messageHash, common.PurposeEpochVoting)
	require.NoError(t, err)
	require.NotNil(t, signature)

	// Verify the signature can recover the correct address
	// Adjust V back to 0/1 for recovery (Gnosis Safe uses 31/32)
	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)
	sigCopy[64] -= 31 // Convert back: 31/32 -> 0/1

	pubkey, err := crypto.Ecrecover(messageHash, sigCopy)
	require.NoError(t, err)

	recoveredAddress := crypto.Keccak256(pubkey[1:])[12:]
	expectedAddress := crypto.PubkeyToAddress(ecdsaKey.PublicKey)

	require.Equal(t, expectedAddress.Bytes(), recoveredAddress,
		"recovered address should match expected address")
}
