package node

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
)

// TestValidatorSigner_Sign tests the Sign method with different purposes.
// It asserts that each purpose produces the V value expected by its verifier,
// and round-trips through the *actual* verifier that runs at consensus time
// (utils.EthStandardVerifyDigest or utils.EthGnosisVerifyDigest) rather than a
// hand-rolled Ecrecover in the test — the whole point of this test is to catch
// sign↔verify drift like the 2026-04-24 eth_usdc incident.
func TestValidatorSigner_Sign(t *testing.T) {
	ecdsaKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privKeyBytes := crypto.FromECDSA(ecdsaKey)
	secp256k1Key, err := kwilcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	identity := secp256k1Key.Public().Bytes()
	address := crypto.PubkeyToAddress(ecdsaKey.PublicKey).Bytes()
	logger := log.DiscardLogger

	signer := NewValidatorSigner(secp256k1Key, identity, logger)
	require.NotNil(t, signer)

	ctx := context.Background()
	messageHash := crypto.Keccak256([]byte("test message"))

	type verifyFn func(sig, digest, addr []byte) error

	tests := []struct {
		name        string
		purpose     string
		expectError bool
		// wantVLow/wantVHigh: acceptable V values for this purpose.
		wantVLow, wantVHigh byte
		// verify: the actual verifier the vote/withdrawal will reach. Nil for
		// error cases.
		verify verifyFn
	}{
		{
			name:      "epoch_voting produces V=27/28 and round-trips via EthStandardVerifyDigest",
			purpose:   common.PurposeEpochVoting,
			wantVLow:  27,
			wantVHigh: 28,
			verify:    utils.EthStandardVerifyDigest,
		},
		{
			name:      "withdrawal_signature produces V=27/28 and round-trips via EthStandardVerifyDigest",
			purpose:   common.PurposeWithdrawalSig,
			wantVLow:  27,
			wantVHigh: 28,
			verify:    utils.EthStandardVerifyDigest,
		},
		{
			name:      "gnosis_safe_signing produces V=31/32 and round-trips via EthGnosisVerifyDigest",
			purpose:   common.PurposeGnosisSafeSigning,
			wantVLow:  31,
			wantVHigh: 32,
			verify:    utils.EthGnosisVerifyDigest,
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
				return
			}

			require.NoError(t, err)
			require.NotNil(t, signature)
			require.Equal(t, 65, len(signature), "signature should be 65 bytes")

			v := signature[64]
			require.Truef(t, v == tt.wantVLow || v == tt.wantVHigh,
				"V must be %d or %d for purpose %q, got %d", tt.wantVLow, tt.wantVHigh, tt.purpose, v)

			require.NoErrorf(t, tt.verify(signature, messageHash, address),
				"signature for purpose %q must round-trip through its real verifier", tt.purpose)
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

// TestValidatorSigner_EpochVoteMatchesMetaExtensionVerifier regression-guards
// the 2026-04-24 eth_usdc incident: validator signed epoch votes with V=31/32
// while the voteEpoch action's non-custodial path verifies with
// utils.EthStandardVerifyDigest (V=27/28), so every vote tx was rejected at
// block-processor time as "invalid signature V: expected 27 or 28, got 32".
//
// This test repeats the exact flow that erc20-bridge/erc20/validator_signer.go
// performs: compute epoch message hash, prefix with "\x19Ethereum Signed
// Message:\n32", sign with PurposeEpochVoting, then run the signature through
// the production verifier at meta_extension.go:1394. Any future change to the
// signer's format that breaks this round-trip will fail here, not in mainnet
// logs.
func TestValidatorSigner_EpochVoteMatchesMetaExtensionVerifier(t *testing.T) {
	ecdsaKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privKeyBytes := crypto.FromECDSA(ecdsaKey)
	secp256k1Key, err := kwilcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	address := crypto.PubkeyToAddress(ecdsaKey.PublicKey).Bytes()
	signer := NewValidatorSigner(secp256k1Key, secp256k1Key.Public().Bytes(), log.DiscardLogger)
	require.NotNil(t, signer)

	// Mimic erc20-bridge/erc20/validator_signer.go:signAndVote —
	// sign the "\x19Ethereum Signed Message:\n32"-prefixed hash.
	rawEpochHash := crypto.Keccak256([]byte("epoch=4dde50aa,rewardRoot=…,blockHash=…"))
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	ethSignedMessageHash := crypto.Keccak256(append(prefix, rawEpochHash...))

	signature, err := signer.Sign(context.Background(), ethSignedMessageHash, common.PurposeEpochVoting)
	require.NoError(t, err)

	// The very function that meta_extension.go:1394 runs at consensus time.
	require.NoError(t,
		utils.EthStandardVerifyDigest(signature, ethSignedMessageHash, address),
		"epoch vote signature must be accepted by the voteEpoch action's verifier; "+
			"if this fails the mainnet bridge will reject all votes with "+
			"\"invalid signature V: expected 27 or 28\"")
}
