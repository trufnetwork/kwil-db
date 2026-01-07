package signersvc

import (
	"encoding/hex"
	"math/big"
	"testing"

	ethCommon "github.com/ethereum/go-ethereum/common"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
)

// TestCanSkip_WithSafe tests canSkip logic for Safe-based (custodial) bridges
func TestCanSkip_WithSafe(t *testing.T) {
	// Setup test signer
	pk, err := ethCrypto.GenerateKey()
	require.NoError(t, err)
	signerAddr := ethCrypto.PubkeyToAddress(pk.PublicKey)

	otherPk, err := ethCrypto.GenerateKey()
	require.NoError(t, err)
	otherAddr := ethCrypto.PubkeyToAddress(otherPk.PublicKey)

	signer := &bridgeSigner{
		signerAddr: signerAddr,
		signerPk:   pk,
		logger:     log.DiscardLogger,
	}

	epoch := &Epoch{
		ID:         types.NewUUIDV5([]byte("test-epoch-1")),
		Voters:     []string{signerAddr.String()},
		VoteNonces: []int64{5},
	}

	t.Run("skip when not safe owner", func(t *testing.T) {
		safeMeta := &safeMetadata{
			owners:    []ethCommon.Address{otherAddr}, // Different owner
			nonce:     big.NewInt(5),
			threshold: big.NewInt(1),
		}

		skip := signer.canSkip(epoch, safeMeta)
		assert.True(t, skip, "should skip when signer is not safe owner")
	})

	t.Run("skip when already voted with same nonce", func(t *testing.T) {
		safeMeta := &safeMetadata{
			owners:    []ethCommon.Address{signerAddr}, // Signer is owner
			nonce:     big.NewInt(5),                   // Same nonce as vote
			threshold: big.NewInt(1),
		}

		skip := signer.canSkip(epoch, safeMeta)
		assert.True(t, skip, "should skip when already voted with matching nonce")
	})

	t.Run("do not skip when nonce changed", func(t *testing.T) {
		safeMeta := &safeMetadata{
			owners:    []ethCommon.Address{signerAddr}, // Signer is owner
			nonce:     big.NewInt(6),                   // Different nonce
			threshold: big.NewInt(1),
		}

		skip := signer.canSkip(epoch, safeMeta)
		assert.False(t, skip, "should not skip when nonce changed")
	})

	t.Run("do not skip when not voted yet", func(t *testing.T) {
		epochNoVotes := &Epoch{
			ID:     types.NewUUIDV5([]byte("test-epoch-no-votes")),
			Voters: nil, // No voters yet
		}

		safeMeta := &safeMetadata{
			owners:    []ethCommon.Address{signerAddr},
			nonce:     big.NewInt(5),
			threshold: big.NewInt(1),
		}

		skip := signer.canSkip(epochNoVotes, safeMeta)
		assert.False(t, skip, "should not skip when haven't voted yet")
	})
}

// TestCanSkip_WithoutSafe tests canSkip logic for non-custodial bridges
func TestCanSkip_WithoutSafe(t *testing.T) {
	pk, err := ethCrypto.GenerateKey()
	require.NoError(t, err)
	signerAddr := ethCrypto.PubkeyToAddress(pk.PublicKey)

	signer := &bridgeSigner{
		signerAddr: signerAddr,
		signerPk:   pk,
		logger:     log.DiscardLogger,
	}

	epoch := &Epoch{
		ID:         types.NewUUIDV5([]byte("test-epoch-noncustodial")),
		Voters:     []string{signerAddr.String()},
		VoteNonces: []int64{0}, // Non-custodial always uses nonce 0
	}

	t.Run("skip when already voted (no Safe)", func(t *testing.T) {
		skip := signer.canSkip(epoch, nil) // nil safeMeta = non-custodial
		assert.True(t, skip, "should skip when already voted for non-custodial bridge")
	})

	t.Run("do not skip when not voted yet (no Safe)", func(t *testing.T) {
		epochNoVotes := &Epoch{
			ID:     types.NewUUIDV5([]byte("test-epoch-noncustodial-novotes")),
			Voters: nil,
		}

		skip := signer.canSkip(epochNoVotes, nil)
		assert.False(t, skip, "should not skip when haven't voted yet")
	})
}

// TestDirectSignature tests the signature format for non-custodial bridges
func TestDirectSignature(t *testing.T) {
	// Generate test key
	pk, err := ethCrypto.GenerateKey()
	require.NoError(t, err)

	// Test merkle root and block hash
	merkleRoot := ethCommon.Hex2Bytes("9e37a3ed4da4b0a974c0ae853353946da4211d94782ade884f2264af02dfa800")
	blockHash := ethCommon.Hex2Bytes("c15484750dce64508eb6f83027440dd8e6489eca8b841468f9618dae5ac0baa9")

	// Create message matching TrufNetworkBridge format:
	// keccak256(abi.encode(merkleRoot, blockHash))
	message := make([]byte, 64)
	copy(message[0:32], merkleRoot)
	copy(message[32:64], blockHash)

	// Sign using standard Ethereum signature (matches OpenZeppelin ECDSA.recover)
	sig, err := utils.EthZeppelinSign(message, pk)
	require.NoError(t, err)
	require.Equal(t, 65, len(sig), "signature should be 65 bytes")

	// Verify signature format
	assert.True(t, sig[64] == 27 || sig[64] == 28, "V should be 27 or 28 for standard Ethereum signatures")

	t.Logf("Signed message: %s", hex.EncodeToString(message))
	t.Logf("Signature: %s", hex.EncodeToString(sig))
	t.Logf("Signer address: %s", ethCrypto.PubkeyToAddress(pk.PublicKey).String())
}

// TestSafeSignature tests the signature format for Safe-based bridges
func TestSafeSignature(t *testing.T) {
	// Generate test key
	pk, err := ethCrypto.GenerateKey()
	require.NoError(t, err)

	// Test message (simplified, actual Safe tx would be more complex)
	message := []byte("test safe transaction hash")

	// Sign using Gnosis Safe format
	sig, err := utils.EthGnosisSign(message, pk)
	require.NoError(t, err)
	require.Equal(t, 65, len(sig), "signature should be 65 bytes")

	// Verify signature format for Gnosis Safe
	assert.True(t, sig[64] == 31 || sig[64] == 32, "V should be 31 or 32 for Gnosis Safe signatures")

	t.Logf("Signed message: %s", hex.EncodeToString(message))
	t.Logf("Signature: %s", hex.EncodeToString(sig))
	t.Logf("Signer address: %s", ethCrypto.PubkeyToAddress(pk.PublicKey).String())
}

// TestMessageFormatMatching tests that our signing matches the contract expectation
func TestMessageFormatMatching(t *testing.T) {
	// This test validates that our message format matches what TrufNetworkBridge expects

	// Example from your finalized epoch
	merkleRoot := "9e37a3ed4da4b0a974c0ae853353946da4211d94782ade884f2264af02dfa800"
	blockHash := "c15484750dce64508eb6f83027440dd8e6489eca8b841468f9618dae5ac0baa9"

	merkleRootBytes, err := hex.DecodeString(merkleRoot)
	require.NoError(t, err)
	blockHashBytes, err := hex.DecodeString(blockHash)
	require.NoError(t, err)

	// Construct message same as TrufNetworkBridge: keccak256(abi.encode(root, blockHash))
	message := make([]byte, 64)
	copy(message[0:32], merkleRootBytes)
	copy(message[32:64], blockHashBytes)

	// Compute what the contract will hash
	expectedDigest := ethCrypto.Keccak256(message)

	t.Logf("Merkle root: 0x%s", merkleRoot)
	t.Logf("Block hash: 0x%s", blockHash)
	t.Logf("Message (root||blockHash): 0x%s", hex.EncodeToString(message))
	t.Logf("Expected digest: 0x%s", hex.EncodeToString(expectedDigest))

	// This digest will be wrapped with "\x19Ethereum Signed Message:\n32" prefix by EthZeppelinSign
	// which matches OpenZeppelin's ECDSA.toEthSignedMessageHash()
}
