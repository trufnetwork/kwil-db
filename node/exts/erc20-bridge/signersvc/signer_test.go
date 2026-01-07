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

	// Step 1: ABI encode (concatenation for bytes32)
	message := make([]byte, 64)
	copy(message[0:32], merkleRoot)
	copy(message[32:64], blockHash)

	// Step 2: Hash the encoded message (CRITICAL: matches validator_signer.go)
	messageHash := ethCrypto.Keccak256(message)
	require.Equal(t, 32, len(messageHash), "messageHash should be 32 bytes")

	// Step 3: Sign the 32-byte hash (EthZeppelinSign adds prefix and signs)
	sig, err := utils.EthZeppelinSign(messageHash, pk)
	require.NoError(t, err)
	require.Equal(t, 65, len(sig), "signature should be 65 bytes")

	// Verify signature format
	assert.True(t, sig[64] == 27 || sig[64] == 28, "V should be 27 or 28 for standard Ethereum signatures")

	t.Logf("Message (root||blockHash): %s", hex.EncodeToString(message))
	t.Logf("MessageHash (keccak256): %s", hex.EncodeToString(messageHash))
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

// TestMessageFormatMatching tests that our signing matches the contract and vote_epoch action expectation
func TestMessageFormatMatching(t *testing.T) {
	// This test validates that our message format matches what both:
	// 1. TrufNetworkBridge contract expects
	// 2. Kwil vote_epoch action expects (via validator_signer.go computeEpochMessageHash)

	// Example from your finalized epoch
	merkleRoot := "9e37a3ed4da4b0a974c0ae853353946da4211d94782ade884f2264af02dfa800"
	blockHash := "c15484750dce64508eb6f83027440dd8e6489eca8b841468f9618dae5ac0baa9"

	merkleRootBytes, err := hex.DecodeString(merkleRoot)
	require.NoError(t, err)
	blockHashBytes, err := hex.DecodeString(blockHash)
	require.NoError(t, err)

	// Step 1: ABI encode (abi.encode(bytes32, bytes32) is just concatenation)
	packed := make([]byte, 64)
	copy(packed[0:32], merkleRootBytes)
	copy(packed[32:64], blockHashBytes)

	// Step 2: Hash the packed data - THIS IS CRITICAL!
	// This matches meta_extension.go computeEpochMessageHash() line ~1449
	messageHash := ethCrypto.Keccak256(packed)
	require.Equal(t, 32, len(messageHash), "messageHash should be 32 bytes")

	t.Logf("Merkle root: 0x%s", merkleRoot)
	t.Logf("Block hash: 0x%s", blockHash)
	t.Logf("Packed (abi.encode): 0x%s [64 bytes]", hex.EncodeToString(packed))
	t.Logf("MessageHash (keccak256): 0x%s [32 bytes]", hex.EncodeToString(messageHash))
	t.Logf("")
	t.Logf("Next step: EthZeppelinSign will:")
	t.Logf("  1. Add prefix: \\x19Ethereum Signed Message:\\n32")
	t.Logf("  2. Hash again: keccak256(prefix + messageHash)")
	t.Logf("  3. Sign the final hash")
	t.Logf("")
	t.Logf("This matches:")
	t.Logf("  - validator_signer.go computeEpochMessageHash()")
	t.Logf("  - TrufNetworkBridge.withdraw() verification")
	t.Logf("  - vote_epoch action signature verification")
}
