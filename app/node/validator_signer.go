package node

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
)

// Allowed signing purposes for validator operations
const (
	PurposeEpochVoting       = "epoch_voting"
	PurposeWithdrawalSig     = "withdrawal_signature"
	PurposeGnosisSafeSigning = "gnosis_safe_signing"
)

// validatorSignerImpl implements common.ValidatorSigner interface.
// It provides controlled access to validator signing operations without
// exposing the raw private key to extensions.
type validatorSignerImpl struct {
	privKey  kwilcrypto.PrivateKey
	identity []byte
	logger   log.Logger
}

var _ common.ValidatorSigner = (*validatorSignerImpl)(nil)

// NewValidatorSigner creates a new ValidatorSigner implementation.
// Returns nil if privKey is nil (for read-only nodes).
func NewValidatorSigner(privKey kwilcrypto.PrivateKey, identity []byte, logger log.Logger) common.ValidatorSigner {
	if privKey == nil {
		return nil
	}
	if logger == nil {
		logger = log.DiscardLogger
	}
	return &validatorSignerImpl{
		privKey:  privKey,
		identity: identity,
		logger:   logger,
	}
}

// Sign signs a message hash for validator operations.
// The purpose parameter identifies the operation type and is validated.
func (v *validatorSignerImpl) Sign(ctx context.Context, messageHash []byte, purpose string) ([]byte, error) {
	// Validate purpose
	if err := v.validatePurpose(purpose); err != nil {
		return nil, err
	}

	// Log the signing operation for audit trail
	v.logger.Debugf("validator signing operation: purpose=%s, messageHash=%x", purpose, messageHash)

	// Only secp256k1 keys are supported for Ethereum-compatible signing
	secp256k1Key, ok := v.privKey.(*kwilcrypto.Secp256k1PrivateKey)
	if !ok {
		return nil, fmt.Errorf("validator signing requires secp256k1 key, but node uses %T", v.privKey)
	}

	// Convert to ECDSA private key for Ethereum-compatible signing
	privKeyBytes := secp256k1Key.Bytes()
	ecdsaKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert validator key to ECDSA: %w", err)
	}

	// Sign based on purpose
	switch purpose {
	case PurposeEpochVoting, PurposeWithdrawalSig:
		// Use Gnosis Safe EIP-191 compatible signature format
		return signGnosisSafeDigest(messageHash, ecdsaKey)
	case PurposeGnosisSafeSigning:
		// Use Gnosis Safe signature format
		return signGnosisSafeDigest(messageHash, ecdsaKey)
	default:
		// Should not reach here due to validatePurpose, but handle defensively
		return nil, fmt.Errorf("unsupported signing purpose: %s", purpose)
	}
}

// Identity returns the validator's public key bytes.
func (v *validatorSignerImpl) Identity() []byte {
	return v.identity
}

// EthereumAddress returns the Ethereum address derived from the validator's public key.
func (v *validatorSignerImpl) EthereumAddress() ([]byte, error) {
	secp256k1Key, ok := v.privKey.(*kwilcrypto.Secp256k1PrivateKey)
	if !ok {
		return nil, fmt.Errorf("validator key is not secp256k1, got %T", v.privKey)
	}

	// Convert to ECDSA private key to get public key
	privKeyBytes := secp256k1Key.Bytes()
	ecdsaKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to ECDSA: %w", err)
	}

	// Compute Ethereum address from public key
	address := crypto.PubkeyToAddress(ecdsaKey.PublicKey)
	return address.Bytes(), nil
}

// CreateSecp256k1Signer creates a transaction signer for this validator.
// Logs access for audit purposes.
func (v *validatorSignerImpl) CreateSecp256k1Signer() (auth.Signer, error) {
	v.logger.Debugf("creating transaction signer for validator")

	secp256k1Key, ok := v.privKey.(*kwilcrypto.Secp256k1PrivateKey)
	if !ok {
		return nil, fmt.Errorf("validator key is not secp256k1, got %T", v.privKey)
	}

	// Return EthPersonalSigner for transaction signing
	return &auth.EthPersonalSigner{Key: *secp256k1Key}, nil
}

// validatePurpose checks if the signing purpose is allowed.
func (v *validatorSignerImpl) validatePurpose(purpose string) error {
	switch purpose {
	case PurposeEpochVoting, PurposeWithdrawalSig, PurposeGnosisSafeSigning:
		return nil
	default:
		return fmt.Errorf("unauthorized signing purpose: %s", purpose)
	}
}

// signGnosisSafeDigest signs a message digest using Gnosis Safe compatible format.
// Returns a 65-byte signature in [R || S || V] format with V = 31 or 32 (EIP-191 prefixed).
func signGnosisSafeDigest(digest []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Sign the digest
	signature, err := crypto.Sign(digest, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	// Adjust V value for Gnosis Safe compatibility
	// crypto.Sign returns V as 0 or 1, Gnosis Safe expects 31 or 32
	if len(signature) == 65 {
		if signature[64] > 1 {
			return nil, fmt.Errorf("unexpected V value: %d (expected 0 or 1)", signature[64])
		}
		signature[64] += 31
	}

	return signature, nil
}
