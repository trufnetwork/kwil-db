package node

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/signprofiles"
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

// Sign signs a message hash for a validator operation. It performs two checks:
// an authorization check (validatePurpose — is this key allowed to sign this
// kind of thing?) and a format lookup (signprofiles.ForPurpose — which on-wire
// encoding does the verifier expect?). The two must agree; the signprofiles
// package's round-trip property test enforces that Format and Verify inside
// each profile are mutually consistent, so as long as the profile exists this
// Sign will produce a signature that the verifier accepts.
//
// Background: the 2026-04-24 eth_usdc incident was a Format↔Verify mismatch
// hardcoded directly in this function. The fix is to keep this function
// dumb — defer format policy to signprofiles. See
// 0MainnetPredictionMarket/8BridgeSignaturePlan-2026-04-24.md.
func (v *validatorSignerImpl) Sign(ctx context.Context, messageHash []byte, purpose string) ([]byte, error) {
	if err := v.validatePurpose(purpose); err != nil {
		return nil, err
	}

	profile, err := signprofiles.ForPurpose(purpose)
	if err != nil {
		// Unreachable in practice: validatePurpose above rejects anything the
		// profile registry doesn't know. Kept as a defense-in-depth backstop
		// so a future purpose added to validatePurpose without a profile
		// registration fails loudly at the first Sign call.
		return nil, fmt.Errorf("validator signing: %w", err)
	}

	v.logger.Debugf("validator signing: purpose=%s profile=%s messageHash=%x",
		purpose, profile.Name, messageHash)

	// Only secp256k1 keys are supported for Ethereum-compatible signing.
	secp256k1Key, ok := v.privKey.(*kwilcrypto.Secp256k1PrivateKey)
	if !ok {
		return nil, fmt.Errorf("validator signing requires secp256k1 key, but node uses %T", v.privKey)
	}

	ecdsaKey, err := crypto.ToECDSA(secp256k1Key.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to convert validator key to ECDSA: %w", err)
	}

	rawSig, err := crypto.Sign(messageHash, ecdsaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	return profile.Format(rawSig), nil
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

// validatePurpose checks if the signing purpose is allowed. The allowed set
// comes from common.AllValidatorPurposes() — the same list the signprofiles
// coverage test iterates, so authz and registry cannot drift apart silently.
func (v *validatorSignerImpl) validatePurpose(purpose string) error {
	for _, allowed := range common.AllValidatorPurposes() {
		if purpose == allowed {
			return nil
		}
	}
	return fmt.Errorf("unauthorized signing purpose: %s", purpose)
}
