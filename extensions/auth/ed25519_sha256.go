package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
)

const (
	// Ed25519Sha256Auth is the authenticator name
	// the "nr" suffix is for NEAR, and provides backwards compatibility
	Ed25519Sha256Auth = "ed25519_nr"

	// ed25519SignatureLength is the expected length of an ed25519 signature
	ed25519SignatureLength = 64
)

// Ed22519Sha256Authenticator is an authenticator that applies the sha256 hash to the message
// before verifying the signature. This is a common standard in ecosystems like NEAR.
type Ed22519Sha256Authenticator struct{}

var _ auth.Authenticator = Ed22519Sha256Authenticator{}

// Identifier returns the hex-encoded public key as the identifier.
// The input must be a 32-byte ed25519 public key.
func (e Ed22519Sha256Authenticator) Identifier(publicKey []byte) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid ed25519 public key size for generating near address: %d", len(publicKey))
	}

	return hex.EncodeToString(publicKey), nil
}

// Verify verifies the signature against the given public key and data.
func (e Ed22519Sha256Authenticator) Verify(publicKey []byte, msg []byte, signature []byte) error {
	pubkey, err := crypto.UnmarshalEd25519PublicKey(publicKey)
	if err != nil {
		return err
	}

	if len(signature) != ed25519SignatureLength {
		return fmt.Errorf("invalid signature length: expected %d, received %d", ed25519SignatureLength, len(signature))
	}

	hash := sha256.Sum256(msg)

	valid, err := pubkey.Verify(hash[:], signature)
	if err != nil {
		return err
	}

	if !valid {
		return crypto.ErrInvalidSignature
	}

	return nil
}

func (e Ed22519Sha256Authenticator) KeyType() crypto.KeyType {
	return crypto.KeyTypeEd25519
}
