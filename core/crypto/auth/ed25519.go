package auth

// ed25519 is a standard signature scheme that uses the ed25519 curve

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/trufnetwork/kwil-db/core/crypto"
)

const (
	// Ed25519Auth is a plain ed25519 authenticator. This is intended as the authenticator for the
	// SDK-provided Ed25519Signer, and must be registered with that name.
	Ed25519Auth = "ed25519"

	// ed25519SignatureLength is the expected length of a signature
	ed25519SignatureLength = 64
)

// Ed25519Authenticator is an authenticator for ed25519 keys.
type Ed25519Authenticator struct{}

var _ Authenticator = Ed25519Authenticator{}

// Address simply returns the hexadecimal encoded public key as the address.
func (e Ed25519Authenticator) Identifier(publicKey []byte) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid ed25519 public key size: %d", len(publicKey))
	}

	return hex.EncodeToString(publicKey), nil
}

// Verify verifies the signature against the given user identifier and data. The
// identifier must be the ed25519 public key bytes.
func (e Ed25519Authenticator) Verify(publicKey []byte, msg []byte, signature []byte) error {
	pubkey, err := crypto.UnmarshalEd25519PublicKey(publicKey)
	if err != nil {
		return err
	}

	if len(signature) != ed25519SignatureLength {
		return fmt.Errorf("invalid signature length: expected %d, received %d", ed25519SignatureLength, len(signature))
	}

	valid, err := pubkey.Verify(msg, signature)
	if err != nil {
		return err
	}

	if !valid {
		return crypto.ErrInvalidSignature
	}

	return nil
}

func (e Ed25519Authenticator) KeyType() crypto.KeyType {
	return crypto.KeyTypeEd25519
}
