/*
Package auth contains any known Authenticator extensions that may be selected at
build-time for use in kwild. Authenticator extensions are used to expand the
type of signatures that may be verified, and define address derivation for the
public keys of the corresponding type.

Build constraints a.k.a. build tags are used to enable extensions in a kwild
binary. See README.md in the extensions package for more information.
*/
package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
)

var (
	// ErrAuthenticatorExists is returned when an authenticator is already registered
	ErrAuthenticatorExists = errors.New("authenticator already exists")
	// ErrAuthenticatorNotFound is returned when an authenticator is not found
	ErrAuthenticatorNotFound = errors.New("authenticator not found")
)

// registeredAuthenticators is the Authenticator registry used by kwild.
var registeredAuthenticators = make(map[string]auth.Authenticator)

// ModOperation is the type used to enumerate authenticator modifications.
type ModOperation int8

// Resolutions may be removed, updated, or added.
const (
	ModRemove ModOperation = iota - 1
	ModUpdate
	ModAdd
)

// RegisterAuthenticator registers, removes, or updates an authenticator with
// the Kwil network.
func RegisterAuthenticator(mod ModOperation, name string, auth auth.Authenticator) error {
	name = strings.ToLower(name)
	if _, ok := registeredAuthenticators[name]; ok {
		switch mod {
		case ModAdd:
			return fmt.Errorf("%w: %s", ErrAuthenticatorExists, name)
		case ModRemove:
			delete(registeredAuthenticators, name)
		case ModUpdate:
			registeredAuthenticators[name] = auth
		}
		return nil
	}
	switch mod {
	case ModRemove, ModUpdate:
		return fmt.Errorf("resolution does not exist to modify (%d)", mod)
	default: // add
	}

	registeredAuthenticators[name] = auth

	return nil
}

// getAuthenticator returns an authenticator by the name it was registered with
func GetAuthenticator(name string) (auth.Authenticator, error) {
	name = strings.ToLower(name)
	auth, ok := registeredAuthenticators[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAuthenticatorNotFound, name)
	}

	return auth, nil
}

func init() {
	err := RegisterAuthenticator(ModAdd, auth.Ed25519Auth, auth.Ed25519Authenticator{})
	if err != nil {
		panic(err)
	}

	err = RegisterAuthenticator(ModAdd, auth.EthPersonalSignAuth, auth.EthSecp256k1Authenticator{})
	if err != nil {
		panic(err)
	}

	err = RegisterAuthenticator(ModAdd, auth.Secp256k1Auth, auth.Secp25k1Authenticator{})
	if err != nil {
		panic(err)
	}
}

func IsAuthTypeValid(authType string) bool {
	_, ok := registeredAuthenticators[authType] // case sensistive to avoid tx maleability
	return ok
}

func GetIdentifierFromSigner(signer auth.Signer) (string, error) {
	return GetIdentifier(signer.AuthType(), signer.CompactID())
}

// GetIdentifier returns the identifier for a given sender and authType.
func GetIdentifier(authType string, sender []byte) (string, error) {
	authn, err := GetAuthenticator(authType)
	if err != nil {
		return "", fmt.Errorf("authenticator not found: %s", authType)
	}

	return authn.Identifier(sender)
}

// GetAuthenticatorKeyType returns the crypto.KeyType for a given authType.
func GetAuthenticatorKeyType(authType string) (crypto.KeyType, error) {
	authn, err := GetAuthenticator(authType)
	if err != nil {
		return "", fmt.Errorf("authenticator not found: %s", authType)
	}
	return authn.KeyType(), nil
}

// VerifySignature verifies a message's signature.
func VerifySignature(sender, msg []byte, sig *auth.Signature) error {
	authn, err := GetAuthenticator(sig.Type)
	if err != nil {
		return err
	}

	return authn.Verify(sender, msg, sig.Data)
}
