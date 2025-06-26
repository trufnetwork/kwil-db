package auth

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"golang.org/x/crypto/sha3"
)

const (
	// EthPersonalSignAuth is the Ethereum "personal sign" authentication type,
	// which uses the secp256k1 signature scheme with a prefixed message and the
	// legacy 256-bit Keccak hash function to mimic most Ethereum wallets. This
	// is intended as the authenticator for the SDK-provided EthPersonalSigner,
	// and must be registered with that name.
	EthPersonalSignAuth = "secp256k1_ep"

	EthAddressIdentLength = 20
)

// EthSecp256k1Authenticator is the authenticator for the Ethereum "personal
// sign" signature type, which is the default signer for Kwil. As such, it is a
// default authenticator.
type EthSecp256k1Authenticator struct{}

var _ Authenticator = EthSecp256k1Authenticator{}

// Identifier returns an ethereum address hex string from address bytes.
// It will include the 0x prefix, and the address will be checksum-able.
func (EthSecp256k1Authenticator) Identifier(ident []byte) (string, error) {
	if len(ident) != 20 {
		return "", fmt.Errorf("invalid eth address with %d bytes", len(ident))
	}
	return eip55ChecksumAddr([20]byte(ident)), nil
}

// eip55ChecksumAddr converts an ethereum address to a EIP55-compliant hex
// string representation of the address.
func eip55ChecksumAddr(addr [20]byte) string {
	var buf [42]byte
	copy(buf[:2], "0x")
	hex.Encode(buf[2:], addr[:])

	// https://eips.ethereum.org/EIPS/eip-55
	sha := sha3.NewLegacyKeccak256()
	sha.Write(buf[2:])
	hash := sha.Sum(nil)
	for i := 2; i < len(buf); i++ {
		hashByte := hash[(i-2)/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0x0f
		}
		if buf[i] > '9' && hashByte > 7 {
			buf[i] -= 32
		}
	}
	return string(buf[:])
}

// Verify verifies applies the Ethereum TextHash digest and verifies the signature
func (EthSecp256k1Authenticator) Verify(identity []byte, msg []byte, signature []byte) error {
	// signature is 65 bytes, [R || S || V] format
	if len(signature) != crypto.Secp256k1SignatureLength {
		return fmt.Errorf("invalid signature length: expected %d, received %d",
			crypto.Secp256k1SignatureLength, len(signature))
	}

	if signature[crypto.RecoveryIDOffset] == 27 ||
		signature[crypto.RecoveryIDOffset] == 28 {
		// Transform yellow paper V from 27/28 to 0/1
		signature = slices.Clone(signature)
		signature[crypto.RecoveryIDOffset] -= 27
	}

	hash := textHash(msg)
	pubkey, err := crypto.RecoverSecp256k1KeyFromSigHash(hash, signature)
	if err != nil {
		return err
	}

	addr := crypto.EthereumAddressFromPubKey(pubkey)

	if !bytes.Equal(addr, identity) {
		return fmt.Errorf("invalid signature: expected address %x, received %x", identity, addr)
	}

	return nil
}

func (EthSecp256k1Authenticator) KeyType() crypto.KeyType {
	return crypto.KeyTypeSecp256k1 // just like the Secp256k1Authenticator
}
