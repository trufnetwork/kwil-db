package peers

import (
	"encoding/hex"
	"testing"

	"github.com/trufnetwork/kwil-db/core/crypto"
)

func TestPeerIDPubKeyRoundTrip(t *testing.T) {
	tests := []struct {
		name           string
		pubKeyHex      string
		pubKeyType     crypto.KeyType
		expectedPeerID string
		// wantErr        bool
	}{
		{
			name:           "valid secp pubkey",
			pubKeyHex:      "0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd",
			pubKeyType:     crypto.KeyTypeSecp256k1,
			expectedPeerID: "16Uiu2HAkx2kfP117VnYnaQGprgXBoMpjfxGXCpizju3cX7ZUzRhv",
		},
		{
			name:           "valid ed25519 pubkey",
			pubKeyHex:      "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
			pubKeyType:     crypto.KeyTypeEd25519,
			expectedPeerID: "12D3KooWK99VoVxNE7XzyBwXEzW7xhK7Gpv85r9F3V3fyKSUKPH5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKeyBytes, err := hex.DecodeString(tt.pubKeyHex)
			if err != nil {
				t.Fatalf("failed to decode pubkey hex: %v", err)
			}

			var pubKey crypto.PublicKey

			switch tt.pubKeyType {
			case crypto.KeyTypeSecp256k1:
				pubKey, err = crypto.UnmarshalSecp256k1PublicKey(pubKeyBytes)
			case crypto.KeyTypeEd25519:
				pubKey, err = crypto.UnmarshalEd25519PublicKey(pubKeyBytes)
			default:
				t.Fatalf("unsupported pubkey type: %v", tt.pubKeyType)
			}

			if err != nil {
				t.Fatalf("failed to unmarshal pubkey: %v", err)
			}

			peerID, err := PeerIDFromPubKey(pubKey)
			if err != nil {
				t.Errorf("PeerIDFromPubKey() error = %v", err)
				return
			}

			if peerID.String() != tt.expectedPeerID {
				t.Errorf("PeerIDFromPubKey() = %v, want %v", peerID, tt.expectedPeerID)
			}

			// Test round trip back to PubKeyFromPeerID
			recoveredPubKey, err := PubKeyFromPeerID(peerID.String())
			if err != nil {
				t.Errorf("PubKeyFromPeerID() error = %v", err)
				return
			}
			if !recoveredPubKey.Equals(pubKey) {
				t.Errorf("PubKeyFromPeerID() = %x, want %x", recoveredPubKey.Bytes(), pubKeyBytes)
			}

		})
	}
}
