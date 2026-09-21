package peers

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/multiformats/go-multiaddr"

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

// dialFail is one address and the reason dialing it failed.
type dialFail struct{ addr, cause string }

// dialErr builds the error swarm returns when every address for a peer failed,
// which is the only shape CompressDialError rewrites.
func dialErr(t *testing.T, skipped int, fails ...dialFail) *swarm.DialError {
	t.Helper()
	dErr := &swarm.DialError{
		Cause:   swarm.ErrAllDialsFailed,
		Skipped: skipped,
	}
	for _, f := range fails {
		addr, err := multiaddr.NewMultiaddr(f.addr)
		if err != nil {
			t.Fatalf("bad fixture address %q: %v", f.addr, err)
		}
		dErr.DialErrors = append(dErr.DialErrors, swarm.TransportError{
			Address: addr,
			Cause:   errors.New(f.cause),
		})
	}
	return dErr
}

func TestCompressDialErrorKeepsCauses(t *testing.T) {
	const (
		refusedAddr  = "/ip4/1.2.3.4/tcp/26656"
		timedOutAddr = "/ip4/5.6.7.8/tcp/26656"
	)

	got := CompressDialError(dialErr(t, 0,
		dialFail{refusedAddr, "connection refused"},
		dialFail{timedOutAddr, "i/o timeout"},
	)).Error()

	// Two addresses that failed for different reasons have to read
	// differently, or the operator cannot tell which fix applies to which.
	for _, want := range []string{
		refusedAddr, "connection refused",
		timedOutAddr, "i/o timeout",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("compressed error lost %q\ngot: %s", want, got)
		}
	}

	// Compressing is the whole reason this function exists: swarm's own
	// Error() spreads the same information over one line per address.
	if strings.Contains(got, "\n") {
		t.Errorf("compressed error must stay on one line, got:\n%s", got)
	}
}

func TestCompressDialErrorReportsSkippedAddresses(t *testing.T) {
	got := CompressDialError(dialErr(t, 7,
		dialFail{"/ip4/1.2.3.4/tcp/26656", "connection refused"},
	)).Error()

	// swarm records at most 16 transport errors and counts the rest. Printing
	// the ones it kept without saying how many it dropped understates how
	// broadly the dial failed.
	if !strings.Contains(got, "and 7 more") {
		t.Errorf("compressed error hides the 7 skipped addresses, got: %s", got)
	}
}

func TestCompressDialErrorStaysMatchable(t *testing.T) {
	// Callers test the result against swarm's sentinel, so rewriting the
	// message must not rewrite the error's identity.
	got := CompressDialError(dialErr(t, 0,
		dialFail{"/ip4/1.2.3.4/tcp/26656", "connection refused"},
	))

	if !errors.Is(got, swarm.ErrAllDialsFailed) {
		t.Errorf("compressed error no longer matches swarm.ErrAllDialsFailed: %v", got)
	}
}

func TestCompressDialErrorPassesOtherErrorsThrough(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"not a dial error", errors.New("context deadline exceeded")},
		{"dial error from another cause", &swarm.DialError{Cause: errors.New("no addresses")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompressDialError(tt.err); got != tt.err {
				t.Errorf("CompressDialError(%v) = %v, want it returned unchanged", tt.err, got)
			}
		})
	}
}

func TestCompressDialErrorFlattensAMultiLineCause(t *testing.T) {
	addr, err := multiaddr.NewMultiaddr("/ip4/1.2.3.4/tcp/26656")
	if err != nil {
		t.Fatalf("bad fixture address: %v", err)
	}

	// errors.Join renders one error per line, so a transport that reports its
	// attempts as a joined error hands back a cause that would split the
	// compressed form over several lines.
	got := CompressDialError(&swarm.DialError{
		Cause: swarm.ErrAllDialsFailed,
		DialErrors: []swarm.TransportError{{
			Address: addr,
			Cause: errors.Join(
				errors.New("connection refused"),
				errors.New("i/o timeout"),
			),
		}},
	}).Error()

	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("compressed error broke onto more than one line: %q", got)
	}

	// Flattening has to keep the two causes apart. Deleting the break instead
	// of replacing it would also pass a no-newline check, while running them
	// together into one unreadable string.
	const want = "connection refused; i/o timeout"
	if !strings.Contains(got, want) {
		t.Errorf("joined causes should stay separated as %q\ngot: %s", want, got)
	}
}
