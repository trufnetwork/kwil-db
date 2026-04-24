// Package signprofiles pairs each signing purpose with both the on-wire
// signature format and the real verifier that format will meet. The package
// exists to make sign↔verify drift — the shape of the 2026-04-24 eth_usdc
// incident, where validator votes were signed V=31/32 but verified as V=27/28
// — impossible to introduce silently. See
// 0MainnetPredictionMarket/8BridgeSignaturePlan-2026-04-24.md for context.
//
// Adding a new signing purpose requires registering a SigningProfile that
// carries both Format and Verify. The round-trip property test in this
// package then automatically exercises Verify(Format(crypto.Sign(...))),
// which fails if the two sides are mismatched. There is no way to ship a new
// purpose that silently drifts.
package signprofiles

import (
	"fmt"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
)

// SigningProfile pairs a signature formatter with the verifier the signature
// will ultimately reach. The package's round-trip property test asserts
//
//	profile.Verify(profile.Format(crypto.Sign(...)), digest, addr) == nil
//
// for every registered profile, so Format and Verify cannot drift apart
// without CI going red.
type SigningProfile struct {
	Name string

	// Format adjusts a raw ECDSA signature (V ∈ {0, 1}, as returned by
	// crypto.Sign) into whatever final on-wire encoding Verify expects.
	// Mutates raw in place and returns it for chaining.
	Format func(raw []byte) []byte

	// Verify is the *actual* verifier the signature will meet at runtime —
	// a direct reference to the production function, not a Go reimplementation.
	// Holding the real function is what makes the round-trip test meaningful;
	// a reimplementation can drift from the real verifier and mask bugs.
	Verify func(sig, digest, addr []byte) error
}

// EpochVote is the profile for validator votes on ERC20 reward epochs.
// Verified inside the voteEpoch Kuneiform action by utils.EthStandardVerifyDigest
// (OpenZeppelin ECDSA.recover-compatible, V=27/28).
var EpochVote = &SigningProfile{
	Name:   "epoch_vote",
	Format: addToV(27),
	Verify: utils.EthStandardVerifyDigest,
}

// Withdrawal is the profile for bridge withdrawal-claim signatures, verified
// on-chain by the bridge's OpenZeppelin-compatible ECDSA.recover (V=27/28).
var Withdrawal = &SigningProfile{
	Name:   "withdrawal",
	Format: addToV(27),
	Verify: utils.EthStandardVerifyDigest,
}

// SafePrevalidated is the profile for signatures consumed by a Gnosis Safe's
// checkNSignatures in pre-validated form (V=31/32, EIP-191).
var SafePrevalidated = &SigningProfile{
	Name:   "safe_prevalidated",
	Format: addToV(31),
	Verify: utils.EthGnosisVerifyDigest,
}

// byPurpose is the single source of truth mapping ValidatorSigner purpose
// constants to signing profiles. The alternative — in-signer switch
// statements or inline sig[64]+=N literals — is the shape that let the
// eth_usdc bug in.
var byPurpose = map[string]*SigningProfile{
	common.PurposeEpochVoting:       EpochVote,
	common.PurposeWithdrawalSig:     Withdrawal,
	common.PurposeGnosisSafeSigning: SafePrevalidated,
}

// ForPurpose returns the profile registered for purpose, or an error if none
// is registered. A missing profile means validatePurpose and the profile
// registry have drifted — always a programming error.
func ForPurpose(purpose string) (*SigningProfile, error) {
	p, ok := byPurpose[purpose]
	if !ok {
		return nil, fmt.Errorf("no signing profile registered for purpose: %q", purpose)
	}
	return p, nil
}

// All returns every registered profile, used by the round-trip property test
// and by any tooling that enumerates signing formats. The returned slice is a
// fresh copy; callers may append without affecting the registry.
func All() []*SigningProfile {
	out := make([]*SigningProfile, 0, len(byPurpose))
	for _, p := range byPurpose {
		out = append(out, p)
	}
	return out
}

// addToV builds a Format closure that adds c to the V byte of a 65-byte
// ECDSA signature. Non-65-byte inputs pass through unchanged so Format never
// panics on malformed input — callers should have length-checked already.
func addToV(c byte) func([]byte) []byte {
	return func(raw []byte) []byte {
		if len(raw) == 65 {
			raw[64] += c
		}
		return raw
	}
}
