package signprofiles_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/signprofiles"
)

// TestAllProfilesRoundTrip is the structural backstop for the sign↔verify
// drift class of bug (2026-04-24 eth_usdc incident: validator votes signed
// V=31/32, verified as V=27/28). It iterates every profile in the registry
// and asserts Verify(Format(crypto.Sign(digest, key)), digest, addr) == nil.
//
// Any profile added to the registry is automatically exercised — no
// test-author diligence required. If CI is green, every registered profile
// has Format and Verify that agree.
func TestAllProfilesRoundTrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	addr := crypto.PubkeyToAddress(key.PublicKey).Bytes()
	digest := crypto.Keccak256([]byte("round-trip property test digest"))

	profiles := signprofiles.All()
	require.NotEmpty(t, profiles, "profile registry is empty — round-trip test is trivially passing")

	for _, profile := range profiles {
		p := profile
		t.Run(p.Name, func(t *testing.T) {
			raw, err := crypto.Sign(digest, key)
			require.NoError(t, err)
			require.Len(t, raw, 65)

			formatted := p.Format(raw)
			require.NoErrorf(t, p.Verify(formatted, digest, addr),
				"profile %q round-trip failed — Format and Verify are mismatched. "+
					"Whoever added or modified this profile paired an incompatible Format with Verify.",
				p.Name)
		})
	}
}

// TestForPurpose_AllKnownPurposesHaveProfiles asserts the authz list and the
// format registry agree. Both sides read common.AllValidatorPurposes, so the
// test verifies every validator-authorized purpose has a registered profile.
// Adding a purpose to the canonical list without registering a profile (or
// vice versa) fails here and points at the specific missing pairing.
func TestForPurpose_AllKnownPurposesHaveProfiles(t *testing.T) {
	for _, purpose := range common.AllValidatorPurposes {
		t.Run(purpose, func(t *testing.T) {
			p, err := signprofiles.ForPurpose(purpose)
			require.NoErrorf(t, err, "purpose %q has no profile in signprofiles.byPurpose", purpose)
			require.NotNil(t, p)
			require.NotEmpty(t, p.Name)
		})
	}
}

func TestForPurpose_UnknownPurposeErrors(t *testing.T) {
	_, err := signprofiles.ForPurpose("not_a_real_purpose")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no signing profile registered")
}
