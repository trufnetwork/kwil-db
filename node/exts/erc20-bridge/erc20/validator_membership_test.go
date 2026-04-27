//go:build kwiltest

package erc20

import (
	"context"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// mockValidators is a minimal common.Validators implementation. Only
// GetValidators is exercised by the membership helpers; the other methods
// panic so an accidental dependency surfaces immediately.
type mockValidators struct {
	validators []*types.Validator
}

func (m *mockValidators) GetValidators() []*types.Validator { return m.validators }

func (m *mockValidators) GetValidatorPower(context.Context, []byte, kwilcrypto.KeyType) (int64, error) {
	panic("mockValidators.GetValidatorPower not used by these tests")
}

func (m *mockValidators) SetValidatorPower(context.Context, sql.Executor, []byte, kwilcrypto.KeyType, int64) error {
	panic("mockValidators.SetValidatorPower not used by these tests")
}

// mockValidatorSigner is a minimal common.ValidatorSigner that only needs to
// answer Identity() / EthereumAddress() for membership tests. Sign / signer
// creation panic to surface accidental use.
type mockValidatorSigner struct {
	identity []byte
	ethAddr  []byte
}

func (m *mockValidatorSigner) Sign(context.Context, []byte, string) ([]byte, error) {
	panic("mockValidatorSigner.Sign not used by these tests")
}

func (m *mockValidatorSigner) EthereumAddress() ([]byte, error) { return m.ethAddr, nil }

func (m *mockValidatorSigner) CreateSecp256k1Signer() (auth.Signer, error) {
	panic("mockValidatorSigner.CreateSecp256k1Signer not used by these tests")
}

func (m *mockValidatorSigner) Identity() []byte { return m.identity }

// genValidator returns a fresh secp256k1 keypair packaged as a *types.Validator
// plus the derived eth address — exactly the shape app.Validators.GetValidators
// returns at runtime.
func genValidator(t *testing.T, power int64) (*types.Validator, ethcommon.Address, []byte) {
	t.Helper()
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)

	pubBytes := ethcrypto.CompressPubkey(&key.PublicKey)
	v := &types.Validator{
		AccountID: types.AccountID{
			Identifier: pubBytes,
			KeyType:    kwilcrypto.KeyTypeSecp256k1,
		},
		Power: power,
	}
	return v, ethcrypto.PubkeyToAddress(key.PublicKey), pubBytes
}

func newAppWith(validators []*types.Validator, signer common.ValidatorSigner) *common.App {
	return &common.App{
		Service: &common.Service{
			Logger:          log.New(),
			ValidatorSigner: signer,
		},
		Validators: &mockValidators{validators: validators},
	}
}

// TestIsLocalNodeActiveValidator covers the gate that decides whether the
// bridge starts the vote_epoch broadcast loop on this node. Sentries (any node
// whose nodekey isn't in the active validator set) must NOT start the loop —
// this is the regression backstop for the 2026-04-25 sentry-vote pollution.
func TestIsLocalNodeActiveValidator(t *testing.T) {
	leader, _, leaderPub := genValidator(t, 1)
	other, _, _ := genValidator(t, 1)
	_, _, sentryPub := genValidator(t, 1)

	t.Run("local pubkey is in active set", func(t *testing.T) {
		app := newAppWith(
			[]*types.Validator{leader, other},
			&mockValidatorSigner{identity: leaderPub},
		)
		require.True(t, isLocalNodeActiveValidator(app))
	})

	t.Run("sentry pubkey not in active set", func(t *testing.T) {
		app := newAppWith(
			[]*types.Validator{leader, other},
			&mockValidatorSigner{identity: sentryPub},
		)
		require.False(t, isLocalNodeActiveValidator(app))
	})

	t.Run("zero-power validator does not satisfy membership", func(t *testing.T) {
		ghost, _, ghostPub := genValidator(t, 0)
		app := newAppWith(
			[]*types.Validator{leader, ghost},
			&mockValidatorSigner{identity: ghostPub},
		)
		require.False(t, isLocalNodeActiveValidator(app))
	})

	t.Run("non-secp256k1 validator excluded", func(t *testing.T) {
		ed := &types.Validator{
			AccountID: types.AccountID{
				Identifier: leaderPub, // same bytes, but wrong key type
				KeyType:    kwilcrypto.KeyTypeEd25519,
			},
			Power: 1,
		}
		app := newAppWith(
			[]*types.Validator{ed},
			&mockValidatorSigner{identity: leaderPub},
		)
		require.False(t, isLocalNodeActiveValidator(app))
	})

	t.Run("nil ValidatorSigner returns false", func(t *testing.T) {
		app := newAppWith([]*types.Validator{leader}, nil)
		require.False(t, isLocalNodeActiveValidator(app))
	})

	t.Run("nil Validators returns false", func(t *testing.T) {
		app := &common.App{
			Service: &common.Service{
				Logger:          log.New(),
				ValidatorSigner: &mockValidatorSigner{identity: leaderPub},
			},
		}
		require.False(t, isLocalNodeActiveValidator(app))
	})

	t.Run("empty identity returns false", func(t *testing.T) {
		app := newAppWith(
			[]*types.Validator{leader},
			&mockValidatorSigner{identity: nil},
		)
		require.False(t, isLocalNodeActiveValidator(app))
	})
}

// TestIsActiveValidatorAddress covers the defense-in-depth gate inside the
// vote_epoch action handler. The handler builds buildValidatorEthAddressMap
// once per invocation and checks membership with a direct map lookup; this
// test exercises the same lookup against the same helper.
func TestIsActiveValidatorAddress(t *testing.T) {
	isActiveValidatorAddress := func(app *common.App, addr ethcommon.Address) bool {
		_, ok := buildValidatorEthAddressMap(app)[addr]
		return ok
	}

	leader, leaderAddr, _ := genValidator(t, 1)
	other, otherAddr, _ := genValidator(t, 1)
	_, sentryAddr, _ := genValidator(t, 1)

	app := newAppWith([]*types.Validator{leader, other}, nil)

	t.Run("active validator address accepted", func(t *testing.T) {
		require.True(t, isActiveValidatorAddress(app, leaderAddr))
		require.True(t, isActiveValidatorAddress(app, otherAddr))
	})

	t.Run("non-validator address rejected", func(t *testing.T) {
		require.False(t, isActiveValidatorAddress(app, sentryAddr))
	})

	t.Run("zero-power validator rejected", func(t *testing.T) {
		ghost, ghostAddr, _ := genValidator(t, 0)
		app := newAppWith([]*types.Validator{leader, ghost}, nil)
		require.False(t, isActiveValidatorAddress(app, ghostAddr))
	})

	t.Run("nil Validators returns false", func(t *testing.T) {
		app := &common.App{Service: &common.Service{Logger: log.New()}}
		require.False(t, isActiveValidatorAddress(app, leaderAddr))
	})
}

// TestGetValidatorSigner_NonValidatorReturnsNil is the integration backstop
// for the gate: even with a non-nil ValidatorSigner, getValidatorSigner must
// return (nil, nil) on a non-validator node so the caller's `if signer != nil`
// check skips the broadcast goroutine. Without this, sentries broadcast votes
// that the leader stores into epoch_votes — the 2026-04-25 incident shape.
func TestGetValidatorSigner_NonValidatorReturnsNil(t *testing.T) {
	leader, leaderAddr, _ := genValidator(t, 1)
	_, sentryAddr, sentryPub := genValidator(t, 1)

	t.Run("validator gets a signer", func(t *testing.T) {
		app := newAppWith(
			[]*types.Validator{leader},
			&mockValidatorSigner{
				identity: leader.Identifier,
				ethAddr:  leaderAddr.Bytes(),
			},
		)
		signer, err := getValidatorSigner(app, types.NewUUIDV5([]byte("test-instance")))
		require.NoError(t, err)
		require.NotNil(t, signer)
	})

	t.Run("sentry gets nil signer", func(t *testing.T) {
		app := newAppWith(
			[]*types.Validator{leader},
			&mockValidatorSigner{
				identity: sentryPub,
				ethAddr:  sentryAddr.Bytes(),
			},
		)
		signer, err := getValidatorSigner(app, types.NewUUIDV5([]byte("test-instance")))
		require.NoError(t, err)
		require.Nil(t, signer)
	})
}
