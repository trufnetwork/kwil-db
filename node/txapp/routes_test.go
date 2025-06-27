package txapp

import (
	"encoding/hex"
	"testing"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"

	"context"

	"math/big"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testType = "test"

func init() {
	err := resolutions.RegisterResolution(testType, resolutions.ModAdd, resolutions.ResolutionConfig{})
	if err != nil {
		panic(err)
	}
}

var (
	privKey1, signer1 = getSigner("81487a6b7bd63f77da1d09758bf657448425c398bbbb63b8a304f0551c182703")
	privKey2, signer2 = getSigner("24ee0732c3f9d7ff2b45def78260968bbdf2d977675e968bcbcf98726c2bddd2")
)

type getVoterPowerFunc func() (int64, error)

func Test_Routes(t *testing.T) {

	// in this testcase we handle the router in a callback, so that
	// we can have scoped data in our mock implementations
	type testcase struct {
		name          string
		fn            func(t *testing.T, callback func()) // required, uses callback to control when the test is run
		payload       types.Payload                       // required
		fee           int64                               // optional, if nil, will automatically use 0
		ctx           *common.TxContext                   // optional, if nil, will automatically create a mock
		from          auth.Signer                         // optional, if nil, will automatically use default validatorSigner1
		getVoterPower getVoterPowerFunc
		err           error // if not nil, expect this error
	}

	// due to the relative simplicity of routes and pricing, I have only tested a few complex ones.
	// as routes / pricing becomes more complex, we should add more tests here.

	testCases := []testcase{
		{
			// this test tests vote_id, as a local validator
			// we expect that it will approve and then attempt to delete the event
			name: "validator_vote_id, as local validator",
			fee:  voting.ValidatorVoteIDPrice,
			getVoterPower: func() (int64, error) {
				return 1, nil
			},
			fn: func(t *testing.T, callback func()) {
				approveCount := 0
				deleteCount := 0

				// override the functions with mocks
				deleteEvent = func(ctx context.Context, db sql.Executor, id *types.UUID) error {
					deleteCount++

					return nil
				}

				approveResolution = func(ctx context.Context, db sql.TxMaker, resolutionID *types.UUID, from []byte, keyType crypto.KeyType) error {
					approveCount++

					return nil
				}

				callback()

				assert.Equal(t, 1, approveCount)
				assert.Equal(t, 1, deleteCount)
			},
			payload: &types.ValidatorVoteIDs{
				ResolutionIDs: []*types.UUID{
					types.NewUUIDV5([]byte("test")),
				},
			},
			from: signer1,
		},
		{
			// this test tests vote_id, as a non-local validator
			// we expect that it will approve and not attempt to delete the event
			name: "validator_vote_id, as non-local validator",
			fee:  voting.ValidatorVoteIDPrice,
			getVoterPower: func() (int64, error) {
				return 1, nil
			},
			fn: func(t *testing.T, callback func()) {
				approveCount := 0
				deleteCount := 0

				// override the functions with mocks
				deleteEvent = func(ctx context.Context, db sql.Executor, id *types.UUID) error {
					deleteCount++

					return nil
				}
				approveResolution = func(_ context.Context, _ sql.TxMaker, _ *types.UUID, _ []byte, _ crypto.KeyType) error {
					approveCount++

					return nil
				}
				callback()

				assert.Equal(t, 1, approveCount)
				assert.Equal(t, 0, deleteCount)
			},
			payload: &types.ValidatorVoteIDs{
				ResolutionIDs: []*types.UUID{
					types.NewUUIDV5([]byte("test")),
				},
			},
			from: signer2,
		},
		{
			// this test tests vote_id, from a non-validator
			// we expect that it will fail
			name: "validator_vote_id, as non-validator",
			fee:  voting.ValidatorVoteIDPrice,
			getVoterPower: func() (int64, error) {
				return 0, nil
			},
			fn: func(t *testing.T, callback func()) {
				callback()
			},
			payload: &types.ValidatorVoteIDs{
				ResolutionIDs: []*types.UUID{
					types.NewUUIDV5([]byte("test")),
				},
			},
			err:  ErrCallerNotValidator,
			from: signer1,
		},
		{
			// testing validator_vote_bodies, as the proposer
			name: "validator_vote_bodies, as proposer",
			fee:  voting.ValidatorVoteIDPrice,
			getVoterPower: func() (int64, error) {
				return 1, nil
			},
			fn: func(t *testing.T, callback func()) {
				deleteCount := 0

				// override the functions with mocks
				deleteEvent = func(ctx context.Context, db sql.Executor, id *types.UUID) error {
					deleteCount++

					return nil
				}
				createResolution = func(_ context.Context, _ sql.TxMaker, _ *types.VotableEvent, _ int64, _ []byte, _ crypto.KeyType) error {
					return nil
				}

				callback()
				assert.Equal(t, 1, deleteCount)
			},
			payload: &types.ValidatorVoteBodies{
				Events: []*types.VotableEvent{
					{
						Type: testType,
						Body: []byte("asdfadsf"),
					},
				},
			},
			ctx: &common.TxContext{
				BlockContext: &common.BlockContext{
					Proposer: privKey1.Public(),
				},
			},
			from: signer1,
		},
		{
			// testing validator_vote_bodies, as a non-proposer
			// should fail
			name: "validator_vote_bodies, as non-proposer",
			fee:  voting.ValidatorVoteIDPrice,
			getVoterPower: func() (int64, error) {
				return 0, nil
			},
			fn: func(t *testing.T, callback func()) {
				deleteCount := 0

				deleteEvent = func(_ context.Context, _ sql.Executor, _ *types.UUID) error {
					deleteCount++

					return nil
				}

				callback()
				assert.Equal(t, 0, deleteCount) // 0, since this does not go through
			},
			payload: &types.ValidatorVoteBodies{
				Events: []*types.VotableEvent{
					{
						Type: testType,
						Body: []byte("asdfadsf"),
					},
				},
			},
			ctx: &common.TxContext{
				BlockContext: &common.BlockContext{
					Proposer: privKey2.Public(),
				},
			},
			from: signer2,
			err:  ErrCallerNotProposer,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// mock getAccount, which is func declared in interfaces.go
			account := &mockAccount{}
			Validators := &mockValidator{
				getVoterFn: tc.getVoterPower,
			}

			// build tx
			tx, err := types.CreateTransaction(tc.payload, "chainid", 1)
			require.NoError(t, err)

			tx.Body.Fee = big.NewInt(0)
			if tc.fee != 0 {
				tx.Body.Fee = big.NewInt(tc.fee)
			}

			err = tx.Sign(tc.from)
			require.NoError(t, err)

			if tc.fn == nil {
				require.Fail(t, "no callback provided")
			}

			tc.fn(t, func() {
				db := &mockTx{&mockDb{}}
				app := &TxApp{
					Accounts:   account,
					Validators: Validators,
				}

				if app.signer == nil {
					app.signer = signer1
				}

				if app.service == nil {
					app.service = &common.Service{
						Logger:   log.DiscardLogger,
						Identity: app.signer.CompactID(),
					}
				}

				if tc.ctx == nil {
					tc.ctx = &common.TxContext{}
				}

				tc.ctx.BlockContext = &common.BlockContext{
					ChainContext: &common.ChainContext{
						NetworkParameters: &types.NetworkParameters{
							DisabledGasCosts: false,
						},
					},
					Proposer: privKey1.Public(),
				}

				res := app.Execute(tc.ctx, db, tx)
				if tc.err != nil {
					require.ErrorIs(t, res.Error, tc.err)
				} else {
					require.NoError(t, res.Error)
				}
			})
		})
	}
}

type mockAccount struct {
}

func (a *mockAccount) GetAccount(_ context.Context, _ sql.Executor, acctID *types.AccountID) (*types.Account, error) {
	return &types.Account{
		ID:      acctID,
		Balance: big.NewInt(0),
		Nonce:   0,
	}, nil
}

func (a *mockAccount) NumAccounts(ctx context.Context, tx sql.Executor) (int64, error) {
	return 1, nil
}

func (a *mockAccount) Spend(_ context.Context, _ sql.Executor, acctID *types.AccountID, amount *big.Int, nonce int64) error {
	return nil
}

func (a *mockAccount) Credit(_ context.Context, _ sql.Executor, acctID *types.AccountID, amount *big.Int) error {
	return nil
}

func (a *mockAccount) Transfer(_ context.Context, _ sql.TxMaker, from, to *types.AccountID, amount *big.Int) error {
	return nil
}

func (a *mockAccount) ApplySpend(_ context.Context, _ sql.Executor, acctID *types.AccountID, amount *big.Int, nonce int64) error {
	return nil
}
func (a *mockAccount) Commit() error {
	return nil
}

func (a *mockAccount) Rollback() {}

type mockValidator struct {
	getVoterFn getVoterPowerFunc
}

func (v *mockValidator) GetValidators() []*types.Validator {
	return nil
}

func (v *mockValidator) GetValidatorPower(_ context.Context, pubKey []byte, pubKeyType crypto.KeyType) (int64, error) {
	return v.getVoterFn()
}

func (v *mockValidator) SetValidatorPower(_ context.Context, _ sql.Executor, pubKey []byte, keyType crypto.KeyType, power int64) error {
	return nil
}

func (v *mockValidator) Commit() error {
	return nil
}

func (v *mockValidator) Rollback() {}

func getSigner(hexPrivKey string) (crypto.PrivateKey, auth.Signer) {
	bts, err := hex.DecodeString(hexPrivKey)
	if err != nil {
		panic(err)
	}
	pk, err := crypto.UnmarshalSecp256k1PrivateKey(bts)
	if err != nil {
		panic(err)
	}

	return pk, auth.GetNodeSigner(pk)
}
