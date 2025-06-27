package blockprocessor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/txapp"
	nodetypes "github.com/trufnetwork/kwil-db/node/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

/*func marshalTx(t *testing.T, tx *types.Transaction) []byte {
	b, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("could not marshal transaction! %v", err)
	}
	return b
}*/

func cloneTx(tx *types.Transaction) *types.Transaction {
	sig := make([]byte, len(tx.Signature.Data))
	copy(sig, tx.Signature.Data)
	sender := make([]byte, len(tx.Sender))
	copy(sender, tx.Sender)
	body := *tx.Body // same nonce
	body.Fee = big.NewInt(0).Set(tx.Body.Fee)
	body.Payload = make([]byte, len(tx.Body.Payload))
	copy(body.Payload, tx.Body.Payload)
	return &types.Transaction{
		Signature: &auth.Signature{
			Data: sig,
			Type: tx.Signature.Type,
		},
		Body:          &body,
		Serialization: tx.Serialization,
		Sender:        sender,
	}
}

// genEd25519Key generates a deterministic ed25519 key
func genEd25519Key(seed []byte) crypto.PrivateKey {
	// seed must be 32 bytes
	hash := sha256.Sum256(seed)
	privKey, _, err := crypto.GenerateEd25519Key(bytes.NewBuffer(hash[:]))
	if err != nil {
		panic(err)
	}
	return privKey
}

// edPubKey generates a deterministic ed25519 public key
func edPubKey(seed []byte) []byte {
	privKey := genEd25519Key(seed)
	return privKey.Public().Bytes()
}

func TestPrepareMempoolTxns(t *testing.T) {
	// To make these tests deterministic, we manually craft certain misorderings
	// and the known expected orderings. Also include some malformed
	// transactions that fail to unmarshal, which really shouldn't happen if the
	// initial check passed but there is graceful handling of this in the code.

	// tA is the template transaction. Several fields may not be nil because of
	// a legacy RLP issue where objects may be encoded that cannot be decoded.

	chainCtx := &common.ChainContext{
		ChainID: "test",
		NetworkParameters: &types.NetworkParameters{
			MaxBlockSize:     6 * 1024 * 1024,
			MaxVotesPerTx:    100,
			DisabledGasCosts: true,
		},
	}

	_, signer := genNodeKeyAndSigner(t)
	bp := &BlockProcessor{
		db:       &mockDB{},
		log:      log.DiscardLogger,
		signer:   signer,
		chainCtx: chainCtx,
		txapp:    &mockTxApp{},
	}

	tA := &types.Transaction{
		Signature: &auth.Signature{
			Data: []byte{},
			Type: auth.Ed25519Auth,
		},
		Body: &types.TransactionBody{
			Description: "t",
			Payload:     []byte(`x`),
			Fee:         big.NewInt(900),
			Nonce:       0,
		},
		Sender: edPubKey([]byte(`guy`)),
	}
	// tAb := marshalTx(t, tA)

	// same sender, incremented nonce
	tB := cloneTx(tA)
	tB.Body.Nonce++
	// tBb := marshalTx(t, tB)

	nextTx := func(tx *types.Transaction) *types.Transaction {
		tx2 := cloneTx(tx)
		tx2.Body.Nonce++
		return tx2
	}

	// second party
	tOtherSenderA := cloneTx(tA)
	tOtherSenderA.Sender = edPubKey([]byte(`otherguy`))
	// tOtherSenderAb := marshalTx(t, tOtherSenderA)

	// Same nonce tx, different body (diff bytes)
	tOtherSenderAbDup := cloneTx(tOtherSenderA)
	tOtherSenderAbDup.Body.Description = "dup" // not "t"
	// tOtherSenderAbDupb := marshalTx(t, tOtherSenderAbDup)

	tOtherSenderB := nextTx(tOtherSenderA)
	// tOtherSenderBb := marshalTx(t, tOtherSenderB)

	tOtherSenderC := nextTx(tOtherSenderB)
	// tOtherSenderCb := marshalTx(t, tOtherSenderC)

	// proposer party
	tProposer := cloneTx(tA)
	tProposer.Sender = bp.signer.CompactID()
	tProposer.Signature.Type = bp.signer.AuthType()
	// tProposerb := marshalTx(t, tProposer)

	zeroFeeTx := cloneTx(tA)
	zeroFeeTx.Body.Fee = &big.Int{}

	tests := []struct {
		name string
		txs  []*types.Transaction
		want []*types.Transaction
		gas  bool
	}{
		{
			"empty",
			[]*types.Transaction{},
			[]*types.Transaction{},
			false,
		},
		{
			"one and only low gas",
			[]*types.Transaction{zeroFeeTx},
			[]*types.Transaction{},
			true,
		},
		{
			"one valid",
			[]*types.Transaction{tA},
			[]*types.Transaction{tA},
			false,
		},
		{
			"two valid",
			[]*types.Transaction{tA, tB},
			[]*types.Transaction{tA, tB},
			false,
		},
		{
			"two valid misordered",
			[]*types.Transaction{tB, tA},
			[]*types.Transaction{tA, tB},
			false,
		},
		{
			"multi-party, one misordered, stable",
			[]*types.Transaction{tOtherSenderA, tB, tOtherSenderB, tA},
			[]*types.Transaction{tOtherSenderA, tA, tOtherSenderB, tB},
			false,
		},
		{
			"multi-party, one misordered, one dup nonce, stable",
			[]*types.Transaction{tOtherSenderA, tOtherSenderAbDup, tB, tA},
			[]*types.Transaction{tOtherSenderA, tA, tB},
			false,
		},
		{
			"multi-party, both misordered, stable",
			[]*types.Transaction{tOtherSenderB, tB, tOtherSenderA, tA},
			[]*types.Transaction{tOtherSenderA, tA, tOtherSenderB, tB},
			false,
		},
		{
			"multi-party, both misordered, alt. stable",
			[]*types.Transaction{tB, tOtherSenderB, tOtherSenderA, tA},
			[]*types.Transaction{tA, tOtherSenderA, tOtherSenderB, tB},
			false,
		},
		// { // can't mix fee...
		// 	"multi-party, big, with invalid in middle",
		// 	[]*types.Transaction{tOtherSenderC, tB, zeroFeeTx, tOtherSenderB, tOtherSenderA, tA},
		// 	[]*types.Transaction{tOtherSenderA, tA, tOtherSenderB, tOtherSenderC, tB},
		// 	true,
		// },
		{
			"multi-party, big, already correct",
			[]*types.Transaction{tOtherSenderA, tA, tOtherSenderB, tOtherSenderC, tB},
			[]*types.Transaction{tOtherSenderA, tA, tOtherSenderB, tOtherSenderC, tB},
			false,
		},
		{
			"multi-party,proposer in the last, reorder",
			[]*types.Transaction{tOtherSenderA, tA, tOtherSenderB, tOtherSenderC, tB, tProposer},
			[]*types.Transaction{tProposer, tOtherSenderA, tA, tOtherSenderB, tOtherSenderC, tB},
			false,
		},
		{
			"multi-party,proposer in the middle, reorder",
			[]*types.Transaction{tOtherSenderA, tA, tOtherSenderB, tProposer, tOtherSenderC, tB},
			[]*types.Transaction{tProposer, tOtherSenderA, tA, tOtherSenderB, tOtherSenderC, tB},
			false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getEvents = func(_ context.Context, _ sql.Executor) ([]*types.VotableEvent, error) {
				return nil, nil
			}

			chainCtx.NetworkParameters.DisabledGasCosts = !tt.gas

			ntxs := make([]*nodetypes.Tx, len(tt.txs))
			for i, tx := range tt.txs {
				ntxs[i] = nodetypes.NewTx(tx)
			}

			readTx, err := bp.db.BeginReadTx(ctx)
			require.NoError(t, err)

			got, invalids, err := bp.prepareBlockTransactions(ctx, readTx, ntxs)
			require.NoError(t, err)

			if len(got) != len(tt.want) {
				t.Errorf("got %d txns, expected %d", len(got), len(tt.want))
			}

			require.Equal(t, len(invalids), len(tt.txs)-len(got))

			for i, txi := range got {
				gotHash := txi.Hash()
				wantHash := tt.want[i].Hash()
				require.Equal(t, gotHash, wantHash)
			}
		})
	}
}

var (
	evt1 = &types.VotableEvent{
		Type: "test",
		Body: []byte("test"),
	}
	evt2 = &types.VotableEvent{
		Type: "test",
		Body: []byte("test2"),
	}
	evt3 = &types.VotableEvent{
		Type: "test",
		Body: []byte("test3"),
	}
)

func genNodeKeyAndSigner(t *testing.T) (crypto.PrivateKey, auth.Signer) {
	nodePrivKey, err := crypto.GeneratePrivateKey(crypto.KeyTypeSecp256k1)
	require.NoError(t, err)

	nodeSigner := auth.GetNodeSigner(nodePrivKey)
	require.NotNil(t, nodeSigner)

	return nodePrivKey, nodeSigner
}

func TestPrepareVoteIDTx(t *testing.T) {
	leaderPrivKey, leaderSigner := genNodeKeyAndSigner(t)
	leaderPubKey := leaderPrivKey.Public()
	valPriv, valSigner := genNodeKeyAndSigner(t)
	_, sentrySigner := genNodeKeyAndSigner(t)
	valSet := []*types.Validator{
		{
			AccountID: types.AccountID{
				Identifier: valPriv.Public().Bytes(),
				KeyType:    crypto.KeyTypeSecp256k1,
			},
			Power: 1,
		},
		{
			AccountID: types.AccountID{
				Identifier: leaderPrivKey.Public().Bytes(),
				KeyType:    crypto.KeyTypeSecp256k1,
			},
			Power: 1,
		},
	}
	genCfg := config.DefaultGenesisConfig()
	genCfg.Leader = types.PublicKey{PublicKey: leaderPubKey}

	netParams := genCfg.NetworkParameters.Clone()
	bp := &BlockProcessor{
		db:     &mockDB{},
		log:    log.DiscardLogger,
		signer: leaderSigner,
		chainCtx: &common.ChainContext{
			ChainID:           "test",
			NetworkParameters: netParams,
		},
		txapp:         &mockTxApp{},
		genesisParams: genCfg,
	}

	testcases := []struct {
		name    string
		signer  auth.Signer
		events  []*types.VotableEvent
		cleanup func()
		fn      func(*testing.T, context.Context, *BlockProcessor, sql.DB, *mockEventStore) error
	}{
		{
			name:   "no voteIDs to broadcast",
			events: []*types.VotableEvent{}, // no events
			signer: valSigner,
			fn: func(t *testing.T, ctx context.Context, bp *BlockProcessor, db sql.DB, es *mockEventStore) error {
				bp.signer = valSigner
				tx, ids, err := bp.PrepareValidatorVoteIDTx(ctx, db)
				require.NoError(t, err)
				require.Nil(t, tx)
				require.Nil(t, ids)
				return nil
			},
		},
		{
			name:   "leader not allowed to broadcast voteIDs",
			events: []*types.VotableEvent{evt1, evt2},
			signer: leaderSigner,
			fn: func(t *testing.T, ctx context.Context, bp *BlockProcessor, db sql.DB, es *mockEventStore) error {
				tx, ids, err := bp.PrepareValidatorVoteIDTx(ctx, db)
				require.NoError(t, err)
				require.Nil(t, tx)
				require.Nil(t, ids)
				return nil
			},
		},
		{
			name:   "sentry node not allowed to broadcast voteIDs",
			events: []*types.VotableEvent{evt1, evt2},
			signer: sentrySigner,
			fn: func(t *testing.T, ctx context.Context, bp *BlockProcessor, db sql.DB, es *mockEventStore) error {
				tx, ids, err := bp.PrepareValidatorVoteIDTx(ctx, db)
				require.NoError(t, err)
				require.Nil(t, tx)
				require.Nil(t, ids)
				return nil
			},
		},
		{
			name:   "validator broadcasts voteIDs in gasless mode",
			signer: valSigner,
			events: []*types.VotableEvent{evt1, evt2},
			fn: func(t *testing.T, ctx context.Context, bp *BlockProcessor, db sql.DB, es *mockEventStore) error {
				tx, ids, err := bp.PrepareValidatorVoteIDTx(ctx, db)
				require.NoError(t, err)
				require.NotNil(t, tx)
				require.NotNil(t, ids)
				require.Len(t, ids, 2)
				return nil
			},
		},
		{
			name:   "insufficient gas to broadcast voteIDs",
			signer: valSigner,
			events: []*types.VotableEvent{evt1, evt2},
			fn: func(t *testing.T, ctx context.Context, bp *BlockProcessor, db sql.DB, es *mockEventStore) error {
				bp.chainCtx.NetworkParameters.DisabledGasCosts = false
				// set price of tx high: 1000
				price = big.NewInt(1000)
				tx, ids, err := bp.PrepareValidatorVoteIDTx(ctx, db)

				require.NoError(t, err)
				require.Nil(t, tx)
				require.Nil(t, ids)
				return nil
			},
			cleanup: func() {
				price = big.NewInt(0)
				bp.chainCtx.NetworkParameters.DisabledGasCosts = true
			},
		},
		{
			name:   "validator has sufficient gas to broadcast voteIDs",
			signer: valSigner,
			events: []*types.VotableEvent{evt1, evt2},
			fn: func(t *testing.T, ctx context.Context, bp *BlockProcessor, db sql.DB, es *mockEventStore) error {
				bp.chainCtx.NetworkParameters.DisabledGasCosts = false
				// set price of tx low: 1
				price = big.NewInt(1000)
				accountBalance = big.NewInt(1000)
				tx, ids, err := bp.PrepareValidatorVoteIDTx(ctx, db)

				require.NoError(t, err)
				require.NotNil(t, tx)
				require.NotNil(t, ids)
				require.Len(t, ids, 2)
				return nil
			},
			cleanup: func() {
				price = big.NewInt(0)
				accountBalance = big.NewInt(0)
				bp.chainCtx.NetworkParameters.DisabledGasCosts = true
			},
		},
		{
			name:   "mark broadcasted for broadcasted voteIDs",
			signer: valSigner,
			events: []*types.VotableEvent{evt1, evt2},
			fn: func(t *testing.T, ctx context.Context, bp *BlockProcessor, db sql.DB, es *mockEventStore) error {
				tx, ids, err := bp.PrepareValidatorVoteIDTx(ctx, db)
				require.NoError(t, err)
				require.NotNil(t, tx)
				require.NotNil(t, ids)
				require.Len(t, ids, 2)

				err = bp.events.MarkBroadcasted(ctx, ids)
				require.NoError(t, err)

				// now no more events to broadcast
				tx, ids, err = bp.PrepareValidatorVoteIDTx(ctx, db)
				require.NoError(t, err)
				require.Nil(t, tx)
				require.Nil(t, ids)

				// add more events
				es.addEvent(evt3)
				tx, ids, err = bp.PrepareValidatorVoteIDTx(ctx, db)
				require.NoError(t, err)
				require.NotNil(t, tx)
				require.NotNil(t, ids)
				require.Len(t, ids, 1)

				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if tc.cleanup != nil {
					tc.cleanup()
				}
			}()

			db := &mockDB{}
			bp.signer = tc.signer
			es := newMockEventStore(tc.events)
			bp.events = es
			bp.validators = newValidatorStore(valSet)

			ctx := context.Background()
			err := tc.fn(t, ctx, bp, db, es) // run the test function
			require.NoError(t, err)
		})
	}
}

func TestPrepareVoteBodyTx(t *testing.T) {
	privKey, signer := genNodeKeyAndSigner(t)
	pubKey := privKey.Public()
	genCfg := config.DefaultGenesisConfig()
	genCfg.Leader = types.PublicKey{PublicKey: pubKey}

	bp := &BlockProcessor{
		db:     &mockDB{},
		log:    log.DiscardLogger,
		signer: signer,
		chainCtx: &common.ChainContext{
			ChainID: "test",
			NetworkParameters: &types.NetworkParameters{
				MaxBlockSize:     6 * 1024 * 1024,
				MaxVotesPerTx:    100,
				DisabledGasCosts: true,
				// No Leader!
			},
		},
		txapp:         &mockTxApp{},
		genesisParams: genCfg,
	}

	readTx, err := bp.db.BeginReservedReadTx(context.Background())
	require.NoError(t, err)

	testcases := []struct {
		name    string
		events  []*types.VotableEvent
		cleanup func()
		fn      func(context.Context, *BlockProcessor, *mockEventStore) error
	}{
		{
			name:   "No events to broadcast(gasless mode)",
			events: []*types.VotableEvent{},
			fn: func(ctx context.Context, bp *BlockProcessor, es *mockEventStore) error {
				tx, err := bp.prepareValidatorVoteBodyTx(ctx, readTx, 1, bp.chainCtx.NetworkParameters.MaxBlockSize)
				require.NoError(t, err)
				require.Nil(t, tx)

				return nil
			},
		},
		{
			name:   "No events to broadcast (gas mode)",
			events: []*types.VotableEvent{},
			cleanup: func() {
				bp.chainCtx.NetworkParameters.DisabledGasCosts = true
			},
			fn: func(ctx context.Context, bp *BlockProcessor, es *mockEventStore) error {
				bp.chainCtx.NetworkParameters.DisabledGasCosts = false

				tx, err := bp.prepareValidatorVoteBodyTx(ctx, readTx, 1, bp.chainCtx.NetworkParameters.MaxBlockSize)
				require.NoError(t, err)
				require.Nil(t, tx)

				return nil
			},
		},
		{
			name:   "atleast 1 event to broadcast",
			events: []*types.VotableEvent{evt1, evt2},
			fn: func(ctx context.Context, bp *BlockProcessor, es *mockEventStore) error {
				tx, err := bp.prepareValidatorVoteBodyTx(ctx, readTx, 1, bp.chainCtx.NetworkParameters.MaxBlockSize)
				require.NoError(t, err)
				require.NotNil(t, tx)

				var payload = &types.ValidatorVoteBodies{}
				err = payload.UnmarshalBinary(tx.Body.Payload)
				require.NoError(t, err)

				require.Len(t, payload.Events, 2)
				return nil
			},
		},
		{
			name:   "enforce maxVotesPerTx limit",
			events: []*types.VotableEvent{evt1, evt2, evt3},
			fn: func(ctx context.Context, bp *BlockProcessor, es *mockEventStore) error {
				bp.chainCtx.NetworkParameters.MaxVotesPerTx = 1

				tx, err := bp.prepareValidatorVoteBodyTx(ctx, readTx, 1, bp.chainCtx.NetworkParameters.MaxBlockSize)
				require.NoError(t, err)
				require.NotNil(t, tx)

				var payload = &types.ValidatorVoteBodies{}
				err = payload.UnmarshalBinary(tx.Body.Payload)
				require.NoError(t, err)

				require.Len(t, payload.Events, 1)
				return nil
			},
			cleanup: func() {
				bp.chainCtx.NetworkParameters.MaxVotesPerTx = 100
			},
		},
		{
			name:   "enforce maxSizePerTx limit",
			events: []*types.VotableEvent{evt1, evt2, evt3},
			fn: func(ctx context.Context, bp *BlockProcessor, es *mockEventStore) error {

				emptyTxSize, err := bp.emptyVoteBodyTxSize()
				require.NoError(t, err)

				// support evt1
				txSize := emptyTxSize + int64(len(evt1.Body)+len(evt1.Type)+8)
				bp.chainCtx.NetworkParameters.MaxBlockSize = txSize + 10 /* buffer */

				tx, err := bp.prepareValidatorVoteBodyTx(ctx, readTx, 1, bp.chainCtx.NetworkParameters.MaxBlockSize)
				require.NoError(t, err)
				require.NotNil(t, tx)

				var payload = &types.ValidatorVoteBodies{}
				err = payload.UnmarshalBinary(tx.Body.Payload)
				require.NoError(t, err)

				require.Len(t, payload.Events, 1)
				return nil

			},
			cleanup: func() {
				bp.chainCtx.NetworkParameters.MaxBlockSize = 6 * 1024 * 1024
			},
		},
		{
			name:   "insufficient funds",
			events: []*types.VotableEvent{evt1, evt2},
			fn: func(ctx context.Context, bp *BlockProcessor, es *mockEventStore) error {
				bp.chainCtx.NetworkParameters.DisabledGasCosts = false
				accountBalance = big.NewInt(0)
				price = big.NewInt(1000)

				tx, err := bp.prepareValidatorVoteBodyTx(ctx, readTx, 1, bp.chainCtx.NetworkParameters.MaxBlockSize)
				require.NoError(t, err)
				require.Nil(t, tx)

				return nil
			},
			cleanup: func() {
				bp.chainCtx.NetworkParameters.DisabledGasCosts = true
			},
		},
		{
			name:   "have sufficient funds",
			events: []*types.VotableEvent{evt1, evt2},
			fn: func(ctx context.Context, bp *BlockProcessor, es *mockEventStore) error {
				bp.chainCtx.NetworkParameters.DisabledGasCosts = false
				accountBalance = big.NewInt(1000)
				price = big.NewInt(1000)

				tx, err := bp.prepareValidatorVoteBodyTx(ctx, readTx, 1, bp.chainCtx.NetworkParameters.MaxBlockSize)
				require.NoError(t, err)
				require.NotNil(t, tx)

				var payload = &types.ValidatorVoteBodies{}
				err = payload.UnmarshalBinary(tx.Body.Payload)
				require.NoError(t, err)

				require.Len(t, payload.Events, 2)
				return nil
			},
			cleanup: func() {
				bp.chainCtx.NetworkParameters.DisabledGasCosts = true
				accountBalance = big.NewInt(0)
				price = big.NewInt(0)
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// cleanup
			defer func() {
				if tc.cleanup != nil {
					tc.cleanup()
				}
			}()

			es := newMockEventStore(tc.events)
			bp.events = es

			getEvents = func(_ context.Context, _ sql.Executor) ([]*types.VotableEvent, error) {
				return es.getEvents(), nil
			}

			if tc.fn != nil {
				tc.fn(context.Background(), bp, es)
			}
		})
	}

}

type mockTxApp struct{}

var accountBalance = big.NewInt(0)

func (m *mockTxApp) AccountInfo(ctx context.Context, db sql.DB, acctID *types.AccountID, getUncommitted bool) (balance *big.Int, nonce int64, err error) {
	return accountBalance, 0, nil
}

func (a *mockTxApp) NumAccounts(ctx context.Context, tx sql.Executor) (int64, int64, error) {
	return 1, 1, nil
}

func (m *mockTxApp) ApplyMempool(ctx *common.TxContext, db sql.DB, tx *types.Transaction) error {
	return nil
}

func (m *mockTxApp) Begin(ctx context.Context, height int64) error {
	return nil
}

func (m *mockTxApp) Commit() error {
	return nil
}

func (m *mockTxApp) Rollback() {}

func (m *mockTxApp) Execute(ctx *common.TxContext, db sql.DB, tx *types.Transaction) *txapp.TxResponse {
	return nil
}

func (m *mockTxApp) Finalize(ctx context.Context, db sql.DB, block *common.BlockContext) (aJ, eJ []*types.AccountID, err error) {
	return nil, nil, nil
}

func (m *mockTxApp) GenesisInit(ctx context.Context, db sql.DB, _ *config.GenesisConfig, chain *common.ChainContext) error {
	return nil
}

func (m *mockTxApp) GetValidators(ctx context.Context, db sql.DB) ([]*types.Validator, error) {
	return nil, nil
}

func (m *mockTxApp) ProposerTxs(ctx context.Context, db sql.DB, txNonce uint64, maxTxSz int64, block *common.BlockContext) ([]*types.Transaction, error) {
	return nil, nil
}

func (m *mockTxApp) UpdateValidator(ctx context.Context, db sql.DB, pubKey []byte, pubKeyType crypto.KeyType, power int64) error {
	return nil
}

func (m *mockTxApp) Reload(ctx context.Context, db sql.DB) error {
	return nil
}

var price = big.NewInt(0)

func (m *mockTxApp) Price(ctx context.Context, db sql.DB, tx *types.Transaction, c *common.ChainContext) (*big.Int, error) {
	return price, nil
}

type mockDB struct{}

func (m *mockDB) BeginDelayedReadTx() sql.OuterReadTx {
	return &mockTx{}
}

func (m *mockDB) BeginPreparedTx(ctx context.Context) (sql.PreparedTx, error) {
	return &mockTx{}, nil
}

func (m *mockDB) BeginReadTx(ctx context.Context) (sql.OuterReadTx, error) {
	return &mockTx{}, nil
}

func (m *mockDB) BeginSnapshotTx(ctx context.Context) (sql.Tx, string, error) {
	return &mockTx{}, "", nil
}

func (m *mockDB) BeginReservedReadTx(ctx context.Context) (sql.Tx, error) {
	return &mockTx{}, nil
}

func (m *mockDB) Execute(ctx context.Context, stmt string, args ...any) (*sql.ResultSet, error) {
	return nil, nil
}

func (m *mockDB) BeginTx(ctx context.Context) (sql.Tx, error) {
	return &mockTx{}, nil
}

func (m *mockDB) AutoCommit(on bool) {}

type mockTx struct{}

func (m *mockTx) Subscribe(ctx context.Context) (<-chan string, func(context.Context) error, error) {
	return make(<-chan string), func(ctx context.Context) error { return nil }, nil
}

func (m *mockTx) Rollback(ctx context.Context) error {
	return nil
}

func (m *mockTx) Commit(ctx context.Context) error {
	return nil
}

func (m *mockTx) Execute(ctx context.Context, stmt string, args ...any) (*sql.ResultSet, error) {
	return nil, nil
}

func (m *mockTx) BeginTx(ctx context.Context) (sql.Tx, error) {
	return &mockTx{}, nil
}

func (m *mockTx) Precommit(ctx context.Context, changes chan<- any) ([]byte, error) {
	return nil, nil
}

type event struct {
	evt         *types.VotableEvent
	broadcasted bool
}

type mockEventStore struct {
	events map[string]event
}

func newMockEventStore(events []*types.VotableEvent) *mockEventStore {
	es := &mockEventStore{events: make(map[string]event)}
	for _, e := range events {
		es.events[e.ID().String()] = event{evt: e, broadcasted: false}
	}
	return es
}

func (m *mockEventStore) addEvent(evt *types.VotableEvent) {
	m.events[evt.ID().String()] = event{evt: evt, broadcasted: false}
}

func (m *mockEventStore) getEvents() []*types.VotableEvent {
	var events []*types.VotableEvent
	for _, e := range m.events {
		events = append(events, e.evt)
	}
	return events
}
func (m *mockEventStore) GetUnbroadcastedEvents(ctx context.Context) ([]*types.UUID, error) {
	var ids []*types.UUID
	for _, e := range m.events {
		if !e.broadcasted {
			ids = append(ids, e.evt.ID())
		}
	}
	return ids, nil
}

func (m *mockEventStore) MarkBroadcasted(ctx context.Context, ids []*types.UUID) error {
	for _, id := range ids {
		if e, ok := m.events[id.String()]; ok {
			e.broadcasted = true
			m.events[id.String()] = e
		}
	}
	return nil
}

func (m *mockEventStore) HasEvents() bool {
	return true
}

func (m *mockEventStore) UpdateStats(cnt int64) {
}

type mockValidatorStore struct {
	valSet []*types.Validator
}

func newValidatorStore(valSet []*types.Validator) *mockValidatorStore {
	return &mockValidatorStore{
		valSet: valSet,
	}
}

func (v *mockValidatorStore) GetValidators() []*types.Validator {
	return v.valSet
}

func (v *mockValidatorStore) ValidatorUpdates() map[string]*types.Validator {
	return nil
}

func (v *mockValidatorStore) LoadValidatorSet(ctx context.Context, db sql.Executor) error {
	return nil
}
