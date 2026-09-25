package consensus

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
)

// signedBy is commit info carrying an agreeing vote from each of keys for the
// block blkID names.
func signedBy(t *testing.T, blkID, appHash ktypes.Hash, keys ...crypto.PrivateKey) *ktypes.CommitInfo {
	t.Helper()
	ci := &ktypes.CommitInfo{AppHash: appHash}
	for _, key := range keys {
		sig, err := ktypes.SignVote(blkID, true, &appHash, key)
		require.NoError(t, err)
		ci.Votes = append(ci.Votes, &ktypes.VoteInfo{AckStatus: ktypes.AckAgree, Signature: *sig})
	}
	return ci
}

func newKey(t *testing.T) crypto.PrivateKey {
	t.Helper()
	priv, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	return priv
}

func testTxn(nonce uint64) *ktypes.Transaction {
	return &ktypes.Transaction{
		Body: &ktypes.TransactionBody{
			PayloadType: "test",
			Payload:     []byte("payload"),
			Fee:         big.NewInt(1),
			Nonce:       nonce,
		},
		Signature: &auth.Signature{Data: []byte("signature"), Type: "secp256k1"},
		Sender:    []byte("sender"),
	}
}

// committedEngine is an engine at height 1 whose validators are keys.
func committedEngine(keys ...crypto.PrivateKey) *ConsensusEngine {
	ce := &ConsensusEngine{validatorSet: make(map[string]ktypes.Validator)}
	for _, key := range keys {
		ce.validatorSet[hex.EncodeToString(key.Public().Bytes())] = ktypes.Validator{Power: 1}
	}
	ce.state.lc = &lastCommit{height: 1}
	return ce
}

func testBlock(height int64, txns ...*ktypes.Transaction) *ktypes.Block {
	return ktypes.NewBlock(height, ktypes.Hash{1}, ktypes.Hash{2}, ktypes.Hash{3}, ktypes.Hash{4},
		time.Unix(1729723553+height, 0), txns)
}

// TestDecodeCommittedTakesTheBlockTheValidatorsCommitted checks that a block
// comes through the check whole when it is the one a majority of validators
// signed at the next height.
func TestDecodeCommittedTakesTheBlockTheValidatorsCommitted(t *testing.T) {
	v1, v2, v3 := newKey(t), newKey(t), newKey(t)
	ce := committedEngine(v1, v2, v3)
	blk := testBlock(2, testTxn(1), testTxn(2))
	appHash := ktypes.Hash{9}

	got, err := ce.decodeCommitted(ktypes.EncodeBlock(blk), signedBy(t, blk.Hash(), appHash, v1, v2), blk.Hash())
	require.NoError(t, err)
	require.Equal(t, blk.Hash(), got.Hash())
	require.Len(t, got.Txns, 2)
}

// TestDecodeCommittedRejectsWhatTheValidatorsDidNotCommit checks, one way at a
// time, that a block which is not the one the validators committed at the
// next height is marked as that, and so is fetched again, not applied.
func TestDecodeCommittedRejectsWhatTheValidatorsDidNotCommit(t *testing.T) {
	v1, v2, v3, outsider := newKey(t), newKey(t), newKey(t), newKey(t)
	ce := committedEngine(v1, v2, v3)
	appHash := ktypes.Hash{9}
	blk := testBlock(2, testTxn(1), testTxn(2))
	raw := ktypes.EncodeBlock(blk)
	signed := signedBy(t, blk.Hash(), appHash, v1, v2)

	// The same header over other transactions: same hash, same votes.
	swapped := testBlock(2, testTxn(1), testTxn(2))
	swapped.Txns[1] = testTxn(3)
	// The same header, one transaction short.
	short := testBlock(2, testTxn(1), testTxn(2))
	short.Txns = short.Txns[:1]
	other := testBlock(2, testTxn(7))
	next := testBlock(3, testTxn(1))

	for _, tc := range []struct {
		name  string
		raw   []byte
		ci    *ktypes.CommitInfo
		blkID ktypes.Hash
	}{
		{"not a block", []byte("not a block"), signed, blk.Hash()},
		{"no commit info", raw, nil, blk.Hash()},
		{"another height", ktypes.EncodeBlock(next), signedBy(t, next.Hash(), appHash, v1, v2), next.Hash()},
		{"under another block's hash and votes", ktypes.EncodeBlock(other), signed, blk.Hash()},
		{"transactions its header does not list", ktypes.EncodeBlock(swapped), signed, blk.Hash()},
		{"fewer transactions than its header says", ktypes.EncodeBlock(short), signed, blk.Hash()},
		{"no votes", raw, signedBy(t, blk.Hash(), appHash), blk.Hash()},
		{"one vote of three", raw, signedBy(t, blk.Hash(), appHash, v1), blk.Hash()},
		{"a vote from someone not a validator", raw, signedBy(t, blk.Hash(), appHash, v1, v2, outsider), blk.Hash()},
		{"votes for another app hash", raw, func() *ktypes.CommitInfo {
			ci := signedBy(t, blk.Hash(), appHash, v1, v2)
			ci.AppHash = ktypes.Hash{8}
			return ci
		}(), blk.Hash()},
		{"parameter updates that cannot apply", raw, func() *ktypes.CommitInfo {
			ci := signedBy(t, blk.Hash(), appHash, v1, v2)
			ci.ParamUpdates = ktypes.ParamUpdates{ktypes.ParamNameMaxBlockSize: "large"}
			return ci
		}(), blk.Hash()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ce.decodeCommitted(tc.raw, tc.ci, tc.blkID)
			require.ErrorIs(t, err, errUncommittedBlock)
			require.Nil(t, got)
		})
	}
}
