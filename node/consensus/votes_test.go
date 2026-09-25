package consensus

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

func TestVerifyVotesRejectsRepeatedSigner(t *testing.T) {
	ce, keys := testEngineWithValidators(t, 4)
	blkID := types.Hash{1}
	appHash := types.Hash{2}

	sig, err := ktypes.SignVote(blkID, true, &appHash, keys[0])
	require.NoError(t, err)
	vote := &ktypes.VoteInfo{AckStatus: ktypes.AckAgree, Signature: *sig}

	err = ce.verifyVotes(&ktypes.CommitInfo{
		AppHash: appHash,
		Votes:   []*ktypes.VoteInfo{vote, vote, vote},
	}, blkID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate vote")

	votes := make([]*ktypes.VoteInfo, 3)
	for i := range votes {
		sig, err := ktypes.SignVote(blkID, true, &appHash, keys[i])
		require.NoError(t, err)
		votes[i] = &ktypes.VoteInfo{AckStatus: ktypes.AckAgree, Signature: *sig}
	}
	require.NoError(t, ce.verifyVotes(&ktypes.CommitInfo{AppHash: appHash, Votes: votes}, blkID))
}

func TestAddVoteRejectsRepeatedSigner(t *testing.T) {
	ce, keys := testEngineWithValidators(t, 4)
	blkID := types.Hash{1}
	appHash := types.Hash{2}

	leaderSig, err := ktypes.SignVote(blkID, true, &appHash, keys[0])
	require.NoError(t, err)
	leaderPub := keys[0].Public()
	ce.state.votes[string(leaderPub.Bytes())] = &ktypes.VoteInfo{
		AckStatus: ktypes.AckAgree,
		Signature: *leaderSig,
	}
	ce.state.blkProp = &blockProposal{height: 1, blkHash: blkID}
	ce.state.blockRes = &blockResult{appHash: appHash}
	ce.state.lc = &lastCommit{}

	// Same signature, but the map key is the hex sender rather than the raw pubkey.
	err = ce.addVote(context.Background(), &vote{msg: &types.AckRes{
		Height:    1,
		ACK:       true,
		BlkHash:   blkID,
		AppHash:   &appHash,
		Signature: leaderSig,
	}}, hex.EncodeToString(leaderPub.Bytes()))
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate vote")
	require.Len(t, ce.state.votes, 1)

	otherSig, err := ktypes.SignVote(blkID, true, &appHash, keys[1])
	require.NoError(t, err)
	otherPub := keys[1].Public().Bytes()
	err = ce.addVote(context.Background(), &vote{msg: &types.AckRes{
		Height:    1,
		ACK:       true,
		BlkHash:   blkID,
		AppHash:   &appHash,
		Signature: otherSig,
	}}, hex.EncodeToString(keys[2].Public().Bytes()))
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match sender")

	err = ce.addVote(context.Background(), &vote{msg: &types.AckRes{
		Height:    1,
		ACK:       true,
		BlkHash:   blkID,
		AppHash:   &appHash,
		Signature: otherSig,
	}}, hex.EncodeToString(otherPub))
	require.NoError(t, err)
	require.Len(t, ce.state.votes, 2)

	// Same signer under another map key must not become the third ack.
	ce.state.votes["duplicate"] = ce.state.votes[hex.EncodeToString(otherPub)]

	ce.processVotes(context.Background())
	require.Len(t, ce.state.votes, 3)
	require.Nil(t, ce.state.commitInfo)
}

func TestProcessVotesSkipsSignatureRecheck(t *testing.T) {
	ce, keys := testEngineWithValidators(t, 4)
	ce.haltChan = make(chan string, 1)
	blkID := types.Hash{1}
	appHash := types.Hash{2}
	ce.state.blkProp = &blockProposal{height: 1, blkHash: blkID}
	ce.state.blockRes = &blockResult{appHash: appHash}
	ce.state.lc = &lastCommit{}

	stranger, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	strangerPub := stranger.Public()
	ce.state.votes["stranger"] = &ktypes.VoteInfo{
		AckStatus: ktypes.AckReject,
		Signature: ktypes.Signature{
			PubKey:     strangerPub.Bytes(),
			PubKeyType: strangerPub.Type(),
			Data:       []byte("not-a-signature"),
		},
	}
	pub0 := keys[0].Public()
	ce.state.votes["wrong-key-type"] = &ktypes.VoteInfo{
		AckStatus: ktypes.AckReject,
		Signature: ktypes.Signature{
			PubKey:     pub0.Bytes(),
			PubKeyType: crypto.KeyTypeEd25519,
			Data:       []byte("not-a-signature"),
		},
	}
	ce.state.votes[hex.EncodeToString(pub0.Bytes())] = &ktypes.VoteInfo{
		AckStatus: ktypes.AckReject,
		Signature: ktypes.Signature{
			PubKey:     pub0.Bytes(),
			PubKeyType: pub0.Type(),
			Data:       []byte("not-a-signature"),
		},
	}
	ce.state.votes["duplicate"] = ce.state.votes[hex.EncodeToString(pub0.Bytes())]
	ce.processVotes(context.Background())
	require.Empty(t, ce.haltChan)

	pub1 := keys[1].Public()
	ce.state.votes[hex.EncodeToString(pub1.Bytes())] = &ktypes.VoteInfo{
		AckStatus: ktypes.AckReject,
		Signature: ktypes.Signature{
			PubKey:     pub1.Bytes(),
			PubKeyType: pub1.Type(),
			Data:       []byte("not-a-signature"),
		},
	}

	ce.processVotes(context.Background())
	select {
	case reason := <-ce.haltChan:
		require.Contains(t, reason, "nacks")
	default:
		t.Fatal("expected halt from votes already accepted by addVote")
	}
}

func TestVerifyVotesStillChecksSignature(t *testing.T) {
	ce, keys := testEngineWithValidators(t, 1)
	pub := keys[0].Public()
	err := ce.verifyVotes(&ktypes.CommitInfo{
		AppHash: types.Hash{2},
		Votes: []*ktypes.VoteInfo{{
			AckStatus: ktypes.AckAgree,
			Signature: ktypes.Signature{
				PubKey:     pub.Bytes(),
				PubKeyType: pub.Type(),
				Data:       []byte("not-a-signature"),
			},
		}},
	}, types.Hash{1})
	require.Error(t, err)
	require.Contains(t, err.Error(), "verifying vote")
}

func testEngineWithValidators(t *testing.T, n int) (*ConsensusEngine, []crypto.PrivateKey) {
	t.Helper()
	keys := make([]crypto.PrivateKey, n)
	ce := &ConsensusEngine{
		log:          log.DiscardLogger,
		validatorSet: make(map[string]ktypes.Validator, n),
		state:        state{votes: make(map[string]*ktypes.VoteInfo)},
	}
	for i := range n {
		priv, pub, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)
		keys[i] = priv
		ce.validatorSet[hex.EncodeToString(pub.Bytes())] = ktypes.Validator{
			AccountID: ktypes.AccountID{
				Identifier: pub.Bytes(),
				KeyType:    pub.Type(),
			},
			Power: 1,
		}
	}
	return ce, keys
}
