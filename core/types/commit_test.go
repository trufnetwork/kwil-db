package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
)

func TestSignature(t *testing.T) {
	t.Run("marshal and unmarshal", func(t *testing.T) {
		sig := &Signature{
			Data:       []byte("signature"),
			PubKey:     []byte("public-key"),
			PubKeyType: crypto.KeyTypeSecp256k1,
		}

		var buf bytes.Buffer
		n1, err := sig.WriteTo(&buf)
		require.NoError(t, err)
		// rd := bytes.NewReader(buf.Bytes())

		var unmarshaled Signature
		n2, err := unmarshaled.ReadFrom(&buf)
		require.NoError(t, err)
		require.Equal(t, n1, n2)
		require.Equal(t, *sig, unmarshaled)
	})

	t.Run("empty signature", func(t *testing.T) {
		sig := &Signature{}

		var buf bytes.Buffer
		_, err := sig.WriteTo(&buf)
		require.ErrorContains(t, err, "invalid key type")
	})

	t.Run("invalid signature length", func(t *testing.T) {
		sig := &Signature{
			Data:       []byte("signature"),
			PubKey:     []byte("public-key"),
			PubKeyType: crypto.KeyTypeSecp256k1,
		}

		var buf bytes.Buffer
		n1, err := sig.WriteTo(&buf)
		require.NoError(t, err)
		buf.Truncate(buf.Len() - 1) // Corrupt the data by truncating

		var unmarshaled Signature
		n2, err := unmarshaled.ReadFrom(&buf)
		require.Error(t, err)
		require.NotEqual(t, n1, n2)
	})
}

func TestVoteInfo(t *testing.T) {
	t.Run("marshal and unmarshal", func(t *testing.T) {
		vote := &VoteInfo{
			Signature: Signature{
				Data:       []byte("signature"),
				PubKey:     []byte("public-key"),
				PubKeyType: crypto.KeyTypeSecp256k1,
			},
			AckStatus: AckReject,
		}

		data, err := vote.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled VoteInfo
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, *vote, unmarshaled)
	})

	t.Run("empty vote info", func(t *testing.T) {
		vote := &VoteInfo{}

		_, err := vote.MarshalBinary()
		require.ErrorContains(t, err, "invalid key type")
	})

	t.Run("invalid data length", func(t *testing.T) {
		vote := &VoteInfo{
			Signature: Signature{
				Data:       []byte("signature"),
				PubKey:     []byte("public-key"),
				PubKeyType: crypto.KeyTypeSecp256k1,
			},
			AckStatus: AckReject,
		}
		data, err := vote.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled VoteInfo
		err = unmarshaled.UnmarshalBinary(data[:len(data)-1])
		require.Error(t, err)
	})

	t.Run("short", func(t *testing.T) {
		vote := &VoteInfo{
			Signature: Signature{
				Data:       []byte("signature"),
				PubKey:     []byte("public-key"),
				PubKeyType: crypto.KeyTypeSecp256k1,
			},
			AckStatus: AckReject,
		}

		data, err := vote.MarshalBinary()
		require.NoError(t, err)

		// Corrupt the data by changing the signature length
		data = data[:len(data)-1]

		var unmarshaled VoteInfo
		err = unmarshaled.UnmarshalBinary(data)
		require.Error(t, err)
	})

	t.Run("AckStatus AckAgree", func(t *testing.T) {
		vote := &VoteInfo{
			Signature: Signature{
				Data:       []byte("signature"),
				PubKey:     []byte("public-key"),
				PubKeyType: crypto.KeyTypeSecp256k1,
			},
			AckStatus: AckAgree,
		}

		data, err := vote.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled VoteInfo
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, vote, &unmarshaled)
	})

	t.Run("AckStatus Diverge With AppHash", func(t *testing.T) {
		hash := HashBytes([]byte("app-hash"))
		vote := &VoteInfo{
			Signature: Signature{
				Data:       []byte("signature"),
				PubKey:     []byte("public-key"),
				PubKeyType: crypto.KeyTypeSecp256k1,
			},
			AckStatus: AckForked,
			AppHash:   &hash,
		}

		data, err := vote.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled VoteInfo
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, vote, &unmarshaled)
	})

	t.Run("AckStatus Diverge Without AppHash", func(t *testing.T) {
		vote := &VoteInfo{
			Signature: Signature{
				Data:       []byte("signature"),
				PubKey:     []byte("public-key"),
				PubKeyType: crypto.KeyTypeSecp256k1,
			},
			AckStatus: AckForked,
		}

		_, err := vote.MarshalBinary()
		require.Error(t, err)
	})
}

func TestSignAndVerifyVote(t *testing.T) {
	privKey, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)

	_, pubKey, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)

	blkID := HashBytes([]byte("test-block-id"))
	appHash := HashBytes([]byte("app-hash"))

	t.Run("Valid And Corrupted Vote", func(t *testing.T) {
		sig, err := SignVote(blkID, true, &appHash, privKey)
		require.NoError(t, err)

		vote := &VoteInfo{
			Signature: *sig,
			AckStatus: AckAgree,
		}
		valid := vote.Verify(blkID, appHash)
		require.NoError(t, valid)

		// Corrupt the signature
		vote.Signature.Data[0]++
		valid = vote.Verify(blkID, appHash)
		require.Error(t, valid)
	})

	t.Run("Sign Ack Vote With Missing AppHash", func(t *testing.T) {
		_, err := SignVote(blkID, true, nil, privKey)
		require.Error(t, err)
	})

	t.Run("Missing AppHash with AckStatusDiverge", func(t *testing.T) {
		sig, err := SignVote(blkID, true, &appHash, privKey)
		require.NoError(t, err)

		vote := &VoteInfo{
			Signature: *sig,
			AckStatus: AckForked,
		}
		// Vote is missing AppHash
		valid := vote.Verify(blkID, appHash)
		require.Error(t, valid)
	})

	t.Run("Incorrect AckStatus in the Vote", func(t *testing.T) {
		sig, err := SignVote(blkID, true, &appHash, privKey)
		require.NoError(t, err)

		vote := &VoteInfo{
			Signature: *sig,
			AckStatus: AckReject, // Disagreed vote should be signed with Ack = false and without AppHash
		}

		valid := vote.Verify(blkID, appHash)
		require.Error(t, valid)
	})

	t.Run("Sign NACK vote without AppHash", func(t *testing.T) {
		sig, err := SignVote(blkID, false, nil, privKey)
		require.NoError(t, err)

		vote := &VoteInfo{
			Signature: *sig,
			AckStatus: AckReject,
		}
		// Vote is missing AppHash
		valid := vote.Verify(blkID, appHash)
		require.NoError(t, valid)
	})

	t.Run("Sign NACK vote with AppHash", func(t *testing.T) {
		sig, err := SignVote(blkID, false, &appHash, privKey)
		require.NoError(t, err)

		vote := &VoteInfo{
			Signature: *sig,
			AckStatus: AckReject,
		}
		// Vote is missing AppHash
		valid := vote.Verify(blkID, appHash)
		require.NoError(t, valid)
	})

	t.Run("Signed With Different Keys", func(t *testing.T) {
		sig, err := SignVote(blkID, true, &appHash, privKey)
		require.NoError(t, err)
		sig.PubKey = pubKey.Bytes()

		vote := &VoteInfo{
			Signature: *sig,
			AckStatus: AckReject,
		}

		// Verify with different key
		valid := vote.Verify(blkID, appHash)
		require.Error(t, valid)
	})

	t.Run("SignVote with nil key", func(t *testing.T) {
		_, err := SignVote(blkID, true, &appHash, nil)
		require.Error(t, err)
	})
}

func TestCommitInfo(t *testing.T) {
	privKey, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)

	blkID := HashBytes([]byte("test-block-id"))
	appHash := HashBytes([]byte("app-hash"))

	t.Run("Zero Votes With Valid AppHash", func(t *testing.T) {
		commit := &CommitInfo{
			AppHash:          appHash,
			Votes:            make([]*VoteInfo, 0),
			ParamUpdates:     ParamUpdates{},
			ValidatorUpdates: make([]*Validator, 0),
		}
		data, err := commit.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled CommitInfo
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, *commit, unmarshaled)
	})

	t.Run("Zero Votes Without AppHash", func(t *testing.T) {
		commit := &CommitInfo{
			Votes:            make([]*VoteInfo, 0),
			ParamUpdates:     ParamUpdates{},
			ValidatorUpdates: make([]*Validator, 0),
		}
		data, err := commit.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled CommitInfo
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, *commit, unmarshaled)
	})

	t.Run("One Vote With AppHash", func(t *testing.T) {
		sig, err := SignVote(blkID, true, &appHash, privKey)
		require.NoError(t, err)

		vote := &VoteInfo{
			Signature: *sig,
			AckStatus: AckAgree,
		}

		commitInfo := &CommitInfo{
			AppHash:          appHash,
			Votes:            make([]*VoteInfo, 0),
			ParamUpdates:     ParamUpdates{},
			ValidatorUpdates: make([]*Validator, 0),
		}
		commitInfo.Votes = append(commitInfo.Votes, vote)

		data, err := commitInfo.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled CommitInfo
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, *commitInfo, unmarshaled)
	})

	t.Run("More Than One Vote", func(t *testing.T) {
		sig1, err := SignVote(blkID, true, &appHash, privKey)
		require.NoError(t, err)

		sig2, err := SignVote(blkID, false, nil, privKey)
		require.NoError(t, err)

		vote1 := &VoteInfo{
			Signature: *sig1,
			AckStatus: AckAgree,
		}

		vote2 := &VoteInfo{
			Signature: *sig2,
			AckStatus: AckReject,
		}

		commitInfo := &CommitInfo{
			AppHash:          appHash,
			Votes:            make([]*VoteInfo, 0),
			ParamUpdates:     ParamUpdates{},
			ValidatorUpdates: make([]*Validator, 0),
		}
		commitInfo.Votes = append(commitInfo.Votes, vote1, vote2)

		data, err := commitInfo.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled CommitInfo
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, *commitInfo, unmarshaled)
	})

	t.Run("WithValidatorUpdates", func(t *testing.T) {
		commit := &CommitInfo{
			AppHash:      appHash,
			Votes:        make([]*VoteInfo, 0),
			ParamUpdates: ParamUpdates{},
			ValidatorUpdates: []*Validator{
				{
					AccountID: AccountID{
						Identifier: []byte("validator-1"),
						KeyType:    crypto.KeyTypeEd25519,
					},
					Power: 200,
				},
				{
					AccountID: AccountID{
						Identifier: []byte("validator-1"),
						KeyType:    crypto.KeyTypeEd25519,
					},
					Power: 300,
				},
			},
		}
		data, err := commit.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled CommitInfo
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)

		require.Equal(t, *commit, unmarshaled)
	})
}
