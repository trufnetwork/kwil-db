package interpreter

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto"
	coreauth "github.com/trufnetwork/kwil-db/core/crypto/auth"
	extauth "github.com/trufnetwork/kwil-db/extensions/auth"
	"github.com/trufnetwork/kwil-db/node/engine"
)

const fixedTs = 1640995200

// makeExecCtx centralizes building a minimal execution context for tests
func makeExecCtx(t *testing.T, proposer crypto.PublicKey, auth string) (*executionContext, []byte, string) {
	t.Helper()

	blk := &common.BlockContext{
		Height:    1,
		Timestamp: fixedTs,
		Proposer:  proposer,
	}

	signer := getSignerBytesForAuth(proposer, auth)
	var caller string
	if signer != nil {
		id, err := extauth.GetIdentifier(auth, signer)
		require.NoError(t, err)
		caller = id
	}

	tx := &common.TxContext{
		Ctx:           context.Background(),
		BlockContext:  blk,
		Signer:        signer,
		Caller:        caller,
		TxID:          "tx",
		Authenticator: auth,
	}

	eng := &common.EngineContext{TxContext: tx}

	return &executionContext{engineCtx: eng, scope: newScope("test")}, signer, caller
}

func hexFromKey(key crypto.PublicKey) string {
	if key == nil {
		return ""
	}
	return hex.EncodeToString(key.Bytes())
}

// 1) Basics and consistency
func TestContextualVars_Basics(t *testing.T) {
	_, pub, err := crypto.GenerateEd25519Key(nil)
	require.NoError(t, err)

	exec, _, _ := makeExecCtx(t, pub, coreauth.Ed25519Auth)

	h, err := exec.getVariable("@height")
	require.NoError(t, err)
	require.NotNil(t, h)

	ts, err := exec.getVariable("@block_timestamp")
	require.NoError(t, err)
	require.NotNil(t, ts)

	leader, err := exec.getVariable("@leader")
	require.NoError(t, err)
	require.IsType(t, (*textValue)(nil), leader)
	require.Equal(t, hexFromKey(pub), leader.(*textValue).String)

	// Nil proposer → empty @leader
	execNil, _, _ := makeExecCtx(t, nil, coreauth.Ed25519Auth)
	leaderNil, err := execNil.getVariable("@leader")
	require.NoError(t, err)
	require.Equal(t, "", leaderNil.(*textValue).String)
}

// 2) Matrix for @leader_sender
func TestLeaderSender_Matrix(t *testing.T) {
	t.Parallel()

	type combo struct {
		name      string
		makeKey   func(t *testing.T) crypto.PublicKey
		auth      string
		wantNull  bool
		wantBytes func(pk crypto.PublicKey) []byte
	}

	secp := func(t *testing.T) crypto.PublicKey {
		_, pk, err := crypto.GenerateSecp256k1Key(nil)
		require.NoError(t, err)
		return pk
	}
	ed := func(t *testing.T) crypto.PublicKey {
		_, pk, err := crypto.GenerateEd25519Key(nil)
		require.NoError(t, err)
		return pk
	}

	cases := []combo{
		{
			name:      "secp × Secp256k1Auth",
			makeKey:   secp,
			auth:      coreauth.Secp256k1Auth,
			wantNull:  false,
			wantBytes: func(pk crypto.PublicKey) []byte { return pk.Bytes() },
		},
		{
			name:     "secp × EthPersonalSignAuth",
			makeKey:  secp,
			auth:     coreauth.EthPersonalSignAuth,
			wantNull: false,
			wantBytes: func(pk crypto.PublicKey) []byte {
				return crypto.EthereumAddressFromPubKey(pk.(*crypto.Secp256k1PublicKey))
			},
		},
		{
			name:      "secp × Ed25519Auth",
			makeKey:   secp,
			auth:      coreauth.Ed25519Auth,
			wantNull:  true,
			wantBytes: nil},
		{
			name:      "ed25519 × Ed25519Auth",
			makeKey:   ed,
			auth:      coreauth.Ed25519Auth,
			wantNull:  false,
			wantBytes: func(pk crypto.PublicKey) []byte { return pk.(*crypto.Ed25519PublicKey).Bytes() },
		},
		{
			name:      "ed25519 × Secp256k1Auth",
			makeKey:   ed,
			auth:      coreauth.Secp256k1Auth,
			wantNull:  true,
			wantBytes: nil,
		},
		{
			name:      "nil proposer × any",
			makeKey:   func(*testing.T) crypto.PublicKey { return nil },
			auth:      coreauth.EthPersonalSignAuth,
			wantNull:  true,
			wantBytes: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			pk := c.makeKey(t)
			exec, _, _ := makeExecCtx(t, pk, c.auth)

			val, err := exec.getVariable("@leader_sender")
			require.NoError(t, err)
			blob, ok := val.(*blobValue)
			require.True(t, ok)

			if c.wantNull {
				require.True(t, blob.Null())
				return
			}
			require.False(t, blob.Null())
			if c.wantBytes != nil {
				require.Equal(t, c.wantBytes(pk), blob.bts)
			}
		})
	}
}

// 3) Determinism within the same block
func TestLeader_DeterminismWithinBlock(t *testing.T) {
	_, pub, err := crypto.GenerateEd25519Key(nil)
	require.NoError(t, err)

	exec1, _, _ := makeExecCtx(t, pub, coreauth.Ed25519Auth)
	// Reuse same EngineContext to simulate same block
	exec2 := &executionContext{engineCtx: exec1.engineCtx, scope: newScope("other")}

	one, err := exec1.getVariable("@leader")
	require.NoError(t, err)
	two, err := exec2.getVariable("@leader")
	require.NoError(t, err)
	require.Equal(t, one.(*textValue).String, two.(*textValue).String)
}

// 4) Invalid context returns ErrInvalidTxCtx
func TestContextualVars_InvalidTxCtx(t *testing.T) {
	exec := &executionContext{
		engineCtx: &common.EngineContext{InvalidTxCtx: true},
		scope:     newScope("test"),
	}
	for _, v := range []string{"@height", "@block_timestamp", "@leader", "@leader_sender", "@caller"} {
		_, err := exec.getVariable(v)
		require.ErrorIs(t, err, engine.ErrInvalidTxCtx, v)
	}
}

// 5) Non-concrete proposer type: wrapped secp256k1 with EthPersonalSignAuth
type secpPubWrapper struct{ inner *crypto.Secp256k1PublicKey }

func (w *secpPubWrapper) Type() crypto.KeyType     { return w.inner.Type() }
func (w *secpPubWrapper) Bytes() []byte            { return w.inner.Bytes() }
func (w *secpPubWrapper) Equals(k crypto.Key) bool { return w.inner.Equals(k) }
func (w *secpPubWrapper) Verify(data []byte, sig []byte) (bool, error) {
	return w.inner.Verify(data, sig)
}

func wrapSecpPub(pk *crypto.Secp256k1PublicKey) crypto.PublicKey { return &secpPubWrapper{inner: pk} }

func TestLeaderSender_WrappedSecp256k1_EthPersonalAuth(t *testing.T) {
	_, generic, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	raw := generic.(*crypto.Secp256k1PublicKey)

	wrapped := wrapSecpPub(raw)
	exec, _, _ := makeExecCtx(t, wrapped, coreauth.EthPersonalSignAuth)

	val, err := exec.getVariable("@leader_sender")
	require.NoError(t, err)
	blob := val.(*blobValue)
	require.False(t, blob.Null())
	require.Equal(t, crypto.EthereumAddressFromPubKey(raw), blob.bts)
}

// 6) Ed25519 regression: matching auth must not be NULL
func TestLeaderSender_Ed25519_MatchingAuth_NotNull(t *testing.T) {
	_, ed, err := crypto.GenerateEd25519Key(nil)
	require.NoError(t, err)

	exec, _, _ := makeExecCtx(t, ed, coreauth.Ed25519Auth)
	val, err := exec.getVariable("@leader_sender")
	require.NoError(t, err)
	blob := val.(*blobValue)
	require.False(t, blob.Null())
	require.Equal(t, ed.Bytes(), blob.bts)
}

// Minimal helper used by makeExecCtx and matrix expectations
func getSignerBytesForAuth(key crypto.PublicKey, authType string) []byte {
	if key == nil {
		return nil
	}
	switch authType {
	case coreauth.EthPersonalSignAuth:
		if pk, ok := key.(*crypto.Secp256k1PublicKey); ok {
			return crypto.EthereumAddressFromPubKey(pk)
		}
	case coreauth.Secp256k1Auth:
		if pk, ok := key.(*crypto.Secp256k1PublicKey); ok {
			return pk.Bytes()
		}
	case coreauth.Ed25519Auth:
		if pk, ok := key.(*crypto.Ed25519PublicKey); ok {
			return pk.Bytes()
		}
	}
	return nil
}
