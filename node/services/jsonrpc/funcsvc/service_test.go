package funcsvc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corecrypto "github.com/trufnetwork/kwil-db/core/crypto"
	coreauth "github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/rpc/json/function"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
)

const testMmTokenName = "mm_token"

func TestVerifySignature_MmTokenContextChecks(t *testing.T) {
	registerTestMmTokenAuthenticator(t)

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Now().UTC()
	req := testMmTokenVerifyRequest(t, pub, signTestMmTokenEnvelope(t, priv, testMmToken{
		Version:          1,
		Aud:              []string{"metamask:user-storage:ukyc", "idos:kwil"},
		SigningPublicKey: base64.RawURLEncoding.EncodeToString(pub),
		IssuedAt:         now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
	}))

	resp, rpcErr := Service{}.VerifySignature(context.Background(), req)
	require.Nil(t, rpcErr)
	require.True(t, resp.Valid)

	req = testMmTokenVerifyRequest(t, pub, signTestMmTokenEnvelope(t, priv, testMmToken{
		Version:          1,
		Aud:              []string{"metamask:user-storage:ukyc", "idos:kwil"},
		SigningPublicKey: base64.RawURLEncoding.EncodeToString(pub),
		IssuedAt:         now.Add(-2 * time.Hour).Format(time.RFC3339),
		ExpiresAt:        now.Add(-time.Hour).Format(time.RFC3339),
	}))

	resp, rpcErr = Service{}.VerifySignature(context.Background(), req)
	require.Nil(t, rpcErr)
	require.False(t, resp.Valid)
	require.Contains(t, resp.Reason, "mm_token expired")
}

func TestVerifySignature_MmTokenRejectsBadEnvelope(t *testing.T) {
	registerTestMmTokenAuthenticator(t)

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	now := time.Now().UTC()
	envelope := signTestMmTokenEnvelope(t, priv, testMmToken{
		Version:          1,
		Aud:              []string{"metamask:user-storage:ukyc", "idos:kwil"},
		SigningPublicKey: base64.RawURLEncoding.EncodeToString(pub),
		IssuedAt:         now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
	})
	envelope = corruptEnvelopeSignature(t, envelope)

	resp, rpcErr := Service{}.VerifySignature(context.Background(), testMmTokenVerifyRequest(t, pub, envelope))
	require.Nil(t, rpcErr)
	require.False(t, resp.Valid)
}

func TestVerifySignature_LegacyAuthenticatorFallback(t *testing.T) {
	privKey, _, err := corecrypto.GenerateEd25519Key(nil)
	require.NoError(t, err)

	signer := coreauth.GetUserSigner(privKey)
	msg := []byte("legacy verifier fallback")
	sig, err := signer.Sign(msg)
	require.NoError(t, err)

	resp, rpcErr := Service{}.VerifySignature(context.Background(), &function.VerifySignatureRequest{
		Signature: &function.TxSignature{
			SignatureBytes: sig.Data,
			SignatureType:  sig.Type,
		},
		Sender: signer.CompactID(),
		Msg:    msg,
	})
	require.Nil(t, rpcErr)
	require.True(t, resp.Valid)
}

func registerTestMmTokenAuthenticator(t *testing.T) {
	t.Helper()

	previous, err := authExt.GetAuthenticator(testMmTokenName)
	if err == nil {
		require.NoError(t, authExt.RegisterAuthenticator(authExt.ModUpdate, testMmTokenName, testMmTokenAuthenticator{}))
		t.Cleanup(func() {
			require.NoError(t, authExt.RegisterAuthenticator(authExt.ModUpdate, testMmTokenName, previous))
		})
		return
	}
	require.True(t, errors.Is(err, authExt.ErrAuthenticatorNotFound))

	require.NoError(t, authExt.RegisterAuthenticator(authExt.ModAdd, testMmTokenName, testMmTokenAuthenticator{}))
	t.Cleanup(func() {
		require.NoError(t, authExt.RegisterAuthenticator(authExt.ModRemove, testMmTokenName, nil))
	})
}

func testMmTokenVerifyRequest(t *testing.T, sender []byte, envelope []byte) *function.VerifySignatureRequest {
	t.Helper()

	return &function.VerifySignatureRequest{
		Signature: &function.TxSignature{
			SignatureBytes: envelope,
			SignatureType:  testMmTokenName,
		},
		Sender: sender,
		Msg:    []byte("kgw verify_signature payload"),
	}
}

type testMmTokenAuthenticator struct{}

func (testMmTokenAuthenticator) Verify(sender, _, signatureData []byte) error {
	_, err := verifyTestMmTokenEnvelope(sender, signatureData)
	return err
}

func (testMmTokenAuthenticator) VerifyWithContext(ctx authExt.VerifyContext, sender, _, signatureData []byte) error {
	token, err := verifyTestMmTokenEnvelope(sender, signatureData)
	if err != nil {
		return err
	}
	if ctx.BlockContext == nil {
		return errors.New("mm_token verification requires block context")
	}

	blockTime := time.Unix(ctx.BlockContext.Timestamp, 0).UTC()
	expiresAt, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid mm_token expires_at: %w", err)
	}
	if !expiresAt.After(blockTime) {
		return errors.New("mm_token expired")
	}

	return nil
}

func (testMmTokenAuthenticator) Identifier(sender []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString(sender), nil
}

func (testMmTokenAuthenticator) KeyType() corecrypto.KeyType {
	return corecrypto.KeyTypeEd25519
}

type testMmTokenEnvelope struct {
	Token     string `json:"token"`
	Signature string `json:"signature"`
}

type testMmToken struct {
	Version          int      `json:"version"`
	Aud              []string `json:"aud"`
	SigningPublicKey string   `json:"signing_public_key"`
	IssuedAt         string   `json:"issued_at"`
	ExpiresAt        string   `json:"expires_at"`
}

func signTestMmTokenEnvelope(t *testing.T, priv ed25519.PrivateKey, token testMmToken) []byte {
	t.Helper()

	tokenJSON, err := json.Marshal(token)
	require.NoError(t, err)

	tokenSignature := ed25519.Sign(priv, tokenJSON)
	envelope, err := json.Marshal(testMmTokenEnvelope{
		Token:     base64.RawURLEncoding.EncodeToString(tokenJSON),
		Signature: base64.RawURLEncoding.EncodeToString(tokenSignature),
	})
	require.NoError(t, err)

	return envelope
}

func corruptEnvelopeSignature(t *testing.T, envelope []byte) []byte {
	t.Helper()

	var decoded testMmTokenEnvelope
	require.NoError(t, json.Unmarshal(envelope, &decoded))

	signature, err := base64.RawURLEncoding.DecodeString(decoded.Signature)
	require.NoError(t, err)
	signature[0] ^= 1
	decoded.Signature = base64.RawURLEncoding.EncodeToString(signature)

	corrupted, err := json.Marshal(decoded)
	require.NoError(t, err)
	return corrupted
}

func verifyTestMmTokenEnvelope(sender, signatureData []byte) (*testMmToken, error) {
	var envelope testMmTokenEnvelope
	if err := json.Unmarshal(signatureData, &envelope); err != nil {
		return nil, fmt.Errorf("invalid mm_token envelope: %w", err)
	}

	tokenJSON, err := base64.RawURLEncoding.DecodeString(envelope.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid mm_token token encoding: %w", err)
	}
	tokenSignature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid mm_token signature encoding: %w", err)
	}

	var token testMmToken
	if err := json.Unmarshal(tokenJSON, &token); err != nil {
		return nil, fmt.Errorf("invalid mm_token token json: %w", err)
	}
	if token.Version != 1 {
		return nil, fmt.Errorf("unsupported mm_token version: %d", token.Version)
	}
	if !hasTestAudience(token.Aud, "idos:kwil") {
		return nil, errors.New("mm_token missing audience")
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(token.SigningPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid mm_token signing_public_key: %w", err)
	}
	if !bytes.Equal(sender, publicKey) {
		return nil, errors.New("mm_token signing_public_key does not match sender")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), tokenJSON, tokenSignature) {
		return nil, errors.New("invalid mm_token signature")
	}

	return &token, nil
}

func hasTestAudience(audiences []string, expected string) bool {
	for _, audience := range audiences {
		if audience == expected {
			return true
		}
	}
	return false
}
