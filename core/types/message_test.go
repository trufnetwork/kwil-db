package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
)

func TestCreateCallMessage(t *testing.T) {
	t.Run("create call message without signer", func(t *testing.T) {
		ac := &ActionCall{
			Namespace: "testdb",
			Action:    "testaction",
			Arguments: nil,
		}

		msg, err := CreateCallMessage(ac, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, msg)
		require.NotNil(t, msg.Body)
		require.NotEmpty(t, msg.Body.Payload)
		require.Empty(t, msg.Body.Challenge)
		require.Empty(t, msg.SignatureData)
		require.Empty(t, msg.AuthType)
		require.Empty(t, msg.Sender)
	})

	t.Run("create call message with signer but no challenge", func(t *testing.T) {
		ac := &ActionCall{
			Namespace: "testdb",
			Action:    "testaction",
			Arguments: nil,
		}

		mockSigner := &mockSigner{
			authType: auth.EthPersonalSignAuth,
			identity: []byte("testidentity"),
		}

		msg, err := CreateCallMessage(ac, nil, mockSigner)
		require.NoError(t, err)
		require.NotNil(t, msg)
		require.Equal(t, mockSigner.authType, msg.AuthType)
		require.Equal(t, mockSigner.identity, []byte(msg.Sender))
		require.Empty(t, msg.SignatureData)
	})

	t.Run("create call message with invalid action call", func(t *testing.T) {
		ac := &ActionCall{
			Namespace: "",
			Action:    "",
			Arguments: nil,
		}

		msg, err := CreateCallMessage(ac, nil, nil)
		require.Error(t, err)
		require.Nil(t, msg)
	})

	t.Run("create call message with signer and challenge", func(t *testing.T) {
		ac := &ActionCall{
			Namespace: "testdb",
			Action:    "testaction",
			Arguments: nil,
		}

		challenge := []byte("testchallenge")
		mockSigner := &mockSigner{
			authType: auth.EthPersonalSignAuth,
			identity: []byte("testidentity"),
		}

		msg, err := CreateCallMessage(ac, challenge, mockSigner)
		require.NoError(t, err)
		require.NotNil(t, msg)
		require.Equal(t, challenge, msg.Body.Challenge)
		require.NotNil(t, msg.SignatureData)
		require.Equal(t, mockSigner.authType, msg.AuthType)
		require.Equal(t, mockSigner.identity, []byte(msg.Sender))
	})
}

type mockSigner struct {
	authType string
	identity []byte
}

func (m *mockSigner) Sign(msg []byte) (*auth.Signature, error) {
	return &auth.Signature{
		Type: m.authType,
		Data: []byte("mocksignature"),
	}, nil
}

func (m *mockSigner) AuthType() string {
	return m.authType
}

func (m *mockSigner) CompactID() []byte {
	return m.identity
}

func (m *mockSigner) PubKey() crypto.PublicKey {
	return nil
}
