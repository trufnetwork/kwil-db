package usersvc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	"github.com/trufnetwork/kwil-db/core/types"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
)

func TestAuthenticatedQueryNilRequest(t *testing.T) {
	svc := &Service{
		log: log.DiscardLogger,
	}

	_, rpcErr := svc.AuthenticatedQuery(context.Background(), nil)

	require.NotNil(t, rpcErr)
	require.Equal(t, jsonrpc.ErrorInvalidParams, rpcErr.Code)
	require.Contains(t, rpcErr.Message, "missing authenticated query request")
}

func TestAuthenticatedQueryNilBody(t *testing.T) {
	svc := &Service{
		log: log.DiscardLogger,
	}

	_, rpcErr := svc.AuthenticatedQuery(context.Background(), &userjson.AuthenticatedQueryRequest{})

	require.NotNil(t, rpcErr)
	require.Equal(t, jsonrpc.ErrorInvalidParams, rpcErr.Code)
	require.Contains(t, rpcErr.Message, "missing authenticated query body")
}

func TestAuthenticatedQueryOpenModeSmokeUnsignedRequest(t *testing.T) {
	svc := &Service{
		log:           log.DiscardLogger,
		privateMode:   false,
		readTxTimeout: defaultReadTxTimeout,
	}

	req := &userjson.AuthenticatedQueryRequest{
		Body: &types.RawStatement{
			Statement: "SELECT 1",
		},
		// Non-nil request but unsigned / no sender: authenticated_query now
		// requires authentication before reaching DB/engine in every RPC mode.
	}

	_, rpcErr := svc.AuthenticatedQuery(context.Background(), req)

	require.NotNil(t, rpcErr)
	require.Equal(t, jsonrpc.ErrorCallChallengeNotFound, rpcErr.Code)
	require.Contains(t, rpcErr.Message, "signed call message with challenge required")
}

func TestAuthenticatedQueryPrivateModeSmokeUnsignedRequest(t *testing.T) {
	svc := &Service{
		log:           log.DiscardLogger,
		privateMode:   true,
		readTxTimeout: defaultReadTxTimeout,
	}

	req := &userjson.AuthenticatedQueryRequest{
		Body: &types.RawStatement{
			Statement: "SELECT 1",
		},
		// Non-nil request but unsigned / no sender: authenticate rejects before DB/engine.
	}

	_, rpcErr := svc.AuthenticatedQuery(context.Background(), req)

	require.NotNil(t, rpcErr)
	require.NotEqual(t, jsonrpc.ErrorAuthenticatedQueryRequiresPrivateRPC, rpcErr.Code,
		"private RPC must not hit the open-mode-only denial")
	require.Equal(t, jsonrpc.ErrorCallChallengeNotFound, rpcErr.Code)
	require.Contains(t, rpcErr.Message, "signed call message with challenge required")
}

func TestAuthenticateOpenModeOptionalForCalls(t *testing.T) {
	svc := &Service{
		log:         log.DiscardLogger,
		privateMode: false,
	}

	rpcErr := svc.authenticate(nil, nil, nil, "", "", authExt.VerifyContext{})

	require.Nil(t, rpcErr)
}

func TestAuthenticateRequiredAcceptsSignedChallenge(t *testing.T) {
	privKey, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)

	signer := auth.GetUserSigner(privKey)
	require.NotNil(t, signer)

	challenge := [32]byte{1, 2, 3}
	req, err := types.CreateAuthenticatedQuery("SELECT 1", nil, challenge[:], signer)
	require.NoError(t, err)

	sigText, err := req.SigText()
	require.NoError(t, err)

	svc := &Service{
		log: log.DiscardLogger,
		challenges: map[[32]byte]time.Time{
			challenge: time.Now().Add(time.Minute),
		},
	}

	rpcErr := svc.authenticateRequired(req.SignatureData, req.Challenge, req.Sender, req.AuthType, sigText, authExt.VerifyContext{})

	require.Nil(t, rpcErr)
	require.Empty(t, svc.challenges, "verified challenges are single-use")
}
