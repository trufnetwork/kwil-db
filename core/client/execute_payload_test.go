package client_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/client"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/types"
)

// stubRPC is a minimal RPCClient: it embeds the interface so that any method we
// do not override panics if called, and implements only the four the
// WrapClient + ExecutePayload path exercises (Health, GetAccount, EstimateCost,
// Broadcast). It captures the transaction handed to Broadcast for assertions.
type stubRPC struct {
	client.RPCClient
	acctNonce int64
	estFee    *big.Int
	gotTx     *types.Transaction
}

func (s *stubRPC) Health(ctx context.Context) (*types.Health, error) {
	return &types.Health{ChainInfo: types.ChainInfo{ChainID: "test-chain"}, Healthy: true}, nil
}

func (s *stubRPC) GetAccount(ctx context.Context, id *types.AccountID, status types.AccountStatus) (*types.Account, error) {
	return &types.Account{ID: id, Nonce: s.acctNonce}, nil
}

func (s *stubRPC) EstimateCost(ctx context.Context, tx *types.Transaction) (*big.Int, error) {
	return s.estFee, nil
}

func (s *stubRPC) Broadcast(ctx context.Context, tx *types.Transaction, sync rpcclient.BroadcastWait) (types.Hash, error) {
	s.gotTx = tx
	return types.Hash{0x01}, nil
}

// TestClient_ExecutePayload proves the generic escape hatch signs and broadcasts
// an arbitrary payload (here MAAExec, the motivating extension payload) with the
// nonce from the account, the fee from EstimateCost, and the payload preserved
// byte-for-byte through the wire round-trip.
func TestClient_ExecutePayload(t *testing.T) {
	ctx := context.Background()

	pk, err := crypto.Secp256k1PrivateKeyFromHex(
		"0000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)
	signer := &auth.EthPersonalSigner{Key: *pk}

	stub := &stubRPC{acctNonce: 5, estFee: big.NewInt(123)}
	c, err := client.WrapClient(ctx, stub, &clientType.Options{
		Signer:            signer,
		ChainID:           "test-chain",
		SkipVerifyChainID: true,
		Silence:           true,
	})
	require.NoError(t, err)

	payload := &types.MAAExec{
		MAAAddress: make([]byte, 20),
		Namespace:  "main",
		Action:     "example_action",
	}

	h, err := c.ExecutePayload(ctx, payload)
	require.NoError(t, err)
	require.Equal(t, types.Hash{0x01}, h, "returns the hash from Broadcast")

	require.NotNil(t, stub.gotTx, "Broadcast must be called")
	require.Equal(t, uint64(6), stub.gotTx.Body.Nonce, "account nonce 5 + 1")
	require.Equal(t, "123", stub.gotTx.Body.Fee.String(), "fee from EstimateCost")
	require.Equal(t, types.PayloadTypeMAAExec, stub.gotTx.Body.PayloadType)
	require.NotEmpty(t, stub.gotTx.Signature.Data, "transaction is signed")

	// The payload survives serialization byte-for-byte.
	var got types.MAAExec
	require.NoError(t, got.UnmarshalBinary(stub.gotTx.Body.Payload))
	require.Equal(t, payload.Namespace, got.Namespace)
	require.Equal(t, payload.Action, got.Action)
	require.Equal(t, payload.MAAAddress, got.MAAAddress)
}
