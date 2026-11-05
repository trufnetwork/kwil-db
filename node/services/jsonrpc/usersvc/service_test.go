package usersvc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	"github.com/trufnetwork/kwil-db/core/types"
)

func TestBroadcastRejectsMissingTx(t *testing.T) {
	svc := &Service{log: log.DiscardLogger}

	_, rpcErr := svc.Broadcast(context.Background(), &userjson.BroadcastRequest{})
	require.NotNil(t, rpcErr)
	require.Equal(t, jsonrpc.ErrorInvalidParams, rpcErr.Code)
}

func TestEstimatePriceRejectsTxWithoutBody(t *testing.T) {
	svc := &Service{log: log.DiscardLogger}

	for _, req := range []*userjson.EstimatePriceRequest{
		{},
		{Tx: &types.Transaction{}},
	} {
		_, rpcErr := svc.EstimatePrice(context.Background(), req)
		require.NotNil(t, rpcErr)
		require.Equal(t, jsonrpc.ErrorInvalidParams, rpcErr.Code)
	}
}

// malformedValues are argument values that unmarshal but cannot be decoded: a
// bool with the not-null marker and no value byte, and a data element with no
// null marker byte at all.
func malformedValues() map[string]*types.EncodedValue {
	return map[string]*types.EncodedValue{
		"bool marker only":   {Type: *types.BoolType, Data: [][]byte{{1}}},
		"text empty element": {Type: *types.TextType, Data: [][]byte{{}}},
	}
}

func TestCallRejectsMalformedArgument(t *testing.T) {
	svc := &Service{log: log.DiscardLogger}

	for name, ev := range malformedValues() {
		t.Run(name, func(t *testing.T) {
			payload, err := types.ActionCall{
				Namespace: "main",
				Action:    "a",
				Arguments: []*types.EncodedValue{ev},
			}.MarshalBinary()
			require.NoError(t, err)

			var rpcErr *jsonrpc.Error
			require.NotPanics(t, func() {
				_, rpcErr = svc.Call(context.Background(), &userjson.CallRequest{
					Body: &types.CallMessageBody{Payload: payload},
				})
			})
			require.NotNil(t, rpcErr)
			require.Equal(t, jsonrpc.ErrorInvalidParams, rpcErr.Code)
		})
	}
}

func TestAuthenticatedQueryRejectsMalformedParameter(t *testing.T) {
	svc := &Service{log: log.DiscardLogger}

	for name, ev := range malformedValues() {
		t.Run(name, func(t *testing.T) {
			var rpcErr *jsonrpc.Error
			require.NotPanics(t, func() {
				_, rpcErr = svc.AuthenticatedQuery(context.Background(), &userjson.AuthenticatedQueryRequest{
					Body: &types.RawStatement{
						Statement:  "SELECT $p",
						Parameters: []*types.NamedValue{{Name: "$p", Value: ev}},
					},
				})
			})
			require.NotNil(t, rpcErr)
			require.Equal(t, jsonrpc.ErrorInvalidParams, rpcErr.Code)
		})
	}
}
