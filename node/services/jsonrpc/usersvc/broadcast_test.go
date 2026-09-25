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

func TestBroadcastRejectsNilBody(t *testing.T) {
	svc := &Service{log: log.DiscardLogger}

	for _, req := range []*userjson.BroadcastRequest{
		{},
		{Tx: &types.Transaction{}},
	} {
		_, rpcErr := svc.Broadcast(context.Background(), req)
		require.NotNil(t, rpcErr)
		require.Equal(t, jsonrpc.ErrorInvalidParams, rpcErr.Code)
		require.Contains(t, rpcErr.Message, "transaction body is required")
	}
}

func TestEstimatePriceRejectsNilBody(t *testing.T) {
	svc := &Service{log: log.DiscardLogger}

	for _, req := range []*userjson.EstimatePriceRequest{
		{},
		{Tx: &types.Transaction{}},
	} {
		_, rpcErr := svc.EstimatePrice(context.Background(), req)
		require.NotNil(t, rpcErr)
		require.Equal(t, jsonrpc.ErrorInvalidParams, rpcErr.Code)
		require.Contains(t, rpcErr.Message, "transaction body is required")
	}
}
