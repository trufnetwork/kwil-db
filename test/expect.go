package test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/test/setup"
)

var txTimeout = 5 * time.Second

func ExpectTxSuccess(t *testing.T, spec setup.JSONRPCClient, ctx context.Context, txHash types.Hash) {
	hash := txHash.String() // intentionally setting this as a variable so we can see it in a debugger
	t.Logf("waiting for tx %s", hash)
	res, err := spec.WaitTx(ctx, txHash, 300*time.Millisecond)
	require.NoError(t, err)

	require.True(t, res.Result.Code == 0, "tx failed: %s", res.Result.Log)
}

func ExpectTxError(t *testing.T, spec setup.JSONRPCClient, ctx context.Context, txHash types.Hash, msg string) {
	hash := txHash.String() // intentionally setting this as a variable so we can see it in a debugger
	t.Logf("waiting for tx %s", hash)
	res, err := spec.WaitTx(ctx, txHash, 300*time.Millisecond)
	require.NoError(t, err)

	require.True(t, res.Result.Code != 0, "tx succeeded")
	require.True(t, strings.Contains(res.Result.Log, msg), "unexpected error message")
}
