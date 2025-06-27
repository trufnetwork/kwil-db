package specifications

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
)

var ErrTxNotConfirmed = errors.New("transaction not confirmed")

func ExpectTxSuccess(t *testing.T, spec TxQueryDsl, ctx context.Context, txHash types.Hash) {
	expectTxSuccess(t, spec, ctx, txHash, defaultTxQueryTimeout)()
}

func expectTxSuccess(t *testing.T, spec TxQueryDsl, ctx context.Context, txHash types.Hash, waitFor time.Duration) func() {
	return func() {
		var status strings.Builder
		require.Eventually(t, func() bool {
			// prevent appending to the prior invocation(s)
			status.Reset()
			if err := spec.TxSuccess(ctx, txHash); err == nil {
				return true
				// Consider failing faster for unexpected errors:
				// } else if !errors.Is(err, driver.ErrTxNotConfirmed) {
				// 	t.Fatal(err)
				// 	return false
			} else {
				status.WriteString(err.Error())
				return false
			}
		}, waitFor, time.Millisecond*300, "tx failed: %s", status.String())
	}
}

func ExpectTxfail(t *testing.T, spec TxQueryDsl, ctx context.Context, txHash types.Hash) {
	expectTxFail(t, spec, ctx, txHash, defaultTxQueryTimeout)()
}

func expectTxFail(t *testing.T, spec TxQueryDsl, ctx context.Context, txHash types.Hash, waitFor time.Duration) func() {
	return func() {
		var status strings.Builder
		require.Eventually(t, func() bool {
			// prevent appending to the prior invocation(s)
			status.Reset()
			if err := spec.TxSuccess(ctx, txHash); err == nil {
				status.WriteString("success")
				return false
			} else {
				status.WriteString(err.Error())
				// NOTE: ErrTxNotConfirmed is not considered a failure, should retry
				return !errors.Is(err, ErrTxNotConfirmed)
			}
		}, waitFor, time.Second*1, "tx should fail - status: %v, hash %x", status.String(), txHash)
	}
}
