package main

import (
	"context"
	"fmt"
	"math/big"
	"time"

	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
)

// timedClient is a wrapper around a common.Client
type timedClient struct {
	clientType.Client
	showReqDur bool
	logger     log.Logger
}

var _ clientType.Client = (*timedClient)(nil)

func (tc *timedClient) Call(ctx context.Context, namespace, action string, inputs []any) (*types.CallResult, error) {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "CallAction")
	}
	return tc.Client.Call(ctx, namespace, action, inputs)
}

func (tc *timedClient) ChainID() string {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "ChainID")
	}
	return tc.Client.ChainID()
}

func (tc *timedClient) ChainInfo(ctx context.Context) (*types.ChainInfo, error) {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "ChainInfo")
	}
	return tc.Client.ChainInfo(ctx)
}

func (tc *timedClient) ExecuteAction(ctx context.Context, dbid string, action string, tuples [][]any, opts ...clientType.TxOpt) (types.Hash, error) {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "ExecuteAction")
	}
	return tc.Client.Execute(ctx, dbid, action, tuples, opts...)
}

func (tc *timedClient) GetAccount(ctx context.Context, id *types.AccountID, status types.AccountStatus) (*types.Account, error) {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "GetAccount")
	}
	return tc.Client.GetAccount(ctx, id, status)
}

func (tc *timedClient) Ping(ctx context.Context) (string, error) {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "Ping")
	}
	return tc.Client.Ping(ctx)
}

func (tc *timedClient) Query(ctx context.Context, query string, params map[string]any, skipAuth bool) (*types.QueryResult, error) {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "Query")
	}
	return tc.Client.Query(ctx, query, params, skipAuth)
}

func (tc *timedClient) TxQuery(ctx context.Context, hash types.Hash) (*types.TxQueryResponse, error) {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "TxQuery")
	}
	return tc.Client.TxQuery(ctx, hash)
}

func (tc *timedClient) WaitTx(ctx context.Context, hash types.Hash, interval time.Duration) (*types.TxQueryResponse, error) {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "WaitTx")
	}
	return tc.Client.WaitTx(ctx, hash, interval)
}

func (tc *timedClient) Transfer(ctx context.Context, to *types.AccountID, amount *big.Int, opts ...clientType.TxOpt) (types.Hash, error) {
	if tc.showReqDur {
		defer tc.printDur(time.Now(), "Transfer")
	}
	return tc.Client.Transfer(ctx, to, amount, opts...)
}

func (tc *timedClient) printDur(t time.Time, method string) {
	tc.logger.Info(fmt.Sprintf("%s took %vms", method, float64(time.Since(t).Microseconds())/1e3)) // not using zap Fields so it is legible
}
