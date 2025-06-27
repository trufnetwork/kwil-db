package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/types"
)

// The harness methods in this file pertain to the embedded dataset schema,
// testScheme.

type asyncResp struct {
	err        error
	res        *types.TxResult
	expectFail bool
}

func (ar *asyncResp) error() error {
	if ar.err != nil {
		return ar.err
	}
	if ar.res.Code != 0 {
		return fmt.Errorf("execution failed with code %d, log: %q",
			ar.res.Code, ar.res.Log)
	}
	return nil
}
func (ar *asyncResp) Error() error {
	err := ar.error()
	if err != nil {
		if ar.expectFail {
			err = errors.Join(err, ErrExpected)
		}
		return err
	}
	if ar.expectFail {
		return errors.New("UNEXPECTEDLY succeeded when it should have failed")
	}
	return nil
}

// With the new SQL schema, drop and deploy aren't client functions. Instead we
// use ExecuteSQL with DDL. e.g. 'DROP NAMESPACE IF EXISTS dbname;' or `{dbname}DROP TABLE t;`

func (h *harness) dropDB(ctx context.Context, namespace string) error {
	var txHash types.Hash
	err := h.underNonceLock(ctx, func(nonce int64) error {
		sql := fmt.Sprintf("DROP NAMESPACE IF EXISTS %s;", namespace)
		var err error
		txHash, err = h.ExecuteSQL(ctx, sql, nil, clientType.WithNonce(nonce))
		return err
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	txResp, err := h.WaitTx(ctx, txHash, txPollInterval)
	if err != nil {
		err = errors.Join(err, h.recoverNonce(ctx))
		return fmt.Errorf("WaitTx (drop): %w", err)
	}
	if code := txResp.Result.Code; code != 0 {
		return fmt.Errorf("drop tx failed (%d): %v", code, txResp.Result.Log)
	}
	return nil
}

func (h *harness) deployDBAsync(ctx context.Context, schemaSQL string) (<-chan asyncResp, error) {
	var txHash types.Hash
	err := h.underNonceLock(ctx, func(nonce int64) error {
		var err error
		txHash, err = h.ExecuteSQL(ctx, schemaSQL, nil, clientType.WithNonce(nonce))
		return err
	})
	if err != nil {
		return nil, err
	}

	promise := make(chan asyncResp, 1)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		resp, err := h.WaitTx(ctx, txHash, txPollInterval)
		if err != nil {
			h.logger.Error("WaitTx", "error", err)
			err = errors.Join(err, h.recoverNonce(ctx))
			promise <- asyncResp{err: err}
			return
		}
		promise <- asyncResp{res: resp.Result}
		h.logger.Info(fmt.Sprintf("database deployed in tx %v in block %d", txHash, resp.Height))
	}()

	return promise, nil
}

func (h *harness) deployDB(ctx context.Context, schemaSQL string) error {
	promise, err := h.deployDBAsync(ctx, schemaSQL)
	if err != nil {
		return err
	}
	res := <-promise
	if res.err != nil {
		return res.err
	}
	txRes := res.res
	if code := txRes.Code; code != 0 {
		return fmt.Errorf("failed to deploy database, code = %d, log = %q", code, txRes.Log)
	}
	return nil
}
