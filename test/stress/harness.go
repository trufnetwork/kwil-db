package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"

	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
)

// harness is a Client driver designed around an embedded dataset Kuneiform
// schema. It has methods to execute actions asynchronously, while track it's
// used nonces so it can correctly make multiple unconfirmed transactions with
// increasing nonces. See underNonceLock and recoverNonce.
type harness struct {
	clientType.Client
	logger log.Logger
	acctID *types.AccountID

	signer auth.Signer

	nonceMtx sync.Mutex
	nonce    int64 // atomic.Int64

	concurrentBroadcast bool // broadcast many before confirm, still coordinate nonces
	nonceChaos          int  // apply random nonce-jitter every 1/n times

	nestedLogger log.Logger

	quiet bool

	// asc actSchemaClient
}

// for about 1 in every f times, produce a non-zero nonce jitter:
// {-2, 1, 1, 2, 3, 4}
func randNonceJitter(f int) int64 {
	if f == 0 {
		return 0
	}
	if rand.Intn(f) > 0 {
		return 0
	}
	n := rand.Int63n(6) - 2
	if n >= 0 { // 0-3 => 1-4
		return n + 1
	}
	return n
}

// this whole method is kinda messes up now; nothing is really concurrent at
// all, the function is just called with the lock released for something else to
// use it.
func (h *harness) underNonceLock(ctx context.Context, fn func(int64) error) error {
	recoverNonce := func() error {
		acct, err := h.GetAccount(ctx, h.acctID, types.AccountStatusPending)
		if err != nil {
			return err
		}
		h.nonce = acct.Nonce
		return nil
	}

	if h.concurrentBroadcast {
		// Grab the next nonce in a thread-safe manner, but do not wait for
		// broadcast to complete to release the lock. If there is a nonce error,
		// there will be more chaos with concurrent broadcasting.
		h.nonceMtx.Lock()
		nonce0 := h.nonce
		h.nonce++
		nonce := h.nonce + randNonceJitter(h.nonceChaos)
		h.nonceMtx.Unlock()
		if err := fn(nonce); err != nil {
			if errors.Is(err, types.ErrInvalidNonce) {
				// Note: several goroutines may all try to do this if they all hit the nonce error
				recoverNonce()
				h.printf("nonce %d was wrong, reverted to %d\n", nonce, h.nonce)
				return err
			}
			if errors.Is(err, context.Canceled) {
				return err
			}

			// For other bcast errors like mempool full, the tx was rejected,
			// but we already advanced nonce. Try to reset the nonce to what we
			// just had and continue. If there are concurrent goroutines that
			// are also using underNonceLock with concurrent broadcast, it is
			// possible we are resetting to the wrong nonce. If this is
			// detected, we'll recover the nonce from RPC.
			h.nonceMtx.Lock()
			if h.nonce == nonce0+1 { // lucky, we can just reset to the nonce we had before
				h.printf("resetting nonce to %d", nonce0)
				h.nonce = nonce0
			} else { // concurrent goroutines may have advanced the nonce
				recoverNonce()
				h.printf("nonce %d was wrong, reverted to %d", nonce, h.nonce)
			}
			h.nonceMtx.Unlock()
			return err
		}
		return nil
	}

	// -sb
	h.nonceMtx.Lock()
	defer h.nonceMtx.Unlock()
	h.nonce++
	h.printf("using next nonce %d", h.nonce)

	if err := fn(h.nonce); err != nil {
		if errors.Is(err, types.ErrInvalidNonce) { // this alone should not happen
			// NOTE: if GetAccount returns only the confirmed nonce, we'll error
			// again shortly if there are others already in mempool.
			recoverNonce()
			h.printf("RESET NONCE TO LATEST REPORTED (underNonceLock): %d", h.nonce)
		} else {
			h.nonce--
		}
		return err
	}
	return nil
}

func (h *harness) recoverNonce(ctx context.Context) error {
	h.nonceMtx.Lock()
	defer h.nonceMtx.Unlock()

	acct, err := h.GetAccount(ctx, h.acctID, types.AccountStatusPending)
	if err != nil {
		return err
	}
	h.nonce = acct.Nonce
	h.printf("RESET NONCE TO LATEST CONFIRMED (recoverNonce): %d", h.nonce)
	return nil
}

func (h *harness) println(args ...any) { //nolint:unused
	if h.quiet {
		return
	}
	h.nestedLogger.Info(fmt.Sprintln(args...))
}

func (h *harness) printf(msg string, args ...any) {
	var hasErr bool
	for _, arg := range args {
		if err, isErr := arg.(error); isErr && !errors.Is(err, ErrExpected) {
			hasErr = true
			break
		}
	}

	fun := h.nestedLogger.Info
	if hasErr {
		fun = h.nestedLogger.Error
	} else if h.quiet {
		return
	}
	fun(fmt.Sprintf(msg, args...))
}

func (h *harness) printRecs(results *types.QueryResult) {
	h.logger.Infoln(strings.Join(results.ColumnNames, ","))
	for _, row := range results.Values {
		rowStr := make([]string, len(row))
		for i, v := range row {
			rowStr[i] = fmt.Sprintf("%v", v)
		}
		h.logger.Info(strings.Join(rowStr, ","))
	}
}

func (h *harness) executeAsync(ctx context.Context, dbid, action string,
	inputs [][]any) (types.Hash, error) {
	var txHash types.Hash
	err := h.underNonceLock(ctx, func(nonce int64) error {
		var err error
		txHash, err = h.Execute(ctx, dbid, action, inputs,
			clientType.WithNonce(nonce) /*, clientType.WithFee(&big.Int{})*/) // TODO: badFee mode
		if err == nil {
			h.printf("broadcasted tx %s, nonce %d", txHash, nonce)
		}
		return err
	})
	if err != nil {
		if errors.Is(err, types.ErrMempoolFull) {
			err = types.ErrMempoolFull // throw out the verbose jsonrpc.Error
		}
		return types.Hash{}, fmt.Errorf("%s: %w", action, err)
	}
	return txHash, nil
}

func (h *harness) execute(ctx context.Context, dbid string, action string,
	inputs [][]any) error {
	txHash, err := h.executeAsync(ctx, dbid, action, inputs)
	if err != nil {
		return err
	}

	// !!!!! if we got a txhash back from the node, mempool should have it
	// time.Sleep(time.Millisecond * 200)
	// !!!!! but it doesn't so WaitTx will spew warnings at first

	txResp, err := h.WaitTx(ctx, txHash, txPollInterval)
	if err != nil {
		err = errors.Join(err, h.recoverNonce(ctx))
		return fmt.Errorf("WaitTx (%v): %w", action, err)
	}
	if code := txResp.Result.Code; code != 0 {
		return fmt.Errorf("%s tx failed (%d): %v", action, code, txResp.Result.Log)
	}
	return nil
}
