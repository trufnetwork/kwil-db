package accounts

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/versioning"

	"github.com/decred/dcrd/container/lru"
)

const (
	AccountsLRUCacheSize = 4000
)

// Accounts represents an in-memory cache of accounts stored in a PostgreSQL database.
// This is primarily used to optimize data reads.
type Accounts struct {
	// protects records and updates fields
	mtx sync.RWMutex
	// records is an in-memory cache of account records. Any available record
	// in this cache is always upto date with the database.
	records *lru.Map[string, *types.Account]

	// updates is a map of account identifiers (hex-encoded) used to record
	// account updates made by the transactions within a block.(spends, credits, transfers, etc.)
	// These updates are applied to the records at the end of the block.
	// Instead of using the repl stream to capture the updates, we use this in-memory cache.
	// These updates are also used in Zero Downtime Migration to capture the spends in a block.
	updates map[string]*types.Account
	log     log.Logger

	// spends is a list of spends that occurred in the block, used to track spends during migration.
	// Updates are different from spends, as they capture the effects of the spends rather than spends itself.
	spends []*Spend
}

type Spend struct {
	Account *types.AccountID
	Amount  *big.Int
	Nonce   uint64
}

const spendVersion = 0

func (s *Spend) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}

	if err := binary.Write(buf, types.SerializationByteOrder, uint16(spendVersion)); err != nil {
		return nil, err
	}

	idBts, err := s.Account.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err := types.WriteBytes(buf, idBts); err != nil {
		return nil, err
	}

	if err := types.WriteBigInt(buf, s.Amount); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, types.SerializationByteOrder, s.Nonce); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *Spend) UnmarshalBinary(data []byte) (err error) {
	buf := bytes.NewReader(data)

	var version uint16
	if err = binary.Read(buf, types.SerializationByteOrder, &version); err != nil {
		return err
	}
	if int(version) != spendVersion {
		return fmt.Errorf("invalid spend version: %d", version)
	}

	idBts, err := types.ReadBytes(buf)
	if err != nil {
		return err
	}

	s.Account = &types.AccountID{}
	if err := s.Account.UnmarshalBinary(idBts); err != nil {
		return err
	}

	if s.Amount, err = types.ReadBigInt(buf); err != nil {
		return err
	}

	return binary.Read(buf, types.SerializationByteOrder, &s.Nonce)
}

func InitializeAccountStore(ctx context.Context, db sql.DB, logger log.Logger) (*Accounts, error) {
	upgradeFns := map[int64]versioning.UpgradeFunc{
		0: initTables,
	}

	err := versioning.Upgrade(ctx, db, schemaName, upgradeFns, accountStoreVersion)
	if err != nil {
		return nil, err
	}

	return &Accounts{
		records: lru.NewMap[string, *types.Account](AccountsLRUCacheSize),
		updates: make(map[string]*types.Account),
		log:     logger,
	}, nil
}

func (*Accounts) NumAccounts(ctx context.Context, tx sql.Executor) (int64, error) {
	return numAccounts(ctx, tx)
}

// GetAccount retrieves the account with the given identifier. If the account does not exist,
// it will return an account with a balance of 0 and a nonce of 0.
func (a *Accounts) GetAccount(ctx context.Context, tx sql.Executor, account *types.AccountID) (*types.Account, error) {
	acct, err := a.getAccount(ctx, tx, account, false)
	if err != nil {
		if err == ErrAccountNotFound {
			return &types.Account{
				ID:      account,
				Balance: big.NewInt(0),
				Nonce:   0,
			}, nil
		}
		return nil, err
	}
	return acct, nil
}

// getAccount retrieves the account with the given identifier.
// If the account does not exist, it will return an error.
// If uncommitted is true, it will check the in-memory cache for the account.
func (a *Accounts) getAccount(ctx context.Context, tx sql.Executor, account *types.AccountID, uncommitted bool) (acct *types.Account, err error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	mapKey := acctMapKey(account)

	var ok bool
	if uncommitted {
		// Check in the updates first to see if the account has been updated in the current block
		acct, ok = a.updates[mapKey]
		if ok {
			return &types.Account{
				ID:      account,
				Balance: big.NewInt(0).Set(acct.Balance),
				Nonce:   acct.Nonce,
			}, nil
		}
	}

	// Check in the records to see if the account has been read before
	acct, ok = a.records.Get(mapKey)
	if ok {
		return &types.Account{
			ID:      account,
			Balance: big.NewInt(0).Set(acct.Balance),
			Nonce:   acct.Nonce,
		}, nil
	}

	acct, err = getAccount(ctx, tx, account)
	if err != nil {
		return nil, err
	}

	// Add the account to the in-memory cache
	evicted := a.records.Put(mapKey, &types.Account{
		ID:      account,
		Balance: big.NewInt(0).Set(acct.Balance),
		Nonce:   acct.Nonce,
	})
	if evicted > 0 {
		a.log.Debugf("Evicted %d accounts from cache", evicted)
	}

	return acct, nil
}

// Credit credits an account with the given amount. If the account does not exist, it will be created.
// A negative amount will be treated as a debit. Accounts cannot have negative balances, and will
// return an error if the amount would cause the balance to go negative.
// It also adds a record to the in-memory cache.
func (a *Accounts) Credit(ctx context.Context, tx sql.Executor, account *types.AccountID, amt *big.Int) error {
	acct, err := a.getAccount(ctx, tx, account, true)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			if amt.Sign() < 0 {
				return ErrNegativeBalance
			}

			return a.createAccount(ctx, tx, account, amt, 0)
		}
		return err
	}

	newBal := new(big.Int).Add(acct.Balance, amt)

	// If the new balance is negative (which is possible with a debit), we should fail
	if newBal.Sign() < 0 {
		return ErrNegativeBalance
	}

	return a.updateAccount(ctx, tx, account, newBal, acct.Nonce)
}

// Spend spends an amount from an account and records nonces. It blocks until the spend is written to the database.
// The nonce passed must be exactly one greater than the account's nonce. If the nonce is not valid, the spend will fail.
// If the account does not have enough funds to spend the amount, an ErrInsufficientFunds error will be returned.
func (a *Accounts) Spend(ctx context.Context, tx sql.Executor, account *types.AccountID, amount *big.Int, nonce int64) error {
	acct, err := a.getAccount(ctx, tx, account, true)
	if err != nil {
		// If amount is 0 and account does not exist, create the account
		// Ensure that the nonce is 1, as this is the first tx spend on this account
		if errors.Is(err, ErrAccountNotFound) && amount.Sign() == 0 && nonce == 1 {
			return a.createAccount(ctx, tx, account, amount, nonce)
		}

		return err
	}

	// Ensure that the nonce is exactly one greater than the account's nonce
	if acct.Nonce+1 != nonce {
		return fmt.Errorf("%w: expected nonce %d, got %d", ErrInvalidNonce, acct.Nonce+1, nonce)
	}

	// Ensure that the balance is sufficient
	newBal := new(big.Int).Sub(acct.Balance, amount)
	if newBal.Sign() < 0 {
		return errInsufficientFunds(account, amount, acct.Balance)
	}

	// track valid spends for migration
	// transfers, credits etc need not be tracked as theya re not allowed during migration
	a.recordSpend(account, amount, nonce)

	return a.updateAccount(ctx, tx, account, newBal, nonce)
}

func (a *Accounts) recordSpend(account *types.AccountID, amount *big.Int, nonce int64) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.spends = append(a.spends, &Spend{
		Account: account,
		Amount:  amount,
		Nonce:   uint64(nonce),
	})

	a.log.Debug("Recorded spend", "account", account, "amount", amount, "nonce", nonce)
}

// GetBlockSpends returns all the spends that occurred in the block.
func (a *Accounts) GetBlockSpends() []*Spend {
	a.mtx.RLock()
	defer a.mtx.RUnlock()

	spends := make([]*Spend, len(a.spends))
	for i, spend := range a.spends {
		spends[i] = &Spend{
			Account: spend.Account,
			Amount:  new(big.Int).Set(spend.Amount),
			Nonce:   spend.Nonce,
		}
	}

	return spends
}

// ApplySpend spends an amount from an account. It blocks until the spend is written to the database.
// This is used by the new nodes during migration to replicate spends from the old network to the new network.
// If the account does not have enough funds to spend the amount, spend the entire balance.
// Nonces on the new network take precedence over the old network, so the nonces are not checked.
func (a *Accounts) ApplySpend(ctx context.Context, tx sql.Executor, account *types.AccountID, amount *big.Int, nonce int64) error {
	acct, err := a.getAccount(ctx, tx, account, true)
	if err != nil {
		// Spends should not occur on accounts that do not exist during migration as credits are disabled.
		return err
	}

	// If the balance is insufficient, spend the entire balance, else spend the amount
	newBal := new(big.Int).Sub(acct.Balance, amount)
	if newBal.Sign() < 0 {
		newBal = big.NewInt(0)
	}

	return a.updateAccount(ctx, tx, account, newBal, acct.Nonce)
}

// Transfer transfers an amount from one account to another. If the from account does not have enough funds to transfer the amount,
// it will fail. If the to account does not exist, it will be created. The amount must be greater than 0.
func (a *Accounts) Transfer(ctx context.Context, db sql.TxMaker, from, to *types.AccountID, amt *big.Int) error {
	if amt.Sign() < 0 {
		return ErrNegativeTransfer
	}

	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Ensure that the from account balance is sufficient.
	account, err := a.getAccount(ctx, tx, from, true)
	if err != nil {
		return err
	}

	newFromBal := new(big.Int).Sub(account.Balance, amt)
	if newFromBal.Sign() < 0 {
		return errInsufficientFunds(from, amt, account.Balance)
	}

	// add the balance to the to new account
	receiver, err := a.getAccount(ctx, tx, to, true)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			err2 := a.createAccount(ctx, tx, to, amt, 0)
			if err2 != nil {
				return err2
			}
		} else {
			return err
		}
	} else {
		newToBal := new(big.Int).Add(receiver.Balance, amt)
		err = a.updateAccount(ctx, tx, to, newToBal, receiver.Nonce)
		if err != nil {
			return err
		}
	}

	// decrement the balance from the from account
	err = a.updateAccount(ctx, tx, from, newFromBal, account.Nonce)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// Commit applies all the updates to the in-memory cache.
// This is called after the updates are written to the pg database.
func (a *Accounts) Commit() error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	for k, v := range a.updates {
		evicted := a.records.Put(k, &types.Account{
			ID:      v.ID,
			Balance: v.Balance,
			Nonce:   v.Nonce,
		})
		if evicted > 0 {
			a.log.Debugf("Evicted %d accounts from cache", evicted)
		}
	}

	a.updates = make(map[string]*types.Account)
	a.spends = nil
	return nil
}

func (a *Accounts) Updates() []*types.Account {
	a.mtx.RLock()
	defer a.mtx.RUnlock()

	var updates []*types.Account
	for _, v := range a.updates {
		updates = append(updates, v)
	}

	return updates
}

func (a *Accounts) Rollback() {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.updates = make(map[string]*types.Account)
	a.spends = nil
}

func acctMapKey(account *types.AccountID) string {
	return string(account.Identifier) + "#" + account.KeyType.String()
}

func (a *Accounts) createAccount(ctx context.Context, tx sql.Executor, account *types.AccountID, amt *big.Int, nonce int64) error {
	kd, ok := crypto.KeyTypeDefinition(account.KeyType)
	if !ok {
		return fmt.Errorf("invalid key type: %s", account.KeyType)
	}
	if err := createAccount(ctx, tx, account.Identifier, kd.EncodeFlag(), amt, nonce); err != nil {
		return err
	}

	// Record the account creation in the updates
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.updates[acctMapKey(account)] = &types.Account{
		ID:      account,
		Balance: big.NewInt(0).Set(amt),
		Nonce:   nonce,
	}

	return nil
}

func (a *Accounts) updateAccount(ctx context.Context, tx sql.Executor, account *types.AccountID, amount *big.Int, nonce int64) error {
	kd, ok := crypto.KeyTypeDefinition(account.KeyType)
	if !ok {
		return fmt.Errorf("invalid key type: %s", account.KeyType)
	}
	if err := updateAccount(ctx, tx, account.Identifier, kd.EncodeFlag(), amount, nonce); err != nil {
		return err
	}

	// Record the account update in the updates
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.updates[acctMapKey(account)] = &types.Account{
		ID:      account,
		Balance: big.NewInt(0).Set(amount),
		Nonce:   nonce,
	}
	return nil
}
