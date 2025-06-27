package accounts

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

const (
	schemaName = `kwild_accts`

	accountStoreVersion = 0

	sqlInitTables = `CREATE TABLE IF NOT EXISTS ` + schemaName + `.accounts (
		identifier BYTEA NOT NULL,
		id_type INT4 NOT NULL,
		balance TEXT NOT NULL, -- consider: NUMERIC(32) for uint256 and pgx.Numeric will handle it and provide a *big.Int field
		nonce BIGINT NOT NULL, -- a.k.a. INT8
		PRIMARY KEY(identifier, id_type)
	);`

	sqlCreateAccount = `INSERT INTO ` + schemaName + `.accounts (identifier, id_type, balance, nonce) VALUES ($1, $2, $3, $4)`

	sqlUpdateAccount = `UPDATE ` + schemaName + `.accounts SET balance = $1, nonce = $2
		WHERE identifier = $3 AND id_type = $4`

	sqlGetAccount = `SELECT balance, nonce FROM ` + schemaName + `.accounts WHERE identifier = $1 AND id_type = $2`

	sqlNumAccounts = `SELECT COUNT(1) FROM ` + schemaName + `.accounts`
)

func initTables(ctx context.Context, tx sql.DB) error {
	_, err := tx.Execute(ctx, sqlInitTables)
	if err != nil {
		return fmt.Errorf("failed to initialize tables: %w", err)
	}

	return nil
}

// updateAccount updates the balance and nonce of an account.
func updateAccount(ctx context.Context, db sql.Executor, acctID []byte, acctType uint32, amount *big.Int, nonce int64) error {
	_, err := db.Execute(ctx, sqlUpdateAccount, amount.String(), nonce, acctID, acctType)
	return err
}

// createAccount creates an account with the given identifier and
// initial balance. The nonce will be set to 0.
func createAccount(ctx context.Context, db sql.Executor, acctID []byte, acctType uint32, amt *big.Int, nonce int64) error {
	_, err := db.Execute(ctx, sqlCreateAccount, acctID, acctType, amt.String(), nonce)
	return err
}

func numAccounts(ctx context.Context, db sql.Executor) (int64, error) {
	results, err := db.Execute(ctx, sqlNumAccounts)
	if err != nil {
		return 0, err
	}
	if len(results.Rows) != 1 {
		return 0, fmt.Errorf("expected 1 row, got %d", len(results.Rows))
	}
	if len(results.Rows[0]) != 1 {
		return 0, fmt.Errorf("expected 1 column, got %d", len(results.Rows[0]))
	}
	count, ok := results.Rows[0][0].(int64)
	if !ok { // bug
		return 0, errors.New("failed to convert account count to int64")
	}
	return count, nil
}

// getAccount retrieves an account from the database.
// if the account is not found, it returns nil, ErrAccountNotFound.
func getAccount(ctx context.Context, db sql.Executor, account *types.AccountID) (*types.Account, error) {
	kd, ok := crypto.KeyTypeDefinition(account.KeyType)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %s", account.KeyType)
	}
	results, err := db.Execute(ctx, sqlGetAccount, []byte(account.Identifier), kd.EncodeFlag())
	if err != nil {
		return nil, err
	}

	if len(results.Rows) == 0 {
		return nil, ErrAccountNotFound
	}
	if len(results.Rows) > 1 {
		return nil, fmt.Errorf("expected 1 row, got %d", len(results.Rows))
	}

	stringBal, ok := results.Rows[0][0].(string)
	if !ok {
		return nil, errors.New("failed to convert stored string balance to big int")
	}

	balance, ok := new(big.Int).SetString(stringBal, 10)
	if !ok {
		return nil, ErrConvertToBigInt
	}

	nonce, ok := results.Rows[0][1].(int64)
	if !ok {
		return nil, errors.New("failed to convert stored nonce to int64")
	}

	return &types.Account{
		ID: &types.AccountID{
			Identifier: account.Identifier,
			KeyType:    account.KeyType,
		},
		Balance: big.NewInt(0).Set(balance),
		Nonce:   nonce,
	}, nil
}
