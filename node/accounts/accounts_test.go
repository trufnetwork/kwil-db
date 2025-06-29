package accounts

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"

	"github.com/decred/dcrd/container/lru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTx struct {
	*mockDB
}

func (m *mockTx) Commit(ctx context.Context) error {
	return nil
}

func (m *mockTx) Rollback(ctx context.Context) error {
	return nil
}

type mockDB struct {
	accessCnt int64
	accts     map[string]*types.Account
}

func newDB() *mockDB {
	return &mockDB{
		accts: make(map[string]*types.Account),
	}
}

func (m *mockDB) BeginTx(ctx context.Context) (sql.Tx, error) {
	return &mockTx{m}, nil
}

func (m *mockDB) Execute(ctx context.Context, stmt string, args ...any) (*sql.ResultSet, error) {
	// mock some expected queries from internal functions
	switch stmt {
	case sqlCreateAccount: // via createAccount and createAccountWithNonce
		acctID := args[0].([]byte)
		idType := args[1].(uint32)
		bal, ok := big.NewInt(0).SetString(args[2].(string), 10)
		if !ok {
			return nil, errors.New("not a string balance")
		}

		keyType, err := crypto.ParseKeyTypeID(idType)
		if err != nil {
			return nil, err
		}

		acct := &types.AccountID{
			Identifier: acctID,
			KeyType:    keyType,
		}

		m.accts[acctMapKey(acct)] = &types.Account{
			ID:      acct,
			Nonce:   args[3].(int64),
			Balance: bal,
		}
		return &sql.ResultSet{
			Status: sql.CommandTag{
				RowsAffected: 1,
				Text:         `INSERT ...`,
			},
		}, nil
	case sqlUpdateAccount: // via updateAccount
		bal, ok := big.NewInt(0).SetString(args[0].(string), 10)
		if !ok {
			return nil, errors.New("not a string balance")
		}
		nonce := args[1].(int64)

		acctID, idType := args[2].([]byte), args[3].(uint32)
		keyType, err := crypto.ParseKeyTypeID(idType)
		if err != nil {
			return nil, err
		}
		acct := &types.AccountID{
			Identifier: acctID,
			KeyType:    keyType,
		}

		account, ok := m.accts[acctMapKey(acct)]
		if !ok {
			return &sql.ResultSet{
				Status: sql.CommandTag{
					RowsAffected: 0,
					Text:         `UPDATE ...`,
				},
			}, nil
		}

		account.Balance = bal
		account.Nonce = nonce

		return &sql.ResultSet{
			Status: sql.CommandTag{
				RowsAffected: 1,
				Text:         `UPDATE ...`,
			},
		}, nil
	case sqlGetAccount: // via getAccount
		m.accessCnt++
		acctID, idType := args[0].([]byte), args[1].(uint32)
		keyType, err := crypto.ParseKeyTypeID(idType)
		if err != nil {
			return nil, err
		}
		acct := &types.AccountID{
			Identifier: acctID,
			KeyType:    keyType,
		}
		account, ok := m.accts[acctMapKey(acct)]
		if !ok {
			return &sql.ResultSet{}, nil // not ErrNoRows since we don't use Scan in pg
		}
		return &sql.ResultSet{
			Columns: []string{"balance", "nonce"},
			Rows: [][]any{
				{account.Balance.String(), account.Nonce},
			},
		}, nil
	default:
		return nil, errors.New("bad query")
	}
}

func (m *mockDB) count() int64 {
	return m.accessCnt
}

type counter interface {
	count() int64
}

var (
	account1 = &types.AccountID{
		Identifier: []byte("account1"),
		KeyType:    crypto.KeyTypeSecp256k1,
	}
	account2 = &types.AccountID{
		Identifier: []byte("account2"),
		KeyType:    crypto.KeyTypeSecp256k1,
	}
	account3 = &types.AccountID{
		Identifier: []byte("account3"),
		KeyType:    crypto.KeyTypeSecp256k1,
	}
)

type acctsTestCase struct {
	name string
	fn   func(t *testing.T, db sql.DB, accounts *Accounts, counter counter, skip bool)
}

func verifyDBAccessCount(t *testing.T, c counter, expected int64, skip bool) {
	if skip {
		return
	}

	assert.Equal(t, expected, c.count())
}

// once we have a way to increase balances in accounts, we will have to add tests
// for spending a valid amount
var acctsTestCases = []acctsTestCase{
	{
		name: "credit and debit",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)

			err = a.Credit(ctx, tx, account1, big.NewInt(100))
			require.NoError(t, err)
			// first credit, access db
			verifyDBAccessCount(t, c, 1, skip)

			key := acctMapKey(account1)
			_, ok := a.records.Get(key)
			require.False(t, ok)

			acct, ok := a.updates[key]
			require.True(t, ok)
			assert.Equal(t, int64(100), acct.Balance.Int64())

			err = a.Credit(ctx, tx, account1, big.NewInt(-100))
			require.NoError(t, err)
			// hits the cache
			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "debit non-existent account",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Credit(ctx, db, account1, big.NewInt(-100))
			require.ErrorIs(t, err, ErrNegativeBalance)
			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "credit and over-debit",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Credit(ctx, db, account1, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			err = a.Credit(ctx, db, account1, big.NewInt(-101))
			require.ErrorIs(t, err, ErrNegativeBalance)
			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "transfer to nonexistent account",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Credit(ctx, db, account1, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			err = a.Transfer(ctx, db, account1, account2, big.NewInt(100))
			require.NoError(t, err)
			// acct1 is in cache, acct2 is not
			verifyDBAccessCount(t, c, 1, skip)

			acc, err := a.GetAccount(ctx, db, account1)
			require.NoError(t, err)
			require.Equal(t, acc.Balance.Int64(), int64(0))
			verifyDBAccessCount(t, c, 1, skip)

			acc, err = a.GetAccount(ctx, db, account2)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(100), acc.Balance)
			verifyDBAccessCount(t, c, 2, skip)
		},
	},
	{
		name: "transfer to existing account",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Credit(ctx, db, account1, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			err = a.Credit(ctx, db, account2, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 2, skip)

			err = a.Transfer(ctx, db, account1, account2, big.NewInt(50))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 2, skip)

			acc, err := a.GetAccount(ctx, db, account1)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(50), acc.Balance)

			acc, err = a.GetAccount(ctx, db, account2)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(150), acc.Balance)
			verifyDBAccessCount(t, c, 2, skip)
		},
	},
	{
		name: "transfer negative amount",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Credit(ctx, db, account1, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			err = a.Transfer(ctx, db, account1, account2, big.NewInt(-50))
			require.ErrorIs(t, err, ErrNegativeTransfer)
			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "transfer more than you have",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Credit(ctx, db, account1, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			err = a.Transfer(ctx, db, account1, account2, big.NewInt(150))
			require.ErrorIs(t, err, ErrInsufficientFunds)
			verifyDBAccessCount(t, c, 1, skip) // acct2 is not accessed as the transfer is invalid
		},
	},
	{
		name: "get non existent account",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			acc, err := a.GetAccount(ctx, db, account1)
			require.NoError(t, err)

			require.Equal(t, big.NewInt(0), acc.Balance)
			require.Equal(t, int64(0), acc.Nonce)
			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "spend from non existent account",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Spend(ctx, db, account1, big.NewInt(100), 1)
			require.ErrorIs(t, err, ErrAccountNotFound)
			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "spend more than you have",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Credit(ctx, db, account1, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			err = a.Spend(ctx, db, account1, big.NewInt(101), 1)
			require.ErrorIs(t, err, ErrInsufficientFunds)

			acc, err := a.GetAccount(ctx, db, account1)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(100), acc.Balance)
			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "spend with invalid nonce",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {

			ctx := context.Background()

			err := a.Credit(ctx, db, account1, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			err = a.Spend(ctx, db, account1, big.NewInt(50), 2)
			require.ErrorIs(t, err, ErrInvalidNonce)

			acc, err := a.GetAccount(ctx, db, account1)
			require.NoError(t, err)

			require.Equal(t, big.NewInt(100), acc.Balance)
			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "valid spend",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Credit(ctx, db, account1, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			err = a.Spend(ctx, db, account1, big.NewInt(50), 1)
			require.NoError(t, err)

			acc, err := a.GetAccount(ctx, db, account1)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(50), acc.Balance)
			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "spend 0 on non-existent account",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			err := a.Spend(ctx, db, account1, big.NewInt(0), 1)
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			acc, err := a.GetAccount(ctx, db, account1)
			require.NoError(t, err)
			assert.Equal(t, big.NewInt(0), acc.Balance)

			require.Equal(t, big.NewInt(0), acc.Balance)
			require.Equal(t, int64(1), acc.Nonce)

			verifyDBAccessCount(t, c, 1, skip)
		},
	},
	{
		name: "Account Cache test",
		fn: func(t *testing.T, db sql.DB, a *Accounts, c counter, skip bool) {
			ctx := context.Background()

			mapKey := acctMapKey(account1)
			_, ok := a.records.Get(mapKey)
			require.False(t, ok)

			err := a.Spend(ctx, db, account1, big.NewInt(0), 1)
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip)

			require.Equal(t, uint32(0), a.records.Len())

			// commit, for the update to be reflected in the cache
			err = a.Commit()
			require.NoError(t, err)

			// len of the cache = 1
			require.Equal(t, uint32(1), a.records.Len())
			_, ok = a.records.Get(mapKey)
			require.True(t, ok)

			// retrieve the account again
			_, err = a.GetAccount(ctx, db, account1)
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 1, skip) // cache hit, no new db accesses

			// access new account
			err = a.Credit(ctx, db, account2, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 2, skip) // cache miss, new db access
			require.Equal(t, uint32(1), a.records.Len())

			err = a.Commit()
			require.NoError(t, err)
			require.Equal(t, uint32(2), a.records.Len())

			// access account1 again
			_, err = a.GetAccount(ctx, db, account1)
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 2, skip) // cache hit, no new db accesses

			// access new account
			err = a.Credit(ctx, db, account3, big.NewInt(100))
			require.NoError(t, err)
			verifyDBAccessCount(t, c, 3, skip) // cache miss, new db access
			require.Equal(t, uint32(2), a.records.Len())

			err = a.Commit()
			require.NoError(t, err)
			require.Equal(t, uint32(2), a.records.Len())

			// this access should have evicted account2 rather than account1
			// as account1 was accessed more recently
			require.Equal(t, uint32(2), a.records.Len())
			_, ok = a.records.Get(acctMapKey(account1))
			require.True(t, ok)
			_, ok = a.records.Get(acctMapKey(account2))
			require.False(t, ok)
		},
	},
}

func Test_Accounts(t *testing.T) {
	for _, tc := range acctsTestCases {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB()
			ctx := context.Background()
			tx, _ := db.BeginTx(ctx)

			accounts := &Accounts{
				records: lru.NewMap[string, *types.Account](2),
				updates: make(map[string]*types.Account),
				log:     log.DiscardLogger,
			}

			tc.fn(t, tx, accounts, db, true)
		})
	}
}
