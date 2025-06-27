package common

import (
	"context"
	"fmt"
	"math/big"
	"strconv"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// Service provides access to general application information to
// extensions.
type Service struct {
	// Logger is a logger for the application
	Logger log.Logger

	// GenesisConfig is the genesis configuration of the network.
	GenesisConfig *config.GenesisConfig

	// LocalConfig is the local configuration of the node.
	LocalConfig *config.Config

	// Identity is the node/validator identity (pubkey).
	Identity []byte // maybe this actuall needs to be crypto.PubKey???
}

// NameLogger returns a new Service with the logger named.
// Every other field is the same pointer as the original.
func (s *Service) NamedLogger(name string) *Service {
	return &Service{
		Logger:        s.Logger.New(name),
		GenesisConfig: s.GenesisConfig,
		LocalConfig:   s.LocalConfig,
		Identity:      s.Identity,
	}
}

// App is an application that can modify and query the local database
// instance.
type App struct {
	// Service is the base application
	Service *Service
	// DB is a connection to the underlying Postgres database
	DB sql.DB
	// Engine is the underlying KwilDB engine, capable of storing and
	// executing against Kuneiform schemas
	Engine Engine
	// Accounts is the account manager for the application
	Accounts Accounts
	// Validators is the validator manager for the application
	Validators Validators
}

// TxContext is contextual information provided to a transaction execution Route
// handler. This is defined in common as it is used by both the internal txapp
// router and extension implementations in extensions/consensus.
type TxContext struct {
	Ctx context.Context
	// BlockContext is the context of the current block.
	BlockContext *BlockContext
	// TxID is the ID of the current transaction.
	TxID string
	// Signer is the public key of the transaction signer.
	Signer []byte
	// Caller is the string identifier of the transaction signer.
	// It is derived from the signer's registered authenticator.
	Caller string
	// Authenticator is the authenticator used to sign the transaction.
	Authenticator string
	// values is a map of values that can be set and retrieved by extensions.
	values map[string]any
}

// SetValue sets a value in the transaction context that can
// be retrieved later.
func (t *TxContext) SetValue(s string, v any) {
	if t.values == nil {
		t.values = make(map[string]any)
	}
	t.values[s] = v
}

// Value retrieves a value from the transaction context.
// If it does not exist, the second return value will be false.
func (t *TxContext) Value(s string) (any, bool) {
	if t.values == nil {
		return nil, false
	}
	v, ok := t.values[s]
	return v, ok
}

// EngineContext is a context that is passed to the engine when executing
// an action or statement.
type EngineContext struct {
	// TxContext is the transaction context of the current transaction.
	TxContext *TxContext
	// OverrideAuthz is a flag that indicates whether the authorization
	// should be overridden. This is used to allow extensions to perform
	// owner-level operations on the database, even if the caller is not
	// the owner.
	OverrideAuthz bool
	// InvalidTxCtx is a flag that indicates whether the transaction context
	// is valid / can be used. There are times when the engine is called
	// while not within a transaction (e.g. by extensions to read in metadata)
	// on startup. In these cases, the transaction context is not valid.
	// This will disable all system variables (e.g. @caller). If users are
	// not in a transaction but still want to use system variables (e.g. in an
	// RPC making read-only calls to the engine), they should set this to false,
	// and make sure to create a fake transaction context.
	// If InvalidTxCtx is set to true, OverrideAuthz should also be set to true.
	InvalidTxCtx bool
}

func (e *EngineContext) Valid() error {
	if e.InvalidTxCtx && !e.OverrideAuthz {
		return fmt.Errorf("invalid transaction context: If InvalidTxCtx is set to true, OverrideAuthz should also be set to true")
	}
	return nil
}

type Engine interface {
	// Call calls an action in the database. The resultFn callback is
	// called for each row in the result set. If the resultFn returns
	// an error, the call will be aborted and the error will be returned.
	Call(ctx *EngineContext, db sql.DB, namespace, action string, args []any, resultFn func(*Row) error) (*CallResult, error)
	// CallWithoutEngineCtx calls an action in the database without needing
	// an engine context. This is useful for extensions that need to interact
	// with the engine outside of a transaction. If possible, use Call instead.
	CallWithoutEngineCtx(ctx context.Context, db sql.DB, namespace, action string, args []any, resultFn func(*Row) error) (*CallResult, error)
	// Execute executes a statement in the database. The fn callback is
	// called for each row in the result set. If the fn returns an error,
	// the call will be aborted and the error will be returned.
	Execute(ctx *EngineContext, db sql.DB, statement string, params map[string]any, fn func(*Row) error) error
	// ExecuteWithoutEngineCtx executes a statement in the database without
	// needing an engine context. This is useful for extensions that need to
	// interact with the engine outside of a transaction. If possible, use
	// Execute instead.
	ExecuteWithoutEngineCtx(ctx context.Context, db sql.DB, statement string, params map[string]any, fn func(*Row) error) error
}

// CallResult is the result of a call to an action.
// It does not include the records, as they should be consumed
// via the resultFn callback.
type CallResult struct {
	// Logs are the logs generated by the action.
	Logs []string
	// Error is an error that is raised during code execution.
	// It is explicitly used for user-defined exceptions thrown
	// with the `error` function.
	Error error // TODO: implement
}

// FormatLogs formats the logs into a string.
func (c *CallResult) FormatLogs() string {
	i := 0
	var str string
	for _, l := range c.Logs {
		if i > 0 {
			str += "\n"
		}
		// increment before formatting so that the first log is 1
		i++
		str += strconv.Itoa(i) + ". " + l

	}

	return str
}

// Row contains information about a row in a table.
type Row struct {
	// ColumnNames are the names of the columns in the row.
	ColumnNames []string
	// ColumnTypes are the types of the columns in the row.
	ColumnTypes []*types.DataType
	// Values are the values of the columns in the row.
	// It is one of the following types:
	// nil, string, int64, []byte, bool, *types.UUID, *types.Decimal,
	// []*string, []*int64, [][]byte, []*bool, []*types.UUID, []*types.Decimal
	Values []any
}

// Accounts is an interface for managing accounts on the Kwil network. It
// should be used to credit, debit, and transfer funds between Kwil accounts.
type Accounts interface {
	// Credit credits an account with the given amount. If the account
	// does not exist, it will be created. A negative amount will be
	// treated as a debit. Accounts cannot have negative balances, and
	// will return an error if the amount would cause the balance to go
	// negative.
	Credit(ctx context.Context, tx sql.Executor, account *types.AccountID, balance *big.Int) error
	// Transfer transfers an amount from one account to another. If the
	// from account does not have enough funds to transfer the amount,
	// it will fail. If the to account does not exist, it will be
	// created. The amount must be greater than 0.
	Transfer(ctx context.Context, tx sql.TxMaker, from, to *types.AccountID, amt *big.Int) error
	// GetAccount retrieves the account with the given identifier. If the
	// account does not exist, it will return an account with a balance
	// of 0 and a nonce of 0.
	GetAccount(ctx context.Context, tx sql.Executor, account *types.AccountID) (*types.Account, error)
	// ApplySpend applies a spend to the account. If the account does not
	// exist, it will be created. If the account does not have enough
	// funds to spend the amount, the entire balance will be spent and
	// the spend will fail.
	ApplySpend(ctx context.Context, tx sql.Executor, account *types.AccountID, amount *big.Int, nonce int64) error
}

// Validators is an interface for managing validators on the Kwil network.
type Validators interface {
	// GetValidatorPower retrieves the power of the given validator. If
	// the validator does not exist, it will return 0.
	GetValidatorPower(ctx context.Context, pubKey []byte, pubKeyType crypto.KeyType) (int64, error)
	// GetValidators retrieves all validators.
	GetValidators() []*types.Validator
	// SetValidatorPower sets the power of a validator. If the target
	// validator does not exist, it will be created with the given power.
	// If set to 0, the target validator will be deleted, and will no
	// longer be considered a validator. It will return an error if a
	// negative power is given.
	SetValidatorPower(ctx context.Context, tx sql.Executor, pubKey []byte, pubKeyType crypto.KeyType, power int64) error
}
