package consensus

import (
	"context"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"

	"math/big"
)

// Payload defines a new transaction payload, including it's type and the
// Route (pricer plus execution handler for the TxApp). There does not seem to
// be a purpose for including the underlying type or a codec for it here since
// the route is the sole interpreter of the payload.
type Payload struct {
	Type  types.PayloadType
	Route Route // must be from here or common, not an internal
}

// Route is type that TxApp requires to execute externally defined routes.
type Route interface {
	// Name returns a string that identifies the route.
	Name() string
	// Price estimates the cost to execute a transaction. Most implementations
	// return a constant value; the App and Transaction will play a role when
	// cost is based on the details of the transaction and the state of the
	// database.
	Price(ctx context.Context, app *common.App, tx *types.Transaction) (*big.Int, error)
	// PreTx performs preliminary actions prior to any database operations,
	// which must be executed inside of the inner transaction created by the
	// router to isolate query failures, ensuring updates to account nonce and
	// balance occur regardless of execution outcome. A Service instance is
	// provided so the route may perform logging or access the node identity if
	// required by the route. This returns a TxCode that indicates should be
	// returned by the router in case of an error. A route may perform all
	// actions with InTx, but others may use PreTx for initial validation prior
	// to creating a nested transaction with the DB backend (expensive).
	PreTx(ctx *common.TxContext, svc *common.Service, tx *types.Transaction) (types.TxCode, error)
	// InTx executes the transaction, which may include state changes via the DB
	// or Engine. The TxCode is returned by the Router, and it should be CodeOk
	// for a nil error.
	InTx(ctx *common.TxContext, app *common.App, tx *types.Transaction) (types.TxCode, string, error)
}
