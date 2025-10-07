// package tx_router routes transactions to the appropriate module(s)
package txapp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/core/utils/order"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
	"github.com/trufnetwork/kwil-db/extensions/hooks"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
	"github.com/trufnetwork/kwil-db/node/accounts"
	"github.com/trufnetwork/kwil-db/node/meta"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"
)

// TxApp is the transaction processor for the Kwil node.
// It is responsible for interpreting payload bodies and routing them properly,
// maintaining a mempool for uncommitted accounts, pricing transactions,
// managing atomicity of the database, and managing the validator set.
type TxApp struct {
	Engine     common.Engine // tracks deployed schemas
	Accounts   Accounts      // tracks account balances and nonces
	Validators Validators    // tracks validator power

	service *common.Service
	// forks forks.Forks

	events Rebroadcaster
	signer auth.Signer

	mempool *mempool

	// list of resolution types
	resTypes []string // How do these get updated runtime?

	// approvedJoins track the join requests approved by this node,
	// reset after every commit
	approvedJoins []*types.AccountID
}

// NewTxApp creates a new router.
func NewTxApp(ctx context.Context, db sql.Executor, engine common.Engine, signer auth.Signer,
	events Rebroadcaster, service *common.Service, accounts Accounts, validators Validators) (*TxApp, error) {
	resTypes := resolutions.ListResolutions()
	slices.Sort(resTypes)

	t := &TxApp{
		Engine:     engine,
		Accounts:   accounts,
		Validators: validators,

		events: events,
		mempool: &mempool{
			accounts:     make(map[string]*types.Account),
			accountMgr:   accounts,
			validatorMgr: validators,
			nodeIdent:    signer,
			log:          service.Logger.New("mempool"),
		},
		signer:   signer,
		resTypes: resTypes,
		service:  service,
	}
	// t.forks.FromMap(service.GenesisConfig.ForkHeights)
	return t, nil
}

// UpdateNodeStatus updates the service's NodeStatus provider.
// This should be called after the BlockProcessor is created to wire up
// the node status for extensions to use.
func (r *TxApp) UpdateNodeStatus(nodeStatus common.NodeStatusProvider) {
	r.service.NodeStatus = nodeStatus
}

// GenesisInit initializes the TxApp. It must be called outside of a session,
// and before any session is started.
// It can assign the initial validator set and initial account balances.
// It is only called once for a new chain.
func (r *TxApp) GenesisInit(ctx context.Context, db sql.DB, genCfg *config.GenesisConfig, chainCtx *common.ChainContext) error {
	// Add Genesis Validators
	for _, validator := range genCfg.Validators {
		err := r.Validators.SetValidatorPower(ctx, db, validator.Identifier, validator.KeyType, validator.Power)
		if err != nil {
			return err
		}
	}

	// Fund Genesis Accounts
	for _, alloc := range genCfg.Allocs {
		keyType, err := crypto.ParseKeyType(alloc.KeyType)
		if err != nil {
			return err
		}

		err = r.Accounts.Credit(ctx, db, &types.AccountID{
			Identifier: alloc.ID.HexBytes,
			KeyType:    keyType,
		}, alloc.Amount)
		if err != nil {
			return err
		}
	}

	initialHash := types.Hash{}
	if len(genCfg.StateHash) == types.HashLen {
		copy(initialHash[:], genCfg.StateHash)
	}

	// we set an initial owner as the initial creator of schemas, roles, etc.
	err := r.Engine.ExecuteWithoutEngineCtx(ctx, db, "TRANSFER OWNERSHIP TO $user", map[string]any{
		"user": genCfg.DBOwner,
	}, nil)
	if err != nil {
		return err
	}

	// genesis hooks
	for _, hook := range hooks.ListGenesisHooks() {
		err := hook.Hook(ctx, &common.App{
			Service:    r.service.NamedLogger(hook.Name),
			DB:         db,
			Engine:     r.Engine,
			Accounts:   r.Accounts,
			Validators: r.Validators,
		}, chainCtx)
		if err != nil {
			return fmt.Errorf("error running genesis hook %s: %w", hook.Name, err)
		}
	}

	return nil
}

// Begin signals that a new block has begun. This creates an outer database
// transaction that may be committed, or rolled back on error or crash.
// It is given the starting networkParams, and is expected to use them to
// use them to store any changes to the network parameters in the database during Finalize.
func (r *TxApp) Begin(ctx context.Context, height int64) error {
	// Before executing transaction in this block, add/remove/update functionality.
	// TODO: active forks, not for the beta
	return nil
}

// Execute executes a transaction.  It will route the transaction to the
// appropriate module(s) for execution and return the response.
// This method must only be called from the consensus engine,
// sequentially, when executing transactions in a block.
func (r *TxApp) Execute(ctx *common.TxContext, db sql.DB, tx *types.Transaction) *TxResponse {
	// RegisterRoute call is not concurrent
	route, ok := routes[tx.Body.PayloadType.String()]
	if !ok {
		return txRes(nil, types.CodeInvalidTxType, "", fmt.Errorf("%w: %s", types.ErrUnknownPayloadType, tx.Body.PayloadType.String()))
	}

	r.service.Logger.Debug("executing transaction", "tx", tx)

	// no need to error out if we cannot track the validator join approval
	r.trackValidatorJoinApprovals(tx)

	// track event count
	return route.Execute(ctx, r, db, tx)
}

// trackValidatorJoinApprovals tracks validator join approvals from this node.
// This is used to add these validators to the peer whitelist.
func (r *TxApp) trackValidatorJoinApprovals(tx *types.Transaction) {
	if tx.Body.PayloadType != types.PayloadTypeValidatorApprove {
		return
	}

	// only track approvals from this node
	if !bytes.Equal(tx.Sender, r.signer.CompactID()) {
		return
	}

	approve := &types.ValidatorApprove{}
	if err := approve.UnmarshalBinary(tx.Body.Payload); err != nil {
		return
	}

	r.approvedJoins = append(r.approvedJoins, &types.AccountID{
		Identifier: approve.Candidate,
		KeyType:    approve.KeyType,
	})
}

// Finalize signals that a block has been finalized. No more changes can be
// applied to the database.
func (r *TxApp) Finalize(ctx context.Context, db sql.DB, block *common.BlockContext) (approvedJoins, expiredJoins []*types.AccountID, err error) {
	expiredJoins, err = r.processVotes(ctx, db, block)
	if err != nil {
		return nil, nil, err
	}

	// end block hooks
	for _, hook := range hooks.ListEndBlockHooks() {
		err := hook.Hook(ctx, &common.App{
			Service:    r.service.NamedLogger(hook.Name),
			DB:         db,
			Engine:     r.Engine,
			Accounts:   r.Accounts,
			Validators: r.Validators,
		}, block)
		if err != nil {
			return nil, nil, fmt.Errorf("error running end block hook: %w", err)
		}
	}

	return r.approvedJoins, expiredJoins, nil
}

// Commit signals that a block's state changes should be committed.
func (r *TxApp) Commit() error {
	r.Accounts.Commit()
	r.Validators.Commit()

	r.mempool.reset()
	r.approvedJoins = nil
	return nil
}

func (r *TxApp) Rollback() {
	r.Accounts.Rollback()
	r.Validators.Rollback()

	r.mempool.reset() // will issue recheck before next block
	r.approvedJoins = nil
}

// processVotes confirms resolutions that have been approved by the network,
// expires resolutions that have expired, and properly credits proposers and voters.
func (r *TxApp) processVotes(ctx context.Context, db sql.DB, block *common.BlockContext) ([]*types.AccountID, error) {
	credits := make(creditMap)

	var finalizedIDs []*types.UUID
	// markedProcessedIDs is a separate list for marking processed, since we do not want to process validator resolutions
	// validator vote IDs are not unique, so we cannot mark them as processed, in case a validator leaves and joins again
	var markProcessedIDs []*types.UUID
	// resolveFuncs tracks the resolve function for each resolution, in the order they are queried.
	// we track this and execute all of these functions after we have found all confirmed resolutions
	// because a resolve function can change a validator's power. This would then change the required power
	// for subsequent resolutions in the same block, which should not happen.
	var resolveFuncs []*struct {
		Resolution  *resolutions.Resolution
		ResolveFunc func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext) error
	}

	totalPower := r.validatorSetPower()

	for _, resolutionType := range r.resTypes {
		cfg, err := resolutions.GetResolution(resolutionType)
		if err != nil {
			return nil, fmt.Errorf("error getting resolution config: %w", err)
		}

		finalized, err := getResolutionsByThresholdAndType(ctx, db, cfg.ConfirmationThreshold, resolutionType, totalPower)
		if err != nil {
			return nil, fmt.Errorf("error getting resolutions: %w", err)
		}

		for _, resolution := range finalized {
			credits.applyResolution(resolution)
			finalizedIDs = append(finalizedIDs, resolution.ID)

			// we do not want to mark processed for validator join and remove events, as they can occur again
			if resolution.Type != voting.ValidatorJoinEventType && resolution.Type != voting.ValidatorRemoveEventType {
				markProcessedIDs = append(markProcessedIDs, resolution.ID)
			}

			resolveFuncs = append(resolveFuncs, &struct {
				Resolution  *resolutions.Resolution
				ResolveFunc func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext) error
			}{
				Resolution:  resolution,
				ResolveFunc: cfg.ResolveFunc,
			})
		}
	}

	// apply all resolutions
	for _, resolveFunc := range resolveFuncs {
		r.service.Logger.Debug("resolving resolution", "type", resolveFunc.Resolution.Type, "id", resolveFunc.Resolution.ID.String())

		tx, err := db.BeginTx(ctx)
		if err != nil {
			return nil, fmt.Errorf("error starting resolution transaction: %w", err)
		}

		err = resolveFunc.ResolveFunc(ctx, &common.App{
			Service:    r.service.NamedLogger("RESOLVE[" + resolveFunc.Resolution.Type + "]"),
			DB:         tx,
			Engine:     r.Engine,
			Accounts:   r.Accounts,
			Validators: r.Validators,
		}, resolveFunc.Resolution, block) // block context include chain context, and thus network params and param updates
		if err != nil {
			r.service.Logger.Warn("error resolving resolution", "type", resolveFunc.Resolution.Type, "id", resolveFunc.Resolution.ID.String(), "error", err)

			if err2 := tx.Rollback(ctx); err2 != nil {
				r.service.Logger.Warn("error rolling back nested resolution transaction", "error", err2)
				return nil, fmt.Errorf("error rolling back transaction: %w", err2)
			}

			// If a resolveFunc fails, we should still continue on, since it
			// simply means some business logic failed in a deployed schema.
			continue
		}

		err = tx.Commit(ctx)
		if err != nil {
			return nil, fmt.Errorf("error committing resolution transaction: %w", err)
		}
	}

	// now we will expire resolutions
	expired, err := getExpired(ctx, db, block.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("error getting expired resolutions: %w", err)
	}

	expiredIDs := make([]*types.UUID, 0, len(expired))
	requiredPowerMap := make(map[string]int64) // map of resolution type to required power

	expiredJoins := make([]*types.AccountID, 0)
	for _, resolution := range expired {
		expiredIDs = append(expiredIDs, resolution.ID)
		if resolution.Type != voting.ValidatorJoinEventType && resolution.Type != voting.ValidatorRemoveEventType {
			markProcessedIDs = append(markProcessedIDs, resolution.ID)
		}

		if resolution.Type == voting.ValidatorJoinEventType {
			req := &voting.UpdatePowerRequest{}
			if err := req.UnmarshalBinary(resolution.Body); err != nil {
				return nil, fmt.Errorf("failed to unmarshal join request: %w", err)
			}

			expiredJoins = append(expiredJoins, &types.AccountID{
				Identifier: req.PubKey,
				KeyType:    req.PubKeyType,
			})
		}

		threshold, ok := requiredPowerMap[resolution.Type]
		if !ok {
			cfg, err := resolutions.GetResolution(resolution.Type)
			if err != nil {
				return nil, fmt.Errorf("error getting resolution config: %w", err)
			}

			// we need to use each configured resolutions refund threshold
			requiredPowerMap[resolution.Type] = requiredPower(ctx, db, cfg.RefundThreshold, totalPower)
		}
		// if it has enough power, we will still refund
		refunded := resolution.ApprovedPower >= threshold
		if refunded {
			credits.applyResolution(resolution)
		}

		r.service.Logger.Info("expiring resolution", "type", resolution.Type, "id", resolution.ID.String(), "refunded", refunded)
	}

	allIDs := append(finalizedIDs, expiredIDs...)
	err = deleteResolutions(ctx, db, allIDs...)
	if err != nil {
		return nil, fmt.Errorf("error deleting resolutions: %w", err)
	}

	err = markProcessed(ctx, db, markProcessedIDs...)
	if err != nil {
		return nil, fmt.Errorf("error marking resolutions as processed: %w", err)
	}

	// This is to ensure that the nodes that never get to vote on this event due to limitation
	// per block vote sizes, they never get to vote and essentially delete the event
	// So this is handled instead when the nodes are approved.
	err = deleteEvents(ctx, db, markProcessedIDs...)
	if err != nil {
		return nil, fmt.Errorf("error deleting events: %w", err)
	}

	// now we will apply credits if gas is enabled.
	// Since it is a map, we need to order it for deterministic results.
	if !block.ChainContext.NetworkParameters.DisabledGasCosts {
		for _, kv := range order.OrderMap(credits) {
			parts := strings.Split(kv.Key, "#")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid key in credit map: %s", kv.Key)
			}

			pubKey, err := hex.DecodeString(parts[0])
			if err != nil {
				return nil, fmt.Errorf("failed to decode public key: %w", err)
			}

			keyType, err := crypto.ParseKeyType(parts[1])
			if err != nil {
				return nil, fmt.Errorf("failed to parse key type: %w", err)
			}

			acct := &types.AccountID{
				Identifier: pubKey,
				KeyType:    keyType,
			}

			err = r.Accounts.Credit(ctx, db, acct, kv.Value)
			if err != nil {
				return nil, fmt.Errorf("error crediting account: %w", err)
			}
		}
	}

	return expiredJoins, nil
}

var (
	ValidatorVoteBodyBytePrice int64 = 1000                  // Per byte cost
	ValidatorVoteIDPrice             = big.NewInt(1000 * 16) // 16 bytes for the UUID
)

// creditMap maps string(public_keys#keytype) to big.Int amounts that should be credited
type creditMap map[string]*big.Int

// applyResolution will calculate the rewards for the proposer and voters of a resolution.
// it will add the rewards to the credit map.
func (c creditMap) applyResolution(res *resolutions.Resolution) {
	// reward voters.
	// this will include the proposer, even if they did not submit a vote id

	for _, voter := range res.Voters {
		// if the voter is the proposer, then we will reward them below,
		// since extra logic is required if they did not submit a vote id
		if bytes.Equal(voter.Identifier, res.Proposer.Identifier) {
			continue
		}
		id := fmt.Sprintf("%s#%s", voter.Identifier.String(), voter.KeyType)

		currentBalance, ok := c[id]
		if !ok {
			currentBalance = big.NewInt(0)
		}

		c[id] = big.NewInt(0).Add(currentBalance, ValidatorVoteIDPrice)
	}

	bodyCost := big.NewInt(ValidatorVoteBodyBytePrice * int64(len(res.Body)))
	proposerKey := config.EncodePubKeyAndType(res.Proposer.Identifier, res.Proposer.KeyType)
	currentBalance, ok := c[proposerKey]
	if !ok {
		currentBalance = big.NewInt(0)
	}

	// reward proposer
	c[proposerKey] = big.NewInt(0).Add(currentBalance, bodyCost)
}

// TxResponse is the response from a transaction.
// It contains information about the transaction, such as the amount spent.
type TxResponse struct {
	// ResponseCode is the response code from the transaction
	ResponseCode types.TxCode

	// Spend is the amount of tokens spent by the transaction
	Spend int64

	// Log is a formatted log message from the DB that is associated with the transaction
	Log string

	// Error is the error returned by the transaction, if any
	Error error
}

// txRes wraps a spend, tx code, and error into a tx response.
// the spend amount is included because an error can occur after the tokens
// are spent.
func txRes(spend *big.Int, code types.TxCode, log string, err error) *TxResponse {
	if spend == nil {
		spend = big.NewInt(0)
	}

	return &TxResponse{
		ResponseCode: code,
		Spend:        spend.Int64(),
		Log:          log,
		Error:        err,
	}
}

// Price estimates the price of a transaction.
// It returns the estimated price in tokens.
func (r *TxApp) Price(ctx context.Context, dbTx sql.DB, tx *types.Transaction, chainContext *common.ChainContext) (*big.Int, error) {
	if chainContext.NetworkParameters.DisabledGasCosts {
		return big.NewInt(0), nil
	}

	route := getRoute(tx.Body.PayloadType.String())
	if route == nil {
		return nil, fmt.Errorf("%w: %s", types.ErrUnknownPayloadType, tx.Body.PayloadType.String())
	}

	return route.Price(ctx, r, dbTx, tx)
}

// checkAndSpend checks the price of a transaction.
// It requires a tx, so that spends can be made transactional with other database interactions.
// it returns the price it will cost to execute the transaction.
// if the transaction does not have enough tokens to pay for the transaction,
// it will return an error.
// if the caller does not have enough tokens to pay for the transaction,
// it will return an error.
// if the transaction does not have the correct nonce, it will return an error.
// it will spend the tokens if the caller has enough tokens.
// It also returns an error code.
// if we allow users to implement their own routes, this function will need to
// be exported.
func (r *TxApp) checkAndSpend(ctx *common.TxContext, tx *types.Transaction, pricer Pricer, dbTx sql.DB) (*big.Int, types.TxCode, error) {
	amt := big.NewInt(0)
	var err error

	if !ctx.BlockContext.ChainContext.NetworkParameters.DisabledGasCosts {
		amt, err = pricer.Price(ctx.Ctx, r, dbTx, tx)
		if err != nil {
			return nil, types.CodeUnknownError, err
		}
	}

	sender, err := TxSenderAcctID(tx)
	if err != nil {
		return nil, types.CodeInvalidSender, err
	}

	// Get account info
	account, err := r.Accounts.GetAccount(ctx.Ctx, dbTx, sender)
	if err == nil {
		r.service.Logger.Debug("account info", "account", tx.Sender, "balance", account.Balance, "nonce", account.Nonce)
	}

	// check if the transaction consented to spending enough tokens
	if tx.Body.Fee.Cmp(amt) < 0 {
		// If the transaction does not consent to spending required tokens for the transaction execution,
		// spend the approved tx fee and terminate the transaction
		err = r.Accounts.Spend(ctx.Ctx, dbTx, sender, tx.Body.Fee, int64(tx.Body.Nonce))
		if errors.Is(err, accounts.ErrInsufficientFunds) {
			// spend as much as possible
			account, err := r.Accounts.GetAccount(ctx.Ctx, dbTx, sender)
			if err != nil { // account will just be empty if not found
				return nil, types.CodeUnknownError, err
			}

			err2 := r.Accounts.Spend(ctx.Ctx, dbTx, sender, account.Balance, int64(tx.Body.Nonce))
			if err2 != nil {
				if errors.Is(err2, accounts.ErrAccountNotFound) {
					return nil, types.CodeInsufficientBalance, errors.New("account has zero balance")
				}
				return nil, types.CodeUnknownError, err2
			}

			// Record spend here as a spend has occurred
			return account.Balance, types.CodeInsufficientBalance, fmt.Errorf("transaction tries to spend %s tokens, but account only has %s tokens", amt.String(), tx.Body.Fee.String())
		}
		if err != nil {
			if errors.Is(err, accounts.ErrAccountNotFound) {
				return nil, types.CodeInsufficientBalance, errors.New("account has zero balance")
			}
			return nil, types.CodeUnknownError, err
		}

		return tx.Body.Fee, types.CodeInsufficientFee, fmt.Errorf("transaction does not consent to spending enough tokens. transaction fee: %s, required fee: %s", tx.Body.Fee.String(), amt.String())
	}

	// spend the tokens
	err = r.Accounts.Spend(ctx.Ctx, dbTx, sender, amt, int64(tx.Body.Nonce))
	if errors.Is(err, accounts.ErrInsufficientFunds) {
		// spend as much as possible
		account, err := r.Accounts.GetAccount(ctx.Ctx, dbTx, sender)
		if err != nil {
			return nil, types.CodeUnknownError, err
		}

		err2 := r.Accounts.Spend(ctx.Ctx, dbTx, sender, account.Balance, int64(tx.Body.Nonce))
		if err2 != nil {
			return nil, types.CodeUnknownError, err2
		}

		return account.Balance, types.CodeInsufficientBalance, fmt.Errorf("transaction tries to spend %s tokens, but account has %s tokens", amt.String(), account.Balance.String())
	}
	if err != nil {
		if errors.Is(err, accounts.ErrAccountNotFound) { // probably wouldn't have passed the fee check
			return nil, types.CodeInsufficientBalance, errors.New("account has zero balance")
		}
		return nil, types.CodeUnknownError, err
	}

	return amt, types.CodeOk, nil
}

// ApplyMempool applies the transactions in the mempool.
// If it returns an error, then the transaction is invalid.
func (r *TxApp) ApplyMempool(ctx *common.TxContext, db sql.DB, tx *types.Transaction) error {
	// check that payload type is valid
	if getRoute(tx.Body.PayloadType.String()) == nil {
		return fmt.Errorf("%w: %s", types.ErrUnknownPayloadType, tx.Body.PayloadType.String())
	}

	return r.mempool.applyTransaction(ctx, tx, db, r.events)
}

// AccountInfo gets account info from either the mempool or the account store.
// It takes a flag to indicate whether it should check the mempool first.
func (r *TxApp) AccountInfo(ctx context.Context, db sql.DB, acctID *types.AccountID, getUnconfirmed bool) (balance *big.Int, nonce int64, err error) {
	var a *types.Account
	if getUnconfirmed {
		a, err = r.mempool.accountInfoSafe(ctx, db, acctID)
	} else {
		a, err = r.Accounts.GetAccount(ctx, db, acctID)
	}
	if err != nil {
		return nil, 0, err
	}

	return a.Balance, a.Nonce, nil
}

func (r *TxApp) NumAccounts(ctx context.Context, db sql.Executor) (int64, int64, error) {
	// TODO: provide a cache for this information so RPC doesn't have to hit DB.
	count, err := r.Accounts.NumAccounts(ctx, db)
	if err != nil {
		return 0, 0, err
	}
	height, _, _, err := meta.GetChainState(ctx, db)
	if err != nil {
		return 0, 0, err
	}
	return count, height, nil
}

// UpdateValidator updates a validator's power.
// It can only be called in between Begin and Finalize.
// The value passed as power will simply replace the current power.
func (r *TxApp) UpdateValidator(ctx context.Context, db sql.DB, pubKey []byte, pubKeyType crypto.KeyType, power int64) error {
	return r.Validators.SetValidatorPower(ctx, db, pubKey, pubKeyType, power)
}

func (r *TxApp) GetValidators() []*types.Validator {
	return r.Validators.GetValidators()
}

func validatorSetPower(validators []*types.Validator) int64 {
	var totalPower int64
	for _, v := range validators {
		totalPower += v.Power
	}
	return totalPower
}

// validatorSetPower returns the total power of the current validator set
// according to the DB.
func (r *TxApp) validatorSetPower() int64 {
	validators := r.Validators.GetValidators()
	return validatorSetPower(validators)
}

// logErr logs an error to TxApp if it is not nil.
// it should be used when committing or rolling back a transaction.
func logErr(l log.Logger, err error) {
	if err != nil {
		l.Error("error committing/rolling back transaction", "error", err)
	}
}

// TxSenderAcctID returns the transaction sender's account ID information.
func TxSenderAcctID(t *types.Transaction) (*types.AccountID, error) {
	if t.Sender == nil {
		return nil, errors.New("transaction sender is nil")
	}
	keyType, err := authExt.GetAuthenticatorKeyType(t.Signature.Type)
	if err != nil {
		return nil, err
	}

	return &types.AccountID{
		Identifier: t.Sender,
		KeyType:    keyType,
	}, nil
}
