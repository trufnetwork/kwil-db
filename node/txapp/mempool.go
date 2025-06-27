package txapp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"
)

type mempool struct {
	accountMgr   Accounts
	validatorMgr Validators

	accounts map[string]*types.Account
	acctsMtx sync.Mutex // protects accounts

	nodeIdent auth.Signer
	log       log.Logger
}

// accountInfo retrieves the account info from the mempool state or the account store.
func (m *mempool) accountInfo(ctx context.Context, tx sql.Executor, acctID *types.AccountID) (*types.Account, error) {
	id, err := acctID.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if acctInfo, ok := m.accounts[string(id)]; ok {
		return acctInfo, nil // there are unconfirmed txs for this account
	}

	// get account from account store
	acct, err := m.accountMgr.GetAccount(ctx, tx, acctID)
	if err != nil {
		return nil, err
	}

	m.accounts[string(id)] = acct
	m.log.Debug("added new account to mempool records", "account", acctID, "nonce", acct.Nonce, "balance", acct.Balance)

	return acct, nil
}

// accountInfoSafe is wraps accountInfo in a mutex lock.
func (m *mempool) accountInfoSafe(ctx context.Context, tx sql.Executor, acctID *types.AccountID) (*types.Account, error) {
	m.acctsMtx.Lock()
	defer m.acctsMtx.Unlock()

	return m.accountInfo(ctx, tx, acctID)
}

// applyTransaction validates account specific info and applies valid transactions to the mempool state.
func (m *mempool) applyTransaction(ctx *common.TxContext, tx *types.Transaction, dbTx sql.Executor, rebroadcaster Rebroadcaster) error {
	// if the network is in a migration, there are numerous
	// transaction types we must disallow.
	// see [internal/migrations/migrations.go] for more info
	status := ctx.BlockContext.ChainContext.NetworkParameters.MigrationStatus
	inMigration := status == types.MigrationInProgress || status == types.MigrationCompleted
	activeMigration := status.Active()
	genesisMigration := status == types.GenesisMigration

	if inMigration {
		switch tx.Body.PayloadType {
		case types.PayloadTypeValidatorJoin:
			return fmt.Errorf("%w: validator join", types.ErrDisallowedInMigration)
		case types.PayloadTypeValidatorLeave:
			return fmt.Errorf("%w: validator leave", types.ErrDisallowedInMigration)
		case types.PayloadTypeValidatorApprove:
			return fmt.Errorf("%w: validator approve", types.ErrDisallowedInMigration)
		case types.PayloadTypeValidatorRemove:
			return fmt.Errorf("%w: validator remove", types.ErrDisallowedInMigration)
		case types.PayloadTypeValidatorVoteIDs:
			return fmt.Errorf("%w: validator vote ids", types.ErrDisallowedInMigration)
		case types.PayloadTypeValidatorVoteBodies:
			return fmt.Errorf("%w: validator vote bodies", types.ErrDisallowedInMigration)
		case types.PayloadTypeRawStatement:
			return fmt.Errorf("%w: raw statement", types.ErrDisallowedInMigration)
		case types.PayloadTypeTransfer:
			return fmt.Errorf("%w: transfer", types.ErrDisallowedInMigration)
		}
	}

	// Migration proposals and its approvals are not allowed once the migration is approved
	if tx.Body.PayloadType == types.PayloadTypeCreateResolution {
		res := &types.CreateResolution{}
		if err := res.UnmarshalBinary(tx.Body.Payload); err != nil {
			return err
		}
		if (activeMigration || genesisMigration) && res.Resolution.Type == voting.StartMigrationEventType {
			return fmt.Errorf("%w: migration resolutions", types.ErrDisallowedInMigration)
		}
	}

	if tx.Body.PayloadType == types.PayloadTypeApproveResolution {
		res := &types.ApproveResolution{}
		if err := res.UnmarshalBinary(tx.Body.Payload); err != nil {
			return err
		}

		resolution, err := resolutionByID(ctx.Ctx, dbTx, res.ResolutionID)
		if err != nil {
			return errors.New("migration proposal not found")
		}

		// check if resolution is a migration resolution
		if (activeMigration || genesisMigration) && resolution.Type == voting.StartMigrationEventType {
			return errors.New("approving migration resolutions are not allowed during migration")
		}
	}

	// seems like maybe this should go in the switch statement below,
	// but I put it here to avoid extra db call for account info
	if tx.Body.PayloadType == types.PayloadTypeValidatorVoteIDs {
		keyType, err := authExt.GetAuthenticatorKeyType(tx.Signature.Type)
		if err != nil {
			return fmt.Errorf("invalid key type: %w", err)
		}

		power, err := m.validatorMgr.GetValidatorPower(ctx.Ctx, tx.Sender, keyType)
		if err != nil {
			return err
		}

		if power == 0 {
			return errors.New("only validators can submit validator vote transactions")
		}

		// reject the transaction if the number of voteIDs exceeds the limit
		voteID := &types.ValidatorVoteIDs{}
		err = voteID.UnmarshalBinary(tx.Body.Payload)
		if err != nil {
			return err
		}
		if maxVotes := ctx.BlockContext.ChainContext.NetworkParameters.MaxVotesPerTx; (int64)(len(voteID.ResolutionIDs)) > maxVotes {
			return fmt.Errorf("number of voteIDs exceeds the limit of %d", maxVotes)
		}
	}

	if tx.Body.PayloadType == types.PayloadTypeValidatorVoteBodies {
		// not sure if this is the right error code
		return errors.New("validator vote bodies can not enter the mempool, and can only be submitted during block proposal")
	}

	// get sender account identifier
	acctID, err := TxSenderAcctID(tx)
	if err != nil {
		return err
	}

	m.acctsMtx.Lock()
	defer m.acctsMtx.Unlock()

	// get account info from mempool state or account store
	acct, err := m.accountInfo(ctx.Ctx, dbTx, acctID)
	if err != nil {
		return err
	}

	// reject the transactions from unfunded user accounts in gasEnabled mode
	if !ctx.BlockContext.ChainContext.NetworkParameters.DisabledGasCosts && acct.Nonce == 0 && acct.Balance.Sign() == 0 {
		delete(m.accounts, string(tx.Sender))
		return types.ErrInsufficientBalance
	}

	// It is normally permissible to accept a transaction with the same nonce as
	// a tx already in mempool (but not in a block), however without gas we
	// would not want to allow that since there is no criteria for selecting the
	// one to mine (normally higher fee).
	if tx.Body.Nonce != uint64(acct.Nonce)+1 {
		// If the transaction with invalid nonce is a ValidatorVoteIDs transaction,
		// then mark the events for rebroadcast before discarding the transaction
		// as the votes for these events are not yet received by the network.

		// Check if the transaction is from the local node and is a ValidatorVoteIDs transaction
		if tx.Body.PayloadType == types.PayloadTypeValidatorVoteIDs &&
			tx.Signature.Type == m.nodeIdent.AuthType() &&
			bytes.Equal(tx.Sender, m.nodeIdent.CompactID()) {
			// Mark these ids for rebroadcast
			voteID := &types.ValidatorVoteIDs{}
			err = voteID.UnmarshalBinary(tx.Body.Payload)
			if err != nil {
				return err
			}

			err = rebroadcaster.MarkRebroadcast(ctx.Ctx, voteID.ResolutionIDs)
			if err != nil {
				return err
			}
		}
		return fmt.Errorf("%w for account %s: got %d, expected %d",
			types.ErrInvalidNonce, hex.EncodeToString(tx.Sender),
			tx.Body.Nonce, acct.Nonce+1)
	}

	spend := big.NewInt(0).Set(tx.Body.Fee) // NOTE: this could be the fee *limit*, but it depends on how the modules work

	switch tx.Body.PayloadType {
	case types.PayloadTypeTransfer:
		transfer := &types.Transfer{}
		err = transfer.UnmarshalBinary(tx.Body.Payload)
		if err != nil {
			return err
		}

		amt := transfer.Amount
		if amt.Cmp(&big.Int{}) < 0 {
			return errors.Join(types.ErrInvalidAmount, errors.New("negative transfer not permitted"))
		}

		if amt.Cmp(acct.Balance) > 0 {
			return types.ErrInsufficientBalance
		}

		spend.Add(spend, amt)
	}

	// We'd check balance against the total spend (fees plus value sent) if we
	// know gas is enabled. Transfers must be funded regardless of transaction
	// gas requirement:

	// if spend.Cmp(acct.balance) > 0 {
	// 	return errors.New("insufficient funds")
	// }

	// Since we're not yet operating with different policy depending on whether
	// gas is enabled for the chain, we're just going to reduce the account's
	// pending balance, but no lower than zero. Tx execution will handle it.
	if spend.Cmp(acct.Balance) > 0 {
		acct.Balance.SetUint64(0)
	} else {
		acct.Balance.Sub(acct.Balance, spend)
	}

	// Account nonces and spends tracked by mempool should be incremented only for the
	// valid transactions. This is to avoid the case where mempool rejects a transaction
	// due to insufficient balance, but the account nonce and spend are already incremented.
	// Due to which it accepts the next transaction with nonce+1, instead of nonce
	// (but Tx with nonce is never pushed to the consensus pool).
	acct.Nonce = int64(tx.Body.Nonce)

	m.log.Debug("applied transaction to mempool state", "account", log.LazyHex(tx.Sender),
		"nonce", acct.Nonce, "balance", acct.Balance)

	return nil
}

// reset clears the in-memory unconfirmed account states.
// This should be done at the end of block commit.
func (m *mempool) reset() {
	m.acctsMtx.Lock()
	defer m.acctsMtx.Unlock()

	m.accounts = make(map[string]*types.Account)
}
