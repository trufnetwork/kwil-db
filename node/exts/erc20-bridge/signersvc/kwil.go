package signersvc

import (
	"context"
	"fmt"
	"math/big"

	"github.com/samber/lo"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/client"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

type RewardInstanceInfo struct {
	Chain       string
	Escrow      string
	EpochPeriod string
	Erc20       string
	Decimals    int64
	Balance     *types.Decimal
	Synced      bool
	SyncedAt    int64
	Enabled     bool
}

type Epoch struct {
	ID             *types.UUID
	StartHeight    int64
	StartTimestamp int64
	EndHeight      int64
	RewardRoot     []byte
	RewardAmount   *types.Decimal
	EndBlockHash   []byte
	Confirmed      bool
	Voters         []string
	VoteNonces     []int64
	VoteSignatures [][]byte
}

type EpochReward struct {
	Recipient string
	Amount    string
}

// bridgeSignerClient defines the ERC20 bridge extension client for signer service.
type bridgeSignerClient interface {
	InstanceInfo(tx context.Context, namespace string) (*RewardInstanceInfo, error)
	GetActiveEpochs(ctx context.Context, namespace string) ([]*Epoch, error)
	GetEpochRewards(ctx context.Context, namespace string, epochID *types.UUID) ([]*EpochReward, error)
	VoteEpoch(ctx context.Context, namespace string, txSigner auth.Signer, epochID *types.UUID, safeNonce int64, signature []byte) (types.Hash, error)
}

type txBcast interface {
	BroadcastTx(ctx context.Context, tx *types.Transaction, sync uint8) (types.Hash, *types.TxResult, error)
}

type engineCall interface {
	CallWithoutEngineCtx(ctx context.Context, db sql.DB, namespace, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error)
}

type nodeApp interface {
	AccountInfo(ctx context.Context, db sql.DB, account *types.AccountID, pending bool) (balance *big.Int, nonce int64, err error)
	Price(ctx context.Context, dbTx sql.DB, tx *types.Transaction) (*big.Int, error)
}

type DB interface {
	sql.ReadTxMaker
	sql.DelayedReadTxMaker
}

type signerClient struct {
	chainID  string
	db       DB
	call     engineCall
	bcast    txBcast
	kwilNode nodeApp
}

func NewSignerClient(chainID string, db DB, call engineCall, bcast txBcast, nodeApp nodeApp) *signerClient {
	return &signerClient{
		chainID:  chainID,
		db:       db,
		call:     call,
		bcast:    bcast,
		kwilNode: nodeApp,
	}
}

func (k *signerClient) InstanceInfo(ctx context.Context, namespace string) (*RewardInstanceInfo, error) {
	info := &RewardInstanceInfo{}

	readTx := k.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	_, err := k.call.CallWithoutEngineCtx(ctx, readTx, namespace, "info", []any{}, func(row *common.Row) error {
		var ok bool

		info.Chain, ok = row.Values[0].(string)
		if !ok {
			return fmt.Errorf("failed to get chain")
		}

		info.Escrow, ok = row.Values[1].(string)
		if !ok {
			return fmt.Errorf("failed to get escrow")
		}

		info.EpochPeriod, ok = row.Values[2].(string)
		if !ok {
			return fmt.Errorf("failed to get epoch period")
		}

		if row.Values[3] != nil {
			info.Erc20, ok = row.Values[3].(string)
			if !ok {
				return fmt.Errorf("failed to get erc20")
			}
		}

		if row.Values[4] != nil {
			info.Decimals, ok = row.Values[4].(int64)
			if !ok {
				return fmt.Errorf("failed to get decimals")
			}
		}

		if row.Values[5] != nil {
			info.Balance, ok = row.Values[5].(*types.Decimal)
			if !ok {
				return fmt.Errorf("failed to get balance")
			}
		}

		info.Synced, ok = row.Values[6].(bool)
		if !ok {
			return fmt.Errorf("failed to get synced")
		}

		if row.Values[7] != nil {
			info.SyncedAt, ok = row.Values[7].(int64)
			if !ok {
				return fmt.Errorf("failed to get synced at")
			}
		}

		info.Enabled, ok = row.Values[8].(bool)
		if !ok {
			return fmt.Errorf("failed to get enabled")
		}

		return nil
	})

	return info, err
}

func (k *signerClient) GetActiveEpochs(ctx context.Context, namespace string) ([]*Epoch, error) {
	var epochs []*Epoch

	readTx := k.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	_, err := k.call.CallWithoutEngineCtx(ctx, readTx, namespace, "get_active_epochs", []any{}, func(row *common.Row) error {
		var ok bool
		e := &Epoch{}

		e.ID, ok = row.Values[0].(*types.UUID)
		if !ok {
			return fmt.Errorf("failed to get id")
		}
		e.StartHeight, ok = row.Values[1].(int64)
		if !ok {
			return fmt.Errorf("failed to get start height")
		}
		e.StartTimestamp, ok = row.Values[2].(int64)
		if !ok {
			return fmt.Errorf("failed to get start timestamp")
		}

		if row.Values[3] != nil {
			e.EndHeight, ok = row.Values[3].(int64)
			if !ok {
				return fmt.Errorf("failed to get end height")
			}
		}

		if row.Values[4] != nil {
			e.RewardRoot, ok = row.Values[4].([]byte)
			if !ok {
				return fmt.Errorf("failed to get reward root")
			}
		}

		if row.Values[5] != nil {
			e.RewardAmount, ok = row.Values[5].(*types.Decimal)
			if !ok {
				return fmt.Errorf("failed to get reward amount")
			}
		}

		if row.Values[6] != nil {
			e.EndBlockHash, ok = row.Values[6].([]byte)
			if !ok {
				return fmt.Errorf("failed to get end block hash")
			}
		}

		e.Confirmed, ok = row.Values[7].(bool)
		if !ok {
			return fmt.Errorf("failed to get confirmed")
		}

		if row.Values[8] != nil {
			voters, ok := row.Values[8].([]*string)
			if !ok {
				return fmt.Errorf("failed to get voters")
			}

			e.Voters = lo.Map(voters, func(v *string, i int) string {
				if v == nil {
					return ""
				}
				return *v

			})
		}

		if row.Values[9] != nil {
			voteNonces, ok := row.Values[9].([]*int64)
			if !ok {
				return fmt.Errorf("failed to get vote nonces")
			}

			e.VoteNonces = lo.Map(voteNonces, func(v *int64, i int) int64 {
				if v == nil {
					return 0
				}
				return *v
			})

		}

		if row.Values[10] != nil {
			e.VoteSignatures, ok = row.Values[10].([][]byte)
			if !ok {
				return fmt.Errorf("failed to get vote signatures")
			}
		}

		epochs = append(epochs, e)
		return nil
	})

	return epochs, err
}

func (k *signerClient) GetEpochRewards(ctx context.Context, namespace string, epochID *types.UUID) ([]*EpochReward, error) {
	var rewards []*EpochReward

	readTx := k.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	_, err := k.call.CallWithoutEngineCtx(ctx, readTx, namespace, "get_epoch_rewards", []any{epochID}, func(row *common.Row) error {
		var ok bool
		e := &EpochReward{}

		e.Recipient, ok = row.Values[0].(string)
		if !ok {
			return fmt.Errorf("failed to get recipient")
		}

		e.Amount, ok = row.Values[1].(string)
		if !ok {
			return fmt.Errorf("failed to get amount")
		}

		rewards = append(rewards, e)

		return nil
	})

	return rewards, err
}

func (k *signerClient) VoteEpoch(ctx context.Context, namespace string, txSigner auth.Signer, epochID *types.UUID, safeNonce int64, signature []byte) (types.Hash, error) {
	inputs := [][]any{{epochID, safeNonce, signature}}
	res, err := k.execute(ctx, namespace, txSigner, "vote_epoch", inputs)
	if err != nil {
		return types.Hash{}, err
	}

	return res, nil
}

func (k *signerClient) estimatePrice(ctx context.Context, tx *types.Transaction) (*big.Int, error) {
	readTx := k.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	return k.kwilNode.Price(ctx, readTx, tx)

}

func (k *signerClient) accountNonce(ctx context.Context, acc *types.AccountID) (uint64, error) {
	readTx := k.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	_, nonce, err := k.kwilNode.AccountInfo(ctx, readTx, acc, true)
	if err != nil {
		return 0, fmt.Errorf("failed to get account info: %w", err)
	}

	return uint64(nonce), nil
}

// execute mimics client.Client.Execute, without client options.
func (k *signerClient) execute(ctx context.Context, namespace string, txSigner auth.Signer, action string, tuples [][]any) (types.Hash, error) {
	encodedTuples := make([][]*types.EncodedValue, len(tuples))
	for i, tuple := range tuples {
		encoded, err := client.EncodeInputs(tuple)
		if err != nil {
			return types.Hash{}, err
		}
		encodedTuples[i] = encoded
	}

	executionBody := &types.ActionExecution{
		Action:    action,
		Namespace: namespace,
		Arguments: encodedTuples,
	}

	tx, err := k.newTx(ctx, executionBody, txSigner)
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to create tx: %w", err)
	}

	// since we wait for commit, res won't be nil
	txHash, _, err := k.bcast.BroadcastTx(ctx, tx, uint8(rpcclient.BroadcastWaitCommit))
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to broadcast tx: %w", err)
	}

	return txHash, nil
}

// newTx mimics client.Client.newTx to create a new tx, without tx options.
func (k *signerClient) newTx(ctx context.Context, data types.Payload, txSigner auth.Signer) (*types.Transaction, error) {
	// Get the latest nonce for the account, if it exists.
	ident, err := types.GetSignerAccount(txSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer account: %w", err)
	}

	nonce, err := k.accountNonce(ctx, ident)
	if err != nil {
		return nil, fmt.Errorf("failed to get account nonce: %w", err)
	}

	// whether account gets balance or not
	nonce += 1

	// build transaction
	tx, err := types.CreateTransaction(data, k.chainID, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	// estimate price
	price, err := k.estimatePrice(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to estimate price: %w", err)
	}

	// set fee
	tx.Body.Fee = price

	// sign transaction
	err = tx.Sign(txSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	return tx, nil
}

var _ bridgeSignerClient = (*signerClient)(nil)
