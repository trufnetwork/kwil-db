package client

import (
	"context"
	"fmt"

	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/types"
)

// newTx creates a new Transaction signed by the Client's Signer
func (c *Client) newTx(ctx context.Context, data types.Payload, txOpts *clientType.TxOptions) (*types.Transaction, error) {
	if c.Signer() == nil {
		return nil, fmt.Errorf("signer must be set to create a transaction")
	}
	if txOpts == nil {
		txOpts = &clientType.TxOptions{}
	}

	var nonce uint64
	if txOpts.Nonce > 0 {
		nonce = uint64(txOpts.Nonce)
	} else {
		ident, err := types.GetSignerAccount(c.Signer())
		if err != nil {
			return nil, fmt.Errorf("failed to get signer account: %w", err)
		}

		// Get the latest nonce for the account, if it exists.
		acc, err := c.txClient.GetAccount(ctx, ident, types.AccountStatusPending)
		if err != nil {
			return nil, err
		}

		// NOTE: an error type would be more robust signalling of a non-existent
		// account, but presently a nil ID is set by internal/accounts.
		if acc.ID != nil && len(acc.ID.Identifier) > 0 {
			nonce = uint64(acc.Nonce + 1)
		} else {
			nonce = 1
		}
	}

	// build transaction
	tx, err := types.CreateTransaction(data, c.chainID, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	// estimate price
	price := txOpts.Fee
	if price == nil {
		price, err = c.txClient.EstimateCost(ctx, tx)
		if err != nil {
			return nil, fmt.Errorf("failed to estimate price: %w", err)
		}
	}

	// set fee
	tx.Body.Fee = price

	// sign transaction
	err = tx.Sign(c.Signer())
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	return tx, nil
}
