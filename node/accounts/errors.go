package accounts

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/trufnetwork/kwil-db/core/types"
)

var (
	ErrInsufficientFunds = errors.New("insufficient funds")
	ErrConvertToBigInt   = errors.New("could not convert to big int")
	ErrInvalidNonce      = errors.New("invalid nonce")
	ErrAccountNotFound   = errors.New("account not found")
	ErrNegativeBalance   = errors.New("negative balance not permitted")
	ErrNegativeTransfer  = errors.New("negative transfer not permitted")
)

// errInsufficientFunds formats an error message for insufficient funds
func errInsufficientFunds(account *types.AccountID, amount *big.Int, balance *big.Int) error {
	return fmt.Errorf("%w: account %s tried to use %s, but only has balance %s",
		ErrInsufficientFunds, account, amount.String(), balance.String())
}
