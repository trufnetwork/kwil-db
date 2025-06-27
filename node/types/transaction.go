package types

import "github.com/trufnetwork/kwil-db/core/types"

// Tx represents an immutable transaction. The constructor will compute the
// hash, which it will return directly from the Hash method. This means that the
// hash is only computed once. However, it is important note that the
// transaction fields should not be changed, because the hash will not be
// correct.
//
// This is intended for use in node internals, primarily mempool and consensus
// engine where the hash is repeatedly accessed on deep call stacks.
//
// In most cases, you should use the Tx type from the core/types package. Be
// aware of the cost of computing the hash, and avoid recomputing it.
//
// If you use this type, be aware of the mutability caveat, and consider the
// cost of the memory allocation, and the persistence of the hash potentially
// after it is no longer needed.
type Tx struct {
	*types.Transaction
	hash types.Hash // computed on construction
}

// NewTx creates a new Tx from a *core/types.Transaction. This computes and
// stores the hash, which is returned by the [Hash] method without any
// recomputation. As such, the transaction fields should not be changed since
// the hash is never recomputed.
func NewTx(tx *types.Transaction) *Tx {
	return &Tx{
		Transaction: tx,
		hash:        tx.Hash(),
	}
}

// Hash returns the hash computed on construction. This shadows the Hash method
// of the *core/types.Transaction.
func (tx Tx) Hash() types.Hash {
	return tx.hash
}

func (tx Tx) Bytes() []byte {
	return tx.Transaction.Bytes()
}
