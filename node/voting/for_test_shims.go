package voting

import (
	"bytes"
	"slices"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
)

// ForTestingAddValidator adds or updates a validator in the in-memory cache.
// It mirrors the semantics of SetValidatorPower but bypasses the DB:
//   - Negative power is rejected (panic, since this is test-only).
//   - Power == 0 removes the validator if it exists.
//   - Otherwise, updates existing entry or appends a new one.
func (v *VoteStore) ForTestingAddValidator(pubKey []byte, keyType crypto.KeyType, power int64) {
	if power < 0 {
		panic("ForTestingAddValidator: negative power not allowed")
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	// Find existing validator by matching (keyType, pubKey).
	idx := -1
	for i, val := range v.validatorSet {
		if val.KeyType == keyType && bytes.Equal(val.Identifier, pubKey) {
			idx = i
			break
		}
	}

	if power == 0 {
		// Remove if exists.
		if idx >= 0 {
			v.validatorSet = slices.Delete(v.validatorSet, idx, idx+1)
		}
		return
	}

	if idx >= 0 {
		// Update existing.
		v.validatorSet[idx].Power = power
	} else {
		// Append new.
		v.validatorSet = append(v.validatorSet, &types.Validator{
			AccountID: types.AccountID{
				Identifier: slices.Clone(pubKey),
				KeyType:    keyType,
			},
			Power: power,
		})
	}
}
