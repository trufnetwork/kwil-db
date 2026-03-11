package voting

import (
	"slices"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
)

// ForTestingAddValidator adds a validator directly to the in-memory cache.
// This bypasses the normal SetValidatorPower + Commit flow and is intended
// only for tests that need to inject validators into the VoteStore.
func (v *VoteStore) ForTestingAddValidator(pubKey []byte, keyType crypto.KeyType, power int64) {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	v.validatorSet = append(v.validatorSet, &types.Validator{
		AccountID: types.AccountID{
			Identifier: slices.Clone(pubKey),
			KeyType:    keyType,
		},
		Power: power,
	})
}
