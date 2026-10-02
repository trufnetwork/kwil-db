package node

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
)

func TestOwnedSchemas(t *testing.T) {
	// The schemas in a mainnet node's database, plus an operator's.
	all := []string{"ds_0a1b", "ext_database_size", "ext_tn_local", "ext_tn_vacuum", "info", "kwil_erc20_meta",
		"kwild_accts", "kwild_chain", "kwild_engine", "kwild_events", "kwild_internal", "kwild_migrations",
		"kwild_voting", "main", "operator_data", "public", "repack"}

	owned, keep := ownedSchemas(all, []string{"main", "info", "kwil_erc20_meta", "dropped_namespace"})

	require.Equal(t, []string{"ds_0a1b", "info", "kwil_erc20_meta", "kwild_accts", "kwild_chain", "kwild_engine",
		"kwild_events", "kwild_internal", "kwild_migrations", "kwild_voting", "main"}, owned)
	require.Equal(t, []string{"ext_database_size", "ext_tn_local", "ext_tn_vacuum", "operator_data", "public", "repack"}, keep)
}

func newPublicKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	_, pub, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	return pub
}

func validatorOf(key crypto.PublicKey) *ktypes.Validator {
	return &ktypes.Validator{AccountID: ktypes.AccountID{Identifier: key.Bytes(), KeyType: key.Type()}, Power: 1}
}

func TestIsValidator(t *testing.T) {
	self, leader, other := newPublicKey(t), newPublicKey(t), newPublicKey(t)

	require.True(t, isValidator(self, self, nil), "the genesis leader")
	require.True(t, isValidator(self, leader, []*ktypes.Validator{validatorOf(other), validatorOf(self)}))
	require.False(t, isValidator(self, leader, []*ktypes.Validator{validatorOf(leader), validatorOf(other)}))
	require.False(t, isValidator(self, nil, nil))

	sameBytesOtherType := validatorOf(self)
	sameBytesOtherType.KeyType = crypto.KeyTypeEd25519
	require.False(t, isValidator(self, leader, []*ktypes.Validator{sameBytesOtherType}))
}

func TestResyncIsOffAtZero(t *testing.T) {
	for _, cfg := range []config.StateSyncConfig{
		{Enable: true, ResyncWhenBehind: 0},
		{Enable: false, ResyncWhenBehind: 10},
	} {
		// No database, block store or network: touching any of them panics.
		ss := &StateSyncService{cfg: &cfg, log: log.DiscardLogger}
		cleared, err := ss.ResyncIfFarBehind(context.Background(), newPublicKey(t), nil)
		require.NoError(t, err)
		require.False(t, cleared)
	}
}
