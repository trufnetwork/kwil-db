package blockprocessor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

func TestCheckTxRejectsNilBody(t *testing.T) {
	bp := &BlockProcessor{}

	for _, ntx := range []*types.Tx{
		nil,
		&types.Tx{},
		types.NewTx(&ktypes.Transaction{}),
	} {
		err := bp.checkTx(context.Background(), nil, ntx, 1, time.Time{}, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "transaction body is required")
	}
}
