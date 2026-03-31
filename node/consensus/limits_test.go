package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaxNumTxnsInBlock(t *testing.T) {
	// maxNumTxnsInBlock bounds the number of transactions per block to prevent
	// superlinear execution time from compounding writes within a single
	// PostgreSQL transaction. Excess transactions stay in the mempool and are
	// included in the next block (~1s later).
	require.Equal(t, 15, maxNumTxnsInBlock,
		"maxNumTxnsInBlock should be 15 to bound block execution time")
}
