package utils

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
	chaintypes "github.com/trufnetwork/kwil-db/core/types/chain"
)

func TestBuildBlockMix(t *testing.T) {
	t.Parallel()

	executePayload := func(calls int) []byte {
		arguments := make([][]*types.EncodedValue, calls)
		payload, err := (&types.ActionExecution{
			Namespace: "idos",
			Action:    "finalize_credentials_as_gateway",
			Arguments: arguments,
		}).MarshalBinary()
		require.NoError(t, err)
		return payload
	}
	block := &chaintypes.Block{
		Header: &types.BlockHeader{Height: 317896},
		Txns: []*types.Transaction{
			blockMixTestTx(types.PayloadTypeExecute, executePayload(2), 1),
			blockMixTestTx(types.PayloadTypeExecute, executePayload(1), 2),
			blockMixTestTx(types.PayloadTypeTransfer, nil, 3),
		},
	}
	result := &chaintypes.BlockResult{
		Height: 317896,
		Hash:   types.HashBytes([]byte("block")),
		TxResults: []types.TxResult{
			{Code: uint32(types.CodeOk), Gas: 5},
			{Code: 1, Gas: 7},
			{Code: uint32(types.CodeOk), Gas: 2},
		},
	}

	mix, err := buildBlockMix(block, result)
	require.NoError(t, err)
	require.Equal(t, int64(317896), mix.Height)
	require.Equal(t, result.Hash.String(), mix.Hash)
	require.Equal(t, 3, mix.Transactions)
	require.Len(t, mix.Actions, 2)
	require.Equal(t, blockActionMix{
		PayloadType:  "execute",
		Namespace:    "idos",
		Action:       "finalize_credentials_as_gateway",
		Transactions: 2,
		Calls:        3,
		Failures:     1,
		TotalSpend:   12,
	}, mix.Actions[0])
	require.Equal(t, blockActionMix{
		PayloadType:  "transfer",
		Transactions: 1,
		Calls:        1,
		TotalSpend:   2,
	}, mix.Actions[1])
	require.Equal(t, "finalize_credentials_as_gateway", mix.Txs[0].Action)
	require.Equal(t, uint32(1), mix.Txs[1].Code)
	require.Equal(t, "transfer", mix.Txs[2].PayloadType)
}

func TestBuildBlockMixRejectsMismatchedResults(t *testing.T) {
	t.Parallel()

	block := &chaintypes.Block{
		Header: &types.BlockHeader{Height: 42},
		Txns:   []*types.Transaction{blockMixTestTx(types.PayloadTypeTransfer, nil, 1)},
	}
	_, err := buildBlockMix(block, &chaintypes.BlockResult{Height: 42})
	require.EqualError(t, err, "block 42 has 1 transactions but 0 results")
}

func blockMixTestTx(payloadType types.PayloadType, payload []byte, nonce uint64) *types.Transaction {
	return &types.Transaction{
		Signature: &auth.Signature{Data: []byte{1}, Type: auth.Ed25519Auth},
		Body: &types.TransactionBody{
			Payload:     payload,
			PayloadType: payloadType,
			Fee:         big.NewInt(0),
			Nonce:       nonce,
			ChainID:     "test",
		},
		Serialization: types.SignedMsgConcat,
		Sender:        []byte{1},
	}
}
