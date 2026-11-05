package txapp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
)

// malformedArgs are argument values that unmarshal from a transaction payload
// but cannot be decoded: a bool with the not-null marker and no value byte,
// and a data element with no null marker byte at all.
func malformedArgs() map[string]*types.EncodedValue {
	return map[string]*types.EncodedValue{
		"bool marker only":   {Type: *types.BoolType, Data: [][]byte{{1}}},
		"text empty element": {Type: *types.TextType, Data: [][]byte{{}}},
		"int array nil elem": {Type: *types.IntArrayType, Data: [][]byte{{0}, nil}},
	}
}

// TestPreTx_MalformedArgumentIsEncodingError checks that every route that
// decodes action or statement arguments fails such a transaction with
// CodeEncodingError instead of panicking during block execution.
func TestPreTx_MalformedArgumentIsEncodingError(t *testing.T) {
	ctx := &common.TxContext{Ctx: context.Background()}

	preTx := func(t *testing.T, route interface {
		PreTx(*common.TxContext, *common.Service, *types.Transaction) (types.TxCode, error)
	}, ctx *common.TxContext, payload []byte) {
		t.Helper()
		tx := &types.Transaction{Body: &types.TransactionBody{Payload: payload}}
		var code types.TxCode
		var err error
		require.NotPanics(t, func() { code, err = route.PreTx(ctx, nil, tx) })
		require.Error(t, err)
		assert.Equal(t, types.CodeEncodingError, code)
	}

	for name, ev := range malformedArgs() {
		t.Run(name, func(t *testing.T) {
			t.Run("execute", func(t *testing.T) {
				payload, err := types.ActionExecution{
					Namespace: "main",
					Action:    "a",
					Arguments: [][]*types.EncodedValue{{ev}},
				}.MarshalBinary()
				require.NoError(t, err)
				preTx(t, &executeActionRoute{}, ctx, payload)
			})

			t.Run("raw statement", func(t *testing.T) {
				payload, err := types.RawStatement{
					Statement:  "SELECT $p",
					Parameters: []*types.NamedValue{{Name: "$p", Value: ev}},
				}.MarshalBinary()
				require.NoError(t, err)
				preTx(t, &rawStatementRoute{}, ctx, payload)
			})

			t.Run("maa_exec", func(t *testing.T) {
				payload, err := types.MAAExec{
					MAAAddress: maaAddr20,
					Namespace:  "main",
					Action:     "ob_place_order",
					Arguments:  []*types.EncodedValue{ev},
				}.MarshalBinary()
				require.NoError(t, err)
				preTx(t, &maaExecRoute{}, maaActivatedTxContext(maaRestricted), payload)
			})
		})
	}
}
