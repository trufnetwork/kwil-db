package display

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
)

// NOTE: could do this for all the other tests,
// but using Example* is more handy and obvious
func Test_RespTxHash(t *testing.T) {
	resp := RespTxHash{1, 2, 3, 4}
	expectJSON := `{"tx_hash":"0102030400000000000000000000000000000000000000000000000000000000"}`
	expectText := `TxHash: 0102030400000000000000000000000000000000000000000000000000000000`

	outText, err := resp.MarshalText()
	assert.NoError(t, err, "MarshalText should not return error")
	assert.Equal(t, expectText, string(outText), "MarshalText should return expected text")

	outJSON, err := resp.MarshalJSON()
	assert.NoError(t, err, "MarshalJSON should not return error")
	assert.Equal(t, expectJSON, string(outJSON), "MarshalJSON should return expected json")
}

func ExampleRespTxHash_text() {
	msg := wrapMsg(RespTxHash{1, 2, 3, 4}, nil)
	prettyPrint(msg, "text", os.Stdout, os.Stderr)
	// Output:
	// TxHash: 0102030400000000000000000000000000000000000000000000000000000000
}

func TestRespTxHash_text_withError(t *testing.T) {
	var stderr bytes.Buffer
	var stdout bytes.Buffer

	err := errors.New("an error")
	msg := wrapMsg(RespTxHash{1, 2, 3, 4}, err)
	prettyPrint(msg, "text", &stdout, &stderr)

	output, err := io.ReadAll(&stdout)
	assert.NoError(t, err, "ReadAll should not return error")
	assert.Equal(t, "", string(output), "stdout should be empty")

	errput, err := io.ReadAll(&stderr)
	assert.NoError(t, err, "ReadAll should not return error")
	assert.Equal(t, "an error\n", string(errput), "stderr should contain error")
}

func ExampleRespTxHash_json() {
	msg := wrapMsg(RespTxHash{1, 2, 3, 4}, nil)
	prettyPrint(msg, "json", os.Stdout, os.Stderr)
	// Output:
	// {
	//   "result": {
	//     "tx_hash": "0102030400000000000000000000000000000000000000000000000000000000"
	//   },
	//   "error": ""
	// }
}

func ExampleRespTxHash_json_withError() {
	err := errors.New("an error")
	msg := wrapMsg(RespTxHash{1, 2, 3, 4}, err)
	prettyPrint(msg, "json", os.Stdout, os.Stderr)
	// Output:
	// {
	//   "result": null,
	//   "error": "an error"
	// }
}

func getExampleTxQueryResponse() *types.TxQueryResponse {
	secp256k1EpSigHex := "cb3fed7f6ff36e59054c04a831b215e514052753ee353e6fe31d4b4ef736acd6155127db555d3006ba14fcb4c79bbad56c8e63b81a9896319bb053a9e253475800"
	secp256k1EpSigBytes, _ := hex.DecodeString(secp256k1EpSigHex)
	secpSig := auth.Signature{
		Data: secp256k1EpSigBytes,
		Type: auth.EthPersonalSignAuth,
	}

	rawPayload := types.ActionExecution{
		Namespace: "xf617af1ca774ebbd6d23e8fe12c56d41d25a22d81e88f67c6c6ee0d4",
		Action:    "create_user",
		Arguments: [][]*types.EncodedValue{
			{
				{
					Type: types.DataType{
						Name: types.TextType.Name,
					},
					Data: [][]byte{[]byte("foo")},
				},
			},
		},
	}

	payloadRLP, err := rawPayload.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return &types.TxQueryResponse{
		Hash:   types.Hash{1, 2, 3, 4},
		Height: 10,
		Tx: &types.Transaction{
			Body: &types.TransactionBody{
				Payload:     payloadRLP,
				PayloadType: rawPayload.Type(),
				Fee:         big.NewInt(100),
				Nonce:       10,
				ChainID:     "asdf",
				Description: "This is a test transaction for cli",
			},
			Serialization: types.SignedMsgConcat,
			Signature:     &secpSig,
		},
		Result: &types.TxResult{
			Code:   0,
			Log:    "This is log",
			Gas:    10,
			Events: nil, // omitted
		},
	}
}

func Example_respTxQuery_text() {
	Print(&RespTxQuery{Msg: getExampleTxQueryResponse(), WithRaw: true}, nil, "text")
	// Transaction ID: 31303234
	// Status: success
	// Height: 10
	// Log: This is log
	// Raw: 0001f8eaf850b841cb3fed7f6ff36e59054c04a831b215e514052753ee353e6fe31d4b4ef736acd6155127db555d3006ba14fcb4c79bbad56c8e63b81a9896319bb053a9e2534758008c736563703235366b315f6570f88ea25468697320697320612074657374207472616e73616374696f6e20666f7220636c69b85a0001f856b8397866363137616631636137373465626264366432336538666531326335366434316432356132326438316538386636376336633665653064348b6372656174655f75736572cecdccc6847465787480c483666f6f8765786563757465640a846173646686636f6e63617480
	// WARNING! HASH MISMATCH:
	// 	Requested 31303234
	// 	Received  f866b4251d21552de1bc5b819a4b563a540146954e956e8150163574ce5325ac
}

func Example_respTxQuery_json() {
	Print(&RespTxQuery{Msg: getExampleTxQueryResponse()}, nil, "json")
	// Output:
	// {
	//   "result": {
	//     "hash": "0102030400000000000000000000000000000000000000000000000000000000",
	//     "height": 10,
	//     "tx": {
	//       "signature": {
	//         "sig": "yz/tf2/zblkFTASoMbIV5RQFJ1PuNT5v4x1LTvc2rNYVUSfbVV0wBroU/LTHm7rVbI5juBqYljGbsFOp4lNHWAA=",
	//         "type": "secp256k1_ep"
	//       },
	//       "body": {
	//         "desc": "This is a test transaction for cli",
	//         "payload": "AAA5AAAAeGY2MTdhZjFjYTc3NGViYmQ2ZDIzZThmZTEyYzU2ZDQxZDI1YTIyZDgxZTg4ZjY3YzZjNmVlMGQ0CwAAAGNyZWF0ZV91c2VyAQABAB4AAAAAAA8AAAAAAAAAAAR0ZXh0AAAAAAABAAMAAABmb28=",
	//         "type": "execute",
	//         "fee": "100",
	//         "nonce": 10,
	//         "chain_id": "asdf"
	//       },
	//       "serialization": "concat",
	//       "sender": null
	//     },
	//     "tx_result": {
	//       "code": 0,
	//       "gas": 10,
	//       "log": "This is log"
	//     },
	//     "warning": "HASH MISMATCH: requested 0102030400000000000000000000000000000000000000000000000000000000; received 53096abc68a1f0a09823a4d8dea302b0ea930715627fc80be7607a9fa714fe60"
	//   },
	//   "error": ""
	// }
}

func Example_respTxQuery_WithRaw_json() {
	Print(&RespTxQuery{Msg: getExampleTxQueryResponse(), WithRaw: true}, nil, "json")
	// Output:
	// {
	//   "result": {
	//     "hash": "0102030400000000000000000000000000000000000000000000000000000000",
	//     "height": 10,
	//     "tx": {
	//       "signature": {
	//         "sig": "yz/tf2/zblkFTASoMbIV5RQFJ1PuNT5v4x1LTvc2rNYVUSfbVV0wBroU/LTHm7rVbI5juBqYljGbsFOp4lNHWAA=",
	//         "type": "secp256k1_ep"
	//       },
	//       "body": {
	//         "desc": "This is a test transaction for cli",
	//         "payload": "AAA5AAAAeGY2MTdhZjFjYTc3NGViYmQ2ZDIzZThmZTEyYzU2ZDQxZDI1YTIyZDgxZTg4ZjY3YzZjNmVlMGQ0CwAAAGNyZWF0ZV91c2VyAQABAB4AAAAAAA8AAAAAAAAAAAR0ZXh0AAAAAAABAAMAAABmb28=",
	//         "type": "execute",
	//         "fee": "100",
	//         "nonce": 10,
	//         "chain_id": "asdf"
	//       },
	//       "serialization": "concat",
	//       "sender": null
	//     },
	//     "tx_result": {
	//       "code": 0,
	//       "gas": 10,
	//       "log": "This is log"
	//     },
	//     "raw": "00009e0141cb3fed7f6ff36e59054c04a831b215e514052753ee353e6fe31d4b4ef736acd6155127db555d3006ba14fcb4c79bbad56c8e63b81a9896319bb053a9e2534758000c736563703235366b315f6570e602225468697320697320612074657374207472616e73616374696f6e20666f7220636c69e8010000390000007866363137616631636137373465626264366432336538666531326335366434316432356132326438316538386636376336633665653064340b0000006372656174655f75736572010001001e00000000000f000000000000000004746578740000000000010003000000666f6f076578656375746501033130300a00000000000000046173646606636f6e63617400",
	//     "warning": "HASH MISMATCH: requested 0102030400000000000000000000000000000000000000000000000000000000; received 53096abc68a1f0a09823a4d8dea302b0ea930715627fc80be7607a9fa714fe60"
	//   },
	//   "error": ""
	// }
}

func Test_TxHashAndExecResponse(t *testing.T) {
	hash := types.Hash{1, 2, 3, 4, 5}
	qr := getExampleTxQueryResponse()
	qr.Hash = hash
	resp := &TxHashAndExecResponse{
		Res: qr,
	}
	expectJSON := `{"tx_hash":"0102030405000000000000000000000000000000000000000000000000000000","height":10,"tx":{"signature":{"sig":"yz/tf2/zblkFTASoMbIV5RQFJ1PuNT5v4x1LTvc2rNYVUSfbVV0wBroU/LTHm7rVbI5juBqYljGbsFOp4lNHWAA=","type":"secp256k1_ep"},"body":{"desc":"This is a test transaction for cli","payload":"AAA5AAAAeGY2MTdhZjFjYTc3NGViYmQ2ZDIzZThmZTEyYzU2ZDQxZDI1YTIyZDgxZTg4ZjY3YzZjNmVlMGQ0CwAAAGNyZWF0ZV91c2VyAQABAB4AAAAAAA8AAAAAAAAAAAR0ZXh0AAAAAAABAAMAAABmb28=","type":"execute","fee":"100","nonce":10,"chain_id":"asdf"},"serialization":"concat","sender":null},"tx_result":{"code":0,"gas":10,"log":"This is log"}}`
	expectText := "Transaction ID: 0102030405000000000000000000000000000000000000000000000000000000\nStatus: success\nHeight: 10\nLogs:\n  This is log"

	outText, err := resp.MarshalText()
	assert.NoError(t, err, "MarshalText should not return error")
	assert.Equal(t, expectText, string(outText), "MarshalText should return expected text")

	outJSON, err := resp.MarshalJSON()
	// fmt.Println(string(outJSON))
	assert.NoError(t, err, "MarshalJSON should not return error")
	assert.Equal(t, expectJSON, string(outJSON), "MarshalJSON should return expected json")
}

func TestRespTxQuery_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		input    *RespTxQuery
		expected string
	}{
		{
			name: "success status",
			input: &RespTxQuery{
				Msg: &types.TxQueryResponse{
					Hash:   types.Hash{0x1}, // simple hash for testing
					Height: 100,
					Result: &types.TxResult{
						Code: uint32(types.CodeOk),
						Log:  "transaction successful",
					},
				},
			},
			expected: "Transaction ID: 0100000000000000000000000000000000000000000000000000000000000000\nStatus: success\nHeight: 100\nLogs:\n  transaction successful",
		},
		{
			name: "failed status",
			input: &RespTxQuery{
				Msg: &types.TxQueryResponse{
					Hash:   types.Hash{0x2}, // different hash
					Height: 50,
					Result: &types.TxResult{
						Code: 1, // non-zero code means failure
						Log:  "transaction failed",
					},
				},
			},
			expected: "Transaction ID: 0200000000000000000000000000000000000000000000000000000000000000\nStatus: failed\nHeight: 50\nLogs:\n  transaction failed",
		},
		{
			name: "pending status",
			input: &RespTxQuery{
				Msg: &types.TxQueryResponse{
					Hash:   types.Hash{0x3},
					Height: -1, // -1 height indicates pending
					Result: &types.TxResult{
						Code: 0,
						Log:  "transaction pending",
					},
				},
			},
			expected: "Transaction ID: 0300000000000000000000000000000000000000000000000000000000000000\nStatus: pending\nHeight: -1\nLogs:\n  transaction pending",
		},
		{
			name: "pending status",
			input: &RespTxQuery{
				Msg: &types.TxQueryResponse{
					Hash:   mustUnmarshalHash("1f456bec9c3819f077a7aafce25cf43ad9ab0a264cbae6efeaa8b92ec0bf4b47"),
					Height: -1, // -1 height indicates pending
					Tx: &types.Transaction{
						Body: &types.TransactionBody{
							PayloadType: types.PayloadTypeExecute,
							Fee:         big.NewInt(100),
							Nonce:       10,
							ChainID:     "asdf",
							Description: "This is a test transaction",
						},
						Serialization: types.SignedMsgConcat,
					},
					Result: &types.TxResult{
						Code: 0,
						Log:  "transaction pending",
					},
				},
			},
			expected: "Transaction ID: 1f456bec9c3819f077a7aafce25cf43ad9ab0a264cbae6efeaa8b92ec0bf4b47\nStatus: pending\nHeight: -1\nLogs:\n  transaction pending",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.input.MarshalText()
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(result))
		})
	}
}

func mustUnmarshalHash(s string) types.Hash {
	h, err := types.NewHashFromString(s)
	if err != nil {
		panic(err)
	}
	return h
}

// This tests that the result of json marshalling TxHashAndExecResponse
// can be unmarshalled into a RespTxQuery. This is important because RespTxQuery
// is used for regular (no --sync flag) transactions, while TxHashAndExecResponse
// is used for --sync transactions. This ensures that anyone can unmarshal the result
// of a --sync transaction into a RespTxQuery.
func Test_MarshallingTxResults(t *testing.T) {
	hash := types.Hash{0x1} // simple hash for testing
	execRes := &TxHashAndExecResponse{
		Res: &types.TxQueryResponse{
			Hash:   hash,
			Height: 100,
			Result: &types.TxResult{
				Code: uint32(types.CodeOk),
				Log:  "transaction successful",
			},
		},
	}

	execBts, err := execRes.MarshalJSON()
	require.NoError(t, err)

	var txRes RespTxHash
	err = txRes.UnmarshalJSON(execBts)
	require.NoError(t, err)

	// check that they have the right hash
	require.Equal(t, hash.String(), txRes.Hex())
}
