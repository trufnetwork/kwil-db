package types

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
)

type TestPayload struct {
	Key   string
	Value string

	marshalError error
}

func (p *TestPayload) MarshalBinary() ([]byte, error) {
	return []byte(fmt.Sprintf("%s=%s", p.Key, p.Value)), p.marshalError
}

func (p *TestPayload) UnmarshalBinary(data []byte) error {
	key, value, ok := bytes.Cut(data, []byte("="))
	if !ok {
		return errors.New("invalid payload format")
	}
	p.Key = string(key)
	p.Value = string(value)
	return nil
}

func (p *TestPayload) Type() PayloadType {
	return "test"
}

func TestTransactionSerialization(t *testing.T) {
	t.Parallel()
	payload := &TestPayload{
		Key:   "dummy",
		Value: "data",
	}

	payloadBts, err := payload.MarshalBinary()
	require.NoError(t, err)

	defDesc := "You are signing a kwil transaction of type test"
	longDesc := "dfhjdshfksdhfkshdkfjsdbfhjsbdfhsbdkfhsbdfhgjsdbfhjsdbjhfbsdkfhjsdfdsbfjhsdbfhjgdsfvbhgsdbfjhsdbfhsjdbfhsdbfshdjbfhdsfvbhsdbfhsdbfshdgfvhsdbfhsdbfhdbfhasfhwegsfwegsfhwedfegsfysegdfysegfhesgfyuwegfywesgfyswegfywuegfuyse"

	chainID := "test-chain"
	nonce := uint64(1)

	// Tests for SerializeMsg:
	// 1. Invalid serialization type
	// 2. Default serialization type
	// 3. Long description

	testcase := []struct {
		name        string
		serType     SignedMsgSerializationType
		desc        string
		expectError bool
	}{
		{
			name:        "invalid serialization type",
			serType:     "invalid",
			desc:        defDesc,
			expectError: true,
		},
		{
			name:        "default serialization type",
			serType:     DefaultSignedMsgSerType, // concat
			desc:        defDesc,
			expectError: false,
		},
		{
			name:        "direct",
			serType:     SignedMsgDirect, // direct
			desc:        defDesc,
			expectError: false,
		},
		{
			name:        "long description",
			serType:     SignedMsgConcat, // concat
			desc:        longDesc,
			expectError: true,
		},
	}

	for _, tt := range testcase {
		txBody := &TransactionBody{
			Description: tt.desc,
			Payload:     payloadBts,
			PayloadType: payload.Type(),
			Fee:         big.NewInt(0),
			Nonce:       nonce,
			ChainID:     chainID,
		}

		msg, err := txBody.SerializeMsg(tt.serType)
		if tt.expectError {
			require.Error(t, err, tt.name)
			continue
		}

		require.NoError(t, err, tt.name)
		require.NotEmpty(t, msg, tt.name)
		// fmt.Println(tt.name, ":", string(msg))
	}

}

func TestTransactionSign(t *testing.T) {
	t.Parallel()
	// Test scenarios:
	// 1. Invalid signer
	// 2. Valid signer: Sign + Verify
	// Signers to test: EthPersonalSigner, Ed25519Signer
	// 3. Invalid serialization type

	payload := &TestPayload{
		Key:   "dummy",
		Value: "data",
	}

	payloadBts, err := payload.MarshalBinary()
	require.NoError(t, err)

	testcases := []struct {
		name          string
		serType       SignedMsgSerializationType
		signer        auth.Signer
		authenticator auth.Authenticator
		expectError   bool
	}{
		{
			name:          "valid ed25519 signer",
			serType:       DefaultSignedMsgSerType,
			signer:        ed25519Signer(t),
			authenticator: auth.Ed25519Authenticator{},
			expectError:   false,
		},
		{
			name:          "valid eth personal signer",
			serType:       DefaultSignedMsgSerType,
			signer:        secp256k1Signer(t),
			authenticator: auth.EthSecp256k1Authenticator{},
			expectError:   false,
		},
		{
			name:          "invalid serialization type",
			serType:       "invalid",
			signer:        secp256k1Signer(t),
			authenticator: auth.EthSecp256k1Authenticator{},
			expectError:   true,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			tx := &Transaction{
				Body: &TransactionBody{
					Payload:     payloadBts,
					PayloadType: payload.Type(),
					Fee:         big.NewInt(0),
					Nonce:       1,
					ChainID:     "test-chain",
				},
				Serialization: tt.serType,
			}

			err = tx.Sign(tt.signer)
			if tt.expectError {
				require.Error(t, err, tt.name)
				return
			}

			require.NoError(t, err, tt.name)

			// Verify the signature
			msg, err := tx.SerializeMsg()
			require.NoError(t, err, "failed to serialize transaction")

			err = tt.authenticator.Verify(tx.Sender, msg, tx.Signature.Data)
			require.NoError(t, err, "signature verification failed")
		})
	}
}

func TestTransactionBodyMarshalUnmarshal(t *testing.T) {
	t.Parallel()

	payload := &TestPayload{
		Key:   "dummy",
		Value: "data",
	}

	payloadBts, err := payload.MarshalBinary()
	require.NoError(t, err)

	testcases := []struct {
		name string
		body *TransactionBody
	}{
		{
			name: "valid transaction body",
			body: &TransactionBody{
				Description: "",
				Payload:     payloadBts,
				PayloadType: payload.Type(),
				Fee:         big.NewInt(1000000),
				Nonce:       1,
				ChainID:     "test-chain",
			},
		},
		{
			name: "empty payload",
			body: &TransactionBody{
				Description: "You are signing a kwil transaction of type test",
				Payload:     nil,
				PayloadType: payload.Type(),
				Fee:         big.NewInt(1000000),
				Nonce:       1,
				ChainID:     "test-chain",
			},
		},
		{
			name: "empty description",
			body: &TransactionBody{
				Description: "",
				Payload:     payloadBts,
				PayloadType: payload.Type(),
				Fee:         big.NewInt(0),
				Nonce:       1,
				ChainID:     "test-chain",
			},
		},
		{
			name: "empty Fee",
			body: &TransactionBody{
				Description: "You are signing a kwil transaction of type test",
				Payload:     payloadBts,
				PayloadType: payload.Type(),
				Fee:         nil,
				Nonce:       1,
				ChainID:     "test-chain",
			},
		},
		{
			name: "zero fee",
			body: &TransactionBody{
				Description: "You are signing a kwil transaction of type test",
				Payload:     payloadBts,
				PayloadType: payload.Type(),
				Fee:         big.NewInt(0),
				Nonce:       1,
				ChainID:     "test-chain",
			},
		},
		{
			name: "empty payload type",
			body: &TransactionBody{
				Description: "You are signing a kwil transaction of type test",
				Payload:     payloadBts,
				PayloadType: "",
				Fee:         big.NewInt(1000000),
				Nonce:       1,
				ChainID:     "test-chain",
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.body.MarshalBinary()
			require.NoError(t, err)

			newBody := &TransactionBody{}
			err = newBody.UnmarshalBinary(data)
			require.NoError(t, err)

			require.Equal(t, tt.body.Description, newBody.Description)
			require.Equal(t, tt.body.PayloadType, newBody.PayloadType)
			fee := tt.body.Fee
			// if fee == nil {
			// 	fee = big.NewInt(0)
			// }
			require.Equal(t, fee, newBody.Fee)
			require.Equal(t, tt.body.Nonce, newBody.Nonce)
			require.Equal(t, tt.body.ChainID, newBody.ChainID)

			newData, err := newBody.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, data, newData)
		})
	}
}

func TestTransactionMarshalUnmarshal(t *testing.T) {
	t.Parallel()

	payload := &TestPayload{
		Key:   "dummy",
		Value: "data",
	}

	payloadBts, err := payload.MarshalBinary()
	require.NoError(t, err)

	signer := secp256k1Signer(t)
	sender := signer.CompactID()

	require.NoError(t, err)

	testcases := []struct {
		name   string
		signer auth.Signer
		fn     func(t *testing.T) *Transaction
	}{
		{
			name:   "valid transaction",
			signer: secp256k1Signer(t),
			fn: func(t *testing.T) *Transaction {
				// sign tx
				tx := &Transaction{
					Body: &TransactionBody{
						Description: "You are signing a kwil transaction of type test",
						Payload:     payloadBts,
						PayloadType: payload.Type(),
						Fee:         big.NewInt(19990),
						Nonce:       1,
						ChainID:     "test-chain",
					},
					Serialization: DefaultSignedMsgSerType,
				}

				err := tx.Sign(secp256k1Signer(t))
				require.NoError(t, err)

				return tx
			},
		},
		{
			name: "empty signature",
			fn: func(t *testing.T) *Transaction {
				tx := &Transaction{
					Body: &TransactionBody{
						Description: "You are signing a kwil transaction of type test",
						Payload:     payloadBts,
						PayloadType: payload.Type(),
						Fee:         big.NewInt(19990),
						Nonce:       1,
						ChainID:     "test-chain",
					},
					Serialization: DefaultSignedMsgSerType,
				}

				err := tx.Sign(secp256k1Signer(t))
				require.NoError(t, err)

				return tx
			},
		},
		{
			name:   "empty signature type",
			signer: secp256k1Signer(t),
			fn: func(t *testing.T) *Transaction {
				tx := &Transaction{
					Body: &TransactionBody{
						Description: "You are signing a kwil transaction of type test",
						Payload:     payloadBts,
						PayloadType: payload.Type(),
						Fee:         big.NewInt(19990),
						Nonce:       1,
						ChainID:     "test-chain",
					},
					Serialization: DefaultSignedMsgSerType,
					Signature: &auth.Signature{
						Data: []byte("signature"),
					},
					Sender: sender,
				}

				return tx
			},
		},
		{
			name: "empty signature data",
			fn: func(t *testing.T) *Transaction {
				tx := &Transaction{
					Body: &TransactionBody{
						Description: "You are signing a kwil transaction of type test",
						Payload:     payloadBts,
						PayloadType: payload.Type(),
						Fee:         big.NewInt(19990),
						Nonce:       1,
						ChainID:     "test-chain",
					},
					Serialization: DefaultSignedMsgSerType,
					Signature: &auth.Signature{
						Type: "secp256k1",
					},
					Sender: sender,
				}

				return tx
			},
		},
		{
			name: "empty body (allowed now)",
			fn: func(t *testing.T) *Transaction {
				return &Transaction{
					Body: nil,
					Signature: &auth.Signature{
						Data: []byte("signature"),
						Type: "secp256k1",
					},
					Sender:        sender,
					Serialization: DefaultSignedMsgSerType,
				}
			},
		},
		{
			name: "empty sender",
			fn: func(t *testing.T) *Transaction {
				return &Transaction{
					Body: &TransactionBody{
						Description: "You are signing a kwil transaction of type test",
						Payload:     payloadBts,
						PayloadType: payload.Type(),
						Fee:         big.NewInt(19990),
						Nonce:       1,
						ChainID:     "test-chain",
					},
					Signature: &auth.Signature{
						Data: []byte("signature"),
						Type: "secp256k1",
					},
					Sender:        []byte{},
					Serialization: DefaultSignedMsgSerType,
				}
			},
		},
		{
			name: "empty serialization type",
			fn: func(t *testing.T) *Transaction {
				return &Transaction{
					Body: &TransactionBody{
						Description: "You are signing a kwil transaction of type test",
						Payload:     payloadBts,
						PayloadType: payload.Type(),
						Fee:         big.NewInt(19990),
						Nonce:       1,
						ChainID:     "test-chain",
					},
					Signature: &auth.Signature{
						Data: []byte("signature"),
						Type: "secp256k1",
					},
					Sender: sender,
				}
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			tx := tt.fn(t)

			data, err := tx.MarshalBinary()
			require.NoError(t, err)

			newTx := &Transaction{}
			err = newTx.UnmarshalBinary(data)
			require.NoError(t, err)

			require.EqualExportedValues(t, tx, newTx)

			newData, err := newTx.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, data, newData)
		})
	}
}

func secp256k1Signer(t *testing.T) *auth.EthPersonalSigner {
	privKey, _, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)

	privKeyBytes := privKey.Bytes()
	k, err := crypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	require.NoError(t, err)

	return &auth.EthPersonalSigner{Key: *k}
}

func ed25519Signer(t *testing.T) *auth.Ed25519Signer {
	privKey, _, err := crypto.GenerateEd25519Key(nil)
	require.NoError(t, err)

	pBytes := privKey.Bytes()
	k, err := crypto.UnmarshalEd25519PrivateKey(pBytes)
	require.NoError(t, err)

	return &auth.Ed25519Signer{Ed25519PrivateKey: *k}
}

func TestTransactionBodyProblemRoundTrip(t *testing.T) {
	t.Skip()
	// data := []byte("\x00\x00\x00\x00D\x00\x00\x00\a\x00\x00\x000000000\f\x00\x00\x00000000000000\t\x00\x00\x00000000000\x02\x00\x00\x000000000000\x00\x00\x00\x000000000000\x06\x00\x00\x00000000\x06\x00\x00\x00000000")
	// data := []byte("\x00\x00\x00\x00D\x00\x00\x00\a\x00\x00\x000000000\f\x00\x00\x00000000000000\t\x00\x00\x00000000000\x02\x00\x00\x00\x00000000000\n\x00\x00\x000000000000\x06\x00\x00\x00000000\x06\x00\x00\x00000000")
	// data := []byte("\x00\x00\x00\x00G\x00\x00\x00\a\x00\x00\x000000000\f\x00\x00\x00000000000000\t\x00\x00\x000000000000\x04\x00\x00\x00100000000000\n\x00\x00\x000000000000\x06\x00\x00\x00000000\x06\x00\x00\x00000000")
	// fee should not be nil:
	data := []byte("\x00\x00\x00\x00G\x00\x00\x00\a\x00\x00\x000000000\f\x00\x00\x00000000000000\x11\x00\x00\x0000000000000000000\x0000000000\n\x00\x00\x000000000000\x06\x00\x00\x00000000\x06\x00\x00\x00000000")

	var tx Transaction
	err := tx.UnmarshalBinary(data)
	if err != nil {
		t.Fatal(err)
	}

	bodyData, err := tx.Body.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var body2 TransactionBody
	err = body2.UnmarshalBinary(bodyData)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, *tx.Body, body2)

	bodyData2, err := body2.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, bodyData, bodyData2)

	newData, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, data[:len(newData)], newData)
}

func TestBigIntRoundTrip(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       *big.Int
		expectError bool
	}{
		{
			name:        "nil big int",
			input:       nil,
			expectError: false,
		},
		{
			name:        "zero value",
			input:       big.NewInt(0),
			expectError: false,
		},
		{
			name:        "positive small number",
			input:       big.NewInt(42),
			expectError: false,
		},
		{
			name:        "negative number",
			input:       big.NewInt(-100),
			expectError: false,
		},
		{
			name:        "large number",
			input:       new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			err := WriteBigInt(buf, tc.input)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			result, err := ReadBigInt(buf)
			require.NoError(t, err)

			if tc.input == nil {
				require.Nil(t, result)
			} else {
				require.Equal(t, tc.input, result)
			}
		})
	}
}

func TestBigIntReadErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       []byte
		expectError bool
	}{
		{
			name:        "empty buffer",
			input:       []byte{},
			expectError: true,
		},
		{
			name:        "truncated length",
			input:       []byte{1, 4},
			expectError: true,
		},
		{
			name:        "invalid length prefix",
			input:       []byte{1, 255, 255, 255, 255},
			expectError: true,
		},
		{
			name:        "missing data",
			input:       []byte{1, 0, 0, 0, 4},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer(tc.input)
			_, err := ReadBigInt(buf)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBigIntWriteErrors(t *testing.T) {
	t.Parallel()

	errWriter := &errorWriter{err: errors.New("write error")}

	testCases := []struct {
		name   string
		writer io.Writer
		input  *big.Int
	}{
		{
			name:   "writer error on nil marker",
			writer: errWriter,
			input:  nil,
		},
		{
			name:   "writer error on value marker",
			writer: &errorWriter{err: errors.New("write error"), failAfter: 1},
			input:  big.NewInt(42),
		},
		{
			name:   "writer error on length",
			writer: &errorWriter{err: errors.New("write error"), failAfter: 2},
			input:  big.NewInt(42),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := WriteBigInt(tc.writer, tc.input)
			require.Error(t, err)
		})
	}
}

type errorWriter struct {
	err       error
	failAfter int
	written   int
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	w.written += len(p)
	if w.written > w.failAfter {
		return 0, w.err
	}
	return len(p), nil
}

func TestReadBytes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       []byte
		expected    []byte
		expectError bool
	}{
		{
			name:        "read zero length",
			input:       []byte{0, 0, 0, 0},
			expected:    []byte{},
			expectError: false,
		},
		{
			name:        "read nil",
			input:       []byte{0xff, 0xff, 0xff, 0xff},
			expected:    nil,
			expectError: false,
		},
		{
			name:        "read exact length data",
			input:       []byte{4, 0, 0, 0, 't', 'e', 's', 't'},
			expected:    []byte("test"),
			expectError: false,
		},
		{
			name:        "truncated length field",
			input:       []byte{4, 0},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "length exceeds available data",
			input:       []byte{10, 0, 0, 0, 't', 'e', 's', 't'},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "read from non-buffer reader",
			input:       []byte{4, 0, 0, 0, 't', 'e', 's', 't'},
			expected:    []byte("test"),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var reader io.Reader
			if tc.name == "read from non-buffer reader" {
				reader = &customReader{bytes.NewReader(tc.input)}
			} else {
				reader = bytes.NewReader(tc.input)
			}

			result, err := ReadBytes(reader)
			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, result)

			w := &bytes.Buffer{}
			err = WriteBytes(w, result)
			require.NoError(t, err)
			result2, err := ReadBytes(w)
			require.NoError(t, err)

			require.Equal(t, result2, result)
		})
	}
}

type customReader struct {
	r *bytes.Reader
}

func (cr *customReader) Read(b []byte) (int, error) {
	return cr.r.Read(b)
}

func Test_TransactionBodyJSONEdgeCases(t *testing.T) {
	t.Run("marshal with zero fee", func(t *testing.T) {
		txB := TransactionBody{
			Description: "test",
			Payload:     []byte("test payload"),
			PayloadType: PayloadTypeExecute,
			Fee:         big.NewInt(0),
			Nonce:       1,
			ChainID:     "test-chain",
		}

		b, err := json.Marshal(txB)
		require.NoError(t, err)

		var decoded TransactionBody
		err = json.Unmarshal(b, &decoded)
		require.NoError(t, err)
		assert.Equal(t, "0", decoded.Fee.String())
	})

	t.Run("marshal with large fee", func(t *testing.T) {
		largeFee := new(big.Int).Exp(big.NewInt(2), big.NewInt(100), nil)
		txB := TransactionBody{
			Description: "test",
			Payload:     []byte("test payload"),
			PayloadType: PayloadTypeExecute,
			Fee:         largeFee,
			Nonce:       1,
			ChainID:     "test-chain",
		}

		b, err := json.Marshal(txB)
		require.NoError(t, err)

		var decoded TransactionBody
		err = json.Unmarshal(b, &decoded)
		require.NoError(t, err)
		assert.Equal(t, largeFee.String(), decoded.Fee.String())
	})

	t.Run("unmarshal with invalid fee string", func(t *testing.T) {
		jsonData := []byte(`{
			"desc": "test",
			"payload": "dGVzdA==",
			"type": "deploy_schema",
			"fee": "not_a_number",
			"nonce": 1,
			"chain_id": "test-chain"
		}`)

		var txB TransactionBody
		err := json.Unmarshal(jsonData, &txB)
		assert.Error(t, err)
	})

	t.Run("unmarshal with empty fee string", func(t *testing.T) {
		jsonData := []byte(`{
			"desc": "test",
			"payload": "dGVzdA==",
			"type": "deploy_schema",
			"fee": "",
			"nonce": 1,
			"chain_id": "test-chain"
		}`)

		var txB TransactionBody
		err := json.Unmarshal(jsonData, &txB)
		require.NoError(t, err)
		assert.Equal(t, "0", txB.Fee.String())
	})

	t.Run("unmarshal with negative fee", func(t *testing.T) {
		jsonData := []byte(`{
			"desc": "test",
			"payload": "dGVzdA==",
			"type": "deploy_schema",
			"fee": "-100",
			"nonce": 1,
			"chain_id": "test-chain"
		}`)

		var txB TransactionBody
		err := json.Unmarshal(jsonData, &txB)
		require.NoError(t, err)
		assert.Equal(t, "-100", txB.Fee.String())
	})

	t.Run("marshal with nil fee", func(t *testing.T) {
		txB := TransactionBody{
			Description: "test",
			Payload:     []byte("test payload"),
			PayloadType: PayloadTypeExecute,
			Fee:         nil,
			Nonce:       1,
			ChainID:     "test-chain",
		}

		b, err := json.Marshal(txB)
		require.NoError(t, err)

		var decoded TransactionBody
		err = json.Unmarshal(b, &decoded)
		require.NoError(t, err)
		assert.Equal(t, "0", decoded.Fee.String())
	})
}

func TestTransactionBody_SerializeSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		body     TransactionBody
		expected int64
	}{
		{
			name: "empty transaction body",
			body: TransactionBody{
				Description: "",            // 1 + 0
				Payload:     nil,           // 1 + 0
				PayloadType: "",            // 1 + 0
				Fee:         big.NewInt(0), // 1 + 1 + 1
				Nonce:       0,             // 8
				ChainID:     "",            // 1 + 0
			},
			expected: 15, // 1 + 0 + 1 + 0 + 1 + 0 + (1 + 1 + 1) + 8 + 1 + 0
		},
		{
			name: "large fee value",
			body: TransactionBody{
				Description: "",                                                    // 1 + 0
				Payload:     nil,                                                   // 1 + 0
				PayloadType: "",                                                    // 1 + 0
				Fee:         new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), // 78 chars: 115792089237316195423570985008687907853269984665640564039457584007913129639936
				Nonce:       0,                                                     // 8
				ChainID:     "",                                                    // 1 + 0
			},
			expected: 92, // 1 + 0 + 1 + 0 + 1 + 0 + (1 + 1 + 78) + 8 + 1 + 0
		},
		{
			name: "nil fee",
			body: TransactionBody{
				Description: "",  // 1 + 0
				Payload:     nil, // 1 + 0
				PayloadType: "",  // 1 + 0
				Fee:         nil, // 1
				Nonce:       0,   // 8
				ChainID:     "",  // 1 + 0
			},
			expected: 13, // 1 + 0 + 1 + 0 + 1 + 0 + (1) + 8 + 1 + 0
		},
		{
			name: "large payload and description",
			body: TransactionBody{
				Description: string(make([]byte, 1000)),
				Payload:     make([]byte, 1000),
				PayloadType: "test",
				Fee:         big.NewInt(1000),
				Nonce:       999999999,
				ChainID:     string(make([]byte, 1000)),
			},
			expected: 3025, // 2 + 1000 + 2 + 1000 + 1 + 4 + (1 + 2 + 4) + 8 + 2 + 1000
		},
		{
			name: "negative fee",
			body: TransactionBody{
				Description: "",
				Payload:     nil,
				PayloadType: "",
				Fee:         big.NewInt(-1000),
				Nonce:       0,
				ChainID:     "",
			},
			expected: 19, // 1 + 0 + 1 + 0 + 1 + 0 + (1 + 2 + 5) + 8 + 1 + 0
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			size := tc.body.SerializeSize()
			require.Equal(t, tc.expected, size)

			// Verify the calculated size matches actual serialization
			data, err := tc.body.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, size, int64(len(data)))
		})
	}
}

func TestTransaction_SerializeSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		tx       Transaction
		expected int64
	}{
		{
			name: "minimal transaction",
			tx: Transaction{
				Body:          &TransactionBody{},
				Signature:     &auth.Signature{},
				Sender:        []byte{},
				Serialization: "",
			},
			expected: 21, // 2 + (1 + 13) + (1 + 2) + 1 + 1
		},
		{
			name: "transaction with data",
			tx: Transaction{
				Body: &TransactionBody{
					Description: "tst",           // 1 + 3
					Payload:     []byte("t"),     // 1 + 1
					PayloadType: "tst",           // 1 + 3
					Fee:         big.NewInt(100), // 1 + 1 + 3
					Nonce:       0,               // 8
					ChainID:     "testchain",     // 1 + 9
				},
				Signature: &auth.Signature{
					Type: "secp256k1",         // 1 + 9
					Data: []byte("signature"), // 1 + 9
				},
				Sender:        []byte("sender"),
				Serialization: "direct",
			},
			expected: 71, // 2 + 1 + (4 + 2 + 4 + 5 + 8 + 10) + 1 + (10 + 10) + 1 + 6 + 1 + 6
		},
		{
			name: "nil body",
			tx: Transaction{
				Body:          nil,
				Signature:     &auth.Signature{},
				Sender:        []byte{1},
				Serialization: "test",
			},
			expected: 13, // 2 + 1 + 0 + 1 + (1 + 1) + 1 + 1 + 1 + 4
		},
		{
			name: "nil signature",
			tx: Transaction{
				Body:          &TransactionBody{},
				Signature:     nil,
				Sender:        []byte{1},
				Serialization: "test",
			},
			expected: 24, // 2 + 1 + (13) + 1 + 0 + 1 + 1 + 1 + 4
		},
		{
			name: "large signature data",
			tx: Transaction{
				Body:          &TransactionBody{},
				Signature:     &auth.Signature{Data: make([]byte, 1000), Type: "test"},
				Sender:        []byte{1},
				Serialization: "test",
			},
			expected: 1032, // 2 + 1 + (13) + 2 + (2 + 1000 + 1 + 4) + 1 + 1 + 1 + 4
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			size := tc.tx.SerializeSize()
			require.Equal(t, tc.expected, size)

			// Verify calculated size matches actual serialization
			data, err := tc.tx.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, size, int64(len(data)))
		})
	}
}

func TestByteReader(t *testing.T) {
	t.Parallel()

	t.Run("use existing ByteReader", func(t *testing.T) {
		existingBR := bytes.NewBuffer([]byte{1, 2, 3}) // also an io.ByteReader to start
		br := newByteReader(existingBR)                // so pass through
		require.Equal(t, existingBR, br)

		b, err := br.ReadByte()
		require.NoError(t, err)
		require.Equal(t, byte(1), b)
	})

	t.Run("create new ByteReader", func(t *testing.T) {
		r := &regularReader{strings.NewReader("abc")} // just an io.Reader, not an io.ByteReader
		br := newByteReader(r)                        // so wraps
		require.IsType(t, &byteReader{}, br)

		b, err := br.ReadByte()
		require.NoError(t, err)
		require.Equal(t, byte('a'), b)
	})

	t.Run("read from empty reader", func(t *testing.T) {
		r := &regularReader{strings.NewReader("")}
		br := newByteReader(r)
		_, err := br.ReadByte()
		require.Error(t, err)
		require.Equal(t, io.EOF, err)
	})

	t.Run("read multiple bytes", func(t *testing.T) {
		r := &regularReader{strings.NewReader("xyz")}
		br := newByteReader(r)

		b1, err := br.ReadByte()
		require.NoError(t, err)
		require.Equal(t, byte('x'), b1)

		b2, err := br.ReadByte()
		require.NoError(t, err)
		require.Equal(t, byte('y'), b2)

		b3, err := br.ReadByte()
		require.NoError(t, err)
		require.Equal(t, byte('z'), b3)

		_, err = br.ReadByte()
		require.Error(t, err)
		require.Equal(t, io.EOF, err)
	})

	t.Run("read from failing reader", func(t *testing.T) {
		r := &errorReader{err: errors.New("read error")}
		br := newByteReader(r)
		_, err := br.ReadByte()
		require.Error(t, err)
		require.Equal(t, "read error", err.Error())
	})
}

type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

type regularReader struct {
	r io.Reader // hide any io.ByteReader methods
}

func (r *regularReader) Read(p []byte) (n int, err error) {
	return r.r.Read(p)
}
func TestCreateTransaction(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		payload     Payload
		chainID     string
		nonce       uint64
		expectError bool
	}{
		{
			name: "valid payload",
			payload: &TestPayload{
				Key:   "test",
				Value: "value",
			},
			chainID:     "test-chain",
			nonce:       1,
			expectError: false,
		},
		{
			name: "payload with marshal fail",
			payload: &TestPayload{
				Key:          "test",
				Value:        "value",
				marshalError: errors.New("boom"),
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := CreateTransaction(tc.payload, tc.chainID, tc.nonce)
			if tc.expectError {
				require.Error(t, err)
				require.Nil(t, tx)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tx)
			require.Equal(t, DefaultSignedMsgSerType, tx.Serialization)
			require.Equal(t, tc.chainID, tx.Body.ChainID)
			require.Equal(t, tc.nonce, tx.Body.Nonce)
			require.Equal(t, big.NewInt(0), tx.Body.Fee)

			if tc.payload != nil {
				require.Equal(t, tc.payload.Type(), tx.Body.PayloadType)
				payloadData, err := tc.payload.MarshalBinary()
				require.NoError(t, err)
				require.Equal(t, payloadData, tx.Body.Payload)
			}
		})
	}
}

func TestCreateNodeTransaction(t *testing.T) {
	t.Parallel()

	payload := &TestPayload{
		Key:   "node",
		Value: "test",
	}
	chainID := "test-chain"
	nonce := uint64(1)

	tx, err := CreateNodeTransaction(payload, chainID, nonce)

	require.NoError(t, err)
	require.NotNil(t, tx)
	require.Equal(t, SignedMsgDirect, tx.Serialization)
}

func TestReadCompactBytes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       []byte
		expected    []byte
		expectError bool
	}{
		{
			name:        "max int64 length",
			input:       append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, make([]byte, 100)...),
			expectError: true,
		},
		{
			name:        "length near int64 max",
			input:       append([]byte{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, make([]byte, 100)...),
			expectError: true,
		},
		{
			name:        "invalid varint encoding",
			input:       []byte{0xff, 0xff, 0xff},
			expectError: true,
		},
		{
			name:        "incomplete data after length",
			input:       []byte{0x08, 0x01, 0x02},
			expectError: true,
		},
		{
			name:        "length larger than remaining data",
			input:       []byte{0x10, 0x01, 0x02, 0x03},
			expectError: true,
		},
		{
			name:     "exact data length match",
			input:    []byte{0x08, 0x01, 0x02, 0x03, 0x04},
			expected: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name:        "invalid negative length",
			input:       []byte{0x03, 0x42},
			expectError: true,
		},
		{
			name:     "single byte data",
			input:    []byte{0x02, 0x42},
			expected: []byte{0x42},
		},
		{
			name:     "explicit zero length",
			input:    []byte{0x00},
			expected: []byte{},
		},
		{
			name:     "nil indicator",
			input:    []byte{0x01},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.input)
			result, err := ReadCompactBytes(reader)

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, result)
		})
	}

	t.Run("with custom reader implementation", func(t *testing.T) {
		bts := []byte{0x08, 0x01, 0x02, 0x03, 0x04}
		r := &regularReader{bytes.NewReader(bts)}
		// br := newByteReader(r)

		result, err := ReadCompactBytes(r)
		require.NoError(t, err)
		require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, result)
	})
}

func TestReadCompactString(t *testing.T) {
	data := []byte("\x8f\x8f\x8f\x80\xa9\xa9\xa9\xa9\xa9\x01")
	var r io.Reader = bytes.NewReader(data)
	_, err := ReadCompactString(r)
	require.Error(t, err)
	require.ErrorContains(t, err, "longer than data length")
}
