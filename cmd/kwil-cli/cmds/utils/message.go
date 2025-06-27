package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	"github.com/trufnetwork/kwil-db/core/types"
)

type transaction struct {
	Raw         []byte
	Tx          *types.Transaction
	WithPayload bool
}

// remarshalPayload attempt to decode and remarshal the payload from RLP to JSON.
func (t *transaction) remarshalPayload() (json.RawMessage, bool) {
	payloadObject, err := types.UnmarshalPayload(t.Tx.Body.PayloadType, t.Tx.Body.Payload)
	if err != nil {
		return nil, false
	}
	payloadJSON, err := json.Marshal(payloadObject)
	if err != nil {
		return nil, false
	}
	return payloadJSON, true
}

func (t *transaction) MarshalJSON() ([]byte, error) {
	if t.WithPayload {
		payloadJSON, _ := t.remarshalPayload()
		tx := struct {
			Tx      *types.Transaction `json:"tx"`
			Payload json.RawMessage    `json:"payload_decoded"`
		}{
			Tx:      t.Tx,
			Payload: payloadJSON,
		}
		return json.MarshalIndent(tx, "", "  ")
	}

	// Decode a fresh Transaction instance and zero out the Payload.
	tx, err := decodeTx(t.Raw)
	if err != nil {
		return nil, err
	}
	tx.Tx.Body.Payload = nil
	return json.MarshalIndent(tx, "", "  ")
}

func (t *transaction) MarshalText() ([]byte, error) {
	txHash := types.HashBytes(t.Raw)
	msg := fmt.Sprintf(`Transaction ID: %s
Sender: %s
Description: %s
Payload type: %s
ChainID: %v
Fee: %s
Nonce: %d
Signature type: %s
Signature: %s
`,
		txHash,
		t.Tx.Sender.String(),
		t.Tx.Body.Description,
		t.Tx.Body.PayloadType,
		t.Tx.Body.ChainID,
		t.Tx.Body.Fee,
		t.Tx.Body.Nonce,
		t.Tx.Signature.Type,
		base64.StdEncoding.EncodeToString(t.Tx.Signature.Data),
	)

	if t.WithPayload { // put it at the end regardless since it' can be big
		// First try to decode the transaction (RLP), then create readable JSON
		// for its display. If either fails, show it as base64.
		payloadJSON, ok := t.remarshalPayload()
		if !ok {
			msg += "Payload (invalid): " + base64.StdEncoding.EncodeToString(t.Tx.Body.Payload) + "\n"
		} else {
			msg += "Payload (json): " + string(payloadJSON) + "\n"
		}
	}

	return []byte(msg), nil
}

type respChainInfo struct {
	Info *types.ChainInfo
}

func (r *respChainInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Info)
}

func (r *respChainInfo) MarshalText() ([]byte, error) {
	msg := fmt.Sprintf(`Chain ID: %s
Height: %d
Hash: %s
Gas: %v
`,
		r.Info.ChainID,
		r.Info.BlockHeight,
		r.Info.BlockHash,
		r.Info.Gas,
	)

	return []byte(msg), nil
}

// respKwilCliConfig is used to represent a kwil-cli config in cli
type respKwilCliConfig struct {
	cfg *config.KwilCliConfig
}

func (r *respKwilCliConfig) MarshalJSON() ([]byte, error) {
	cfg := r.cfg.ToPersistedConfig()
	cfg.PrivateKey = "***"
	return json.Marshal(cfg)
}

func printStruct(cfg interface{}, w io.StringWriter, prefix string) error {
	v := reflect.ValueOf(cfg)
	t := v.Type()

	if t.Kind() == reflect.Ptr {
		v = v.Elem()
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return errors.New("not a struct")
	}

	for i := range v.NumField() {
		field := t.Field(i)
		fieldValue := v.Field(i)
		if field.Type.Kind() == reflect.Struct {
			w.WriteString(field.Name + ":\n")
			return printStruct(fieldValue.Interface(), w, prefix+"    ")
		}
		w.WriteString(fmt.Sprintf("%s%s: %v\n", prefix, field.Name, fieldValue))
	}
	return nil
}

func (r *respKwilCliConfig) MarshalText() ([]byte, error) {
	var msg bytes.Buffer
	cfg := r.cfg.ToPersistedConfig()
	cfg.PrivateKey = "***"

	if err := printStruct(cfg, &msg, ""); err != nil {
		return nil, err
	}

	return msg.Bytes(), nil
}
