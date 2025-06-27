package key

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/trufnetwork/kwil-db/core/crypto"
)

type NodeKeyFile struct {
	Key crypto.PrivateKey
}

func (nk NodeKeyFile) MarshalJSON() ([]byte, error) {
	if nk.Key == nil {
		return nil, errors.New("key is nil")
		// return []byte(`null`), nil
	}
	return json.Marshal(struct {
		Key  string `json:"key"`
		Type string `json:"type"`
	}{
		Key:  hex.EncodeToString(nk.Key.Bytes()),
		Type: nk.Key.Type().String(),
	})
}

func (nk *NodeKeyFile) UnmarshalJSON(data []byte) error {
	aux := struct {
		Key  string `json:"key"`
		Type string `json:"type"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	keyBytes, err := hex.DecodeString(aux.Key)
	if err != nil {
		return err
	}

	keyType, err := crypto.ParseKeyType(aux.Type)
	if err != nil {
		return err
	}

	// Create private key based on type
	privateKey, err := crypto.UnmarshalPrivateKey(keyBytes, keyType)
	if err != nil {
		return err
	}

	nk.Key = privateKey

	return nil
}

func LoadNodeKey(path string) (crypto.PrivateKey, error) {
	var nk NodeKeyFile
	keyFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(keyFile, &nk); err != nil {
		return nil, err
	}
	return nk.Key, nil
}

func SaveNodeKey(path string, pk crypto.PrivateKey) error {
	keyFile, err := json.Marshal(&NodeKeyFile{Key: pk})
	if err != nil {
		return err
	}
	return os.WriteFile(path, keyFile, 0600)
}
