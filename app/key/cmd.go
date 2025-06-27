package key

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
)

func KeyCmd() *cobra.Command {
	keyCmd := &cobra.Command{
		Use:   "key",
		Short: "Tools for private key generation and inspection",
		Long:  "The `key` command provides subcommands for private key generation and inspection. These are the private keys that identify the node on the network and provide validator transaction signing capability.",
	}

	keyCmd.AddCommand(
		GenCmd(),
		InfoCmd(),
	)
	display.BindOutputFormatFlag(keyCmd)
	return keyCmd
}

func privKeyInfo(priv crypto.PrivateKey) *PrivateKeyInfo {
	var keyText, keyFmt string
	s, ok := priv.(interface{ ASCII() (string, string) })
	if ok {
		keyFmt, keyText = s.ASCII()
	} else {
		keyText = hex.EncodeToString(priv.Bytes())
		keyFmt = "hex"
	}
	var address string
	if priv.Type() == crypto.KeyTypeSecp256k1 {
		if s := auth.GetUserSigner(priv); s != nil {
			address, _ = authExt.GetIdentifierFromSigner(s)
		}

	}
	return &PrivateKeyInfo{
		KeyType:        priv.Type().String(),
		PrivateKeyText: keyText,
		privKeyFmt:     keyFmt,
		PublicKeyHex:   hex.EncodeToString(priv.Public().Bytes()),
		NodeID:         hex.EncodeToString(priv.Public().Bytes()) + "#" + priv.Type().String(),
		Address:        address,
	}
}

type PrivateKeyInfo struct {
	KeyType        string `json:"key_type"`
	PrivateKeyText string `json:"private_key_text"`
	privKeyFmt     string `json:"-"`
	PublicKeyHex   string `json:"public_key_hex"`
	NodeID         string `json:"node_id,omitempty"`
	// Address is an optional field that may be set for certain key types that
	// can generate an address depending on the signature (auth) type used.
	Address string `json:"user_address,omitempty"`
}

func (p *PrivateKeyInfo) MarshalJSON() ([]byte, error) {
	type pki PrivateKeyInfo
	return json.Marshal((*pki)(p))
}

func (p *PrivateKeyInfo) MarshalText() ([]byte, error) {
	if p.Address != "" {
		return []byte(fmt.Sprintf(`Key type: %s
Private key (%s): %s
Public key (plain hex): %v
Node ID: %s
Equivalent User Address: %s`,
			p.KeyType,
			p.privKeyFmt,
			p.PrivateKeyText,
			p.PublicKeyHex,
			p.NodeID,
			p.Address,
		)), nil
	}
	return []byte(fmt.Sprintf(`Key type: %s
Private key (%s): %s
Public key (plain hex): %v
Node ID: %s`,
		p.KeyType,
		p.privKeyFmt,
		p.PrivateKeyText,
		p.PublicKeyHex,
		p.NodeID,
	)), nil
}
