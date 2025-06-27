package account

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
)

type respAccount struct {
	Identifier types.HexBytes `json:"identifier"`
	KeyType    string         `json:"key_type"`
	Balance    string         `json:"balance"`
	Nonce      int64          `json:"nonce"`
}

func (r *respAccount) MarshalJSON() ([]byte, error) {
	type respAccountAlias respAccount
	return json.Marshal((*respAccountAlias)(r))
}

func (r *respAccount) MarshalText() ([]byte, error) {
	var msg string
	if len(r.Identifier) == auth.EthAddressIdentLength &&
		r.KeyType == string(crypto.KeyTypeSecp256k1) {
		addr, err := auth.EthSecp256k1Authenticator{}.Identifier(r.Identifier)
		if err != nil {
			addr = hex.EncodeToString(r.Identifier)
		}
		msg = fmt.Sprintf(`%s (Ethereum %s)
Balance: %s
Nonce: %d
`, addr, r.KeyType, r.Balance, r.Nonce)
	} else if len(r.Identifier) == 0 {
		msg = fmt.Sprintf(`%s
Balance: %s
Nonce: %d
`, "[Account not found]", r.Balance, r.Nonce)
	} else {
		msg = fmt.Sprintf(`%x (%s)
Balance: %s
Nonce: %d
`, r.Identifier, r.KeyType, r.Balance, r.Nonce)
	}

	return []byte(msg), nil
}

/*xxx
type respAccount struct {
	// Identifier string `json:"identifier"`
	Balance string `json:"balance"`
	Nonce   int64  `json:"nonce"`
}

func (r *respAccount) MarshalJSON() ([]byte, error) {
	type respAccountAlias respAccount // avoid infinite recursion
	return json.Marshal((*respAccountAlias)(r))
}

func (r *respAccount) MarshalText() ([]byte, error) {
	msg := fmt.Sprintf(`Balance: %s
Nonce: %d
`, r.Balance, r.Nonce)

	return []byte(msg), nil
}
*/
