package utils

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
)

var (
	generateLong    = `Generates a new key ECDSA pair using the secp256k1 curve.`
	generateExample = `# Generate a new key pair
$ kwil-cli utils generate-key
Private key: 5ecb2ce01dee61729f70e75830d2f0cd151514193f2e05816aad5c453a85edbd
Public key: 0489590f68d80907d74df59b8d9392b78e060a015f4bc58f346820e0d3266d805766bc14fad70b1b8e8a76bab87c4239345790560b00bca7bf5bc7c6bc3c34a4d5
Address: 0x7C4239345790560b00bcA7bF5bC7c6BC3C34a4D5`
)

// GenerateKeyCmd returns the command for generating a new key pair.
func generateKeyCmd() *cobra.Command {
	var out string
	var cmd = &cobra.Command{
		Use:     "generate-key",
		Short:   "Generates a new key pair.",
		Long:    generateLong,
		Example: generateExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, pubKey, err := crypto.GenerateSecp256k1Key(nil)
			if err != nil {
				return display.PrintErr(cmd, err)
			}
			pubKeyBts := pubKey.Bytes()

			pubKeyHex := hex.EncodeToString(pubKeyBts)
			address, err := auth.EthSecp256k1Authenticator{}.Identifier(auth.GetUserSigner(pk).CompactID())
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			if out != "" {
				full, err := writeToFile(out, []byte(hex.EncodeToString(pk.Bytes())+"\n"))
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				res := privateKeyFileRes{
					PrivateKeyPath: full,
					PublicKey:      pubKeyHex,
					Address:        address,
				}

				return display.PrintCmd(cmd, &res)
			} else {
				res := privateKeyRes{
					PrivateKey: hex.EncodeToString(pk.Bytes()),
					PublicKey:  pubKeyHex,
					Address:    address,
				}

				return display.PrintCmd(cmd, &res)
			}
		},
	}

	cmd.Flags().StringVarP(&out, "out", "o", "", "Output file for the generated key pair.")

	return cmd
}

type privateKeyFileRes struct {
	PrivateKeyPath string `json:"private_key_path"`
	PublicKey      string `json:"public_key"`
	Address        string `json:"address"`
}

func (p *privateKeyFileRes) MarshalJSON() ([]byte, error) {
	type res privateKeyFileRes // prevent recursion
	return json.Marshal((*res)(p))
}

func (p *privateKeyFileRes) MarshalText() (text []byte, err error) {
	bts := []byte("Private key written to ")
	bts = append(bts, p.PrivateKeyPath...)
	bts = append(bts, []byte("\nPublic key: ")...)
	bts = append(bts, p.PublicKey...)
	bts = append(bts, []byte("\nAddress:    ")...)
	bts = append(bts, p.Address...)
	return bts, nil
}

type privateKeyRes struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`
}

func (p *privateKeyRes) MarshalJSON() ([]byte, error) {
	type res privateKeyRes // prevent recursion
	return json.Marshal((*res)(p))
}

func (p *privateKeyRes) MarshalText() (text []byte, err error) {
	bts := []byte("Private key: ")
	bts = append(bts, p.PrivateKey...)
	bts = append(bts, []byte("\nPublic key:  ")...)
	bts = append(bts, p.PublicKey...)
	bts = append(bts, []byte("\nAddress:     ")...)
	bts = append(bts, p.Address...)
	return bts, nil
}

// writeToFile exands the path and writes the private key to the file.
func writeToFile(path string, data []byte) (string, error) {
	path, err := helpers.ExpandPath(path)
	if err != nil {
		return "", err
	}

	return path, os.WriteFile(path, data, 0644)
}
