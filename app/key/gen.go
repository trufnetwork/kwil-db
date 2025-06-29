package key

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/crypto"
)

var (
	genExample = `# Generate a new key and save it to ./priv_key
kwild key gen --key-file ./priv_key

# Generate a raw private key
kwild key gen --raw`
)

func GenCmd() *cobra.Command {
	var raw bool // if true, output hex private key only
	var out string

	cmd := &cobra.Command{
		Use:     "gen [<keytype>]",
		Short:   "Generate a private key for validator use.",
		Long:    "The `gen` command generates a private key for use by validators.",
		Example: genExample,
		Args:    cobra.RangeArgs(0, 1),
		// Override the root command's PersistentPreRunE, so that we don't
		// try to read the config from a ~/.kwild directory
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			keyType := crypto.KeyTypeSecp256k1 // default with 0 args
			if len(args) > 0 {
				var err error
				keyType, err = crypto.ParseKeyType(args[0])
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("invalid key type (%s): %w", args[0], err))
				}
			}

			privKey, err := crypto.GeneratePrivateKey(keyType)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			if out == "" {
				if raw {
					return display.PrintCmd(cmd, display.RespString(hex.EncodeToString(privKey.Bytes())))
				}
				return display.PrintCmd(cmd, privKeyInfo(privKey))
			}

			if err := SaveNodeKey(out, privKey); err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, display.RespString("Private key written to "+out))
		},
	}

	cmd.Flags().BoolVarP(&raw, "raw", "R", false, "just print the private key hex without other encodings, public key, or node ID")
	cmd.Flags().StringVarP(&out, "key-file", "o", "", "file to which the new private key is written (stdout by default)")

	return cmd
}
