package key

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/crypto"

	"github.com/spf13/cobra"
)

var (
	infoLong = `Display information about a private key.

The private key can either be passed as a key file path, or as a hex-encoded string.`

	infoExample = `# Using a key file
kwild key info --key-file ~/.kwild/nodekey.json

# Using a hex-encoded string
kwild key info 381d28cf348c9efbf7d26ea54b647e2cb646d3b98cdeec0f1053a5ff599a036a0aa381bd4aad1670a39977d5416bfac7bd060765adc58a4bb16bbbafeefbae34`
)

func InfoCmd() *cobra.Command {
	var privkeyFile string

	cmd := &cobra.Command{
		Use:     "info",
		Short:   "Display information about a private key.",
		Long:    infoLong,
		Example: infoExample,
		Args:    cobra.MaximumNArgs(1),
		// Override the root command's PersistentPreRunE, so that we don't
		// try to read the config from a ~/.kwild directory
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			// if len(args) == 1, then the private key is passed as a hex string
			// otherwise, it is passed as a file path
			if len(args) == 1 {
				keyHex, keyTypeStr, _ := strings.Cut(args[0], "#")
				keyBts, err := hex.DecodeString(keyHex)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("private key not valid hex: %w", err))
				}
				keyType := crypto.KeyTypeSecp256k1 // default
				if keyTypeStr != "" {
					keyType, err = crypto.ParseKeyType(keyTypeStr)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("invalid key type (%s): %w", keyTypeStr, err))
					}
				}
				priv, err := crypto.UnmarshalPrivateKey(keyBts, keyType)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("invalid key: %w", err))
				}
				return display.PrintCmd(cmd, privKeyInfo(priv))
			} else if privkeyFile != "" {
				key, err := LoadNodeKey(privkeyFile)
				if err != nil {
					return display.PrintErr(cmd, err)
				}
				return display.PrintCmd(cmd, privKeyInfo(key))
			}

			cmd.Usage()
			return errors.New("must provide with the private key file or hex string")
		},
	}

	cmd.Flags().StringVarP(&privkeyFile, "key-file", "o", "", "file containing the private key to display")

	return cmd
}
