package configure

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers/prompt"
	"github.com/trufnetwork/kwil-db/core/crypto"

	"github.com/spf13/cobra"
)

var configureLong = `Configure the Kwil CLI with persistent global settings.

This command will prompt you for the following settings:

- Kwil RPC provider URL: the RPC URL of the Kwil node you wish to connect to.
- Kwil Chain ID: the chain ID of the Kwil node you wish to connect to.  If left empty, the Kwil node will provide this value.
- Private Key: the private key to use for signing transactions.  If left empty, the Kwil CLI will not sign transactions.`

var configureExample = `kwil-cli configure`

func NewCmdConfigure() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "configure",
		Short:   "Configure the Kwil CLI with persistent global settings.",
		Long:    configureLong,
		Example: configureExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			if display.ShouldSilence(cmd) {
				return display.PrintErr(cmd, errors.New("cannot configure run in silence mode"))
			}

			// config.LoadPersistedConfig() => just the config file
			conf, err := config.ActiveConfig() // considering merged config including flags and env
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			err = runErrs(conf,
				promptRPCProvider,
				promptChainID,
				promptPrivateKey,
			)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return config.PersistConfig(conf)
		},
	}

	return cmd
}

func runErrs(conf *config.KwilCliConfig, fns ...func(*config.KwilCliConfig) error) error {
	for _, fn := range fns {

		err := fn(conf)
		if err != nil {
			return err
		}
	}

	return nil
}

func promptRPCProvider(conf *config.KwilCliConfig) error {
	prompt := &prompt.Prompter{
		Label:   "Kwil RPC provider URL",
		Default: conf.Provider,
	}
	res, err := prompt.Run()
	if err != nil {
		return err
	}

	conf.Provider = res

	return nil
}

func promptChainID(conf *config.KwilCliConfig) error {
	prompt := &prompt.Prompter{
		Label:   "Kwil Chain ID (leave empty to trust a server-provided value)",
		Default: conf.ChainID,
	}
	res, err := prompt.Run()
	if err != nil { // NOTE: empty is valid (no error)
		return err
	}

	conf.ChainID = res

	return nil
}

func promptPrivateKey(conf *config.KwilCliConfig) error {
	var defaultPrivKeyHex string
	if conf.PrivateKey != nil {
		defaultPrivKeyHex = hex.EncodeToString(conf.PrivateKey.Bytes())
	}
	pr := &prompt.Prompter{
		Label:   "Private Key",
		Default: defaultPrivKeyHex,
	}
	res, err := pr.Run()
	if err != nil {
		return err
	}

	if res == "" {
		conf.PrivateKey = nil
		return nil
	}

	var pk *crypto.Secp256k1PrivateKey
	pkBts, err := hex.DecodeString(res)
	if err == nil {
		pk, err = crypto.UnmarshalSecp256k1PrivateKey(pkBts)
	}
	if err != nil {
		fmt.Printf("invalid private key: %v\n", err)
		promptAskAgain := &prompt.Prompter{
			Label: "Would you like to enter another? (y/n)",
		}
		res2, err := promptAskAgain.Run()
		if err != nil {
			return err
		}

		if res2 == "y" || res == "yes" {
			return promptPrivateKey(conf)
		}

		return nil
	}

	conf.PrivateKey = pk

	return nil
}
