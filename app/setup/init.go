package setup

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/custom"
	"github.com/trufnetwork/kwil-db/app/key"
	"github.com/trufnetwork/kwil-db/app/node/conf"
	"github.com/trufnetwork/kwil-db/app/shared/bind"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/core/utils"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
	"github.com/trufnetwork/kwil-db/node"
)

const (
	nodeDirPerm           = 0755
	emptyBlockTimeoutFlag = "consensus.empty-block-timeout"
)

var (
	genesisValidatorGas, _ = big.NewInt(0).SetString("10000000000000000000000", 10)
)

var (
	initLong = `The ` + "`init`" + ` command facilitates quick setup of an isolated Kwil node either on a fresh network in which that node is the single validator or to join an existing network.

This permits rapid prototyping and evaluation of Kwil functionality. An output directory can be specified using the ` + "`--output-dir`" + `" flag.

If no output directory is specified, the node will be initialized ` + "`./testnet`" + `.`

	initExample = `# Initialize a node, with a new network, in the directory ~/.kwil-new
kwild setup init -r ~/.kwild-new

# Run the init command with --allocs flag to initialize a node with initial account balances. 
The allocs flag should be a comma-separated list of <id#keyType:amount> pairs where the id is the account address or the pubkey and keyType is either "secp256k1" or "ed25519". If id is the ethereum address prefixed with "0x", the keyType is optional as shown below.

kwild setup init --allocs "0xc89D42189f0450C2b2c3c61f58Ec5d628176A1E7:10000000000000000000000,0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1:56000000000" -r ~/.kwild
`
)

func InitCmd() *cobra.Command {
	var genesisPath, keyFile string
	var genFlags genesisFlagConfig

	cmd := &cobra.Command{
		Use:               "init",
		Short:             "Generate configuration for a Kwil node.",
		Long:              initLong,
		Example:           initExample,
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		Args: cobra.NoArgs,
		// Override parent persistent prerun so we don't try to read an existing
		// config file; only the default+flags+env for generating a new root.
		PersistentPreRunE: bind.ChainPreRuns(bind.MaybeEnableCLIDebug,
			conf.PreRunBindFlags, conf.PreRunBindEnvMatching, conf.PreRunPrintEffectiveConfig),
		RunE: func(cmd *cobra.Command, args []string) error {
			rootDir, err := bind.RootDir(cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			// Ensure the root directory exists
			outDir, err := node.ExpandPath(rootDir)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			// Ensure the output directory does not already exist...
			if _, err := os.Stat(outDir); err == nil {
				return display.PrintErr(cmd, fmt.Errorf("output directory %s already exists", outDir))
			}

			// create the output directory
			if err := os.MkdirAll(outDir, nodeDirPerm); err != nil {
				return display.PrintErr(cmd, err)
			}

			cfg := conf.ActiveConfig()

			bind.Debugf("effective node config (toml):\n%s", bind.LazyPrinter(func() string {
				rawToml, err := cfg.ToTOML()
				if err != nil {
					return fmt.Errorf("failed to marshal config to toml: %w", err).Error()
				}
				return string(rawToml)
			}))

			if cfg.Consensus.ProposeTimeout < config.MinProposeTimeout {
				return display.PrintErr(cmd, fmt.Errorf("propose timeout must be at least %s", config.MinProposeTimeout.String()))
			}

			// if the user has specified genesis state, copy it to the new directory
			if cmd.Flags().Changed("genesis-state") {
				genesisState := cfg.GenesisState
				genesisState, err = node.ExpandPath(genesisState)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				stateFile := config.GenesisStateFileName(outDir)

				if err := utils.CopyFile(genesisState, stateFile); err != nil {
					return display.PrintErr(cmd, err)
				}
				cfg.GenesisState = stateFile
			}

			var privKey crypto.PrivateKey
			if cmd.Flags().Changed("key-file") {
				if keyFile, err = node.ExpandPath(keyFile); err != nil {
					return display.PrintErr(cmd, err)
				}
				privKey, err = key.LoadNodeKey(keyFile)
				if err != nil {
					return display.PrintErr(cmd, err)
				}
				err = utils.CopyFile(keyFile, config.NodeKeyFilePath(outDir))
				if err != nil {
					return display.PrintErr(cmd, err)
				}
			} else {
				// Generate and save the node key to the root directory
				privKey, err = crypto.GeneratePrivateKey(crypto.KeyTypeSecp256k1)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				if err := key.SaveNodeKey(config.NodeKeyFilePath(rootDir), privKey); err != nil {
					return display.PrintErr(cmd, err)
				}
			}

			genFile := config.GenesisFilePath(outDir)
			if genesisPath != "" {
				// Init for the node to join an existing network
				if genesisPath, err = node.ExpandPath(genesisPath); err != nil {
					return display.PrintErr(cmd, err)
				}

				// Load and save rather than copy file so that we validate the file.
				genCfg, err := config.LoadGenesisConfig(genesisPath)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("failed to load genesis file: %w", err))
				}

				if err := genCfg.SaveAs(genFile); err != nil {
					return display.PrintErr(cmd, fmt.Errorf("failed to copy genesis file: %w", err))
				}
			} else { // Init command for creating a new network, new genesis file will be created
				genCfg := config.DefaultGenesisConfig()
				genCfg, err = mergeGenesisFlags(genCfg, cmd, &genFlags)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("failed to create genesis file: %w", err))
				}

				if genCfg.Leader.PublicKey == nil {
					genCfg.Leader = types.PublicKey{PublicKey: privKey.Public()}
				}

				if !ensureLeaderInValidators(genCfg) {
					return display.PrintErr(cmd, errors.New("leader must be in validators"))
				}

				// If DB owner is not set, set it to the node's public key
				if genCfg.DBOwner == "" {
					signer := auth.GetUserSigner(privKey)
					ident, err := authExt.GetIdentifierFromSigner(signer)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("failed to get identifier for dbOwner: %w", err))
					}
					genCfg.DBOwner = ident
				}

				// allocate some initial balance to validators if gas is enabled and
				// if no funds are allocated to that validators.
				if !genCfg.DisabledGasCosts {
					for _, v := range genCfg.Validators {
						genCfg.Allocs = append(genCfg.Allocs, config.GenesisAlloc{
							ID: config.KeyHexBytes{
								HexBytes: v.AccountID.Identifier,
							},
							KeyType: v.Identifier.String(),
							Amount:  genesisValidatorGas,
						})
					}
				}

				if cfg.GenesisState != "" {
					genCfg.StateHash, err = appHashFromSnapshotFile(cfg.GenesisState)
					if err != nil {
						return display.PrintErr(cmd, err)
					}
				}

				if err := genCfg.SaveAs(genFile); err != nil {
					return display.PrintErr(cmd, err)
				}
			}

			// Save the config to the root directory
			if err := cfg.SaveAs(config.ConfigFilePath(rootDir)); err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, display.RespString(fmt.Sprintf("Kwil node configuration generated at %s", outDir)))
		},
	}

	defaultCfg := custom.DefaultConfig()
	bind.SetFlagsFromStruct(cmd.Flags(), defaultCfg)
	bindGenesisFlags(cmd, &genFlags)

	// genesis config flags
	cmd.Flags().StringVarP(&genesisPath, "genesis", "g", "", "path to genesis file")

	cmd.Flags().StringVarP(&keyFile, "key-file", "k", "", "path to node key file")

	return cmd
}

func ensureLeaderInValidators(genCfg *config.GenesisConfig) bool {
	if len(genCfg.Validators) == 0 {
		genCfg.Validators = []*types.Validator{
			{
				AccountID: types.AccountID{
					Identifier: genCfg.Leader.PublicKey.Bytes(),
					KeyType:    genCfg.Leader.Type(),
				},
				Power: 1,
			},
		}
		return true
	}

	return slices.ContainsFunc(genCfg.Validators, func(v *types.Validator) bool {
		return bytes.Equal(v.AccountID.Identifier, genCfg.Leader.PublicKey.Bytes()) &&
			v.AccountID.KeyType == genCfg.Leader.PublicKey.Type()
	})
}
