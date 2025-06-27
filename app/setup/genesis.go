package setup

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node"
)

var (
	genesisLong = `The ` + "`genesis`" + ` command creates a new ` + "`genesis.json`" + ` file with optionally specified modifications.

Validators and balance allocations should have the format "pubkey:power", "address:balance" respectively.`

	genesisExample = `# Create a new genesis.json file in a specific directory with a specific chain ID and a validator with 1 power
kwild setup genesis --out /path/to/directory --chain-id mychainid --validator 890fe7ae9cb1fa6177555d5651e1b8451b4a9c64021c876236c700bc2690ff1d:1

# Create a new genesis.json with the specified allocation
kwild setup genesis --alloc 0x7f5f4552091a69125d5dfcb7b8c2659029395bdf:100`
)

type genesisFlagConfig struct {
	chainID    string
	validators []string
	allocs     []string
	networkParams
}

type networkParams struct {
	withGas       bool
	leader        string
	dbOwner       string
	maxBlockSize  int64
	joinExpiry    time.Duration
	maxVotesPerTx int64
}

func GenesisCmd() *cobra.Command {
	var flagCfg genesisFlagConfig
	var output string

	cmd := &cobra.Command{
		Use:               "genesis",
		Short:             "Create a new genesis.json file",
		Long:              genesisLong,
		Example:           genesisExample,
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		Args: cobra.NoArgs,
		// Override the root command's PersistentPreRunE, so that we don't
		// try to read the config from a ~/.kwild directory.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir, err := node.ExpandPath(output)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to expand output path: %w", err))
			}

			err = os.MkdirAll(outDir, nodeDirPerm)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to create output directory: %w", err))
			}

			conf := config.DefaultGenesisConfig()
			conf, err = mergeGenesisFlags(conf, cmd, &flagCfg)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to create genesis file: %w", err))
			}

			// Leader must be explicitly specified.
			if conf.Leader.PublicKey == nil {
				return display.PrintErr(cmd, errors.New("leader must be specified"))
			}

			// Ensure leader is in validators. If validators are unset, make
			// leader the one validator; if validators are set, ensure leader is
			// in the set or error.
			if !ensureLeaderInValidators(conf) {
				return display.PrintErr(cmd, errors.New("leader must be in validators"))
			}

			if conf.DBOwner == "" {
				// Get the leader's equivalent "user" identifier string, which for
				// secp256k1 may be the corresponding Ethereum address. This allows
				// the leader's private key to be used with kwil-cli transactions
				// that result in a Kwil engine @caller that is an Ethereum address.
				// This is almost certainly only appropriate for testing!
				conf.DBOwner, _ = auth.GetUserIdentifier(conf.Leader.PublicKey)
			}

			genesisFile := config.GenesisFilePath(outDir)
			existingFile, err := os.Stat(genesisFile)
			if err == nil && existingFile.IsDir() {
				return display.PrintErr(cmd, fmt.Errorf("a directory already exists at %s, please remove it first", genesisFile))
			} else if err == nil {
				return display.PrintErr(cmd, fmt.Errorf("file already exists at %s, please remove it first", genesisFile))
			}

			err = conf.SaveAs(genesisFile)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to save genesis file: %w", err))
			}

			return display.PrintCmd(cmd, display.RespString("Created genesis.json file at "+genesisFile))
		},
	}

	bindGenesisFlags(cmd, &flagCfg)
	cmd.Flags().StringVar(&output, "out", "", "Output directory for the genesis.json file. The file will be named `genesis.json`.")

	return cmd
}

// bindGenesisFlags binds the genesis configuration flags to the given command.
func bindGenesisFlags(cmd *cobra.Command, cfg *genesisFlagConfig) {
	cmd.Flags().StringVar(&cfg.chainID, chainIDFlag, "", "chainID for the genesis.json file")
	cmd.Flags().StringSliceVar(&cfg.validators, validatorsFlag, nil, "public key, keyType and power of initial validator(s), may be specified multiple times") // accept: [hexpubkey1#keyType1:power1]
	cmd.Flags().StringSliceVar(&cfg.allocs, allocsFlag, nil, "address and initial balance allocation(s) in the format id#keyType:amount")
	bindNetworkParamsFlags(cmd, &cfg.networkParams)
}

func bindNetworkParamsFlags(cmd *cobra.Command, cfg *networkParams) {
	cmd.Flags().BoolVar(&cfg.withGas, withGasFlag, false, "include gas costs in the genesis.json file")
	cmd.Flags().StringVar(&cfg.leader, leaderFlag, "", "public key of the block proposer")
	cmd.Flags().StringVar(&cfg.dbOwner, dbOwnerFlag, "", "owner of the database")
	cmd.Flags().Int64Var(&cfg.maxBlockSize, maxBlockSizeFlag, 0, "maximum block size")
	cmd.Flags().DurationVar(&cfg.joinExpiry, joinExpiryFlag, 0, "Number of blocks before a join proposal expires")
	cmd.Flags().Int64Var(&cfg.maxVotesPerTx, maxVotesPerTxFlag, 0, "Maximum votes per transaction")
}

const (
	chainIDFlag       = "chain-id"
	validatorsFlag    = "validator"
	allocsFlag        = "alloc"
	withGasFlag       = "with-gas"
	leaderFlag        = "leader"
	dbOwnerFlag       = "db-owner"
	maxBlockSizeFlag  = "max-block-size"
	joinExpiryFlag    = "join-expiry"
	maxVotesPerTxFlag = "max-votes-per-tx"
)

// mergeGenesisFlags merges the genesis configuration flags with the given configuration.
func mergeGenesisFlags(conf *config.GenesisConfig, cmd *cobra.Command, flagCfg *genesisFlagConfig) (*config.GenesisConfig, error) {
	if cmd.Flags().Changed(chainIDFlag) {
		conf.ChainID = flagCfg.chainID
	}

	if cmd.Flags().Changed(validatorsFlag) {
		conf.Validators = nil
		for _, v := range flagCfg.validators {
			parts := strings.Split(v, ":")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid format for validator, expected key#keyType:power, received: %s", v)
			}

			power, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid power for validator: %s", parts[1])
			}

			keyType := crypto.KeyTypeSecp256k1
			keyParts := strings.Split(parts[0], "#")

			if len(keyParts) > 2 {
				return nil, fmt.Errorf("invalid format for validator, expected key#keyType:power, received: %s", v)
			} else if len(keyParts) == 2 {
				keyType, err = crypto.ParseKeyType(keyParts[1])
				if err != nil {
					return nil, fmt.Errorf("invalid key type for validator: %s", keyParts[1])
				}
			}

			hexPub, err := hex.DecodeString(keyParts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid public key for validator: %s", parts[0])
			}

			_, err = crypto.UnmarshalPublicKey(hexPub, keyType)
			if err != nil {
				return nil, fmt.Errorf("invalid public key for validator: %s", parts[0])
			}

			conf.Validators = append(conf.Validators, &types.Validator{
				AccountID: types.AccountID{
					Identifier: hexPub,
					KeyType:    keyType,
				},
				Power: power,
			})
		}
	}

	if cmd.Flags().Changed(allocsFlag) {
		conf.Allocs = nil
		allocs, err := parseAllocs(flagCfg.allocs)
		if err != nil {
			return nil, err
		}
		conf.Allocs = append(conf.Allocs, allocs...)
	}

	return mergeNetworkParamFlags(conf, cmd, &flagCfg.networkParams)
}

func parseAllocs(allocs []string) ([]config.GenesisAlloc, error) {
	var res []config.GenesisAlloc
	for _, a := range allocs {
		parts := strings.Split(a, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format for alloc, expected id#keyType:balance, received: %s", a)
		}

		// 0x addresses: <address>:<balance>
		// others: <pubkey#keyType>:<balance>
		keyParts := strings.Split(parts[0], "#")
		var keyType crypto.KeyType
		var keyStr string
		var err error

		if strings.HasPrefix(parts[0], "0x") {
			if len(keyParts) != 1 {
				return nil, fmt.Errorf("invalid address for alloc: %s, expected format <address:balance>", parts[0])
			}
			keyStr = strings.TrimPrefix(parts[0], "0x")
			keyType = crypto.KeyTypeSecp256k1
		} else {
			if len(keyParts) != 2 {
				return nil, fmt.Errorf("invalid address for alloc: %s, expected format <key#keyType:balance>", parts[0])
			}
			keyType, err = crypto.ParseKeyType(keyParts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid key type for validator: %s", keyParts[1])
			}
			keyStr = keyParts[0]
		}

		balance, ok := new(big.Int).SetString(parts[1], 10)
		if !ok {
			return nil, fmt.Errorf("invalid balance for alloc: %s", parts[1])
		}

		id, err := hex.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid hex address for alloc: %s", keyStr)
		}

		res = append(res, config.GenesisAlloc{
			ID: config.KeyHexBytes{
				HexBytes: id,
			},
			KeyType: keyType.String(),
			Amount:  balance,
		})
	}
	return res, nil
}

func mergeNetworkParamFlags(conf *config.GenesisConfig, cmd *cobra.Command, flagCfg *networkParams) (*config.GenesisConfig, error) {
	if cmd.Flags().Changed(withGasFlag) {
		conf.DisabledGasCosts = !flagCfg.withGas
	}

	if cmd.Flags().Changed(leaderFlag) {
		pubkeyBts, keyType, err := config.DecodePubKeyAndType(flagCfg.leader)
		if err != nil {
			return nil, err
		}
		pubkey, err := crypto.UnmarshalPublicKey(pubkeyBts, keyType)
		if err != nil {
			return nil, err
		}
		conf.Leader = types.PublicKey{PublicKey: pubkey}
	}

	if cmd.Flags().Changed(dbOwnerFlag) {
		conf.DBOwner = flagCfg.dbOwner
	}

	if cmd.Flags().Changed(maxBlockSizeFlag) {
		conf.MaxBlockSize = flagCfg.maxBlockSize
	}

	if cmd.Flags().Changed(joinExpiryFlag) {
		conf.JoinExpiry = types.Duration(flagCfg.joinExpiry)
	}

	if cmd.Flags().Changed(maxVotesPerTxFlag) {
		conf.MaxVotesPerTx = flagCfg.maxVotesPerTx
	}

	return conf, nil
}
