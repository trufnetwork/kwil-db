package node

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/custom"
	"github.com/trufnetwork/kwil-db/app/node/conf"
	"github.com/trufnetwork/kwil-db/app/shared/bind"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/node/metrics"
	"github.com/trufnetwork/kwil-db/version"
)

const (
	emptyBlockTimeoutFlag = "consensus.empty-block-timeout"
)

func StartCmd() *cobra.Command {
	var autogen bool
	var dbOwner string
	cmd := &cobra.Command{
		Use:               "start",
		Short:             "Start the node",
		Long:              "The `start` command starts the Kwil DB blockchain node.",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		Version: version.KwilVersion,
		Example: custom.BinaryConfig.NodeCmd + " start -r .testnet",
		RunE: func(cmd *cobra.Command, args []string) error {
			rootDir := conf.RootDir()

			extConfs, err := parseExtensionFlags(args)
			if err != nil {
				return err
			}

			cfg := conf.ActiveConfig()

			// we don't need to worry about order of priority with applying the extension
			// flag configs because flags are always highest priority

			// we merge the flags here because we don't want to totally delete all
			// other extension flags. For example, if we have the extension
			// "my_ext" configured with key "foo" and value "bar" in the config file,
			// and we pass the flag "--extension.erc20.rpc=http://localhost:8545",
			// we want to keep the "foo" key in the "my_ext" extension.
			for extName, extConf := range extConfs {
				existing, ok := cfg.Extensions[extName]
				if !ok {
					existing = make(map[string]string)
				}

				for k, v := range extConf {
					existing[k] = v
				}

				cfg.Extensions[extName] = existing
			}

			bind.Debugf("effective node config (toml):\n%s", bind.LazyPrinter(func() string {
				rawToml, err := cfg.ToTOML()
				if err != nil {
					return fmt.Errorf("failed to marshal config to toml: %w", err).Error()
				}
				return string(rawToml)
			}))

			stopProfiler, err := startProfilers(profMode(cfg.ProfileMode), cfg.ProfileFile)
			if err != nil {
				cmd.Usage()
				return err
			}
			defer stopProfiler()

			if cfg.Telemetry.Enable {
				stopMetrics, err := metrics.StartOTEL(cmd.Context(), metrics.WithOTELEndpoint(cfg.Telemetry.OTLPEndpoint))
				if err != nil {
					cmd.Usage()
					return err
				}
				defer stopMetrics(context.Background())
			}

			// Set the empty block timeout to the propose timeout if not set
			// if the node is running in autogen mode
			if !cmd.Flags().Changed(emptyBlockTimeoutFlag) && autogen {
				cfg.Consensus.EmptyBlockTimeout = cfg.Consensus.ProposeTimeout
			}

			err = runNode(cmd.Context(), rootDir, cfg, autogen, dbOwner)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("node stopped with error: %w", err))
			}
			return nil
		},
	}

	// Other node flags have config file and env analogs, and will be loaded
	// into koanf where the values are merged.
	defaultCfg := custom.DefaultConfig() // not config.DefaultConfig(), so custom command config is used
	bind.SetFlagsFromStruct(cmd.Flags(), defaultCfg)

	cmd.SetVersionTemplate(custom.BinaryConfig.NodeCmd + " {{printf \"version %s\" .Version}}\n")
	cmd.Flags().BoolVarP(&autogen, "autogen", "a", false,
		"auto generate private key, genesis file, and config file if not exist")
	cmd.Flags().StringVarP(&dbOwner, "db-owner", "d", "", "owner of the database. This is either a hex pubkey or an address string")

	return cmd
}

// parseExtensionFlags parses the extension flags from the command line and
// returns a map of extension names to their configured values
func parseExtensionFlags(args []string) (map[string]map[string]string, error) {
	exts := make(map[string]map[string]string)
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--extensions.") {
			return nil, fmt.Errorf("expected extension flag, got %q", args[i])
		}
		// split the flag into the extension name and the flag name;
		// last part can have values like URL, will verify only 3 segements in the flag below
		parts := strings.SplitN(args[i], ".", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid extension flag %q", args[i])
		}

		extName := parts[1]

		// get the extension map for the extension name.
		// if it doesn't exist, create it.
		ext, ok := exts[extName]
		if !ok {
			ext = make(map[string]string)
			exts[extName] = ext
		}

		// we now need to get the flag value. Flags can be passed
		// as either "--extension.extname.flagname value" or
		// "--extension.extname.flagname=value"
		if strings.Contains(parts[2], "=") {
			// flag value is in the same argument
			val := strings.SplitN(parts[2], "=", 2)

			// flag can only have 3 segements
			if strings.Contains(val[0], ".") {
				return nil, fmt.Errorf("invalid extension flag %q", args[i])
			}

			ext[val[0]] = val[1]
		} else {
			// flag can only have 3 segements
			if strings.Contains(parts[2], ".") {
				return nil, fmt.Errorf("invalid extension flag %q", args[i])
			}

			// flag value is in the next argument
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing value for extension flag %q", args[i])
			}

			if strings.HasPrefix(args[i+1], "--") {
				return nil, fmt.Errorf("missing value for extension flag %q", args[i])
			}

			ext[parts[2]] = args[i+1]
			i++
		}
	}

	return exts, nil
}
