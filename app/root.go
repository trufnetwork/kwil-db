package app

import (
	"context"
	"os"
	"path/filepath"

	"github.com/trufnetwork/kwil-db/app/blacklist"
	"github.com/trufnetwork/kwil-db/app/block"
	"github.com/trufnetwork/kwil-db/app/custom"
	"github.com/trufnetwork/kwil-db/app/key"
	"github.com/trufnetwork/kwil-db/app/migration"
	"github.com/trufnetwork/kwil-db/app/node"
	"github.com/trufnetwork/kwil-db/app/node/conf"
	"github.com/trufnetwork/kwil-db/app/params"
	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/seed"
	"github.com/trufnetwork/kwil-db/app/setup"
	"github.com/trufnetwork/kwil-db/app/shared"
	"github.com/trufnetwork/kwil-db/app/shared/bind"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	verCmd "github.com/trufnetwork/kwil-db/app/shared/version"
	"github.com/trufnetwork/kwil-db/app/snapshot"
	"github.com/trufnetwork/kwil-db/app/utils"
	"github.com/trufnetwork/kwil-db/app/validator"
	"github.com/trufnetwork/kwil-db/app/whitelist"
	"github.com/trufnetwork/kwil-db/config"
	_ "github.com/trufnetwork/kwil-db/extensions" // a base location where all extensions can be registered
	_ "github.com/trufnetwork/kwil-db/extensions/auth"
	"github.com/trufnetwork/kwil-db/version"

	"github.com/spf13/cobra"
)

var defaultRoot = func() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kwild")
}()

// RootCmd is the root cobra command for the application. See also [RunRootCmd].
func RootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               custom.BinaryConfig.NodeCmd,
		Short:             custom.BinaryConfig.ProjectName + " daemon",
		Long:              custom.BinaryConfig.ProjectName + " node and utilities",
		DisableAutoGenTag: true,
		// SilenceErrors hides command syntax errors too, which is not desired.
		SilenceUsage: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		Version: version.KwilVersion,
		// PersistentPreRunE so k has all the settings in all (sub)command's RunE funcs
		PersistentPreRunE: bind.ChainPreRuns(bind.MaybeEnableCLIDebug,
			conf.PreRunBindEarlyRootDirEnv, conf.PreRunBindEarlyRootDirFlag, // bind root from env and flag first
			conf.PreRunBindConfigFileStrict[config.Config], // then config file
			conf.PreRunBindFlags,                           // then flags
			conf.PreRunBindEnvMatching,                     // then env vars
			conf.PreRunPrintEffectiveConfig),
	}

	// Pass any errors from the child command's context back to the root
	// command's context. main or whatever can pull it out with
	// shared.CmdCtxErr. Alternatively, this function could set the value in a
	// *error that is returned with the Command, but that's more confusing.
	cmd.PersistentPostRunE = func(child *cobra.Command, args []string) error {
		shared.SetCmdCtxErr(cmd, shared.CmdCtxErr(child)) // more specific than cmd.SetContext(child.Context())
		return nil
	}

	bind.BindDebugFlag(cmd) // --debug enabled CLI debug mode (shared.Debugf output)

	conf.BindDefaultsWithRootDir(custom.DefaultConfig(), defaultRoot)

	bind.BindRootDir(cmd, defaultRoot, "root directory") // --root/-r accessible with bind.RootDir from *any* subcommand

	display.BindOutputFormatFlag(cmd) // --output/-o

	// There is a virtual "node" command grouping, but no actual "node" command yet.
	cmd.AddCommand(node.StartCmd())       // needs merged config
	cmd.AddCommand(node.PrintConfigCmd()) // needs merged config

	// This group of command uses the merged config for fallback admin listen
	// addr if the --rpcserver flag is not set.
	cmd.AddCommand(rpc.NewAdminCmd())
	cmd.AddCommand(validator.NewValidatorsCmd())
	cmd.AddCommand(params.NewConsensusCmd())
	cmd.AddCommand(whitelist.WhitelistCmd())
	cmd.AddCommand(blacklist.BlacklistCmd())
	cmd.AddCommand(block.NewBlockExecCmd())
	cmd.AddCommand(migration.NewMigrationCmd())

	cmd.AddCommand(setup.SetupCmd()) // only kinda needs merged config for `setup reset`

	cmd.AddCommand(key.KeyCmd())
	cmd.AddCommand(snapshot.NewSnapshotCmd())

	cmd.AddCommand(seed.SeedCmd())
	cmd.AddCommand(utils.NewCmdUtils())
	cmd.AddCommand(verCmd.NewVersionCmd())

	// Apply the custom help function to the current command
	shared.ApplySanitizedHelpFuncRecursively(cmd)

	return cmd
}

// RunRootCmd executes the root command with the provided context, which may be
// the background context or a cancellable context such as one that listens for
// interrupt signals. In a main function, a non-nil error typically results in a
// non-zero exit code, but that is up to the application developer. There is no
// need to print the error to stdout as the application will print all results,
// including errors, according to the output format. See BindOutputFormatFlag.
func RunRootCmd(ctx context.Context) error {
	rootCmd := RootCmd()

	if err := rootCmd.ExecuteContext(ctx); err != nil { // command syntax error
		return err
	}

	// For a command / application error, which handles the output themselves,
	// we detect those case where display.PrintErr() is called so that we can
	// return a non-zero exit code, which is important for scripting etc.
	return shared.CmdCtxErr(rootCmd)
}
