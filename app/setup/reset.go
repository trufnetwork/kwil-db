package setup

import (
	"context"
	"fmt"
	"os"

	"github.com/trufnetwork/kwil-db/app/custom"
	"github.com/trufnetwork/kwil-db/app/node/conf"
	"github.com/trufnetwork/kwil-db/app/shared/bind"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/node"
	"github.com/trufnetwork/kwil-db/node/pg"

	"github.com/spf13/cobra"
)

var (
	resetLong = `To delete all of a Kwil node's data files, use the ` + "`reset`" + ` command. If the root directory is not specified, the node's default root directory will be used.

WARNING: This command should not be used on production systems. This should only be used to reset disposable test nodes.`

	resetExample = `# Delete all of a Kwil node's data files
kwild setup reset -r "~/.kwild"`
)

func ResetCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:     "reset",
		Short:   "Reset blockchain data and the application state.",
		Long:    resetLong,
		Example: resetExample,
		Args:    cobra.NoArgs,
		// Override the root's PersistentPreRunE to bind only the config file,
		// not the full node flag set.
		PersistentPreRunE: bind.ChainPreRuns(conf.PreRunBindEarlyRootDirEnv,
			conf.PreRunBindEarlyRootDirFlag,
			conf.PreRunBindConfigFileStrict[config.Config]), // but not the flags
		RunE: func(cmd *cobra.Command, args []string) error {
			rootDir, err := bind.RootDir(cmd)
			if err != nil {
				return err // the parent command needs to set a persistent flag named "root"
			}

			rootDir, err = node.ExpandPath(rootDir)
			if err != nil {
				return err
			}
			if _, err := os.Stat(rootDir); os.IsNotExist(err) {
				return fmt.Errorf("root directory %s does not exist", rootDir)
			}

			dbCfg := conf.ActiveConfig().DB
			pgConf, err := bind.GetPostgresFlags(cmd, &dbCfg)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to get postgres flags: %v", err))
			}

			err = resetPGState(cmd.Context(), pgConf)
			if err != nil {
				return err
			}
			fmt.Printf("Postgres state reset. Host: %s; Port: %s; Database: %s\n", pgConf.Host, pgConf.Port, pgConf.DBName)

			if all {
				// remove the blockstore if all is set
				chainDir := config.BlockstoreDir(rootDir)
				if err := os.RemoveAll(chainDir); err != nil {
					return err
				}
				fmt.Printf("Blockstore directory removed: %s\n", chainDir)

				// remove rcvd_snaps if exists
				snapDir := config.ReceivedSnapshotsDir(rootDir)
				if err := os.RemoveAll(snapDir); err != nil {
					return err
				}
				fmt.Printf("Statesync snapshots directory removed: %s\n", snapDir)

				// remove snapshots if exists
				snapDir = config.LocalSnapshotsDir(rootDir)
				if err := os.RemoveAll(snapDir); err != nil {
					return err
				}
				fmt.Println("Snapshots directory removed", snapDir)

				// remove the migrations directory
				migrationsDir := config.MigrationDir(rootDir)
				if err := os.RemoveAll(migrationsDir); err != nil {
					return err
				}
				fmt.Println("Migrations directory removed", migrationsDir)

				// remove genesis state file if exists
				genesisFile := config.GenesisStateFileName(rootDir)
				os.Remove(genesisFile) // ignore error
				fmt.Println("Genesis state file removed", genesisFile)

				// leader.json file if exists
				leaderFile := config.LeaderUpdatesFilePath(rootDir)
				os.Remove(leaderFile) // ignore error
				fmt.Println("Leader file removed", leaderFile)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "reset all data, if this is not set, only the app state will be reset")
	bind.BindPostgresFlags(cmd, &custom.DefaultConfig().DB)

	return cmd
}

// resetPGState drops and creates the database.
func resetPGState(ctx context.Context, conf *pg.ConnConfig) error {
	dropDB := conf.DBName
	conf.DBName = "postgres"
	defer func() { conf.DBName = dropDB }()

	conn, err := pg.NewPool(ctx, &pg.PoolConfig{
		ConnConfig: *conf,
		MaxConns:   2, // requires 2 connections
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Execute(ctx, "DROP DATABASE "+dropDB)
	if err != nil {
		return err
	}

	_, err = conn.Execute(ctx, "CREATE DATABASE "+dropDB+" OWNER kwild")
	if err != nil {
		return err
	}

	return nil
}
