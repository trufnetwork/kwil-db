package cmds

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/cmds/common"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

var (
	execSQLLong = `Execute SQL statements against a database.

This command executes SQL and DDL statements against a database.  It is meant to be used for statements that
do not return data, such as INSERT, UPDATE, DELETE, CREATE TABLE, etc. For SELECT statements, use the 'query'
command.

This command requires a private key. Each statement issued will use the private key to author a transaction
to the network.`

	execSQLExample = `# Execute a create table statement
kwil-cli exec-sql "CREATE TABLE my_table (id int primary key, name text)"

# Execute a create table statement from a file
kwil-cli exec-sql --file /path/to/file.sql

# Execute an insert statement with parameters
kwil-cli exec-sql "INSERT INTO my_table (id, name) VALUES ($id, $name)" --param id:int=1 --param name:text=foo`
)

func execSQLCmd() *cobra.Command {
	var sqlStmt, sqlFilepath string
	var params []string

	cmd := &cobra.Command{
		Use:     "exec-sql",
		Short:   "Execute SQL against a database",
		Long:    execSQLLong,
		Example: execSQLExample,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			txFlags, err := common.GetTxFlags(cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			params, err := parseParams(params)
			if err != nil {
				return err
			}

			var stmt string
			if len(args) > 0 {
				stmt = args[0]
			}
			if sqlStmt != "" {
				if stmt != "" {
					return display.PrintErr(cmd, fmt.Errorf(`received two SQL statements: "%s" and "%s"`, stmt, sqlStmt))
				}
				stmt = sqlStmt
			}
			if sqlFilepath != "" {
				if stmt != "" {
					return display.PrintErr(cmd, fmt.Errorf(`received two SQL statements: "%s" and file "%s"`, stmt, sqlFilepath))
				}

				expanded, err := helpers.ExpandPath(sqlFilepath)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				file, err := os.ReadFile(expanded)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				stmt = string(file)
			}

			if stmt == "" {
				return display.PrintErr(cmd, fmt.Errorf("no SQL statement provided"))
			}

			_, err = parse.Parse(stmt)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to parse SQL statement: %s", err))
			}

			return client.DialClient(cmd.Context(), cmd, 0, func(ctx context.Context, cl clientType.Client, conf *config.KwilCliConfig) error {
				txHash, err := cl.ExecuteSQL(ctx, stmt, params, clientType.WithNonce(txFlags.NonceOverride), clientType.WithSyncBroadcast(txFlags.SyncBroadcast))
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				return common.DisplayTxResult(ctx, cl, txHash, cmd)
			})
		},
	}

	cmd.Flags().StringVarP(&sqlStmt, "stmt", "s", "", "the SQL statement to execute")
	cmd.Flags().StringVarP(&sqlFilepath, "file", "f", "", "the file containing the SQL statement(s) to execute")
	// this has to be StringArrayVar because if the user is passing an array, it will contain a comma, but it itself is a single parameter.
	// If we use StringSliceVar, it will split the array into multiple parameters.
	cmd.Flags().StringArrayVarP(&params, "param", "p", nil, `the parameters to pass to the SQL statement. format: "key:type=value"`)
	common.BindTxFlags(cmd)
	return cmd
}
