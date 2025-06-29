package database

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
)

var (
	executeLong = `Execute SQL or an action against a database.

To execute a SQL statement against the database, use the --sql flag.  The SQL statement will be executed with the
arguments passed as parameters.  The arguments are specified as $name:value.  For example, to execute the SQL
statement "SELECT * FROM users WHERE age > 25", you would specify the following:
` + "`" + `kwil-cli database execute --sql "INSERT INTO ids (id) VALUES ($age);" age:25` + "`" + `

To specify an action to execute, you can pass the action name as the first positional argument, or as the --action flag.
The action name is specified as the first positional argument, and the action parameters as all subsequent arguments.`

	executeExample = `# Executing a CREATE TABLE statement on the "somedb" database namespace
kwil-cli database execute --sql "CREATE TABLE users (id UUID, name TEXT, age INT8);" --namespace mydb
	
# Executing the ` + "`" + `create_user($username, $age)` + "`" + ` action on the "somedb" database
kwil-cli database execute --action create_user username:satoshi age:32 --namespace somedb
`
)

func executeCmd() *cobra.Command {
	var sqlStmt string
	var sqlFilepath string

	cmd := &cobra.Command{
		Use:        "execute --sql <sql_stmt> <parameter_1:value_1> <parameter_2:value_2> ...",
		Short:      "Execute SQL or an action against a database.",
		Long:       executeLong,
		Example:    executeExample,
		Deprecated: `Use "kwil-cli exec-action" or "kwil-cli exec-sql" instead.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.DialClient(cmd.Context(), cmd, 0, func(ctx context.Context, cl clientType.Client, conf *config.KwilCliConfig) error {
				/*
					There is a bit of awkward history here required to make things backwards compatible.
					Prior to v0.10, the execute command was _only_ to execute actions, as it was not possible to give
					direct SQL statements. In v0.9 this was done by specifying the action name as the first argument.
					Prior to v0.9, the action name was specified as a flag. This was changed to a positional argument
					in v0.9 to make it more user-friendly. However, most users never actually upgraded to v0.9.

					To support all of these, the command has two flags: --sql and --action. If --sql is specified, it
					will take a string, and execute that SQL statement with all arguments as parameters. If --action
					is specified, it will take a string and execute that action with all args as parameters. If neither
					is specified, it will assume that the first argument is the action name, and all subsequent arguments
					are the parameters.
				*/

				namespace, wasSet, err := getSelectedNamespace(cmd)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error getting selected namespace from CLI flags: %w", err))
				}

				// if sql is not changed, then it is an action
				if !cmd.Flags().Changed("sql") && !cmd.Flags().Changed("sql-file") {
					action, args, err := getSelectedAction(cmd, args)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("error getting selected action: %w", err))
					}

					parsedArgs, err := parseInputs(args)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("error parsing inputs: %w", err))
					}

					inputs, err := buildExecutionInputs(ctx, cl, namespace, action, []map[string]string{parsedArgs})
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("error getting inputs: %w", err))
					}

					// Could actually just directly pass nonce to the client method,
					// but those methods don't need tx details in the inputs.
					txHash, err := cl.Execute(ctx, namespace, action, inputs,
						clientType.WithNonce(nonceOverride), clientType.WithSyncBroadcast(syncBcast))
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("error executing database: %w", err))
					}
					// If sycnBcast, and we have a txHash (error or not), do a query-tx.
					if len(txHash) != 0 && syncBcast {
						time.Sleep(500 * time.Millisecond) // otherwise it says not found at first
						resp, err := cl.TxQuery(ctx, txHash)
						if err != nil {
							return display.PrintErr(cmd, fmt.Errorf("tx query failed: %w", err))
						}
						return display.PrintCmd(cmd, display.NewTxHashAndExecResponse(resp))
					}
					return display.PrintCmd(cmd, display.RespTxHash(txHash))
				}

				if actionFlagSet(cmd) {
					return display.PrintErr(cmd, fmt.Errorf("cannot specify both (--sql or --sql-file) and --action"))
				}

				if sqlStmt == "" && sqlFilepath == "" {
					return display.PrintErr(cmd, fmt.Errorf("either --sql or --sql-file must be set"))
				}
				if sqlStmt != "" && sqlFilepath != "" {
					return display.PrintErr(cmd, fmt.Errorf("cannot specify both --sql and --sql-file"))
				}
				var stmt string
				if sqlFilepath != "" {
					expanded, err := helpers.ExpandPath(sqlFilepath)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("error expanding path: %w", err))
					}

					file, err := os.ReadFile(expanded)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("error reading file: %w", err))
					}
					stmt = string(file)
				} else {
					stmt = sqlStmt
				}

				stmt = strings.TrimSpace(stmt)

				// if the namespace is set, we should prepend it to the statement
				if wasSet {
					if strings.HasPrefix(stmt, "{") {
						return display.PrintErr(cmd, fmt.Errorf("cannot specify both --namespace and a statement with a {namespace} prefix"))
					}
					stmt = fmt.Sprintf("{%s}%s", namespace, stmt)
				}

				parsed, err := parseInputs(args)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error parsing inputs: %w", err))
				}

				args := make(map[string]interface{}, len(parsed))
				for k, v := range parsed {
					args[k] = v
				}

				// If we're here, we're executing a SQL statement.
				txHash, err := cl.ExecuteSQL(ctx, stmt, args, clientType.WithNonce(nonceOverride), clientType.WithSyncBroadcast(syncBcast))
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error executing SQL statement: %w", err))
				}
				// If sycnBcast, and we have a txHash (error or not), do a query-tx.
				if len(txHash) != 0 && syncBcast {
					time.Sleep(500 * time.Millisecond) // otherwise it says not found at first
					resp, err := cl.TxQuery(ctx, txHash)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("tx query failed: %w", err))
					}
					return display.PrintCmd(cmd, display.NewTxHashAndExecResponse(resp))
				}
				return display.PrintCmd(cmd, display.RespTxHash(txHash))
			})
		},
	}

	bindFlagsTargetingAction(cmd) // --namespace/-n , --action/-a
	cmd.Flags().StringVarP(&sqlStmt, "sql", "s", "", "the SQL statement to execute")
	cmd.Flags().StringVarP(&sqlFilepath, "sql-file", "f", "", "the file containing the SQL statement to execute")
	return cmd
}

// inputs will be received as args.  The args will be in the form of
// $argname:value.  Example $username:satoshi $age:32
func parseInputs(args []string) (map[string]string, error) {
	inputs := make(map[string]string, len(args))

	for _, arg := range args {
		ensureInputFormat(&arg)

		// split the arg into name and value.  only split on the first ':'
		split := strings.SplitN(arg, ":", 2)
		if len(split) != 2 {
			return nil, fmt.Errorf("invalid argument: %s.  argument must be in the form of $name:value", arg)
		}

		inputs[split[0]] = split[1]
	}

	return inputs, nil
}
