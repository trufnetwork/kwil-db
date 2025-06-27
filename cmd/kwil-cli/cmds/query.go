package cmds

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

var (
	queryLong = `Execute a SELECT statement against the database.

This command executes a SELECT statement against the database and formats the results in a table.
It can only be used to execute SELECT statements, and cannot be used with any other type of SQL statement.
If you need to execute a SQL statement that modifies the database, use the 'exec-sql' command.

It is not required to have a private key configured, unless the RPC you are calling is in private mode, or
you are talking to Kwil Gateway.`

	queryExample = `# Execute a simple SELECT statement
kwil-cli query "SELECT * FROM my_table"

# Execute a SELECT statement with a named parameter
kwil-cli query "SELECT * FROM my_table WHERE id = $id" --param id:int=1`
)

func queryCmd() *cobra.Command {
	var namedParams []string
	var gwAuth, rpcAuth bool
	var stmt string

	cmd := &cobra.Command{
		Use:     "query",
		Short:   "Execute a SELECT statement against the database",
		Long:    queryLong,
		Example: queryExample,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sqlStmt string
			switch {
			case stmt != "" && len(args) == 0:
				sqlStmt = stmt
			case stmt == "" && len(args) == 1:
				sqlStmt = args[0]
			case stmt != "" && len(args) == 1:
				return display.PrintErr(cmd, fmt.Errorf("cannot provide both a --stmt flag and an argument"))
			case stmt == "" && len(args) == 0:
				return display.PrintErr(cmd, fmt.Errorf("no SQL statement provided"))
			default:
				return display.PrintErr(cmd, fmt.Errorf("unexpected error"))
			}

			var dialFlags uint8
			if gwAuth {
				// if calling kgw, then not only do we need a private key, but we also need to authenticate
				dialFlags = client.UsingGateway
			}
			if rpcAuth {
				// if calling a kwil node, then we need to authenticate
				dialFlags = dialFlags | client.AuthenticatedCalls
			}
			if dialFlags == 0 {
				// if neither of the above, private key is not required
				dialFlags = client.WithoutPrivateKey
			}

			params, err := parseParams(namedParams)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			_, err = parse.Parse(sqlStmt)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to parse SQL statement: %s", err))
			}

			return client.DialClient(cmd.Context(), cmd, dialFlags, func(ctx context.Context, cl clientType.Client, conf *config.KwilCliConfig) error {
				res, err := cl.Query(ctx, sqlStmt, params, !rpcAuth)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				return display.PrintCmd(cmd, &respRelations{Data: res, cmd: cmd})
			})
		},
	}

	cmd.Flags().StringVarP(&stmt, "stmt", "s", "", "the SELECT statement to execute")
	// this has to be StringArrayVar because if the user is passing an array, it will contain a comma, but it itself is a single parameter.
	// If we use StringSliceVar, it will split the array into multiple parameters.
	cmd.Flags().StringArrayVarP(&namedParams, "param", "p", nil, `named parameters that will be used in the query. format: "key:type=value"`)
	cmd.Flags().BoolVar(&rpcAuth, "rpc-auth", false, "signals that the query is being made to a kwil node and should be authenticated with the private key")
	cmd.Flags().BoolVar(&gwAuth, "gateway-auth", false, "signals that the query is being made to a gateway and should be authenticated with the private key")
	display.BindTableFlags(cmd)
	return cmd
}

// respRelations is a slice of maps that represent the relations(from set theory)
// of a database in cli
type respRelations struct {
	// to avoid recursive call of MarshalJSON
	Data *types.QueryResult
	// conf for table formatting
	cmd *cobra.Command
}

func (r *respRelations) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Data)
}

func (r *respRelations) MarshalText() ([]byte, error) {
	return display.FormatTable(r.cmd, r.Data.ColumnNames, getStringRows(r.Data.Values))
}
