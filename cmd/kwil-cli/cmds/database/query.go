package database

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
)

var (
	queryLong = `Query a database using an ad-hoc SQL SELECT statement.

Requires a SQL SELECT statement as an argument.

You specify the database namespace to execute this against with the ` + "`--namespace` flag." + `

Note that ad-hoc queries will be rejected on RPC servers that are operating with
authenticated call requests enabled.`

	queryExample = `# Querying the "users" table in the "somedb" database namespace
kwil-cli database query "SELECT * FROM users WHERE age > 25" --namespace somedb`
)

func queryCmd() *cobra.Command {
	fmtConf := tableConfig{}
	var noAuth bool
	cmd := &cobra.Command{
		Use:        `query <select_statement>`,
		Short:      "Query a database using an ad-hoc SQL SELECT statement.",
		Long:       queryLong,
		Example:    queryExample,
		Deprecated: `Use "kwil-cli query" instead.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.DialClient(cmd.Context(), cmd, client.WithoutPrivateKey,
				func(ctx context.Context, client clientType.Client, conf *config.KwilCliConfig) error {
					if len(args) == 0 {
						return display.PrintErr(cmd, fmt.Errorf("no query provided"))
					}

					params := make(map[string]any)
					if len(args) > 1 {
						ins, err := parseInputs(args[1:])
						if err != nil {
							return display.PrintErr(cmd, fmt.Errorf("error parsing inputs: %w", err))
						}

						for k, v := range ins {
							params[k] = v
						}
					}

					data, err := client.Query(ctx, args[0], params, noAuth)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("error querying database: %w", err))
					}

					resp := &respRelations{
						Data: data,
						conf: &fmtConf,
					}

					return display.PrintCmd(cmd, resp)
				})
		},
	}

	cmd.Flags().BoolVar(&noAuth, "no-auth", false, "Do not authenticate in query requests even if private key is configured.")
	cmd.Flags().IntVarP(&fmtConf.width, "width", "w", 0, "Set the width of the table columns. Text beyond this width will be wrapped.")
	cmd.Flags().BoolVar(&fmtConf.topAndBottomBorder, "row-border", false, "Show border lines between rows.")
	cmd.Flags().IntVar(&fmtConf.maxRowWidth, "max-row-width", 0, "Set the maximum width of the row. Text beyond this width will be truncated.")

	return cmd
}
