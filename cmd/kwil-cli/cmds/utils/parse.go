package utils

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

func parseCmd() *cobra.Command {
	var in, out string
	var removePositions bool

	cmd := &cobra.Command{
		Use:   "parse",
		Short: "Parses SQL and returns the AST.",
		Long: `Parses SQL and returns the AST.

It can either be given a file or a string on the command line to parse.
It can be given an out file where it will write the AST to a file.
If no out file is given, it will simply print whether it was successful or not.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sql string
			if len(args) == 1 {
				sql = args[0]
				if in != "" {
					return display.PrintErr(cmd, fmt.Errorf("cannot provide both a file and a string as an argument"))
				}
			} else {
				if in == "" {
					return display.PrintErr(cmd, fmt.Errorf("must provide either a file or a string as an argument"))
				}

				in, err := helpers.ExpandPath(in)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				file, err := os.ReadFile(in)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				sql = string(file)
			}

			res, err := parse.ParseWithErrListener(sql)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			if out != "" {
				if removePositions {
					parse.RecursivelyVisitPositions(res.Statements, func(gp parse.GetPositioner) {
						fmt.Println(1)
						gp.Clear()
					})
				}

				bts, err := json.MarshalIndent(res, "", "  ")
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				full, err := writeToFile(out, bts)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				var msg string
				if res.ParseErrs.Err() != nil {
					msg = fmt.Sprintf("%s\n", res.ParseErrs.Err())
				}
				msg += fmt.Sprintf("AST written to %s", full)

				return display.PrintCmd(cmd, display.RespString(msg))
			}

			if res.ParseErrs.Err() != nil {
				return display.PrintErr(cmd, res.ParseErrs.Err())
			}

			return display.PrintCmd(cmd, display.RespString("AST parsed successfully"))
		},
	}

	cmd.Flags().StringVarP(&out, "out", "o", "", "Output file to write the AST to.")
	cmd.Flags().StringVarP(&in, "in", "i", "", "A file that SQL should be read from.")
	cmd.Flags().BoolVarP(&removePositions, "remove-positions", "r", false, "Remove positions from the AST.")
	return cmd
}
