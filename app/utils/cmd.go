package utils

import (
	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

func NewCmdUtils() *cobra.Command {
	var utilsCmd = &cobra.Command{
		Use:     "utils",
		Aliases: []string{"common"},
		Short:   "Miscellaneous utility commands.",
		Long:    "The `utils` commands provide various miscellaneous utility commands such as `query-tx` for querying a transaction status.",
	}

	utilsCmd.AddCommand(
		txQueryCmd(),
	)

	rpc.BindRPCFlags(utilsCmd)
	display.BindOutputFormatFlag(utilsCmd)

	return utilsCmd
}
