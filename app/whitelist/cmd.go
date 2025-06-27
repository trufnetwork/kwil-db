package whitelist

import (
	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

var peersCmd = &cobra.Command{
	Use:   "whitelist",
	Short: "Manage a node's peer whitelist",
}

func WhitelistCmd() *cobra.Command {
	peersCmd.AddCommand(
		addCmd(),
		removeCmd(),
		listCmd(),
	)
	display.BindOutputFormatFlag(peersCmd)

	return peersCmd
}
