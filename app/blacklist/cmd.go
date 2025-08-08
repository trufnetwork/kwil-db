package blacklist

import (
	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

var blacklistCmd = &cobra.Command{
	Use:   "blacklist",
	Short: "Manage a node's peer blacklist",
	Long:  "The `blacklist` command allows you to manage the node's peer blacklist, including adding peers, removing peers, and listing blacklisted peers.",
}

func BlacklistCmd() *cobra.Command {
	blacklistCmd.AddCommand(
		addCmd(),
		removeCmd(),
		listCmd(),
	)
	display.BindOutputFormatFlag(blacklistCmd)

	return blacklistCmd
}
