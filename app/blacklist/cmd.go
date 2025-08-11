package blacklist

import (
	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

func BlacklistCmd() *cobra.Command {
	blacklistCmd := &cobra.Command{
		Use:   "blacklist",
		Short: "Manage a node's peer blacklist",
		Long:  "The `blacklist` command allows you to manage the node's peer blacklist, including adding nodes, removing nodes, and listing blacklisted nodes.",
	}

	blacklistCmd.AddCommand(
		addCmd(),
		removeCmd(),
		listCmd(),
	)
	display.BindOutputFormatFlag(blacklistCmd)

	return blacklistCmd
}
