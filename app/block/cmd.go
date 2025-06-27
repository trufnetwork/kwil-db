package block

import (
	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

var blockCmd = &cobra.Command{
	Use:   "block",
	Short: "Leader block execution commands",
	Long:  "The `block` command group has subcommands for managing leader block execution, including status and aborting.",
}

func NewBlockExecCmd() *cobra.Command {
	blockCmd.AddCommand(
		statusCmd(),
		abortCmd(),
	)

	rpc.BindRPCFlags(blockCmd)
	display.BindOutputFormatFlag(blockCmd)
	return blockCmd
}
