package migration

import (
	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
)

func approveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "approve <proposal_id>",
		Short:   "Approve a migration proposal.",
		Example: "kwild migrate approve <proposal_id>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			proposalID, err := types.ParseUUID(args[0])
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			txHash, err := clt.ApproveResolution(ctx, proposalID)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, display.RespTxHash(txHash))
		},
	}

	return cmd
}
