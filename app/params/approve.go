package params

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/consensus"
)

func approveUpdateProposalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "approve <proposal_id>",
		Short:   "Approve a consensus update proposal.",
		Example: "consensus approve <proposal_id>",
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

			resStat, err := clt.ResolutionStatus(ctx, proposalID)
			if err != nil {
				return display.PrintErr(cmd, err)
			}
			if resStat.Type != consensus.ParamUpdatesResolutionType {
				return display.PrintErr(cmd, fmt.Errorf("proposal is not a consensus update proposal, is %v", resStat.Type))
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
