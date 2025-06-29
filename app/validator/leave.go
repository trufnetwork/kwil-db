package validator

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

var (
	leaveLong = "The `leave` command submits a transaction to leave the validator set. This node will be removed from the validator set if the transaction is included in a block."

	leaveExample = `# Leave the validator set
kwild validators leave`
)

func leaveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "leave",
		Short:   "Leave the validator set (your node must be a validator).",
		Long:    leaveLong,
		Example: leaveExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			txHash, err := clt.Leave(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, display.RespTxHash(txHash))
		},
	}

	return cmd
}
