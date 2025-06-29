package validator

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"
)

var (
	approveLong = "The `approve` command creates and approves an active join request for a candidate validator using the node's validator keys to publish an approval transaction. If enough validators approve the join request, the candidate validator will be added to the validator set."

	approveExample = `# Approve a join request for a candidate validator by providing the validator info in format <hexPubkey#pubkeytype>
kwild validators approve 6ecaca8e9394c939a858c2c7b47acb1db26a96d7ab38bd702fa3820c5034e9d0#1`
)

func approveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "approve <joiner>",
		Short:   "Approve an active join request for a candidate validator (your node must be a validator).",
		Long:    approveLong,
		Example: approveExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			joinerPubKey, keyType, err := config.DecodePubKeyAndType(args[0])
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			txHash, err := clt.Approve(ctx, joinerPubKey, keyType)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, display.RespTxHash(txHash))
		},
	}

	return cmd
}
