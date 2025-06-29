package validator

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"
)

var (
	removeLong = "The `remove` command votes to remove a validator from the validator set. If enough validators vote to remove the validator, the validator will be removed from the validator set."

	removeExample = `# Remove a validator from the validator set by providing the validator info in format <hexPubkey#pubkeytype>
kwild validators remove e16141e4def3a7f2dfc5bbf40d50619b4d7bc9c9f670fcad98327b0d3d7b97b6#0`
)

func removeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove <validator>",
		Short:   "Votes to remove a validator from the validator set (this node must be a validator).",
		Long:    removeLong,
		Example: removeExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			validatorBts, valKeyType, err := config.DecodePubKeyAndType(args[0])
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			txHash, err := clt.Remove(ctx, validatorBts, valKeyType)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, display.RespTxHash(txHash))
		},
	}

	return cmd
}
