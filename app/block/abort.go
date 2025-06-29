package block

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

func abortCmd() *cobra.Command {
	var txIDs []string

	cmd := &cobra.Command{
		Use:   `abort <block_height>`,
		Short: "Abort active execution of the current block.",
		Long:  "Aborts the execution of the current block if it is at given height, and removes specified transactions from the mempool.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			blockHeight, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("invalid block height: %w", err))
			}

			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			err = clt.AbortBlockExecution(ctx, blockHeight, txIDs)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&txIDs, "txns", "t", nil, "Transaction IDs to remove from the mempool")

	return cmd
}
