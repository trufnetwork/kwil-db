package common

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	client "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/types"
)

// BindTxFlags binds the flags for a transaction.
// It should be used with commands that author transactions.
func BindTxFlags(cmd *cobra.Command) {
	cmd.Flags().Int64P("nonce", "N", -1, "nonce override (-1 means request from server)")
	cmd.Flags().Bool("sync", false, "synchronous broadcast (wait for it to be included in a block)")
}

type TxFlags struct {
	NonceOverride int64
	SyncBroadcast bool
}

func GetTxFlags(cmd *cobra.Command) (*TxFlags, error) {
	nonce, err := cmd.Flags().GetInt64("nonce")
	if err != nil {
		return nil, err
	}
	sync, err := cmd.Flags().GetBool("sync")
	if err != nil {
		return nil, err
	}

	return &TxFlags{
		NonceOverride: nonce,
		SyncBroadcast: sync,
	}, nil
}

// DisplayTxResult takes a tx hash and decides whether to wait for it and print the tx result,
// or just print the tx hash. It will display the result of the transaction.
func DisplayTxResult(ctx context.Context, client1 client.Client, txHash types.Hash, cmd *cobra.Command) error {
	txFlags, err := GetTxFlags(cmd)
	if err != nil {
		return display.PrintErr(cmd, err)
	}

	if len(txHash) > 0 && txFlags.SyncBroadcast {
		// time.Sleep(500 * time.Millisecond) // TODO: remove once we have fixed race condition
		resp, err := client1.TxQuery(ctx, txHash)
		if err != nil {
			return display.PrintErr(cmd, err)
		}
		return display.PrintCmd(cmd, display.NewTxHashAndExecResponse(resp))
	}
	return display.PrintCmd(cmd, display.RespTxHash(txHash))
}
