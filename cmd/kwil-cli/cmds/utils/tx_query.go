package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/types"
)

func txQueryCmd() *cobra.Command {
	var raw bool
	var full bool
	cmd := &cobra.Command{
		Use:   "query-tx <tx_id>",
		Short: "Queries a transaction from the blockchain. Requires 1 argument: the hex encoded transaction id.",
		Long:  `Queries a transaction from the blockchain. Requires 1 argument: the hex encoded transaction id.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.DialClient(cmd.Context(), cmd, client.WithoutPrivateKey, func(ctx context.Context, client clientType.Client, conf *config.KwilCliConfig) error {
				txHash, err := types.NewHashFromString(args[0])
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error decoding transaction id: %w", err))
				}

				msg, err := client.TxQuery(ctx, txHash)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error querying transaction: %w", err))
				}

				if full {
					return display.PrintCmd(cmd, &displayFullTxQuery{Msg: msg})
				}

				return display.PrintCmd(cmd, &display.RespTxQuery{Msg: msg, WithRaw: raw})
			})
		},
	}

	cmd.Flags().BoolVarP(&raw, "raw", "R", false, "also display the bytes of the serialized transaction")
	cmd.Flags().BoolVarP(&full, "full", "F", false, "display the full transaction details")

	return cmd
}

type displayFullTxQuery struct {
	Msg *types.TxQueryResponse
}

func (d *displayFullTxQuery) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Msg)
}

func (d *displayFullTxQuery) MarshalText() (text []byte, err error) {
	str := strings.Builder{}

	str.WriteString(fmt.Sprintf("TxHash: %s\n", d.Msg.Hash.String()))
	str.WriteString(fmt.Sprintf("Height: %d\n", d.Msg.Height))

	txInfoBts, err := json.MarshalIndent(d.Msg.Tx, "", "  ")
	if err != nil {
		return nil, err
	}

	str.WriteString(fmt.Sprintf("TxInfo: %s\n", string(txInfoBts)))

	txResultBts, err := json.MarshalIndent(d.Msg.Result, "", "  ")
	if err != nil {
		return nil, err
	}

	str.WriteString(fmt.Sprintf("TxResult: %s\n", string(txResultBts)))

	return []byte(str.String()), nil
}
