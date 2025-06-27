package utils

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
)

func decodeTx(txBts []byte) (*transaction, error) {
	var tx types.Transaction
	err := tx.UnmarshalBinary(txBts)
	if err != nil {
		return nil, err
	}
	return &transaction{
		Raw: txBts,
		Tx:  &tx,
	}, nil
}

// fromStdIn returns a line from the input reader and trims leading and trailing
// whitespace.
func fromStdIn(in io.Reader) ([]byte, error) {
	str, err := bufio.NewReader(in).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(str), nil
}

func decodeTxCmd() *cobra.Command {
	var withPayload bool
	var cmd = &cobra.Command{
		Use:   "decode-tx",
		Short: "Decodes a raw transaction.",
		Long:  "Decodes a raw transaction. Given the bytes of a transaction in base64, give a structured output.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var txStr string
			var err error
			if args[0] == "-" {
				argReader := cmd.InOrStdin()
				txStrB, err := fromStdIn(argReader)
				if err != nil {
					return display.PrintErr(cmd, err)
				}
				txStr = string(txStrB)
			} else {
				txStr = args[0]
			}
			txBts, err := hex.DecodeString(txStr)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			tx, err := decodeTx(txBts)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			tx.WithPayload = withPayload
			return display.PrintCmd(cmd, tx)
		},
	}

	cmd.Flags().BoolVar(&withPayload, "payload", false, "also show the payload, which may be large")

	return cmd
}
