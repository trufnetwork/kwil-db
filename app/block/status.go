package block

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	types "github.com/trufnetwork/kwil-db/core/types/admin"
)

func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Get the status of any ongoing block execution.",
		Example: "kwild block status",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			status, err := clt.BlockExecStatus(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &respBlockExecStatus{Status: status})
		},
	}

	return cmd
}

type respBlockExecStatus struct {
	Status *types.BlockExecutionStatus `json:"status"`
}

func (r *respBlockExecStatus) MarshalJSON() ([]byte, error) {
	return json.MarshalIndent(r.Status, "", "  ")
}

func (r *respBlockExecStatus) MarshalText() ([]byte, error) {
	if r.Status == nil {
		return []byte("No block execution in progress"), nil
	}

	var msg bytes.Buffer
	msg.WriteString("Block Execution Status:\n")
	msg.WriteString(fmt.Sprintf("  Block Height: %d\n", r.Status.Height))
	msg.WriteString(fmt.Sprintf("  Execution Started at: %s\n", r.Status.StartTime))

	status := "Completed"
	firstTx := false // first tx in progress, rest of tx following it are not started
	for _, tx := range r.Status.TxInfo {
		if !tx.Status {
			if firstTx {
				status = "Not Started"
			} else {
				status = "In Progress"
				firstTx = true
			}
		}

		msg.WriteString(fmt.Sprintf("  Tx: %s  (%s)\n", tx.ID.String(), status))
	}

	if !r.Status.EndTime.IsZero() {
		msg.WriteString(fmt.Sprintf("  Execution Ended at: %s\n", r.Status.EndTime))
	}

	return msg.Bytes(), nil
}
