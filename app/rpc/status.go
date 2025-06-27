package rpc

import (
	"context"
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	types "github.com/trufnetwork/kwil-db/core/types/admin"
)

var (
	statusLong = "The `status` command retrieves and prints the node's status."

	statusExample = `# Print a running node's status
kwild admin status --rpcserver /tmp/kwild.socket`
)

func statusCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "status",
		Short:   "Print the node's status information.",
		Long:    statusLong,
		Example: statusExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := context.Background()
			client, err := AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			status, err := client.Status(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &statusMsg{status: status})
		},
	}

	BindRPCFlags(cmd)

	return cmd
}

// statusMsg is a wrapper around the Status type that
// implements the MsgFormatter interface.
type statusMsg struct {
	status *types.Status
}

var _ display.MsgFormatter = (*statusMsg)(nil)

func (s *statusMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.status)
}

func (s *statusMsg) MarshalText() ([]byte, error) {
	return json.MarshalIndent(s.status, "", "  ")
}
