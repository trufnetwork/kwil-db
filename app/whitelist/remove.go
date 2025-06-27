package whitelist

import (
	"context"
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

func removeCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "remove <peerID>",
		Short:   "Remove a peer from the node's whitelist and disconnect it.",
		Long:    "The `remove` command removes a peer from the node's whitelist and disconnects it.",
		Example: "kwild whitelist remove <peerID>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			client, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			err = client.RemovePeer(ctx, args[0])
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &removeMsg{peerID: args[0]})
		},
	}
	rpc.BindRPCFlags(cmd)

	return cmd
}

type removeMsg struct {
	peerID string
}

var _ display.MsgFormatter = (*addMsg)(nil)

func (a *removeMsg) MarshalText() ([]byte, error) {
	return []byte("Removed peer " + a.peerID), nil
}

func (a *removeMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.peerID)
}
