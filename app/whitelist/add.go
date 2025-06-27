package whitelist

import (
	"context"
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

func addCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "add <peerID>",
		Short:   "Add a peer to the node's connection whitelist.",
		Long:    "The `add` command adds a peer to the node's whitelist of peers to accept connections from.",
		Example: "kwild whitelist add <peerID>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			client, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			err = client.AddPeer(ctx, args[0])
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &addMsg{peerID: args[0]})
		},
	}
	rpc.BindRPCFlags(cmd)

	return cmd
}

type addMsg struct {
	peerID string
}

var _ display.MsgFormatter = (*addMsg)(nil)

func (a *addMsg) MarshalText() ([]byte, error) {
	return []byte("Whitelisted peer " + a.peerID), nil
}

func (a *addMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.peerID)
}
