package whitelist

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

func listCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "list",
		Short:   "List the peers in the node's whitelist.",
		Long:    "The `list` command lists the peers in the node's whitelist.",
		Example: "kwild whitelist list",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			client, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			peers, err := client.ListPeers(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &listPeersMsg{peers: peers})
		},
	}
	rpc.BindRPCFlags(cmd)

	return cmd
}

type listPeersMsg struct {
	peers []string
}

var _ display.MsgFormatter = (*listPeersMsg)(nil)

func (l *listPeersMsg) MarshalText() ([]byte, error) {
	return []byte("Whitelisted Peers:  \n" + strings.Join(l.peers, "\n")), nil
}

func (l *listPeersMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.peers)
}
