package blacklist

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

func removeCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "remove <nodeID>",
		Short:   "Remove a node from the node's blacklist.",
		Long:    "The `remove` command removes a node from the node's blacklist. The nodeID must be in the format HEX#secp256k1 or HEX#ed25519.",
		Example: "kwild blacklist remove 0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			err = client.RemoveBlacklistedPeer(ctx, args[0])
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

var _ display.MsgFormatter = (*removeMsg)(nil)

func (r *removeMsg) MarshalText() ([]byte, error) {
	return []byte("Removed node " + r.peerID + " from blacklist"), nil
}

func (r *removeMsg) MarshalJSON() ([]byte, error) {
	result := struct {
		NodeID  string `json:"node_id"`
		Removed bool   `json:"removed"`
	}{
		NodeID:  r.peerID,
		Removed: true,
	}
	return json.Marshal(result)
}
