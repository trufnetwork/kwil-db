package blacklist

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

func addCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "add <nodeID>",
		Short: "Add a node to the node's blacklist.",
		Long:  "The `add` command adds a node to the node's blacklist with an optional reason and duration. The nodeID must be in the format HEX#secp256k1 or HEX#ed25519.",
		Example: `kwild blacklist add 0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1
kwild blacklist add 0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1 --reason="malicious behavior"
kwild blacklist add 0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#secp256k1 --reason="connection issues" --duration="1h"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			// Get flag values
			reason, err := cmd.Flags().GetString("reason")
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			durationStr, err := cmd.Flags().GetString("duration")
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			// Parse duration string to time.Duration
			var duration time.Duration
			if durationStr != "" {
				duration, err = time.ParseDuration(durationStr)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("invalid duration format: %w", err))
				}
				// Validate that duration is positive
				if duration <= 0 {
					return display.PrintErr(cmd, fmt.Errorf("duration must be positive, got: %s", duration))
				}
			}

			err = client.BlacklistPeer(ctx, args[0], reason, duration)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &addMsg{
				peerID:   args[0],
				reason:   reason,
				duration: durationStr,
			})
		},
	}

	// Add flags for reason and duration
	cmd.Flags().String("reason", "manual", "Reason for blacklisting the peer")
	cmd.Flags().String("duration", "", "Duration for blacklist (e.g., 1h, 30m, 2h15m30s). Empty means permanent")

	rpc.BindRPCFlags(cmd)

	return cmd
}

type addMsg struct {
	peerID   string
	reason   string
	duration string
}

var _ display.MsgFormatter = (*addMsg)(nil)

func (a *addMsg) MarshalText() ([]byte, error) {
	durationType := "permanent"
	if a.duration != "" {
		durationType = fmt.Sprintf("duration: %s", a.duration)
	}

	return []byte(fmt.Sprintf("Blacklisted node %s (reason: %s, %s)", a.peerID, a.reason, durationType)), nil
}

func (a *addMsg) MarshalJSON() ([]byte, error) {
	result := struct {
		NodeID    string `json:"node_id"`
		Reason    string `json:"reason"`
		Duration  string `json:"duration,omitempty"`
		Permanent bool   `json:"permanent"`
	}{
		NodeID:    a.peerID,
		Reason:    a.reason,
		Duration:  a.duration,
		Permanent: a.duration == "",
	}
	return json.Marshal(result)
}
