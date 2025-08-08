package blacklist

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	adminjson "github.com/trufnetwork/kwil-db/core/rpc/json/admin"
)

func listCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "list",
		Short:   "List blacklisted nodes.",
		Long:    "The `list` command shows all blacklisted nodes with their reasons, blacklist time, and expiration.",
		Example: "kwild blacklist list",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			client, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			peers, err := client.ListBlacklistedPeers(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &listBlacklistedPeersMsg{peers: peers})
		},
	}
	rpc.BindRPCFlags(cmd)

	return cmd
}

type listBlacklistedPeersMsg struct {
	peers []adminjson.BlacklistEntryJSON
}

var _ display.MsgFormatter = (*listBlacklistedPeersMsg)(nil)

func (l *listBlacklistedPeersMsg) MarshalText() ([]byte, error) {
	if len(l.peers) == 0 {
		return []byte("No blacklisted nodes"), nil
	}

	var output strings.Builder
	output.WriteString("Blacklisted Nodes:\n\n")

	// Header
	output.WriteString(fmt.Sprintf("%-70s %-20s %-20s %-10s %s\n",
		"NODE ID", "REASON", "BLACKLISTED", "TYPE", "EXPIRES AT"))
	output.WriteString(strings.Repeat("-", 140) + "\n")

	for i := range l.peers {
		peer := &l.peers[i]
		// Truncate peer ID if too long
		peerID := peer.PeerID
		if len(peerID) > 67 {
			peerID = peerID[:67] + "..."
		}

		// Format blacklist time
		blacklistedTime := "Unknown"
		if peer.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, peer.Timestamp); err == nil {
				blacklistedTime = t.Format("2006-01-02T15:04:05Z")
			}
		}

		// Type and expiration
		peerType := "Permanent"
		expiresAt := "-"
		if !peer.Permanent && peer.ExpiresAt != "" {
			peerType = "Temporary"
			if t, err := time.Parse(time.RFC3339, peer.ExpiresAt); err == nil {
				expiresAt = t.Format("2006-01-02T15:04:05Z")
			}
		}

		output.WriteString(fmt.Sprintf("%-70s %-20s %-20s %-10s %s\n",
			peerID, peer.Reason, blacklistedTime, peerType, expiresAt))
	}

	return []byte(output.String()), nil
}

func (l *listBlacklistedPeersMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.peers)
}
