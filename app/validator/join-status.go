package validator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/types"
)

var (
	joinStatusLong    = "The `query` command gets the status of a pending validator join request."
	joinStatusExample = `# Query the status of a pending validator join request, by providing the validator info in format <hexPubkey#pubkeytype>
kwild validators join-status 6ecaca8e9394c939a858c2c7b47acb1db26a96d7ab38bd702fa3820c5034e9d0#0`
)

func joinStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "join-status <joiner>",
		Short:   "Get the status of a pending validator join request.",
		Long:    joinStatusLong,
		Example: joinStatusExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			pubkeyBts, pubKeyType, err := config.DecodePubKeyAndType(args[0])
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			data, err := clt.JoinStatus(ctx, pubkeyBts, pubKeyType)
			if err != nil {
				if errors.Is(err, client.ErrNotFound) {
					//lint:ignore ST1005 this error message is read from the CLI and reads better with capitalization and punctuation
					return display.PrintErr(cmd, errors.New("No active join request for that validator. Have they already been approved?"))
				}
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &respValJoinStatus{Data: data})
		},
	}

	return cmd
}

// respValJoinStatus represent the status of a validator join request in cli
type respValJoinStatus struct {
	Data *types.JoinRequest
}

// respValJoinRequest is customized json format for respValJoinStatus
type respValJoinRequest struct {
	Candidate *types.AccountID   `json:"candidate"`
	Power     int64              `json:"power"`
	Board     []*types.AccountID `json:"board"`
	Approved  []bool             `json:"approved"`
}

func (r *respValJoinStatus) MarshalJSON() ([]byte, error) {
	joinReq := &respValJoinRequest{
		Candidate: r.Data.Candidate,
		Power:     r.Data.Power,
		Board:     make([]*types.AccountID, len(r.Data.Board)),
		Approved:  r.Data.Approved,
	}
	for i := range r.Data.Board {
		joinReq.Board[i] = &types.AccountID{
			Identifier: r.Data.Board[i].Identifier,
			KeyType:    r.Data.Board[i].KeyType,
		}
	}

	return json.Marshal(joinReq)
}

func (r *respValJoinStatus) MarshalText() ([]byte, error) {
	approved := 0
	for _, a := range r.Data.Approved {
		if a {
			approved++
		}
	}

	needed := int(math.Ceil(float64(len(r.Data.Board)) * 2 / 3))

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("Candidate: %s\n", r.Data.Candidate.PrettyString()))
	msg.WriteString(fmt.Sprintf("Requested Power: %d\n", r.Data.Power))
	msg.WriteString(fmt.Sprintf("Expiration Timestamp: %s\n", r.Data.ExpiresAt.String()))

	msg.WriteString(fmt.Sprintf("%d Approvals Received From Existing Validators (%d needed):\n", approved, needed))

	for i := range r.Data.Board {
		approvedTerm := "✅ approved"
		if !r.Data.Approved[i] {
			approvedTerm = "❌ not approved"
		}

		msg.WriteString(fmt.Sprintf("  %s: %s\n",
			r.Data.Board[i].PrettyString(), approvedTerm))
	}

	return msg.Bytes(), nil
}
