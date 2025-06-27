package validator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
)

var (
	listJoinRequestsLong = `The ` + "`list-join-requests`" + ` command lists all pending join requests.
	
Join requests are created when a validator wants to join the validator set. The validator must be approved by 2/3 of the current validator set to be added to the validator set.
Each join request has an expiration block height, after which it is no longer valid.`

	listJoinRequestsExample = `# List all pending join requests
kwild validators list-join-requests`
)

func listJoinRequestsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list-join-requests",
		Short:   "List all pending join requests.",
		Long:    listJoinRequestsLong,
		Example: listJoinRequestsExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			pending, err := clt.ListPendingJoins(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &respJoinList{Joins: pending, cmd: cmd})
		},
	}

	display.BindTableFlags(cmd)
	return cmd
}

type respJoinList struct {
	cmd   *cobra.Command
	Joins []*types.JoinRequest
}

func (r *respJoinList) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Joins)
}

func (r *respJoinList) MarshalText() ([]byte, error) {
	var msg bytes.Buffer

	if len(r.Joins) == 0 {
		msg.WriteString("No pending join requests")
		return msg.Bytes(), nil
	}

	needed := int(math.Ceil(float64(len(r.Joins[0].Board)) * 2 / 3))

	approvalTerm := "approvals"
	if needed == 1 {
		approvalTerm = "approval"
	}

	var rows [][]string
	for _, j := range r.Joins {
		approvals := 0
		for _, a := range j.Approved {
			if a {
				approvals++
			}
		}

		row := []string{j.Candidate.PrettyString(), fmt.Sprintf("%d", j.Power), fmt.Sprintf("%d", approvals), j.ExpiresAt.String()}
		rows = append(rows, row)
	}

	// could be ideal to use the SQL table formatting here
	msg.WriteString(fmt.Sprintf("Pending join requests (%d %s needed):\n", needed, approvalTerm))

	bts, err := display.FormatTable(r.cmd, []string{"Candidate", "Power", "Approvals", "Expiration"}, rows)
	if err != nil {
		return nil, err
	}
	msg.Write(bts)

	return msg.Bytes(), nil
}
