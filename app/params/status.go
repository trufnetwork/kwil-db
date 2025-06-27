package params

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/consensus"
)

func showUpdateProposalCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "update-status <proposal_id>",
		Short:   "Pending consensus update proposal status.",
		Long:    "Get the status of a pending consensus update proposal.",
		Example: ``,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			proposalID, err := types.ParseUUID(args[0])
			if err != nil {
				return display.PrintErr(cmd, err)
			}
			status, err := clt.ResolutionStatus(ctx, proposalID)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			if status.Type != consensus.ParamUpdatesResolutionType {
				return display.PrintErr(cmd, fmt.Errorf("proposal is not a consensus update proposal, is %v", status.Type))
			}

			updateProps, err := clt.ListUpdateProposals(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}
			propIdx := slices.IndexFunc(updateProps, func(p *types.ConsensusParamUpdateProposal) bool {
				return p.ID == *proposalID
			})
			if propIdx == -1 {
				return display.PrintErr(cmd, fmt.Errorf("proposal not found"))
			}
			prop := updateProps[propIdx]
			return display.PrintCmd(cmd, MsgUpdateResolutionStatus{
				ResStatus: MsgResolutionStatus{PendingResolution: *status, indent: "\t"},
				Proposal:  prop,
			})
		},
	}
}

type MsgUpdateResolutionStatus struct {
	ResStatus MsgResolutionStatus                 `json:"status"`
	Proposal  *types.ConsensusParamUpdateProposal `json:"proposal"`
}

func (urs MsgUpdateResolutionStatus) MarshalText() ([]byte, error) {
	rsStr, err := urs.ResStatus.MarshalText()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("Resolution Status:\n")
	buf.Write(rsStr)
	buf.WriteString("\nUpdate Proposal:\n")
	fmt.Fprintf(&buf, "\tID:         %s\n", urs.Proposal.ID)
	fmt.Fprintf(&buf, "\tDescription:   %s\n", urs.Proposal.Description)
	fmt.Fprintf(&buf, "\tUpdates: %s\n", urs.Proposal.Updates.String())

	return buf.Bytes(), nil
}

func (urs MsgUpdateResolutionStatus) MarshalJSON() ([]byte, error) {
	type alias MsgUpdateResolutionStatus
	return json.Marshal(alias(urs))
}

type MsgResolutionStatus struct {
	types.PendingResolution

	indent string
}

func (rs MsgResolutionStatus) MarshalText() ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%sID:         %s\n", rs.indent, rs.ResolutionID)
	fmt.Fprintf(&buf, "%sType:       %s\n", rs.indent, rs.Type)
	fmt.Fprintf(&buf, "%sExpiresAt:  %s\n", rs.indent, rs.ExpiresAt)
	fmt.Fprintf(&buf, "%sBoard:      %s\n", rs.indent, rs.Board)
	fmt.Fprintf(&buf, "%sApprovals:  %v\n", rs.indent, rs.Approved)
	return buf.Bytes(), nil
}

func (rs MsgResolutionStatus) MarshalJSON() ([]byte, error) {
	type alias MsgResolutionStatus
	return json.Marshal(alias(rs))
}
