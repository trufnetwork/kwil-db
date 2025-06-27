package params

import (
	"bytes"
	"encoding/json"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
)

func listUpdateProposalsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list-proposals",
		Short:   "List all the pending consensus update proposals.",
		Long:    "List all the pending migration proposals.",
		Example: ``,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			updateProps, err := clt.ListUpdateProposals(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &UpdateProposals{updateProps: updateProps})
		},
	}

	return cmd
}

type UpdateProposals struct {
	updateProps []*types.ConsensusParamUpdateProposal
}

func (up UpdateProposals) MarshalJSON() ([]byte, error) {
	return json.Marshal(up.updateProps)
}

func (up *UpdateProposals) MarshalText() ([]byte, error) {
	if len(up.updateProps) == 0 {
		return []byte("No consensus update proposals found."), nil
	}

	var msg bytes.Buffer
	msg.WriteString("Update proposals:\n")

	for _, prop := range up.updateProps {
		msg.WriteString("\tID: " + prop.ID.String())
		msg.WriteString("\tDescription: " + prop.Description)
		msg.WriteString("\tParamUpdates: " + prop.Updates.String())
		msg.WriteString("\n")
	}
	return msg.Bytes(), nil
}
