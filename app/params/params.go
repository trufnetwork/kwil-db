package params

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
)

func showConsensusParams() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "params",
		Short:   "Show active consensus parameters.",
		Long:    "Show active consensus parameters.",
		Example: ``,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			params, err := clt.ConsensusParams(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &msgConsensusParams{params: params})
		},
	}

	return cmd
}

type msgConsensusParams struct {
	params *types.NetworkParameters
}

func (cp msgConsensusParams) MarshalJSON() ([]byte, error) {
	return json.MarshalIndent(cp.params, "", "    ")
}

func (cp msgConsensusParams) MarshalText() ([]byte, error) {
	return []byte(cp.params.String()), nil
}
