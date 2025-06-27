package params

import (
	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
)

var consensusCmd = &cobra.Command{
	Use:   "consensus",
	Short: "Functions for dealing with consensus update proposals",
	Long:  "The consensus command provides functions for dealing with consensus update proposals.",
}

func NewConsensusCmd() *cobra.Command {
	consensusCmd.AddCommand(
		proposeUpdatesCmd(),
		listUpdateProposalsCmd(),
		approveUpdateProposalCmd(),
		showUpdateProposalCmd(),
		showConsensusParams(),
	)

	rpc.BindRPCFlags(consensusCmd)
	return consensusCmd
}
