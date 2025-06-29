package validator

import (
	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
)

const validatorsLong = "The validators command provides functions for creating and broadcasting validator-related transactions (join/approve/leave), and retrieving information on the current validators and join requests."

func NewValidatorsCmd() *cobra.Command {
	validatorsCmd := &cobra.Command{
		Use:   "validators",
		Short: "Validator related actions",
		Long:  validatorsLong,
	}

	validatorsCmd.AddCommand(
		joinCmd(),
		joinStatusCmd(),
		listCmd(),
		approveCmd(),
		removeCmd(),
		leaveCmd(),
		listJoinRequestsCmd(),
		promoteCmd(),
	)

	rpc.BindRPCFlags(validatorsCmd)
	display.BindOutputFormatFlag(validatorsCmd)

	return validatorsCmd
}
