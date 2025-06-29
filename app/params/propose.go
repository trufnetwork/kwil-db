package params

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/consensus"
)

var (
	proposeLong = `Submit a proposal to update the consensus parameters.`

	proposeExample = `...`
)

func proposeUpdatesCmd() *cobra.Command {
	var description, updatesJSON string
	var yes bool

	cmd := &cobra.Command{
		Use:     "propose",
		Short:   "Submit a migration proposal.",
		Long:    proposeLong,
		Example: proposeExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			if description == "" {
				return display.PrintErr(cmd, errors.New("description must not be empty"))
			}

			var updates types.ParamUpdates
			err = json.Unmarshal([]byte(updatesJSON), &updates)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("bad updates json: %w", err))
			}
			if err = types.ValidateUpdates(updates); err != nil {
				return display.PrintErr(cmd, fmt.Errorf("invalid updates: %w", err))
			}

			proposal := consensus.ParamUpdatesDeclaration{
				Description:  description,
				ParamUpdates: updates,
			}

			if !yes {
				if err = promptConfirmUpdatesProposal(proposal); err != nil {
					return display.PrintErr(cmd, err)
				}
			}

			proposalBts, err := proposal.MarshalBinary()
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			txHash, err := clt.CreateResolution(ctx, proposalBts, consensus.ParamUpdatesResolutionType)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			id := types.VotableEventID(consensus.ParamUpdatesResolutionType, proposalBts)

			return display.PrintCmd(cmd, &display.RespResolutionBroadcast{
				TxHash: txHash,
				ID:     id,
			})

		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt.")
	cmd.Flags().StringVarP(&description, "description", "d", "", "Description of the consensus parameter update proposal.")
	cmd.Flags().StringVarP(&updatesJSON, "updates", "u", "{}", "Parameter updates in JSON format.")

	return cmd
}

func promptConfirmUpdatesProposal(proposal consensus.ParamUpdatesDeclaration) error {
	fmt.Println("Please review the following proposal:")
	fmt.Println()
	fmt.Println("Description:", proposal.Description)
	fmt.Println()
	fmt.Println("Updates:", proposal.ParamUpdates.String())
	fmt.Println()

	if promptYesNo("Do you want to submit this proposal?") {
		return nil
	}

	return errors.New("user declined to submit proposal")
}

func promptYesNo(question string) bool {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%s (y/n): ", question)
		if scanner.Scan() {
			input := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if input == "y" || input == "yes" {
				return true
			} else if input == "n" || input == "no" {
				return false
			} else {
				fmt.Println("Invalid input. Please enter 'y' or 'n'.")
			}
		} else {
			// Handle EOF or input error
			fmt.Println("Error reading input. Please try again.")
		}
	}
}
