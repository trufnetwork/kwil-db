package validator

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"
)

var (
	promoteExample = `# Promote a new leader starting from block height 1000
kwild validators promote 02c57268fc884fa88425c7e5c19d3af263d1c64dd8b8f3f8c0fb31bb622d1fdab8#secp256k1 1000`

	promoteLong = `This command promotes a new leader starting from the specified block height. If the majority of validators agree, the new leader will be promoted from the given height. It is crucial for the validator being promoted to also promote themselves, otherwise, they will not propose a block when required. The specified height must not be an already committed block height, or the command will be rejected. This command will create or update the leader-updates.json file in the node's root directory, and when these updates are applied by the node at the specified height, the file will be deleted.`
)

func promoteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "replace-leader <candidate> <height>",
		Short:   "Promote a validator to leader starting from the specified height.",
		Long:    promoteLong,
		Example: promoteExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			pubKey, keyType, err := config.DecodePubKeyAndType(args[0])
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			height, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			err = clt.Promote(ctx, pubKey, keyType, height)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, promoteStatus{
				Height: height,
				PubKey: args[0],
			})
		},
	}

	return cmd
}

type promoteStatus struct {
	Height int64  `json:"height"`
	PubKey string `json:"pubkey"`
}

func (ps promoteStatus) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("Node will start accepting proposals from %s from height %d.\nThe new leader and majority of the validators must run this command for the leader replacement to be successful.", ps.PubKey, ps.Height)), nil
}

func (ps promoteStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Height int64  `json:"height"`
		PubKey string `json:"pubkey"`
	}{
		Height: ps.Height,
		PubKey: ps.PubKey,
	})
}
