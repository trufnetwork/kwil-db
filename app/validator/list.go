package validator

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
)

var (
	listLong = `List the current validator set of the network.`

	listExample = `# List the current validator set of the network
kwild validators list`
)

func listCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",                      // validators list
		Aliases: []string{"list-validators"}, // validators list-validators
		Short:   "List the current validator set of the network.",
		Long:    listLong,
		Example: listExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			data, err := clt.ListValidators(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &respValSets{Data: data, cmd: cmd})
		},
	}

	display.BindTableFlags(cmd)
	return cmd
}

// respValSets represent current validator set in cli
type respValSets struct {
	Data []*types.Validator
	cmd  *cobra.Command
}

type valInfo struct {
	PubKey     string `json:"pubkey"`
	PubKeyType string `json:"pubkey_type"`
	Power      int64  `json:"power"`
}

func (r *respValSets) MarshalJSON() ([]byte, error) {
	valInfos := make([]*valInfo, len(r.Data))
	for i, v := range r.Data {
		valInfos[i] = &valInfo{
			PubKey:     v.Identifier.String(),
			Power:      v.Power,
			PubKeyType: v.KeyType.String(),
		}
	}

	return json.Marshal(valInfos)
}

func (r *respValSets) MarshalText() ([]byte, error) {
	var rows [][]string
	for _, v := range r.Data {
		row := []string{
			v.PrettyString(),
			strconv.FormatInt(v.Power, 10),
		}
		rows = append(rows, row)
	}

	return display.FormatTable(r.cmd, []string{"Identifier", "Power"}, rows)
}
