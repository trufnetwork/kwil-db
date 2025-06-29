package migration

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
)

func networkStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Get the migration status of the network.",
		Example: `# Get the migration status of the network.
		kwild migrate status`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			status, err := clt.MigrationStatus(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &migrationStatus{
				Status:        status.Status,
				StartHeight:   status.StartHeight,
				EndHeight:     status.EndHeight,
				CurrentHeight: status.CurrentHeight,
			})
		},
	}
}

type migrationStatus struct {
	Status        types.MigrationStatus `json:"status"`
	StartHeight   int64                 `json:"start_height"`
	EndHeight     int64                 `json:"end_height"`
	CurrentHeight int64                 `json:"current_height"`
}

func (m *migrationStatus) MarshalJSON() ([]byte, error) {
	type alias migrationStatus
	return json.Marshal((*alias)(m)) // slice off methods to avoid recursive call
}

func (m *migrationStatus) MarshalText() ([]byte, error) {
	if m.Status.NoneActive() {
		if m.StartHeight == 0 && m.EndHeight == 0 {
			return []byte("No active migration on the network."), nil
		}
		return []byte("Genesis migration completed. No active migration on the network."), nil
	}

	if m.Status == types.GenesisMigration {
		return []byte("Genesis migration in progress."), nil
	}

	return []byte(fmt.Sprintf("Migration Status: %s\n"+
		"Start Height: %d\n"+
		"End Height: %d\n"+
		"Current Block: %d\n",
		m.Status, m.StartHeight, m.EndHeight, m.CurrentHeight)), nil
}
