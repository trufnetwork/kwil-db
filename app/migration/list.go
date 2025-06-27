package migration

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
)

func listCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proposals",
		Short: "List all the pending migration proposals.",
		Long:  "List all the pending migration proposals.",
		Example: `# List all the pending migration proposals.
kwild migrate proposals`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			migrations, err := clt.ListMigrations(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &MigrationsList{migrations: migrations})
		},
	}

	return cmd
}

type MigrationsList struct {
	migrations []*types.Migration
}

func (m *MigrationsList) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.migrations)
}

func (m *MigrationsList) MarshalText() ([]byte, error) {
	if len(m.migrations) == 0 {
		return []byte("No migrations found."), nil
	}

	var msg bytes.Buffer
	msg.WriteString("Migrations:\n")

	for _, migration := range m.migrations {
		msg.WriteString(fmt.Sprintf("%s:\n", migration.ID))
		msg.WriteString(fmt.Sprintf("\tactivationPeriod: %d\n", migration.ActivationPeriod))
		msg.WriteString(fmt.Sprintf("\tmigrationDuration: %d\n", migration.Duration))
		msg.WriteString(fmt.Sprintf("\ttimestamp: %s\n", migration.Timestamp))
	}
	return msg.Bytes(), nil
}
