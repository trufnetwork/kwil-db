package rpc

import (
	"context"
	"encoding/json"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"

	"github.com/spf13/cobra"
)

var (
	dumpCfgLong    = "The `dump-config` command retrieves and displays the active config from the running node."
	dumpCfgExample = `# Get the current config from the node.
kwild admin dump-config --rpcserver /tmp/kwild.socket`
)

func dumpCfgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "dump-config",
		Short:   "Get and display the current config from the node.",
		Long:    dumpCfgLong,
		Example: dumpCfgExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := context.Background()
			client, err := AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			bts, err := client.GetConfig(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			var cfg config.Config
			err = cfg.FromTOML(bts)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &cfgMsg{toml: bts, cfg: &cfg})
		},
	}

	BindRPCFlags(cmd)

	return cmd
}

type cfgMsg struct {
	toml []byte
	cfg  *config.Config
}

var _ display.MsgFormatter = (*cfgMsg)(nil)

func (c *cfgMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		OK   bool   `json:"ok"`
		TOML string `json:"toml"`
	}{
		OK:   true,
		TOML: string(c.toml),
	})
}

func (c *cfgMsg) MarshalText() ([]byte, error) {
	return c.cfg.ToTOML()
}
