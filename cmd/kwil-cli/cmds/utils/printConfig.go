package utils

import (
	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
)

func printConfigCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "print-config",
		Short: "Print the current CLI configuration.",
		Long:  "Print the current CLI configuration.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.ActiveConfig()
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, &respKwilCliConfig{cfg: cfg})
		},
	}

	return cmd
}
