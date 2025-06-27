package utils

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
)

func pingCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "ping",
		Short: "Ping the kwil provider endpoint.  If successful, returns 'pong'.",
		Long:  "Ping the kwil provider endpoint.  If successful, returns 'pong'.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return client.DialClient(cmd.Context(), cmd, client.WithoutPrivateKey,
				func(ctx context.Context, client clientType.Client, cfg *config.KwilCliConfig) error {
					res, err := client.Ping(ctx)
					if err != nil {
						return display.PrintErr(cmd, err)
					}

					return display.PrintCmd(cmd, display.RespString(res))
				},
			)
		},
	}

	return cmd
}
