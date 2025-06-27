package utils

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	cTypes "github.com/trufnetwork/kwil-db/core/client/types"
)

var (
	chainInfoLong = `Display information about the connected Kwil network.`
)

func chainInfoCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "chain-info",
		Short: chainInfoLong,
		Long:  chainInfoLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return client.DialClient(cmd.Context(), cmd, client.WithoutPrivateKey, func(ctx context.Context, client1 cTypes.Client, cfg *config.KwilCliConfig) error {
				chainInfo, err := client1.ChainInfo(ctx)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				return display.PrintCmd(cmd, &respChainInfo{Info: chainInfo})
			})
		},
	}

	return cmd
}
