package utils

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/gatewayclient"
)

var authCmdDesc = `Authenticate with a Kwil Gateway using a private key.

The ` + `"` + `authenticate` + `"` + ` command will prompt you to sign a challenge from the Kwil Gateway. It
will store the returned auth cookie in ` + `"` + `~/.kwil-cli/auth` + `"` + ` for future use.

The Kwil CLI automatically handles authentication and re-authentication, however this tool
can be used to manually authenticate to a Kwil Gateway.
`

var authCmdExample = `# Authenticate to a Kwil Gateway

kwil-cli utils authenticate`

// kgwAuthnCmd is the command to authenticate to a KGW provider.
// This is not part of Kwil API.
func kgwAuthnCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "authenticate",
		Short:   "Authenticate with a Kwil Gateway using a private key.",
		Long:    authCmdDesc,
		Example: authCmdExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return client.DialClient(cmd.Context(), cmd, client.UsingGateway,
				func(ctx context.Context, client clientType.Client, cfg *config.KwilCliConfig) error {
					if cfg.PrivateKey == nil {
						return display.PrintErr(cmd, errors.New("private key not provided"))
					}

					gatewayClient, ok := client.(*gatewayclient.GatewayClient)
					if !ok {
						return display.PrintErr(cmd, errors.New("client is not a gateway client. this is an internal bug"))
					}

					err := gatewayClient.Authenticate(ctx)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("authentication failed: %w", err))
					}

					// we do not need to persist the cookie since DialClient will do that for us

					return display.PrintCmd(cmd, display.RespString("Success"))
				})
		},
	}

	return cmd
}
