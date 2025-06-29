package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers"
	"github.com/trufnetwork/kwil-db/core/client"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/gatewayclient"
)

// These are bit flags used signal certain client features.
// TODO: replace this with the options themselves.
const (
	// WithoutPrivateKey is a flag that can be passed to DialClient to indicate
	// that the client does not require the private key for signing. If set in
	// the config, the private key will still be loaded to set the call message
	// sender and to infer owner in database call commands.
	WithoutPrivateKey uint8 = 1 << iota

	// UsingGateway is a flag that can be passed to DialClient to indicate that the client is talking to a gateway.
	// Since very few commands use the gateway, we bind this to specific commands instead of making it a global flag.
	UsingGateway

	// AuthenticatedCalls indicates that call messages should include a
	// signature and a server-provided challenge if the client is talking to a
	// private kwild node.
	AuthenticatedCalls
)

type RoundTripper func(ctx context.Context, client clientType.Client, conf *config.KwilCliConfig) error

// DialClient dials a kwil node and calls the passed function with the client.
// It includes the command that is being run, so that it can read global flags.
func DialClient(ctx context.Context, cmd *cobra.Command, flags uint8, fn RoundTripper) error {
	conf, err := config.ActiveConfig()
	if err != nil {
		return err
	}

	if conf.Provider == "" {
		return errors.New("rpc provider url is required")
	}

	needPrivateKey := flags&WithoutPrivateKey == 0
	authCalls := flags&AuthenticatedCalls != 0

	clientConfig := clientType.DefaultOptions()
	if conf.PrivateKey != nil {
		clientConfig.Signer = &auth.EthPersonalSigner{Key: *conf.PrivateKey}
		if needPrivateKey { // only check chain ID if signing something
			clientConfig.ChainID = conf.ChainID
		}
	} else if needPrivateKey && !authCalls {
		// private key checks for call messages are done after creating the client
		// as this requires whether the Kwild node is in private mode or not.
		return errors.New("private key not provided")
	}

	// if not using the gateway, then we can simply create a regular client and return
	if flags&UsingGateway == 0 {
		client, err := client.NewClient(ctx, conf.Provider, clientConfig)
		if err != nil {
			return err
		}

		// if we are making authenticated calls, we need to ensure that the private key is provided
		// if the Kwild node is in private mode.
		if authCalls && client.PrivateMode() && conf.PrivateKey == nil {
			return errors.New("private key not provided for authenticated calls")
		}

		return fn(ctx, client, conf)
	}

	// if we reach here, we are talking to a gateway

	providerDomain, err := getDomain(conf.Provider)
	if err != nil {
		return err
	}

	// Assumption that the nodes behind the gateway are not in the private mode.
	client, err := gatewayclient.NewClient(ctx, conf.Provider, &gatewayclient.GatewayOptions{
		Options: *clientConfig,
		AuthSignFunc: func(message string, signer auth.Signer) (*auth.Signature, error) {
			assumeYes, err := helpers.GetAssumeYesFlag(cmd)
			if err != nil {
				return nil, err
			}

			if !assumeYes {
				err := promptMessage(message)
				if err != nil {
					return nil, err
				}
			}

			toSign := []byte(message)
			sig, err := signer.Sign(toSign)
			if err != nil {
				return nil, err
			}

			return sig, nil
		},
		AuthCookieHandler: func(c *http.Cookie) error {
			// persist the cookie
			return SaveCookie(KGWAuthTokenFilePath(), providerDomain, clientConfig.Signer.CompactID(), c)
		},
	})
	if err != nil {
		return err
	}

	if clientConfig.Signer == nil {
		return fn(ctx, client, conf)
	}

	cookie, err := LoadPersistedCookie(KGWAuthTokenFilePath(), providerDomain, clientConfig.Signer.CompactID())
	if err == nil && cookie != nil {
		// if setting fails, then don't do fail usage- failure likely means that the client has
		// switched providers, and the cookie is no longer valid.  The gatewayclient will re-authenticate.
		// delete the cookie if it is invalid
		err = client.SetAuthCookie(cookie)
		if err != nil {
			err2 := DeleteCookie(KGWAuthTokenFilePath(), providerDomain, clientConfig.Signer.CompactID())
			if err2 != nil {
				return fmt.Errorf("failed to delete cookie: %w", err2)
			}
		}
	}

	err = fn(ctx, client, conf)
	if err != nil {
		return err
	}

	// NOTE: if we set GatewayOptions.AuthCookieHandler, we would remove the
	// above client.GetAuthCookie and SaveCookie calls since it would be
	// automatic. Which do approach do we prefer?

	return nil
}

// promptMessage prompts the user to sign a message. Return an error if user
// declines to sign.
func promptMessage(msg string) error {
	// display the message to user
	fmt.Println(msg)

	prompt := promptui.Prompt{
		Label:     "Do you want to sign this message?",
		IsConfirm: true,
	}

	_, err := prompt.Run()
	if err != nil {
		return errors.New("you declined to sign")
	}

	return nil
}
