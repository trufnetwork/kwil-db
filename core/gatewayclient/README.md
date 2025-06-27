# Kwil Gateway(KGW) Go Client

This package provides a Go client for interacting with a Kwil Gateway(KGW).

The major feature this client provides compared to `core/client` is cookie-based
authentication for data privacy concerned read requests. It'll automatically
try to authenticate with the gateway if the gateway requires it.

This package is used by the `kwil-cli ` to interact with the Kwil Gateway, mainly
the `kwil-cli database call` subcommand. When you specify `--authenticate` flag,
`kwil-cli database call` will use this gateway client to make the request.

## Usage

### Get familiar with `core/client`

Read the `core/client` [README](../client/README.md) to get familiar with the
basic functionalities of the client. The `core/gatewayclient` package is built
on top of `core/client`, so you can use all the functionalities provided by `core/client`.

### Create a Kwil Gateway Client

To use this client, you need to create a new client with the `NewClient` function
from `github.com/trufnetwork/kwil-db/core/gatewayclient` package.

```go
clt, err := gatewayclient.NewClient(ctx, kgwProvider, &gatewayclient.GatewayOptions{
    Options: clientType.Options{
        Signer: &auth.EthPersonalSigner{Key: *pk},
    },
    AuthSignFunc: nil,
})

```

### Options

`GatewayOptions` is a struct that embeds `github.com/trufnetwork/kwil-db/core/types/client.Options`.

It also has two other optional fields:
- `AuthSignFunc`, allows you to provide a custom signing function for authentication, you can use it to do extra logic when the message is signed.
  If not provided, the client will use the default function which just call `signer.Sign([]byte(message))`.
- `AuthCookieHandler`, allows you to do extra logic when the cookie jar tries to save cookie.

An example using those options in `kwil-cli`:
- `Options`, see [core/client](../client/README.md) for more details.
- `AuthSignFunc`, to prompt the user to sign the message
- `AuthCookieHandler`, to save the cookie to a file every time the client receives a cookie.

```go
// cmd/kwil-cli/client/roundtripper.go L66

client, err := gatewayclient.NewClient(ctx, conf.Provider, &gatewayclient.GatewayOptions{
    Options: clientConfig,
    AuthSignFunc: func(message string, signer auth.Signer) (*auth.Signature, error) {
        assumeYes, err := GetAssumeYesFlag(cmd)
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
        return SaveCookie(KGWAuthTokenFilePath(), providerDomain, clientConfig.Signer.Identity(), c)
    },
})
```