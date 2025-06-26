// package jsonrpc implements a JSON-RPC client for the Kwil gateway service.

package jsonrpc

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/rpc/client/gateway"
)

// Client is a JSON-RPC client for the Kwil gateway service. It use the
// JSONRPCClient from the rpcclient package for the actual JSON-RPC communication,
// and implements gateway service methods.
type Client struct {
	*rpcclient.JSONRPCClient

	conn *http.Client
}

// NewClient creates a new gateway json rpc client, target should be the base URL
// of the gateway server, and should not include "/rpc/v1" as that is appended
// automatically. If the client does not have a cookie jar, an error is returned.
func NewClient(target *url.URL, opts ...gateway.ClientOption) (*Client, error) {
	c := gateway.DefaultClientOptions()
	c.JSONRPCClient = rpcclient.NewJSONRPCClient(target)
	for _, o := range opts {
		o(c)
	}

	g := &Client{
		conn:          c.Conn,
		JSONRPCClient: c.JSONRPCClient,
	}

	// if the caller passed a custom http client without a cookie jar, return an error
	if g.conn.Jar == nil {
		return nil, errors.New("gateway http client must have a cookie jar")
	}

	return g, nil
}

var _ gateway.Client = (*Client)(nil)

// Authn authenticates the client with the gateway.
// It sets the returned cookie in the client's cookie jar.
func (g *Client) Authn(ctx context.Context, auth *gateway.AuthnRequest) error {
	res := &gateway.AuthnResponse{}
	err := g.CallMethod(ctx, string(gateway.MethodAuthn), auth, res)
	return err
}

// GetAuthnParameter returns the auth parameter for the client.
func (g *Client) GetAuthnParameter(ctx context.Context) (*gateway.AuthnParameterResponse, error) {
	res := &gateway.AuthnParameterResponse{}
	err := g.CallMethod(ctx, string(gateway.MethodAuthnParam), &gateway.AuthnParameterRequest{}, res)
	return res, err
}
