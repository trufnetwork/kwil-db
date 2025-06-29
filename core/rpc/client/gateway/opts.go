package gateway

import (
	"net/http"
	"net/http/cookiejar"

	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
)

type ClientOption func(*clientOptions)

// WithHTTPClient sets the http client for the client.
// This allows custom http clients to be used.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *clientOptions) {
		c.Conn = client
	}
}

// WithJSONRPCClient sets the jsonrpc client for the client.
// This allows custom user clients to be used.
func WithJSONRPCClient(userClient *rpcclient.JSONRPCClient) ClientOption {
	return func(c *clientOptions) {
		c.JSONRPCClient = userClient
	}
}

type clientOptions struct {
	Conn          *http.Client
	JSONRPCClient *rpcclient.JSONRPCClient
}

// DefaultClientOptions returns the default client options, which ensure the
// connection has a cookie jar.
func DefaultClientOptions() *clientOptions {
	jar, _ := cookiejar.New(nil)
	return &clientOptions{
		Conn: &http.Client{
			Jar: jar,
		},
	}
}
