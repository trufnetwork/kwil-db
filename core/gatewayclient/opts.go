package gatewayclient

import (
	"net/http"

	clientType "github.com/trufnetwork/kwil-db/core/client/types"
)

// GatewayOptions are options that can be set for the gateway client
type GatewayOptions struct {
	clientType.Options

	// AuthSignFunc is a function that will be used to sign gateway
	// authentication messages. By default, it's set to just sign the message
	// using the client's signer.
	AuthSignFunc GatewayAuthSignFunc

	// AuthCookieHandler is a function that will be called whenever a cookie is
	// being set to cookie jar. No default is set.
	AuthCookieHandler func(*http.Cookie) error
}

// DefaultOptions returns the default options for the gateway client.
func DefaultOptions() *GatewayOptions {
	return &GatewayOptions{
		Options:      *clientType.DefaultOptions(),
		AuthSignFunc: defaultGatewayAuthSignFunc,
	}
}

// Apply applies the passed options to the receiver.
func (c *GatewayOptions) Apply(opt *GatewayOptions) {
	if opt == nil {
		return
	}

	c.Options.Apply(&opt.Options)

	if opt.AuthSignFunc != nil {
		c.AuthSignFunc = opt.AuthSignFunc
	}
	if opt.AuthCookieHandler != nil {
		c.AuthCookieHandler = opt.AuthCookieHandler
	}
}
