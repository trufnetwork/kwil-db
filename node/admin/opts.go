package adminclient

import (
	"github.com/trufnetwork/kwil-db/core/log"
)

type Opt func(*AdminClient)

// WithLogger sets the logger for the admin client.
func WithLogger(logger log.Logger) Opt {
	return func(c *AdminClient) {
		c.log = logger
	}
}

// WithPass specifies a password to use, if password authentication is enable on
// the server.
func WithPass(pass string) Opt {
	return func(c *AdminClient) {
		c.pass = pass
	}
}

// WithTLS provides the required files for the admin client to use TLS, and
// possibly client authenticated TLS. kwildCertFile may be omitted if the
// service is issued a TLS certificate by a root CA. The client files may be
// omitted if not using TLS for client authentication, only for transport
// encryption and server authentication. The server must be configured
// appropriately.
func WithTLS(kwildCertFile, clientKeyFile, clientCertFile string) Opt {
	return func(c *AdminClient) {
		c.kwildCertFile = kwildCertFile
		c.clientKeyFile = clientKeyFile
		c.clientCertFile = clientCertFile
	}
}
