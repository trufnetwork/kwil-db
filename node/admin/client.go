// package adminclient provides a client for the Kwil admin service.
// The admin service is used to perform node administrative actions,
// such as submitting validator transactions, retrieving node status, etc.
package adminclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"time"

	"github.com/trufnetwork/kwil-db/core/log"
	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	adminRpc "github.com/trufnetwork/kwil-db/core/rpc/client/admin"
	adminjson "github.com/trufnetwork/kwil-db/core/rpc/client/admin/jsonrpc"
	"github.com/trufnetwork/kwil-db/core/rpc/transport"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/utils/url"
)

// AdminClient is a client for the Kwil admin service.
// It inherits both the admin and tx services.
type AdminClient struct {
	adminSvcClient

	log log.Logger

	pass string

	// optional TLS files
	kwildCertFile  string
	clientKeyFile  string
	clientCertFile string
}

// AdminSvcClient is the txsvc client interface.
// It allows us to selectively expose the txsvc client methods.
type adminSvcClient interface {
	adminRpc.AdminClient

	// The rest is a subset of the interface of core/client.Client.

	// Ping pings the connected node.
	Ping(ctx context.Context) (string, error)
	// TxQuery queries a transaction by hash.
	TxQuery(ctx context.Context, txHash types.Hash) (*types.TxQueryResponse, error)

	ListUpdateProposals(ctx context.Context) ([]*types.ConsensusParamUpdateProposal, error)

	ConsensusParams(ctx context.Context) (*types.NetworkParameters, error)

	// migration methods
	ListMigrations(ctx context.Context) ([]*types.Migration, error)
	MigrationStatus(ctx context.Context) (*types.MigrationState, error)
	GenesisState(ctx context.Context) (*types.MigrationMetadata, error)
	GenesisSnapshotChunk(ctx context.Context, height uint64, chunkIdx uint32) ([]byte, error)
	LoadChangeset(ctx context.Context, height int64, index int64) ([]byte, error)
	ChangesetMetadata(ctx context.Context, height int64) (int64, []int64, error)
}

// defaultTransport constructs a new http.Transport that is equivalent to the
// http.DefaultTransport, but a new instance.
func defaultTransport() *http.Transport {
	defaultDial := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           defaultDial.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

type dialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func prepareHTTPDialerURL(target string) (*neturl.URL, dialerFunc, error) {
	// Subtle way to default to either http or https, and to allow target to
	// include a scheme, including the pseudo-scheme "unix://".
	var parsedURL *neturl.URL
	{
		parsedTarget, err := url.ParseURLWithDefaultScheme(target, "http://")
		if err != nil {
			return nil, nil, err
		}
		parsedURL = parsedTarget.URL()
		// NOTE: for unix:// URLs, url.ParseURL... leaves Path empty and Host
		// set to the socket file path.
	}

	switch url.Scheme(parsedURL.Scheme) {
	case url.HTTP: // includes unix targets with no scheme like /var/run/kwild.socket
	case url.HTTPS:
		if parsedURL.Host == "" {
			return nil, nil, errors.New("https with a unix socket not allowed")
		}
	case url.UNIX:
		// reparse with http scheme to make a url we can use with http.Client requests
		parsedURL.Scheme = "http"
		parsedURL.Path, parsedURL.Host = parsedURL.Host, "" // make the unix dialer
		var err error
		parsedURL, err = neturl.Parse(parsedURL.String())
		if err != nil {
			return nil, nil, err
		}
		// Host should now be empty, with Path containing the socket path
	default:
		return nil, nil, fmt.Errorf("invalid scheme %q (must be http or https)", parsedURL.Scheme)
	}

	// For a unix socket, override the dialer. It dials the unix socket file
	// system path. The host in the URL is ignored; it is just a placeholder.
	var dialer dialerFunc
	if parsedURL.Host == "" {
		socketPath := parsedURL.Path
		parsedURL.Host, parsedURL.Path = "local.socket", "" // http://local.socket
		dialer = func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}
	} else if parsedURL.Port() == "" {
		// Taking this liberty for admin tool, which is unlikely to be exposed
		// with DNS and implied port 80/443.
		parsedURL.Host += ":8584"
	}

	return parsedURL, dialer, nil
}

// NewClient creates a new admin client . The target arg is usually either
// "127.0.0.1:8584" or "/path/to/socket.socket". The scheme http:// or https://
// may be included, to dictate if TLS is required or not. If no scheme is given,
// http:// is assumed. UNIX socket transport may not use TLS. The endpoint path
// is a separate argument to distinguish it from the UNIX socket file path.
//
// For example,
//
//	adminclient.NewClient(ctx, "/run/kwild.sock")
func NewClient(ctx context.Context, target string, opts ...Opt) (*AdminClient, error) {
	c := &AdminClient{
		log: log.DiscardLogger,
	}
	for _, opt := range opts {
		opt(c)
	}

	trans := defaultTransport() // http.DefaultTransport.(*http.Transport) // http.RoundTripper

	// Validate and standardize the URL, and make a dialer if a unix socket.
	targetURL, dialer, err := prepareHTTPDialerURL(target)
	if err != nil {
		return nil, fmt.Errorf("bad url: %w", err)
	}
	trans.DialContext = dialer // remains nil for non-unix

	// This http.Transport's TLS config does not mean it will use TLS. The
	// scheme dictates that. But append RootCAs and client Certificates if
	// config has them.
	tlsConfig := transport.DefaultClientTLSConfig()
	trans.TLSClientConfig = tlsConfig

	// Set RootCAs if we have a kwild cert file.
	if c.kwildCertFile != "" {
		pemCerts, err := os.ReadFile(c.kwildCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read cert file: %w", err)
		}
		if !tlsConfig.RootCAs.AppendCertsFromPEM(pemCerts) {
			return nil, errors.New("credentials: failed to append certificates")
		}
	}

	// Set Certificates for client authentication, if required
	if c.clientKeyFile != "" && c.clientCertFile != "" {
		authCert, err := tls.LoadX509KeyPair(c.clientCertFile, c.clientKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, authCert)
	}

	cl := adminjson.NewClient(targetURL,
		rpcclient.WithHTTPClient(&http.Client{
			Transport: trans,
		}),
		rpcclient.WithLogger(c.log),
		rpcclient.WithPass(c.pass),
	)
	c.adminSvcClient = cl

	return c, nil
}
