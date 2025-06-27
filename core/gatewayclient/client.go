// package gatewayclient implements a client for kwild that can also authenticate
// with a kwil gateway.
package gatewayclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/trufnetwork/kwil-db/core/client"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	userClient "github.com/trufnetwork/kwil-db/core/rpc/client/chain/jsonrpc"
	"github.com/trufnetwork/kwil-db/core/rpc/client/gateway"
	gwClient "github.com/trufnetwork/kwil-db/core/rpc/client/gateway/jsonrpc"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	"github.com/trufnetwork/kwil-db/core/types"
)

// GatewayClient is a client that is made to interact with a kwil gateway.
// It inherits the functionality of the main Kwil client, but also provides
// authentication cookies to the gateway.
// It automatically handles the authentication process with the gateway.
type GatewayClient struct {
	client.Client // core client

	target *url.URL

	conn          *http.Client // the "connection"
	gatewayClient gateway.Client

	gatewaySigner GatewayAuthSignFunc // a hook for when the gateway authentication is needed

	authCookie *http.Cookie // might need a mutex
}

var _ clientType.Client = (*GatewayClient)(nil)

// customAuthCookieJar implements the http.CookieJar interface used by an
// http.Client. It uses a net/http/cookiejar.Jar to manage retrieval and
// expiration of cookies for the http.Client requests, and a provided function
// that is called when SetCookies receives a cookie with Name set to
// kgwAuthCookieName ("kgw_session"). This function can be anything, from
// storing the cookie in a struct field or writing it to disk.
type customAuthCookieJar struct {
	jar              *cookiejar.Jar
	handleAuthCookie func(c *http.Cookie) error
}

var _ http.CookieJar = (*customAuthCookieJar)(nil)

func (acj *customAuthCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	acj.jar.SetCookies(u, cookies)
	if acj.handleAuthCookie == nil {
		return
	}
	for _, c := range cookies {
		if c.Name == kgwAuthCookieName || c.Name == kgwAuthCookieNameSecure {
			acj.handleAuthCookie(c)
		}
	}
}

func (acj *customAuthCookieJar) Cookies(u *url.URL) []*http.Cookie {
	return acj.jar.Cookies(u)
}

// NewClient creates a new gateway client. The target should be the root URL of
// the gateway. It uses core/client as the underlying client to interact with
// the gateway for kwil-db specific jsonrpc requests, core/rpc/client/gateway/jsonrpc
// for gateway specific jsonrpc requests, and sharing the same http connection.
// See GatewayOptions for options that can be set.
func NewClient(ctx context.Context, target string, opts *GatewayOptions) (*GatewayClient, error) {
	options := DefaultOptions()
	options.Apply(opts)

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	persistJar := &customAuthCookieJar{jar: cookieJar}

	httpConn := &http.Client{
		Jar: persistJar,
	}

	parsedTarget, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}

	jsonrpcClientOpts := []rpcclient.RPCClientOpts{
		// so txClient and gatewayClient can share the connection
		rpcclient.WithHTTPClient(httpConn),
	}

	if options != nil {
		jsonrpcClientOpts = append(jsonrpcClientOpts,
			rpcclient.WithLogger(options.Logger),
		)
	}

	txClient := userClient.NewClient(parsedTarget, jsonrpcClientOpts...)
	userClient, err := client.WrapClient(ctx, txClient, &options.Options)
	if err != nil {
		return nil, fmt.Errorf("wrap client: %w", err)
	}

	gatewayClient, err := gwClient.NewClient(parsedTarget,
		// reuse the same http connection
		gateway.WithJSONRPCClient(txClient.JSONRPCClient),
	)
	if err != nil {
		return nil, fmt.Errorf("create gateway rpc client: %w", err)
	}

	g := &GatewayClient{
		Client:        *userClient,
		conn:          httpConn,
		gatewaySigner: options.AuthSignFunc,
		gatewayClient: gatewayClient,
		target:        parsedTarget,
	}

	optAuthCookieHandler := options.AuthCookieHandler
	persistJar.handleAuthCookie = func(c *http.Cookie) error {
		g.authCookie = c

		if optAuthCookieHandler == nil {
			return nil
		}
		return optAuthCookieHandler(c)
	}

	return g, nil
}

// Call call an action. It returns the result records.  If authentication is needed,
// it will call the gatewaySigner to sign the authentication message.
func (c *GatewayClient) Call(ctx context.Context, namespace string, action string, inputs []any) (*types.CallResult, error) {
	// we will try to call with the current cookies set.  If we receive an error and it is an auth error,
	// we will re-auth and retry.  We will only retry once.
	res, err := c.Client.Call(ctx, namespace, action, inputs)
	if err == nil {
		return res, nil
	}

	var jsonRPCErr *jsonrpc.Error
	if errors.As(err, &jsonRPCErr) {
		if jsonRPCErr.Code != jsonrpc.ErrorKGWNotAuthorized {
			return nil, err
		}
	}

	// we need to authenticate
	err = c.authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("authenticate error: %w", err)
	}

	// retry the call
	return c.Client.Call(ctx, namespace, action, inputs)
}

// authenticate authenticates the client with the gateway.
func (c *GatewayClient) authenticate(ctx context.Context) error {
	authParam, err := c.gatewayClient.GetAuthnParameter(ctx)
	if err != nil {
		if errors.Is(err, rpcclient.ErrNotFound) {
			return fmt.Errorf("failed to get auth parameter. are you sure you're talking to a gateway? err: %w", err)
		}
		return fmt.Errorf("get authn parameter: %w", err)
	}

	// remove trailing slash, avoid the confusing case like "http://example.com/" != "http://example.com"
	// This is also done in the kgw, https://github.com/trufnetwork/kgw/pull/42
	// With switching to JSON rpc in KGW, the domain should not include the path.
	targetDomain := c.target.Scheme + "://" + c.target.Host
	// backward compatibility if the Domain is not returned by the gateway
	// Those fields are returned from kgw in https://github.com/trufnetwork/kgw/pull/40
	if authParam.Domain != "" && authParam.Domain != targetDomain {
		return fmt.Errorf("domain mismatch: configured '%s' != remote %s",
			targetDomain, authParam.Domain)
	}

	if authParam.ChainID != "" && authParam.ChainID != c.Client.ChainID() {
		return fmt.Errorf("chain ID mismatch: configured '%s' !=  remote '%s'",
			c.Client.ChainID(), authParam.ChainID)
	}

	if authParam.Version != "" && authParam.Version != kgwAuthVersion {
		return fmt.Errorf("authn version mismatch: configured '%s' != remote '%s'",
			kgwAuthVersion, authParam.Version)
	}

	// as we've already checked the domain, URI won't surprise us; we can just
	// use what KGW returned
	msg := composeGatewayAuthMessage(authParam, targetDomain, authParam.URI, kgwAuthVersion, c.Client.ChainID())

	if c.Signer() == nil {
		return fmt.Errorf("cannot authenticate to gateway without a signer")
	}
	sig, err := c.gatewaySigner(msg, c.Signer())
	if err != nil {
		return fmt.Errorf("sign message: %w", err)
	}

	// send the auth request
	err = c.gatewayClient.Authn(ctx, &gateway.AuthnRequest{
		Nonce:     authParam.Nonce,
		Sender:    c.Signer().CompactID(),
		Signature: sig,
	})
	if err != nil {
		return fmt.Errorf("gateway authn: %w", err)
	}

	return nil
}

// GetAuthCookie returns the authentication cookie currently being used.
// If no authentication cookie is being used, it returns nil, false.
func (c *GatewayClient) GetAuthCookie() (cookie *http.Cookie, found bool) {
	return c.authCookie, c.authCookie != nil
}

// SetAuthCookie sets the authentication cookie to be used.
// If the cookie is not valid for the client target, it returns an error.
// It will overwrite any existing authentication cookie.
func (c *GatewayClient) SetAuthCookie(cookie *http.Cookie) error {
	// ref https://stackoverflow.com/a/16328399.
	// KGW already set the cookie domain without port in
	// https://github.com/trufnetwork/kgw/pull/18/files#diff-5b365c916e8b28d0115f136435a03daa1ef6df8cf0eb49479c556923545b56c7R60
	targetDomain := strings.Split(c.target.Host, ":")[0]
	if cookie.Domain != "" && cookie.Domain != targetDomain {
		return fmt.Errorf("cookie domain %s not valid for host %s", cookie.Domain, c.target.Host)
	}
	if cookie.Name != kgwAuthCookieName && cookie.Name != kgwAuthCookieNameSecure {
		return fmt.Errorf("cookie name %s not valid", cookie.Name)
	}

	c.conn.Jar.SetCookies(c.target, []*http.Cookie{cookie})

	c.authCookie = cookie

	return nil
}

// Authenticate will authenticate the client with the gateway.
// This is not necessary, as the client will automatically authenticate when needed,
// however it can be useful if the client desires to control when the authentication
// occurs / wants to manually force re-authentication.
func (c *GatewayClient) Authenticate(ctx context.Context) error {
	return c.authenticate(ctx)
}
