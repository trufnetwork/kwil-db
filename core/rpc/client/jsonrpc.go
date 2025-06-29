// Package client provides some base Kwil rpc clients.
// JSONRPCClient is a JSON-RPC (API v1) client supports only HTTP POST, no
// WebSockets yet.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"sync/atomic"

	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
)

// JSONRPCClient will use the commands to make certain requests
//  - "params" field is set to the marshalled request structs
//  - the "method" in the outer request type is instead of the endpoint, all POST
//  - "id" is set to a counter's value
//	- "jsonrpc" set to "2.0"
//	- make http POST request with marshalled Request
//	- unmarshal response into Response
//	- if "error" field is set, the Error type is returned as Go error
//	- maybe compare "id" to expected ID from request
//	- unmarshal the "result" (json.RawMessage) into the method's result type

// note compared to http grpc gateway:
//
//  - the structs marshal into json objects, set in "params" field of request.
//    with the old http gateway, endpoints were defined with associated
//    message (pb) types sent in POST, or just GET with endpoint implying method.
//  - the "method" in the outer request type is instead of the endpoint, all POST

// JSONRPCClient is a JSON-RPC client that handles JSON RPC communication.
// It is a low-level client that does not care about the specifics of the
// JSON-RPC methods or responses.
type JSONRPCClient struct {
	conn *http.Client

	endpoint string
	log      log.Logger

	basicAuthHdr string

	reqID atomic.Uint64
}

// NewJSONRPCClient creates a new JSONRPCClient for a provider at a given base URL
// of an HTTP server where the "/rpc/v1" rooted. i.e. The URL should not include
// "/rpc/v1" as that is appended automatically.
func NewJSONRPCClient(url *url.URL, opts ...RPCClientOpts) *JSONRPCClient {
	// This client uses API v1 methods and request/response types.
	url = url.JoinPath("/rpc/v1")

	clientOpts := &clientOptions{
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
			},
		},
		log: log.DiscardLogger, // log.NewStdOut(log.InfoLevel),
	}
	for _, opt := range opts {
		opt(clientOpts)
	}

	var basicAuthHdr string
	if clientOpts.pass != "" { // user is ignored on server verification
		basicAuthHdr = "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+clientOpts.pass))
	}

	return &JSONRPCClient{
		endpoint:     url.String(),
		conn:         clientOpts.client,
		log:          clientOpts.log,
		basicAuthHdr: basicAuthHdr,
	}
}

type RPCClientOpts func(*clientOptions)

type clientOptions struct {
	client *http.Client
	log    log.Logger
	pass   string
}

func WithLogger(log log.Logger) RPCClientOpts {
	return func(c *clientOptions) {
		c.log = log
	}
}

func WithPass(pass string) RPCClientOpts {
	return func(c *clientOptions) {
		c.pass = pass
	}
}

func WithHTTPClient(client *http.Client) RPCClientOpts {
	return func(c *clientOptions) {
		c.client = client
	}
}

func (cl *JSONRPCClient) nextReqID() string {
	id := cl.reqID.Add(1)
	return strconv.FormatUint(id, 10)
}

// NOTE: make a BaseClient with CallMethod only.

// CallMethod makes a JSON-RPC request to the server. The method is the name of
// the method to call, cmd is the request parameter, and res is the response object.
// If the server returns a jsonrpc.Error, it's a business logic error.
func (cl *JSONRPCClient) CallMethod(ctx context.Context, method string, cmd, res any) error {
	// res needs to be a pointer otherwise we can't unmarshal into it.
	if rtp := reflect.TypeOf(res); rtp.Kind() != reflect.Ptr {
		return errors.New("result must be a pointer")
	}

	// Marshal the params.
	params, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	// Marshal the request.
	id := cl.nextReqID()
	req := jsonrpc.NewRequest(id, method, params)

	request, err := json.Marshal(req)
	if err != nil {
		return err
	}

	// Build and perform the http request.
	requestReader := bytes.NewReader(request)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cl.endpoint, requestReader)
	if err != nil {
		return fmt.Errorf("failed to construct new http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if cl.basicAuthHdr != "" {
		httpReq.Header.Set("Authorization", cl.basicAuthHdr) // httpReq.SetBasicAuth("user", cl.pass)
	}

	httpResponse, err := cl.conn.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http post failed: %w", err)
	}
	defer httpResponse.Body.Close()

	// For the most part we ignore the http status code in favor of structured
	// errors in the response, but in case we cannot decode any response body,
	// get an error based on the http status code.
	var httpErr error
	switch status := httpResponse.StatusCode; status {
	case http.StatusOK: // expected with nil resp.Error
	case http.StatusUnauthorized:
		httpErr = ErrUnauthorized
	case http.StatusNotFound:
		httpErr = ErrNotFound
	case http.StatusInternalServerError:
		httpErr = errors.New("server error")
	default:
		if status >= 400 {
			httpErr = errors.New(http.StatusText(status))
		}
	}

	resp := &jsonrpc.Response{}
	err = json.NewDecoder(httpResponse.Body).Decode(resp)
	if err != nil {
		if httpErr != nil {
			return httpErr
		}
		return fmt.Errorf("failed to decode response: %w", errors.Join(err, httpErr))
	}

	if resp.Error != nil {
		return clientError(resp.Error)
	} // any not OK http status code should have

	if resp.JSONRPC != "2.0" { // indicates response body was not a jsonrpc.Response but didn't fail Decode
		if httpErr != nil {
			return httpErr
		}
		return fmt.Errorf("invalid JSON-RPC response")
	}

	// if resp.ID != id {
	// 	fmt.Printf("got id %v, expected %v\n", resp.ID, id)
	// } // who cares, this is http post

	if err = json.Unmarshal(resp.Result, res); err != nil {
		return fmt.Errorf("failed to decode result as response: %w", errors.Join(err, httpErr))
	}

	return nil
}

// clientError joins a jsonrpc.Error with a client.RPCError and any appropriate
// named error kind like ErrNotFound, ErrUnauthorized, etc. based on the code.
func clientError(jsonRPCErr *jsonrpc.Error) error {
	rpcErr := &RPCError{ // @Jon, should we change this to RPCError instead of *RPCError ?
		Msg:  jsonRPCErr.Message,
		Code: int32(jsonRPCErr.Code),
	}
	err := errors.Join(jsonRPCErr, rpcErr)

	switch jsonRPCErr.Code {
	case jsonrpc.ErrorEngineDatasetNotFound, jsonrpc.ErrorTxNotFound, jsonrpc.ErrorValidatorNotFound,
		jsonrpc.ErrorBlkNotFound:
		return errors.Join(ErrNotFound, err)
	case jsonrpc.ErrorUnknownMethod:
		return errors.Join(ErrMethodNotFound, err)
	// case jsonrpc.ErrorUnauthorized: // not yet used on server
	// 	return errors.Join(client.ErrUnauthorized, err)
	// case jsonrpc.ErrorInvalidSignature: // or leave this to core/client.Client to detect and report
	// 	return errors.Join(client.ErrInvalidSignature, err)
	default:
	}

	return err
}
