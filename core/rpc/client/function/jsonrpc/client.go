// package jsonrpc implements a JSON-RPC client for the Kwil function service.

package jsonrpc

import (
	"context"
	"fmt"
	"net/url"

	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/rpc/client/function"
	jsonFunction "github.com/trufnetwork/kwil-db/core/rpc/json/function"
)

// Client is a JSON-RPC client for the Kwil function service. It uses the
// JSONRPCClient from the rpcclient package for the actual JSON-RPC communication,
// and implements function service methods.
type Client struct {
	*rpcclient.JSONRPCClient
}

// NewClient creates a new json rpc client, target should be the base URL
// of the provider server, and should not include "/rpc/v1" as that is appended
// automatically.
// NOTE: No error will be returned.
func NewClient(target *url.URL, opts ...rpcclient.RPCClientOpts) *Client {
	g := &Client{
		JSONRPCClient: rpcclient.NewJSONRPCClient(target, opts...),
	}

	return g
}

var _ function.FunctionServiceClient = (*Client)(nil)

func (c *Client) VerifySignature(ctx context.Context, sender []byte, signature *auth.Signature, message []byte) error {
	result := &jsonFunction.VerifySignatureResponse{}
	err := c.CallMethod(ctx, string(jsonFunction.MethodVerifySig), &jsonFunction.VerifySignatureRequest{
		Sender: sender,
		Msg:    message,
		Signature: &jsonFunction.TxSignature{
			SignatureBytes: signature.Data,
			SignatureType:  signature.Type,
		},
	}, result)

	if err != nil { // protocol/communication level error
		return err
	}

	if result.Reason != "" {
		return fmt.Errorf("%w: %s", function.ErrInvalidSignature, result.Reason)
	}

	// NOTE: Forget why I put both `valid` and `error` in the response.
	// if `valid` is false, `error` should not be empty.
	// This might be not needed, but I just keep it here.
	if !result.Valid {
		return function.ErrInvalidSignature
	}

	return nil
}
