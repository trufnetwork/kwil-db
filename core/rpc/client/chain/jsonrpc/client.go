package jsonrpc

import (
	"context"
	"net/url"

	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/rpc/client/chain"
	"github.com/trufnetwork/kwil-db/core/rpc/client/user"
	userClient "github.com/trufnetwork/kwil-db/core/rpc/client/user/jsonrpc"
	chainjson "github.com/trufnetwork/kwil-db/core/rpc/json/chain"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	"github.com/trufnetwork/kwil-db/core/types"
	chaintypes "github.com/trufnetwork/kwil-db/core/types/chain"
)

// Client is a chain RPC client. It provides all methods of the user RPC
// service, plus methods that are specific to the chain service.
type Client struct {
	*userClient.Client // expose all user service methods, and methods for chain svc
}

// Version reports the version of the running node.
func (c *Client) Version(ctx context.Context) (string, error) {
	req := &userjson.VersionRequest{}
	res := &userjson.VersionResponse{}
	err := c.CallMethod(ctx, string(chainjson.MethodVersion), req, res)
	if err != nil {
		return "", err
	}
	return res.KwilVersion, err
}

func (c *Client) BlockByHeight(ctx context.Context, height int64) (*chaintypes.Block, *chaintypes.CommitInfo, error) {
	req := &chainjson.BlockRequest{
		Height: height,
		Raw:    true, // we'll decode
	}
	res := &chainjson.BlockResponse{}
	err := c.CallMethod(ctx, string(chainjson.MethodBlock), req, res)
	if err != nil {
		return nil, nil, err
	}
	block, err := types.DecodeBlock(res.RawBlock)
	if err != nil {
		return nil, nil, err
	}
	return block, res.CommitInfo, nil
}

func (c *Client) BlockByHash(ctx context.Context, hash types.Hash) (*chaintypes.Block, *chaintypes.CommitInfo, error) {
	req := &chainjson.BlockRequest{
		Hash: hash,
		Raw:  true, // we'll decode
	}
	res := &chainjson.BlockResponse{}
	err := c.CallMethod(ctx, string(chainjson.MethodBlock), req, res)
	if err != nil {
		return nil, nil, err
	}
	block, err := types.DecodeBlock(res.RawBlock)
	if err != nil {
		return nil, nil, err
	}
	return block, res.CommitInfo, nil
}

func (c *Client) BlockResultByHeight(ctx context.Context, height int64) (*chaintypes.BlockResult, error) {
	req := &chainjson.BlockResultRequest{
		Height: height,
	}
	res := &chainjson.BlockResultResponse{}
	err := c.CallMethod(ctx, string(chainjson.MethodBlockResult), req, res)
	if err != nil {
		return nil, err
	}
	return (*chaintypes.BlockResult)(res), nil
}

func (c *Client) BlockResultByHash(ctx context.Context, hash types.Hash) (*chaintypes.BlockResult, error) {
	req := &chainjson.BlockResultRequest{
		Hash: hash,
	}
	res := &chainjson.BlockResultResponse{}
	err := c.CallMethod(ctx, string(chainjson.MethodBlockResult), req, res)
	if err != nil {
		return nil, err
	}
	return (*chaintypes.BlockResult)(res), nil
}

func (c *Client) Tx(ctx context.Context, hash types.Hash) (*chaintypes.Tx, error) {
	req := &chainjson.TxRequest{
		Hash: hash,
	}
	res := &chainjson.TxResponse{}
	err := c.CallMethod(ctx, string(chainjson.MethodTx), req, res)
	if err != nil {
		return nil, err
	}
	return (*chaintypes.Tx)(res), err
}

func (c *Client) Genesis(ctx context.Context) (*chaintypes.Genesis, error) {
	req := &chainjson.GenesisRequest{}
	res := &chainjson.GenesisResponse{}
	err := c.CallMethod(ctx, string(chainjson.MethodGenesis), req, res)
	if err != nil {
		return nil, err
	}
	return res, err
}

func (c *Client) ConsensusParams(ctx context.Context) (*types.NetworkParameters, error) {
	req := &chainjson.ConsensusParamsRequest{}
	res := &chainjson.ConsensusParamsResponse{}
	err := c.CallMethod(ctx, string(chainjson.MethodConsensusParams), req, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *Client) Validators(ctx context.Context) (int64, []*types.Validator, error) {
	req := &chainjson.ValidatorsRequest{}
	res := &chainjson.ValidatorsResponse{}
	err := c.CallMethod(ctx, string(chainjson.MethodValidators), req, res)
	if err != nil {
		return 0, nil, err
	}

	return res.Height, res.Validators, nil
}

func (c *Client) UnconfirmedTxs(ctx context.Context) (total int, tx []chaintypes.NamedTx, err error) {
	req := &chainjson.UnconfirmedTxsRequest{}
	res := &chainjson.UnconfirmedTxsResponse{}
	err = c.CallMethod(ctx, string(chainjson.MethodUnconfirmedTxs), req, res)
	if err != nil {
		return 0, nil, err
	}

	return res.Total, res.Txs, nil
}

// NewClient constructs a new chain Client.
func NewClient(u *url.URL, opts ...rpcclient.RPCClientOpts) *Client {
	userClient := userClient.NewClient(u, opts...)
	return &Client{
		Client: userClient,
	}
}

var _ user.TxSvcClient = (*Client)(nil) // via embedded userClient.Client
var _ chain.Client = (*Client)(nil)     // with extra methods
