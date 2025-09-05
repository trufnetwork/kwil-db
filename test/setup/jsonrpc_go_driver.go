package setup

import (
	"context"
	"fmt"

	"github.com/trufnetwork/kwil-db/core/client"
	cTypes "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/gatewayclient"
	"github.com/trufnetwork/kwil-db/core/types"
)

// jsonrpcGoDriver uses the Go client to interact with the kwil node
type jsonrpcGoDriver struct {
	cTypes.Client
	privateKey crypto.PrivateKey
	log        logFunc
}

var _ JSONRPCClient = (*jsonrpcGoDriver)(nil)

func newClient(ctx context.Context, endpoint string, l logFunc, _ *testingContext, opts *ClientOptions) (JSONRPCClient, error) {
	if opts == nil {
		opts = &ClientOptions{}
	}
	opts.ensureDefaults()

	var signer auth.Signer
	switch pk := opts.PrivateKey.(type) {
	case *crypto.Secp256k1PrivateKey:
		signer = &auth.EthPersonalSigner{Key: *pk}
	case *crypto.Ed25519PrivateKey:
		signer = &auth.Ed25519Signer{Ed25519PrivateKey: *pk}
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", opts.PrivateKey)
	}

	clOpts := &cTypes.Options{
		Signer: signer,
	}

	var cl cTypes.Client
	var err error
	if opts.UsingKGW {
		cl, err = gatewayclient.NewClient(ctx, endpoint, &gatewayclient.GatewayOptions{
			Options: *clOpts,
		})
	} else {
		cl, err = client.NewClient(ctx, endpoint, clOpts)
	}
	if err != nil {
		return nil, err
	}

	return &jsonrpcGoDriver{
		privateKey: opts.PrivateKey,
		Client:     cl,
		log:        l,
	}, nil
}

func (c *jsonrpcGoDriver) PrivateKey() crypto.PrivateKey {
	return c.privateKey
}

func (c *jsonrpcGoDriver) PublicKey() crypto.PublicKey {
	return c.privateKey.Public()
}

// TxSuccess checks if the transaction was successful
func (c *jsonrpcGoDriver) TxSuccess(ctx context.Context, txHash types.Hash) error {
	resp, err := c.TxQuery(ctx, txHash)
	if err != nil {
		return fmt.Errorf("failed to query: %w", err)
	}

	// NOTE: THIS should not be considered a failure, should retry
	if resp.Height < 0 {
		return ErrTxNotConfirmed
	}

	if resp.Result.Code != uint32(types.CodeOk) {
		return fmt.Errorf("transaction not ok: %s", resp.Result.Log)
	}

	return nil
}

func (c *jsonrpcGoDriver) Identifier() string {
	ident, err := auth.GetUserIdentifier(c.privateKey.Public())
	if err != nil {
		panic(err)
	}

	return ident
}
