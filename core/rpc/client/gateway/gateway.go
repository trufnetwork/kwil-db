package gateway

import (
	"context"

	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	"github.com/trufnetwork/kwil-db/core/types"
)

// Client is the interface for the Kwil gateway client.
type Client interface {
	// Authn sends an authentication request to the gateway.
	// It will set a cookie in the client if successful.
	Authn(ctx context.Context, req *AuthnRequest) error

	// GetAuthnParameter returns the parameters that will be used to compose the
	// authentication message that will be signed by the client.
	GetAuthnParameter(ctx context.Context) (*AuthnParameterResponse, error)
}

// AuthnRequest is a request for authentication from the kgw.
type AuthnRequest struct {
	Nonce     string          `json:"nonce"`  // identifier for authn session
	Sender    types.HexBytes  `json:"sender"` // sender public key
	Signature *auth.Signature `json:"signature"`
}

type AuthnResponse struct{}

type AuthnParameterRequest struct{}

// AuthnParameterResponse defines the result when request for gateway(KGW)
// authentication. It's the parameters that will be used to compose the
// message(SIWE like) to sign.
type AuthnParameterResponse struct {
	Nonce          string `json:"nonce"`
	Statement      string `json:"statement"` // optional
	IssueAt        string `json:"issue_at"`
	ExpirationTime string `json:"expiration_time"`
	// client can use those to precheck before signing
	ChainID string `json:"chain_id"` // the chain id of the gateway
	Domain  string `json:"domain"`   // the domain of the gateway
	Version string `json:"version"`  // the authn version used by the gateway
	URI     string `json:"uri"`      // the endpoint used for authn
}

const (
	MethodAuthn      jsonrpc.Method = "kgw.authn"
	MethodAuthnParam jsonrpc.Method = "kgw.authn_param"
	//MethodLogout    jsonrpc.Method = "kgw.logout"
)
