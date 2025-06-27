package funcsvc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	"github.com/trufnetwork/kwil-db/core/rpc/json/function"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
	rpcserver "github.com/trufnetwork/kwil-db/node/services/jsonrpc"
	"github.com/trufnetwork/kwil-db/version"
)

type Service struct{}

const (
	apiVerMajor = 0
	apiVerMinor = 1
	apiVerPatch = 0

	serviceName = "function"
)

var (
	apiSemver = fmt.Sprintf("%d.%d.%d", apiVerMajor, apiVerMinor, apiVerPatch)
)

// The function Service must be usable as a Svc registered with a JSON-RPC Server.
var _ rpcserver.Svc = (*Service)(nil)

func (svc *Service) Name() string {
	return serviceName
}

// The marshalled Health response is static, so we marshal it once.
var healthResp, _ = json.Marshal(function.HealthResponse{
	Healthy: true,
	Version: apiSemver,
})

// Health for the function service is just a non-empty string, no real health.
func (svc *Service) Health(context.Context) (json.RawMessage, bool) {
	return healthResp, true
}

func verHandler(context.Context, *userjson.VersionRequest) (*userjson.VersionResponse, *jsonrpc.Error) {
	return &userjson.VersionResponse{
		Service:     serviceName,
		Version:     apiSemver,
		Major:       apiVerMajor,
		Minor:       apiVerMinor,
		Patch:       apiVerPatch,
		KwilVersion: version.KwilVersion,
	}, nil
}

func (svc *Service) Methods() map[jsonrpc.Method]rpcserver.MethodDef {
	return map[jsonrpc.Method]rpcserver.MethodDef{
		function.MethodVersion: rpcserver.MakeMethodDef(verHandler,
			"retrieve the API version of the function service",
			"service info including semver and kwild version"),
		function.MethodVerifySig: rpcserver.MakeMethodDef(svc.VerifySignature,
			"verify a message signature",
			"validity of the signature and any reason for failure"),
	}
}

// VerifySignature checks the signature with the given public key and message.
// This only verifies the signature against known kwil-db singing schema, which
// is determined by the signature's type.
func (Service) VerifySignature(_ context.Context, req *function.VerifySignatureRequest) (*function.VerifySignatureResponse, *jsonrpc.Error) {
	convSignature := auth.Signature{
		Data: req.Signature.SignatureBytes,
		Type: req.Signature.SignatureType,
	}

	err := authExt.VerifySignature(req.Sender, req.Msg, &convSignature)
	if err != nil {
		return &function.VerifySignatureResponse{
			Valid:  false,
			Reason: err.Error(),
		}, nil
	}

	return &function.VerifySignatureResponse{
		Valid: true,
	}, nil
}
