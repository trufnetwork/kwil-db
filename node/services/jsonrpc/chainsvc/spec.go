package chainsvc

//go:generate go run genopenrpcspec.go

import "github.com/trufnetwork/kwil-db/node/services/jsonrpc/openrpc"

var (
	SpecInfo = openrpc.Info{
		Title:       "Kwil DB chain service",
		Description: `The JSON-RPC chain service for Kwil DB.`,
		License: &openrpc.License{ // the spec file's license
			Name: "CC0-1.0",
			URL:  "https://creativecommons.org/publicdomain/zero/1.0/legalcode",
		},
		Version: apiSemver,
	}
)
