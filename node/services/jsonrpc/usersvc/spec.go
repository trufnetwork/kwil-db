package usersvc

//go:generate go run genopenrpcspec.go

import (
	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/openrpc"
)

var (
	SpecInfo = openrpc.Info{
		Title:       "Kwil DB user service",
		Description: `The JSON-RPC user service for Kwil DB.`,
		License: &openrpc.License{ // the spec file's license
			Name: "CC0-1.0",
			URL:  "https://creativecommons.org/publicdomain/zero/1.0/legalcode",
		},
		Version: "0.2.0",
	}
)
