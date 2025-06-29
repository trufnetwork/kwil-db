// This file is ignored in a regular package build. This is only used by go
// generate to create an OpenRPC JSON specification file for a server that
// providing the user service.

//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"

	rpcserver "github.com/trufnetwork/kwil-db/node/services/jsonrpc"
	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/chainsvc"
)

func main() {
	if err := writeSpec(); err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func writeSpec() error {
	spec := rpcserver.MakeOpenRPCSpec(&chainsvc.Service{}, chainsvc.SpecInfo)

	out, err := os.Create("chain.openrpc.json")
	if err != nil {
		return err
	}
	defer out.Close()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(spec)
}
