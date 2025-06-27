package rpcserver

import (
	"reflect"

	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/openrpc"
)

// MakeOpenRPCSpec creates an OpenRPC spec from a service.
func MakeOpenRPCSpec(svc Svc, specInfo openrpc.Info) openrpc.Spec {
	methodDefs := make(map[string]*openrpc.MethodDefinition)
	for method, def := range svc.Methods() {
		methodDefs[string(method)] = &openrpc.MethodDefinition{
			Description:  def.Desc,
			RequestType:  def.ReqType,
			ResponseType: def.RespType,
			RespTypeDesc: def.RespDesc,
		}
	}
	knownSchemas := make(map[reflect.Type]openrpc.Schema)
	methods := openrpc.InventoryAPI(methodDefs, knownSchemas)
	schemas := make(map[string]openrpc.Schema)
	for _, schema := range knownSchemas {
		schemas[schema.Name()] = schema
	}
	return openrpc.Spec{
		OpenRPC: "1.2.4",
		Info:    specInfo,
		Methods: methods,
		Components: openrpc.Components{
			Schemas: schemas,
		},
	}
}
