package openrpc

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/trufnetwork/kwil-db/core/types"
)

type accountRequest struct {
	Identifier types.HexBytes       `json:"identifier"`
	Status     *types.AccountStatus `json:"status,omitempty"` // Mapped to URL query parameter `status`.
}

type accountResponse struct {
	Identifier types.HexBytes `json:"identifier,omitempty"`
	Balance    string         `json:"balance"`
	Nonce      int64          `json:"nonce"`
}

func TestInventory(t *testing.T) {
	handlerTypes := map[string]*MethodDefinition{
		"user.account": {
			Description:  "get an account's status",
			RequestType:  reflect.TypeOf(accountRequest{}),
			ResponseType: reflect.TypeOf(accountResponse{}),
			RespTypeDesc: "balance and nonce of an accounts",
		},
	}

	knownSchemas := make(map[reflect.Type]Schema)
	methods := InventoryAPI(handlerTypes, knownSchemas)

	schemas := make(map[string]Schema)
	for _, schema := range knownSchemas {
		schemas[schema.Name()] = schema
	}

	spec := Spec{
		OpenRPC: "1.2.4",
		Info: Info{
			Title:       "kwil test API",
			Description: "this is just a test API's specification",
			License: &License{
				Name: "MIT",
			},
			Version: "1.21.0",
		},
		Methods: methods,
		Components: Components{
			Schemas: schemas,
		},
	}

	b, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(b))
}
