package openrpc

import (
	"cmp"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/trufnetwork/kwil-db/core/types"
)

type MethodDefinition struct {
	Description  string
	Summary      string
	RequestType  reflect.Type
	ResponseType reflect.Type
	RespTypeDesc string
	// Errors ...
}

// InventoryAPI iterates through all handler types, making a map of all unique
// OpenRPC schemas and building a []Method with every Param populated and
// referencing a Schema if an "object" instead of a plain type.
func InventoryAPI(handlerDefs map[string]*MethodDefinition, knownSchemas map[reflect.Type]Schema) []Method {
	if knownSchemas == nil {
		knownSchemas = make(map[reflect.Type]Schema)
	}

	for _, def := range handlerDefs {
		reflectTypeInfo(def.ResponseType, knownSchemas)
		// Request types do not become known schemas since we treat each field
		// of the request type as a parameter.
	}

	var methods []Method

	for method, def := range handlerDefs {
		// Request params from the request type
		reflectTypeInfo(def.RequestType, knownSchemas)
		reqSchema := knownSchemas[def.RequestType] // the non-$ref schema with Properties
		if def.RequestType.Kind() == reflect.Struct {
			delete(knownSchemas, def.RequestType)
		}
		params := make([]Param, 0, len(reqSchema.Properties))
		for paramName, paramSchema := range reqSchema.Properties {
			req := paramSchema.required
			param := Param{
				Name:     paramName,
				Required: &req,
				Schema:   paramSchema.Referenced(),
				// Description: ? tag ?
			}
			params = append(params, param)
		}
		slices.SortFunc(params, func(a, b Param) int {
			// Required params first, then alphabetical.
			aReq := a.Required != nil && *a.Required
			bReq := b.Required != nil && *b.Required
			if aReq == bReq {
				return cmp.Compare(a.Name, b.Name)
			}
			if aReq {
				return -1
			}
			return 1
		})

		// Response param
		respType := def.ResponseType
		respSchema := knownSchemas[def.ResponseType] // reflectTypeInfo(respType, knownSchemas)
		result := Param{
			Name:        lowerFirstChar(respType.Name()),
			Schema:      respSchema.Referenced(),
			Description: def.RespTypeDesc,
		}

		byNameOnly := ParamsByName
		methods = append(methods, Method{
			Name:        method,
			Params:      params,
			Result:      result,
			Description: def.Description,
			// Summary: , ???
			// Errors...
			ParamFmt: &byNameOnly,
		})
	}

	slices.SortFunc(methods, func(a, b Method) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return methods
}

func lowerFirstChar(s string) string {
	r, sz := utf8.DecodeRuneInString(s)
	if sz == 0 {
		return s
	}
	if r == utf8.RuneError {
		return s
	}
	return strings.ToLower(string(r)) + s[sz:]
}

func typeToSchemaType(t reflect.Type) string {
	// Some special cases first. These are types that our JSON-RPC service
	// should marshal as a JSON string. In some cases this is by virtue of the
	// type implementing json.Marshaller. In other cases, a different type that
	// has a field of this type has it's own MarshalJSON method for special
	// handling of that field. The special case of []byte reflects the behavior
	// of the encoding/json package that uses a base64 string rather than a JSON
	// "array".
	switch t {
	case reflect.TypeOf((*big.Int)(nil)), reflect.TypeFor[big.Int]():
		// A big.Int field should marshal to/from a string.
		return "string"
	case reflect.TypeFor[types.HexBytes]():
		// HexBytes defines MarshalJSON/UnmarshalJSON methods to represent
		// []byte as a hexadecimal string.
		return "string"
	case reflect.TypeFor[types.UUID](): // MarshalJSON also makes JSON string
		return "string"
	case reflect.TypeFor[types.Decimal](): // MarshalJSON also makes JSON string
		return "string"
	case reflect.TypeFor[[]byte]():
		// A regular []byte field is a base64 string.
		return "string"
	}

	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Bool:
		return "boolean"
	case reflect.String:
		return "string"
	case reflect.Slice:
		// []byte should be caught above, but it could be a []uint8 or
		// something else where the element type is an underlying uint8.
		if t.Elem().Kind() == reflect.Uint8 {
			return "string" // Treat []byte as a base64 encoded string
		}
		return "array"
	case reflect.Array:
		return "array"
	case reflect.Map:
		return "object"
	case reflect.Ptr, reflect.Struct, reflect.Interface:
		return "object" // handling of these types requires recursive schema generation
	default:
		return "object"
	}
}

// reflectTypeInfo ensures that the type is a known Schema, recursively
// identifying any other objects in fields if the type is an object. The
// returned Schema is a "$ref" schema. Access the knownSchemas map for the
// Schema with Properties set.
func reflectTypeInfo(t reflect.Type, knownSchemas map[reflect.Type]Schema) Schema {
	// Return a schema reference if it has been defined already.
	if s, have := knownSchemas[t]; have {
		if s.Type != "object" { // should be objects only in the schemas map
			panic(s)
		}
		return s.Referenced()
	}

	basicType := typeToSchemaType(t)
	schema := Schema{
		Type:  basicType,
		rType: t,
	}

	// Some basic types require no recursion, properties, or items.
	switch basicType {
	case "string", "boolean", "integer", "number":
		return schema
	}
	// Anything else requires recursion or additional Schema fields to be set
	// other than Type.

	switch t.Kind() {
	case reflect.Ptr:
		return reflectTypeInfo(t.Elem(), knownSchemas) // recursively reflect dereferenced type

	case reflect.Struct:
		// For an "object" (dereferenced if pointer), set the "properties".
		// Recurse for each field's type, merging fields of embedded types.
		schema.Properties = make(map[string]Schema)
		for i := range t.NumField() {
			field := t.Field(i)

			if field.Anonymous { // embedded field
				fieldType := field.Type
				if fieldType.Kind() == reflect.Struct { // merge properties of embedded struct
					reflectTypeInfo(fieldType, knownSchemas)
					anonSchema := knownSchemas[fieldType] // non-$ref schema
					for propName, propSchema := range anonSchema.Properties {
						schema.Properties[propName] = propSchema
					}
				} else { // non-struct, include the field itself
					fieldName := fieldType.Name()
					if fieldName == "" {
						fieldName = field.Name
					}
					schema.Properties[fieldName] = reflectTypeInfo(fieldType, knownSchemas)
				}
			}

			var optional bool
			fieldName, have := field.Tag.Lookup("json")
			if have {
				parts := strings.Split(fieldName, ",")
				fieldName = parts[0]
				optional = slices.Contains(parts[1:], "omitempty")
			} else {
				fieldName = field.Name
			}
			propSchema := reflectTypeInfo(field.Type, knownSchemas)
			propSchema.required = !optional
			schema.Properties[fieldName] = propSchema
		}

		// sj, _ := json.Marshal(schema)
		// fmt.Println(t.Name(), string(sj))

		knownSchemas[t] = schema   // store non-$ref schema
		return schema.Referenced() // return $ref schema

	case reflect.Slice, reflect.Array:
		// Set "items" to define the type of the element in the "array" schema.
		elemType := t.Elem()
		ti := reflectTypeInfo(elemType, knownSchemas)
		schema.Items = &ti
		return schema

	case reflect.Interface:
		// Represent interfaces as a generic object, assuming no specific
		// properties can be inferred.
		schema.Type = "object"
		schema.AdditionalProperties = true // Allow any properties since the exact structure is not known
		return schema

	case reflect.Map:
		// We can treat a map as an object, but without an instance (value) of
		// the map, we can't infer the properties names (the string keys).
		if t.Key().Kind() != reflect.String {
			panic(fmt.Sprintf("unsupported map key type %v", t.Key().Kind()))
		}
		schema.Type = "object"
		schema.AdditionalProperties = true // the keys (fields) of the map are not known
		return schema

	default:
		panic(fmt.Sprintf("unsupported type for OpenRPC spec generation: %v", t.Kind()))
	}
}
