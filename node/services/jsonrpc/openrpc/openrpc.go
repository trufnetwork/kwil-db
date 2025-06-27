package openrpc

import (
	"reflect"

	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
)

// Spec is the structure of an openrpc JSON file.
type Spec struct {
	// OpenRPC is the semantic version of the OpenRPC spec used. This should be
	// used by tooling specifications and clients to interpret the OpenRPC
	// document. This is not related to the Info.Version string.
	OpenRPC string `json:"openrpc"`
	// Info provides metadata about the API.
	Info Info `json:"info"`
	// Methods is a list of the available methods for the API.
	Methods []Method `json:"methods"`
	// Components holds various schemas (object definitions) for the spec.
	Components Components `json:"components"`
	// Servers []...
	Docs *ExternalDocs `json:"externalDocs,omitempty"`
}

type ExternalDocs struct {
	// Description is a verbose explanation of the target documentation. GitHub
	// Flavored Markdown syntax MAY be used for rich text representation.
	Description string `json:"description,omitempty"`
	// URL is the target documentation URL.
	URL string `json:"url,omitempty"`
}

// Info describes the RPC service.
type Info struct {
	// Title is the title of the application. e.g. kwild user RPC service.
	Title string `json:"title"`
	// Description is a verbose description of the application, which may be in
	// Markdown format.
	Description string `json:"description,omitempty"`
	// License is license information for the exposed API.
	License *License `json:"license,omitempty"`
	Contact *Contact `json:"contact,omitempty"`
	// Version is the version of the OpenRPC document, which is distinct from
	// the OpenRPC Specification version or the API implementation version.
	Version string `json:"version,omitempty"`
}

type Contact struct {
	// Name is the identifying name of the contact person/organization.
	Name string `json:"name,omitempty"`
	// URL is the URL pointing to the contact information.
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// License specifies the license for the service definition.
type License struct {
	// Name is the name of the license used for the exposed API.
	Name string `json:"name"`
	// URL is a link to the license used for the API.
	URL string `json:"url,omitempty"`
}

// Method describes an RPC method. The required fields are the method's name and
// the input parameters. Describes the interface for the given method name. The
// method name is used as the method field of the JSON-RPC body. It therefore
// MUST be unique.
type Method struct {
	Name        string           `json:"name"`
	Summary     string           `json:"summary,omitempty"`
	Description string           `json:"description,omitempty"`
	Params      []Param          `json:"params"`
	Result      Param            `json:"result"`
	Deprecated  bool             `json:"deprecated,omitempty"`
	Errors      []*jsonrpc.Error `json:"errors,omitempty"`
	// Tags
	// ExternalDocs

	// ParamFmt is the expected format of the parameters ("by-position",
	// "by-name", or "either"). We currently only support "by-name".
	ParamFmt *ParamStructure `json:"paramStructure,omitempty"`
}

type ParamStructure string

const (
	ParamsByName     ParamStructure = "by-name"
	ParamsByPosition ParamStructure = "by-position"
	ParamsEither     ParamStructure = "either"
)

// Error defines an application level error.
// type Error struct {
// 	Code    int32
// 	Message string
// 	Data    json.RawMessage
// }

// Param describes an input parameter or a result. The required fields are the
// parameter's name and the schema definition.
type Param struct {
	Name        string `json:"name"`
	Schema      Schema `json:"schema"`
	Required    *bool  `json:"required,omitempty"` // in method inputs ([]Param)
	Description string `json:"description,omitempty"`
	// Summary string // short summary
}

// type SchemaType string

const (
	TypeString  = "string"
	TypeInteger = "integer"
	TypeNumber  = "number"
	TypeBoolean = "boolean"
	TypeObject  = "object"
	TypeArray   = "array"
)

// Schema is a type definition in OpenRPC. Only Type is required. For an
// "object" type, Properties should be set. For an "array" type, Items should be
// set to define the element type.
//
// This corresponds to the "application/schema+json" media type outlined in
// https://json-schema.org/draft-07/json-schema-core
type Schema struct {
	Type                 string            `json:"type"`
	Properties           map[string]Schema `json:"properties,omitempty"`
	AdditionalProperties bool              `json:"additionalProperties,omitempty"`
	Items                *Schema           `json:"items,omitempty"` // Schema for array items

	// Ref indicates a reference object. When set, a JSON Schema defined in the
	// Components is referenced.
	// https://json-schema.org/draft-07/json-schema-core#rfc.section.8.3
	Ref string `json:"$ref,omitempty"`

	// contextual fields when parsing from Go API types
	required bool
	rType    reflect.Type
}

// Referenced returns a "$ref" Schema if the Type is an "object".
// The value of the reference is "#/components/schemas/" + s.Name()
func (s *Schema) Referenced() Schema {
	if s.Type != "object" {
		return *s
	}
	return Schema{
		Type:  s.Type,
		Ref:   "#/components/schemas/" + s.Name(),
		rType: s.rType,
	}
}

// Name returns the Schema's name as the name of the underlying reflect.Type
// with the first character lower-cased.
func (s *Schema) Name() string {
	return lowerFirstChar(s.rType.Name()) // s.name // don't want to marshal, but expose the value
}

// Components represent the top level "components" object. The "schemas" used in
// the API's methods are defined here.
type Components struct {
	Schemas map[string]Schema `json:"schemas"`
}
