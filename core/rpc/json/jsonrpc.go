// Package jsonrpc defines the types required by JSON-RPC 2.0 servers and
// clients.
//
// For the Kwil RPC services, the following are also defined here:
//   - Known method names.
//   - The shared objects used in request parameters and response. These
//     types are the JSON-RPC "schema".
//   - Error codes and structured error data objects.
package jsonrpc

import (
	"encoding/json"
	"fmt"
	"math"
)

// Method is a type used for all recognized JSON-RPC method names.
type Method string

// Error is the "error" object defined by JSON-RPC 2.0
type Error struct {
	// Code is an integer error code. Values on [-32768,-32000] are reserved by
	// JSON-RPC 2.0, but any other values may be used.
	Code ErrorCode `json:"code"`
	// Message is a "A String providing a short description of the error."
	Message string `json:"message"`
	// Data is "a Primitive or Structured value that contains additional
	// information about the error. This may be omitted. The value of this
	// member is defined by the Server (e.g. detailed error information, nested
	// errors etc.). The requester may attempt to unmarshal into the expected
	// detailed error type for the method.
	Data json.RawMessage `json:"data,omitempty"`
}

// NewError constructs a new error.
func NewError(code ErrorCode, message string, data json.RawMessage) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Data:    data,
	}
}

var _ error = (*Error)(nil)
var _ error = Error{} // can't have pointer receiver for this to work

// Error satisfies the Go error interface.
func (e Error) Error() string {
	data, _ := json.MarshalIndent(e.Data, "", "  ")
	return fmt.Sprintf("jsonrpc.Error: code = %d, message = %v, data = %s",
		e.Code, e.Message, string(data))
}

// Request is the "request" object defined by JSON-RPC 2.0. The Params field may
// be either named (and object) or positional (an array). The initial
// implementation of the server will support named only.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"` // int, string, null
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"` // object in 2.0, array in 1.0
}

// integerID converts a float64 id to an int64 only if that is lossless. A bare
// int64(f) conversion saturates to math.MinInt64 for NaN, Inf, and values at or
// beyond 2^63, and truncates a fractional part.
func integerID(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) ||
		f < -9223372036854775808.0 || f >= 9223372036854775808.0 {
		return 0, false
	}
	return int64(f), true
}

func stdID(id any) any {
	switch t := id.(type) {
	case float64: // json numeric unmarshals to float64 with any field
		if i, ok := integerID(t); ok {
			return i
		}
		return t // not an exact int64, leave it as is rather than corrupt it
	case string: // string is the other allowed type
		return t
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, uintptr:
		return t
	case nil: // NULL is also permitted, although discouraged outside of ntfns
		return nil
	default:
		return fmt.Sprintf("%v", id) // Probably not intended, but any string is allowed.
	}
}

// NewRequest creates a new Request for certain method given the structured
// request parameters struct marshalled to JSON. The id is permitted to be a
// string or numeric.
func NewRequest(id any, method string, params json.RawMessage) *Request {
	return &Request{
		JSONRPC: "2.0",
		ID:      stdID(id), // keep the type, but it should be string, float64, or nil
		Method:  method,
		Params:  params,
	}
}

// A request may be unmarshalled with json.Unmarshal. The ID field must either
// be a string or float64 (that's how json unmarshals integers into an any by
// default). If it is nil, that is a notification, which we aren't using
// initially.

// Response is the "response" object defined by JSON-RPC 2.0. The "result" field
// is required on success, and may be any shape determined by the method.
// Either the "response" or "error" field are expected to be set.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"` // object, marshalled by handler
	Error   *Error          `json:"error,omitempty"`
}

// NewErrorResponse constructs a new Response for a request ID and Error.
func NewErrorResponse(id any, rpcErr *Error) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   rpcErr,
	}
}

// NewResponse encodes the result and creates a Response.
func NewResponse(id any, result any) (*Response, error) {
	id = stdID(id)
	if id == 0 {
		return nil, fmt.Errorf("id = 0 not allowed for response-type message")
	}
	resJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  resJSON,
	}, nil
}
