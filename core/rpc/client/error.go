package client

import (
	"errors"
	"fmt"

	"github.com/trufnetwork/kwil-db/core/types"
)

// The following errors may be detected by consumers using errors.Is.
var (
	ErrNotFound = types.ErrNotFound

	// ErrUnauthorized is returned when the client is not authenticated
	// It is the equivalent of http status code 401
	ErrUnauthorized   = errors.New("unauthorized")
	ErrMethodNotFound = errors.New("method not found")
	ErrInvalidRequest = errors.New("invalid request")
	ErrNotAllowed     = errors.New("not allowed")
)

// RPCError is a common error type used by any RPC client implementation to
// provide a detectable error to consumers using errors.As. We may define our
// own codes. Instances of RPCError may also be combined with other error types
// defined above using errors.Join.
type RPCError struct {
	Msg  string
	Code int32
}

func (err RPCError) Error() string {
	return fmt.Sprintf("err code = %d, msg = %v", err.Code, err.Msg)
}
