// package function specifies the client interface for Kwil's function service.
package function

import (
	"context"
	"errors"

	"github.com/trufnetwork/kwil-db/core/crypto/auth"
)

type FunctionServiceClient interface {
	VerifySignature(ctx context.Context, sender []byte, signature *auth.Signature, message []byte) error
}

var ErrInvalidSignature = errors.New("invalid signature")
