package auth_test

import (
	"encoding/hex"
	"testing"

	"github.com/trufnetwork/kwil-db/extensions/auth"

	"github.com/stretchr/testify/require"
)

func Test_Ed25519Sha256Near(t *testing.T) {
	publicKey := "0aa611bf555596912bc6f9a9f169f8785918e7bab9924001895798ff13f05842"
	signature := "089bcf52220dad77abc2cfcb1639bcb2944fdf64e0b173f40cd0d144bdbf7808f4eff3716eb3e98ed40be3ab126e1449d5f57efbe5626673059edc90e9cd9801"
	message := []byte("foo")
	pubKeyBts, err := hex.DecodeString(publicKey)
	require.NoError(t, err, "error decode public key")

	signatureBts, err := hex.DecodeString(signature)
	require.NoError(t, err, "error decode signature")

	authenticator := auth.Ed22519Sha256Authenticator{}

	err = authenticator.Verify(pubKeyBts, message, signatureBts)
	require.NoError(t, err, "error verifying signature")
}
