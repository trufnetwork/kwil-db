package consensus

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckTxAdmissionPanicBecomesError(t *testing.T) {
	err := checkTxAdmission(func() error {
		panic("nil signature")
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "transaction validation failed")
	require.ErrorContains(t, err, "nil signature")

	sentinel := errors.New("rejected")
	err = checkTxAdmission(func() error { return sentinel })
	require.ErrorIs(t, err, sentinel)

	require.NoError(t, checkTxAdmission(func() error { return nil }))
}
