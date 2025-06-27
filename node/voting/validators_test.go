package voting

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/crypto"
)

func Test_MarshalUnmarshalPowerRequest(t *testing.T) {
	t.Run("marshal unmarshal", func(t *testing.T) {
		req := &UpdatePowerRequest{
			PubKey:     []byte{0x12, 0x34},
			PubKeyType: crypto.KeyTypeSecp256k1,
			Power:      100,
		}

		data, err := req.MarshalBinary()
		require.NoError(t, err)

		req2 := &UpdatePowerRequest{}
		err = req2.UnmarshalBinary(data)
		require.NoError(t, err)

		require.Equal(t, req, req2)
	})

	t.Run("marshal unmarshal empty", func(t *testing.T) {
		req := &UpdatePowerRequest{
			PubKey:     []byte{},
			PubKeyType: crypto.KeyTypeEd25519,
			Power:      10,
		}

		data, err := req.MarshalBinary()
		require.NoError(t, err)

		req2 := &UpdatePowerRequest{}
		err = req2.UnmarshalBinary(data)
		require.NoError(t, err)

		require.Equal(t, req, req2)
	})
}
