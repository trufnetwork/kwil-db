package types

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/crypto"
)

func Test_AccountIDRoundtrip(t *testing.T) {
	t.Run("Valid AccountID", func(t *testing.T) {
		acctID := &AccountID{
			Identifier: []byte("test"),
			KeyType:    crypto.KeyTypeSecp256k1,
		}

		b, err := acctID.MarshalBinary()
		require.NoError(t, err)

		var acctIDBack AccountID
		err = acctIDBack.UnmarshalBinary(b)
		require.NoError(t, err)

		require.Equal(t, acctID, &acctIDBack)
	})

	t.Run("Invalid KeyType Marshal", func(t *testing.T) {
		acctID := &AccountID{
			Identifier: []byte("test"),
			KeyType:    "invalidType",
		}

		_, err := acctID.MarshalBinary()
		require.Error(t, err)
	})

	t.Run("Invalid KeyType Unmarshal", func(t *testing.T) {
		acctID := &AccountID{
			Identifier: []byte("test"),
		}

		buf := new(bytes.Buffer)
		err := binary.Write(buf, SerializationByteOrder, uint16(AccountIDVersion))
		require.NoError(t, err)
		err = WriteBytes(buf, acctID.Identifier)
		require.NoError(t, err)
		// Invalid KeyType
		err = binary.Write(buf, SerializationByteOrder, uint16(3))
		require.NoError(t, err)

		var acctIDBack AccountID
		err = acctIDBack.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})
}

func Test_ValidatorRoundtrip(t *testing.T) {
	val := &Validator{
		AccountID: AccountID{
			Identifier: []byte("test"),
			KeyType:    crypto.KeyTypeSecp256k1,
		},
		Power: 100,
	}

	b, err := val.MarshalBinary()
	require.NoError(t, err)

	var valBack Validator
	err = valBack.UnmarshalBinary(b)
	require.NoError(t, err)

	require.Equal(t, val, &valBack)
}
