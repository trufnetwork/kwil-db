package serialize_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/types/serialize"
)

type testBinaryMarshaler struct {
	data []byte
}

func (t *testBinaryMarshaler) MarshalBinary() ([]byte, error) {
	return t.data, nil
}

func (t *testBinaryMarshaler) UnmarshalBinary(data []byte) error {
	t.data = data
	return nil
}

type nonBinaryMarshaler struct{}

func TestEncodeDecode(t *testing.T) {
	encoder := serialize.BinaryCodec.Encode
	// encoder := func(val any) ([]byte, error) {
	// 	return serialize.EncodeWithEncodingType(val, serialize.EncodingTypeBinary)
	// }
	decoder := serialize.BinaryCodec.Decode
	// decoder := func(bts []byte, val any) error {
	// 	return serialize.DecodeWithEncodingType(bts, val, serialize.EncodingTypeBinary)
	// }

	t.Run("encode nil value", func(t *testing.T) {
		bts, err := encoder(nil)
		require.NoError(t, err)
		require.Nil(t, bts)
	})

	t.Run("encode nil interface", func(t *testing.T) {
		var val *testBinaryMarshaler
		bts, err := encoder(val)
		require.NoError(t, err)
		require.Nil(t, bts)
	})

	t.Run("encode non-binary marshaler", func(t *testing.T) {
		val := &nonBinaryMarshaler{}
		_, err := encoder(val)
		require.Error(t, err)
	})

	t.Run("decode nil", func(t *testing.T) {
		err := decoder([]byte{1, 2, 3}, nil)
		require.Error(t, err)
	})

	t.Run("decode nil pointer", func(t *testing.T) {
		var p *int
		err := decoder([]byte{1, 2, 3}, p)
		require.Error(t, err)
	})

	t.Run("decode non-pointer", func(t *testing.T) {
		val := testBinaryMarshaler{}
		err := decoder([]byte{1, 2, 3}, val)
		require.Error(t, err)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		val := &testBinaryMarshaler{data: []byte{1, 2, 3}}
		err := decoder(nil, val)
		require.NoError(t, err)
		require.Nil(t, val.data)
	})

	t.Run("decode non-binary unmarshaler", func(t *testing.T) {
		val := &nonBinaryMarshaler{}
		err := decoder([]byte{1, 2, 3}, val)
		require.Error(t, err)
	})

	t.Run("successful encode decode", func(t *testing.T) {
		original := &testBinaryMarshaler{data: []byte{1, 2, 3}}
		encoded, err := encoder(original)
		require.NoError(t, err)
		require.Equal(t, []byte{1, 2, 3}, encoded)

		decoded := &testBinaryMarshaler{}
		err = decoder(encoded, decoded)
		require.NoError(t, err)
		require.Equal(t, original.data, decoded.data)
	})
}
