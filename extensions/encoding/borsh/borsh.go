package borsh

import (
	"github.com/near/borsh-go"

	"github.com/trufnetwork/kwil-db/core/types/serialize"
)

func init() {
	serialize.RegisterCodec(Codec)
}

const EncodingTypeBorsh = serialize.EncodingTypeCustom + 2

var Codec = &serialize.Codec{
	Type: EncodingTypeBorsh,
	Name: "Borsh",
	Encode: func(val any) ([]byte, error) {
		return borsh.Serialize(val)
	},
	Decode: func(bts []byte, v any) error {
		return borsh.Deserialize(v, bts)
	},
}
