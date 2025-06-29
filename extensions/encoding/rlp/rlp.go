package rlp

// This is a temporary file to allow for internal node code to use the legacy
// RLP serializations. The transaction payloads in core no longer use RLP, so
// this is taken out of the core module.

import (
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/trufnetwork/kwil-db/core/types/serialize"
)

func init() {
	serialize.RegisterCodec(Codec)
}

// RLP is still used in a few places in the node codebase, including
// extensions/resolutions/credit/credit.go and node/migrations.
// TODO: change that ^^^

const EncodingTypeRLP = serialize.EncodingTypeCustom + 1

var Codec = &serialize.Codec{
	Type: EncodingTypeRLP,
	Name: "RLP",
	Encode: func(val any) ([]byte, error) {
		return rlp.EncodeToBytes(val)
	},
	Decode: func(bts []byte, v any) error {
		return rlp.DecodeBytes(bts, v)
	},
}
