//go:build kwiltest

package types

import "math/big"

// BigIntToHash32 converts big.Int to a 32-byte array (big-endian) for ERC20 value data.
func BigIntToHash32(b *big.Int) [32]byte {
	var out [32]byte
	if b == nil {
		return out
	}
	bs := b.Bytes()
	if len(bs) > 32 {
		copy(out[:], bs[len(bs)-32:])
		return out
	}
	copy(out[32-len(bs):], bs)
	return out
}
