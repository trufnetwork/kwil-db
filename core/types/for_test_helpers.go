//go:build kwiltest

package types

import "math/big"

// BigIntToHash32 converts a big.Int to a 32-byte array.
func BigIntToHash32(n *big.Int) [32]byte {
	var out [32]byte
	b := n.Bytes()
	copy(out[32-len(b):], b)
	return out
}
