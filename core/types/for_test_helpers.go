//go:build kwiltest

package types

import "math/big"

// BigIntToHash32 converts a non-negative big.Int to a 32-byte big-endian array for ERC20 value data.
// Note: values > 256 bits are truncated to the least-significant 32 bytes.
func BigIntToHash32(n *big.Int) [32]byte {
	var out [32]byte
	b := n.Bytes()
	copy(out[32-len(b):], b)
	return out
}
