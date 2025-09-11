//go:build kwiltest

package erc20

// Export SINGLETON for tests in the same package under kwiltest tag.
func init() { _SINGLETON = &extensionInfo{instances: newInstanceMap()} }
