//go:build kwiltest

package erc20

// Export SINGLETON for tests in the same package under kwiltest tag.
var _SINGLETON *extensionInfo

func init() { _SINGLETON = &extensionInfo{instances: newInstanceMap()} }
