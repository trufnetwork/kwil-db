package extensions

// this file simply exists so that other registration files can be dropped in this directory
// this directory has 0 dependencies, so it can import anything
// it is imported by cmd/kwild/main.go, so any other files in this directory will be compiled

import (
	// DEPRECATED: eth_deposits listener is deprecated in favor of the ERC20 bridge extension
	// This import is kept for backward compatibility with production deployments
	// that still depend on the eth_deposits system.
	_ "github.com/trufnetwork/kwil-db/extensions/listeners/eth_deposits"
)
