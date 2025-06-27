package extensions

// this file simply exists so that other registration files can be dropped in this directory
// this directory has 0 dependencies, so it can import anything
// it is imported by cmd/kwild/main.go, so any other files in this directory will be compiled

import (
	_ "github.com/trufnetwork/kwil-db/extensions/listeners/eth_deposits"
)
