package main

import (
	"os"

	// NOTE: if extensions are used to build a kwild with new transaction
	// payload types or serialization methods, the same extension packages that
	// register those types with core module packages would be imported here so
	// that the client can work with them too. While the client does is not
	// concerned with activation heights, it could need to use new functionality
	// introduced by the consensus extensions.

	"github.com/trufnetwork/kwil-db/app/shared"
	root "github.com/trufnetwork/kwil-db/cmd/kwil-cli/cmds"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
)

func main() {
	root := root.NewRootCmd()
	if err := root.Execute(); err != nil {
		config.PreRunPrintEffectiveConfig(root, nil) // only when --debug is set
		os.Exit(-1)
	}

	// For a command / application error, which handle the output themselves, we
	// detect those case where display.PrintErr() is called so that we can
	// return a non-zero exit code, which is important for scripting etc.
	if err := shared.CmdCtxErr(root); err != nil {
		os.Exit(-1)
	}

	os.Exit(0)
}
