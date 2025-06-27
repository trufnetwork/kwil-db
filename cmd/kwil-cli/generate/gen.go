package main

import (
	"flag"

	"github.com/trufnetwork/kwil-db/app/shared/generate"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/cmds"
)

var (
	out string
)

func main() {
	flag.StringVar(&out, "out", "./dist", "output directory")

	flag.Parse()

	err := generate.WriteDocs(cmds.NewRootCmd(), out)
	if err != nil {
		panic(err)
	}
}
