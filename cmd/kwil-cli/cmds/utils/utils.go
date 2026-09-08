package utils

import (
	"github.com/spf13/cobra"
)

func NewCmdUtils() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "utils",
		Aliases: []string{"common"},
		Short:   "Various CLI utility commands.",
		Long:    "Various CLI utility commands.",
	}

	cmd.AddCommand(
		pingCmd(),
		parseCmd(),
		printConfigCmd(),
		txQueryCmd(),
		decodeTxCmd(),
		chainInfoCmd(),
		kgwAuthnCmd(),
		testCmd(),
		generateKeyCmd(),
		blockMixCmd(),
	)

	return cmd
}
