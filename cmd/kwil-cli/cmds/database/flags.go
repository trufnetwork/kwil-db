package database

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/node/engine"
)

const (
	nameFlag       = "namespace"
	actionNameFlag = "action"
)

// getSelectedNamespace returns the namespace selected by the user.
// If none is provided, it returns the default namespace.
// If the namespace flag is not set, returns wasSet as false.
func getSelectedNamespace(cmd *cobra.Command) (namespace string, wasSet bool, err error) {
	if !cmd.Flags().Changed(nameFlag) {
		return engine.DefaultNamespace, false, nil
	}

	name, err := cmd.Flags().GetString(nameFlag)
	if err != nil {
		return "", false, fmt.Errorf("failed to get name from flag: %w", err)
	}

	return name, true, nil
}

// bindFlagsTargetingAction binds the flags for any command that targets an action.
// This includes the `execute`, `call`, and `batch` commands.
func bindFlagsTargetingAction(cmd *cobra.Command) {
	cmd.Flags().StringP(nameFlag, "n", "", "the target database namespace")
	cmd.Flags().StringP(actionNameFlag, "a", "", "the target action name")
}

// getSelectedAction returns the action name that the user selected.
// It is made to be backwards compatible with the old way of passing the action name as the --action flag.
// In v0.9, we changed this to have the action be passed as the first positional argument in
// all commands that require it.  This function will check if the --action flag was passed, and if it was,
// it will return that.  If it was not passed, it will return the first positional argument, and return the args
// with the first element removed.
func getSelectedAction(cmd *cobra.Command, args []string) (action string, args2 []string, err error) {
	if actionFlagSet(cmd) {
		action, err = cmd.Flags().GetString(actionNameFlag)
		if err != nil {
			return "", nil, err
		}
	} else {
		if len(args) < 1 {
			return "", nil, errors.New("missing action name or SQL statement")
		}

		action = args[0]
		args = args[1:]
	}

	return strings.ToLower(action), args, nil
}

func actionFlagSet(cmd *cobra.Command) bool {
	return cmd.Flags().Changed(actionNameFlag)
}
