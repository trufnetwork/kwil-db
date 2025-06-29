package database

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/csv"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"

	"github.com/spf13/cobra"
)

var (
	supportedBatchFileTypes = []string{"csv"}
)

var (
	batchLong = `Batch executes an action on a database using inputs from a CSV file.

To map a CSV column name to an action input, use the ` + "`--map-inputs`" + ` flag.
The format is ` + "`--map-inputs <csv_column_1>:<action_input_1>,<csv_column_2>:<action_input_2>`." +
		`  If the ` + "`--map-inputs`" + ` flag is not passed, the CSV column name will be used as the action input name.

You can also specify the input values directly using the ` + "`" + `--values` + "`" + ` flag, delimited by a colon.
These values will apply to all inserted rows, and will override the CSV column mappings.

You can specify the namespace with the ` + "`--namespace`" + ` flag.`

	batchExample = `# Given a CSV file with the following contents:
# id,name,age
# 1,john,25
# 2,jane,30
# 3,jack,35

# Executing the ` + "`" + `create_user($user_id, $username, $user_age, $created_at)` + "`" + ` action in the "mydb" database namespace
kwil-cli database batch create_user --path ./users.csv --namespace mydb --map-inputs "id:user_id,name:username,age:user_age" --values created_at:$(date +%s)`
)

// batch is used for batch operations on databases
func batchCmd() *cobra.Command {
	var filePath string
	var csvColumnMappings []string
	var inputValueMappings []string // these override the csv column mappings

	cmd := &cobra.Command{
		Use:        "batch <action>",
		Short:      "Batch execute an action using inputs from a CSV file.",
		Long:       batchLong,
		Example:    batchExample,
		Deprecated: `Use "kwil-cli exec-action" instead.`,
		Args:       cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.DialClient(cmd.Context(), cmd, 0, func(ctx context.Context, cl clientType.Client, conf *config.KwilCliConfig) error {
				namespace, _, err := getSelectedNamespace(cmd)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error getting selected namespace from CLI flags: %w", err))
				}

				action, _, err := getSelectedAction(cmd, args)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error getting selected action: %w", err))
				}

				fileType, err := getFileType(filePath)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error getting file type: %w", err))
				}

				if !isSupportedBatchFileType(fileType) {
					return display.PrintErr(cmd, fmt.Errorf("unsupported file type: %s", fileType))
				}

				file, err := os.Open(filePath)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error opening file: %w", err))
				}

				inputs, err := buildInputs(file, fileType, csvColumnMappings, inputValueMappings)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error building inputs: %w", err))
				}

				tuples, err := buildExecutionInputs(ctx, cl, namespace, action, inputs)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error creating action inputs: %w", err))
				}

				txHash, err := cl.Execute(ctx, namespace, strings.ToLower(action), tuples,
					clientType.WithNonce(nonceOverride), clientType.WithSyncBroadcast(syncBcast))
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error executing action: %w", err))
				}
				// If sycnBcast, and we have a txHash (error or not), do a query-tx.
				if len(txHash) != 0 && syncBcast {
					time.Sleep(500 * time.Millisecond) // otherwise it says not found at first
					resp, err := cl.TxQuery(ctx, txHash)
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("tx query failed: %w", err))
					}
					return display.PrintCmd(cmd, display.NewTxHashAndExecResponse(resp))
				}
				return display.PrintCmd(cmd, display.RespTxHash(txHash))
			})
		},
	}

	bindFlagsTargetingAction(cmd) // --namespace/-n , --action/-a
	cmd.Flags().StringSliceVarP(&csvColumnMappings, "map-inputs", "m", []string{}, "csv column to action parameter mappings (e.g. csv_id:user_id, csv_name:user_name)")
	cmd.Flags().StringSliceVarP(&inputValueMappings, "values", "v", []string{}, "action parameter mappings applied to all executions (e.g. id:123, name:john)")
	cmd.Flags().StringVarP(&filePath, "path", "p", "", "path to the CSV file to use")

	cmd.MarkFlagRequired("path")
	return cmd
}

// buildInputs builds the inputs for the file
func buildInputs(file *os.File, fileType string, columnMappingFlag []string, inputMappings []string) ([]map[string]string, error) {
	switch fileType {
	case "csv":
		return buildCsvInputs(file, columnMappingFlag, inputMappings)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", fileType)
	}
}

func addInputMappings(inputs []map[string]string, inputMappings []string) ([]map[string]string, error) {
	for _, inputMapping := range inputMappings {
		parts := strings.SplitN(inputMapping, ":", 2)
		if len(parts) != 2 {
			return inputs, fmt.Errorf("invalid input mapping: %s", inputMapping)
		}

		ensureInputFormat(&parts[0])

		for _, input := range inputs {
			input[parts[0]] = parts[1]
		}
	}

	return inputs, nil
}

// buildCsvInputs builds the inputs for a csv file
func buildCsvInputs(file *os.File, columnMappings []string, inputMappings []string) ([]map[string]string, error) {
	data, err := csv.Read(file, csv.ContainsHeader)
	if err != nil {
		return nil, fmt.Errorf("error reading csv: %w", err)
	}

	colMappings, err := buildColumnMappings(columnMappings, data.Header)
	if err != nil {
		return nil, fmt.Errorf("error building column mappings: %w", err)
	}

	ins, err := data.BuildInputs(colMappings)
	if err != nil {
		return nil, fmt.Errorf("error building inputs: %w", err)
	}

	ins, err = addInputMappings(ins, inputMappings)
	if err != nil {
		return nil, fmt.Errorf("error adding input mappings: %w", err)
	}

	return ins, nil
}

// buildColumnMappings builds the map used to map columns to inputs
// if the mapping provided is empty, it will use the column name as the input name
// if will dynamically add the $ to the input name if it is not provided
func buildColumnMappings(mappings []string, headers []string) (map[string]string, error) {
	if len(mappings) > 0 {
		return convertColumnMappings(mappings)
	}

	return convertHeadersToColumnMappings(headers), nil
}

func convertHeadersToColumnMappings(headers []string) map[string]string {
	res := make(map[string]string)

	for _, header := range headers {
		actionInput := header

		ensureInputFormat(&actionInput)

		res[header] = actionInput
	}

	return res
}

// convertColumnMappings converts a list of mappings in the form of "id:$id" to a map
func convertColumnMappings(mappings []string) (map[string]string, error) {
	res := make(map[string]string, len(mappings))

	for _, mapping := range mappings {
		parts := strings.Split(mapping, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid mapping: %s", mapping)
		}

		ensureInputFormat(&parts[1])
		res[parts[0]] = parts[1]
	}

	return res, nil
}

func ensureInputFormat(in *string) {
	if !strings.HasPrefix(*in, "$") {
		*in = "$" + *in
	}
}

func isSupportedBatchFileType(fileType string) bool {
	return slices.Contains(supportedBatchFileTypes, fileType)
}

func getFileType(path string) (string, error) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid file path: %s", path)
	}

	return parts[len(parts)-1], nil
}
