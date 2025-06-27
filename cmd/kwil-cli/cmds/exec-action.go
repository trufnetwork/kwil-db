package cmds

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/cmds/common"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/csv"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
)

var (
	execActionLong = `Execute an action against the database.
	
This command executes an action against the database. It is meant to only call actions that write to the database,
and will not return any results from the action. If you need to see results, use the 'call-action' command instead.

This command requires a private key, and it will author a transaction from the private key to the network.

Actions can be given any mix of positional and named parameters in order to execute an action one. If you wish
to batch execute an action, you can provide a CSV file, and map the CSV column names to either the action parameter
name or the action parameter position. If any named parameters are specified while using a CSV file, then all batch
action calls will set the named parameter to the same value.`

	execActionExample = `# Execute the action 'register' with no parameters
kwil-cli exec-action register

# Execute the action 'register' with a positional parameter

kwil-cli exec-action register text:satoshi

# Execute the action 'register' with a one positional parameter and one named parameter
# Assume the action signature REGISTER($name text, $age int)
kwil-cli exec-action register text:satoshi --param age:int=30

# Execute the action 'register' with a CSV file
# Assume the action signature REGISTER($name text, $age int), and
# the CSV file has the following contents:
# name,age
# satoshi,30
kwil-cli exec-action register --csv /path/to/file.csv --csv-mapping name:0 --csv-mapping age:1

# Execute the action 'register' with a CSV file, but override all ages to be 10
# Assume the same action signature and CSV file as above
kwil-cli exec-action register --csv /path/to/file.csv --csv-mapping name:0 --param age:int=10`
)

func execActionCmd() *cobra.Command {
	var namespace, csvFile string
	var namedParams, csvParams []string

	cmd := &cobra.Command{
		Use:     "exec-action",
		Short:   "Execute an action against the database.",
		Long:    execActionLong,
		Example: execActionExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return display.PrintErr(cmd, fmt.Errorf("no action provided"))
			}

			txFlags, err := common.GetTxFlags(cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			if len(args) > 1 && csvFile != "" {
				return display.PrintErr(cmd, fmt.Errorf("cannot specify both CSV file and positional parameters"))
			}

			// if csv file is specified, it is a batch action
			if csvFile != "" {
				path, err := helpers.ExpandPath(csvFile)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				file, err := os.Open(path)
				if err != nil {
					return display.PrintErr(cmd, err)
				}
				defer file.Close()

				csv, err := csv.Read(file, csv.ContainsHeader)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				if len(csv.Records) == 0 {
					return display.PrintErr(cmd, errors.New("no records found in CSV file"))
				}

				return client.DialClient(cmd.Context(), cmd, 0, func(ctx context.Context, cl clientType.Client, conf *config.KwilCliConfig) error {
					// if named params are specified (they are here with csv), we need to query the action to find their positions
					paramList, err := GetParamList(ctx, func(ctx context.Context, query string, args map[string]any) (*types.QueryResult, error) {
						return cl.Query(ctx, query, args, false)
					}, namespace, args[0])
					if err != nil {
						return display.PrintErr(cmd, err)
					}

					inputs, err := csvToParams(paramList, csv, csvParams, namedParams)
					if err != nil {
						return display.PrintErr(cmd, err)
					}

					tx, err := cl.Execute(ctx, namespace, args[0], inputs, clientType.WithNonce(txFlags.NonceOverride), clientType.WithSyncBroadcast(txFlags.SyncBroadcast))
					if err != nil {
						return display.PrintErr(cmd, err)
					}

					return common.DisplayTxResult(ctx, cl, tx, cmd)
				})
			}

			// positional parameters
			var params []any
			for _, p := range args[1:] {
				_, param, err := parseTypedParam(p)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				params = append(params, param)
			}

			return client.DialClient(cmd.Context(), cmd, 0, func(ctx context.Context, cl clientType.Client, conf *config.KwilCliConfig) error {
				// if named params are specified, we need to query the action to find their positions
				if len(namedParams) > 0 {
					paramList, err := GetParamList(ctx, func(ctx context.Context, query string, args map[string]any) (*types.QueryResult, error) {
						return cl.Query(ctx, query, args, false)
					}, namespace, args[0])
					if err != nil {
						return display.PrintErr(cmd, err)
					}

					_, values, pos, err := getNamedParams(paramList, namedParams)
					if err != nil {
						return display.PrintErr(cmd, err)
					}
					// there is a case where an action has 3 parameters, but only 2 are specified positionally,
					// with the 3rd being specified as a named parameter. In this case, we need to ensure that the
					// length of params is the same as the length of actionParams
					for i, p := range pos {
						if p >= len(params) {
							params = append(params, make([]any, p-len(params)+1)...)
						}

						params[p] = values[i]
					}
				}

				tx, err := cl.Execute(ctx, namespace, args[0], [][]any{params}, clientType.WithNonce(txFlags.NonceOverride), clientType.WithSyncBroadcast(txFlags.SyncBroadcast))
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				return common.DisplayTxResult(ctx, cl, tx, cmd)
			})
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "namespace to execute the action in")
	// this has to be StringArrayVar because if the user is passing an array, it will contain a comma, but it itself is a single parameter.
	// If we use StringSliceVar, it will split the array into multiple parameters.
	cmd.Flags().StringArrayVarP(&namedParams, "param", "p", nil, `named parameters that will override any positional or CSV parameters. format: "name:type=value"`)
	cmd.Flags().StringVar(&csvFile, "csv", "", "CSV file containing the parameters to pass to the action")
	cmd.Flags().StringSliceVarP(&csvParams, "csv-mapping", "m", nil, `mapping of CSV columns to action parameters. format: "csv_column:action_param_name" OR "csv_column:action_param_position"`)
	common.BindTxFlags(cmd)
	return cmd
}

type actionParamInfo struct {
	datatype *types.DataType
	pos      int
}

func actionParamInfoMap(p []NamedParameter) map[string]*actionParamInfo {
	m := make(map[string]*actionParamInfo)
	for i, p := range p {
		m[strings.TrimPrefix(p.Name, "$")] = &actionParamInfo{
			datatype: p.Type,
			pos:      i,
		}
	}

	return m
}

// csvToParams takes a CSV file, a mapping of CSV columns to action parameters, and named parameters and returns the ordered parameters.
func csvToParams(namedParams []NamedParameter, c *csv.CSV, mapping []string, named []string) ([][]any, error) {
	// we need to take the CSV file and its mappings and match that up with the action parameters.
	splitMapping, err := splitMapping(mapping)
	if err != nil {
		return nil, err
	}

	// actionParamTypeMap maps the name of the action parameter to its type
	actionParamTypeMap := actionParamInfoMap(namedParams)

	namedVals, values, _, err := getNamedParams(namedParams, named)
	if err != nil {
		return nil, fmt.Errorf("error getting named parameters: %w", err)
	}

	// for all found namedVals in the named params, we need to ensure they arent specified in the CSV mapping
	for _, name := range namedVals {
		if _, ok := splitMapping[name]; ok {
			return nil, fmt.Errorf(`parameter "%s" cannot be both mapped to a CSV column and a named parameter`, name)
		}
	}

	// now, we will construct a 2d array of parameters to pass to the action.
	vals := make([][]any, len(c.Records))
	for i := range c.Records {
		vals[i] = make([]any, len(namedParams))
	}

	for csvColName, paramName := range splitMapping {
		idx := c.GetColumnIndex(csvColName)
		if idx == -1 {
			return nil, fmt.Errorf("column %s not found in CSV file", csvColName)
		}

		getInfo := func(name string) (*actionParamInfo, error) {
			// if paramName is an integer, it is a positional parameter
			pos, err := strconv.ParseInt(name, 10, 64)
			if err == nil {
				pos-- // 1-indexed to 0-indexed
				if int(pos) >= len(namedParams) {
					return nil, fmt.Errorf("invalid position %d", pos)
				}

				return &actionParamInfo{
					datatype: namedParams[pos].Type,
					pos:      int(pos),
				}, nil
			}

			// if it is not an integer, it is a named parameter
			info, ok := actionParamTypeMap[name]
			if !ok {
				return nil, fmt.Errorf(`action does not have a parameter named "%s"`, name)
			}

			return info, nil
		}

		for i, rec := range c.Records {
			info, err := getInfo(paramName)
			if err != nil {
				return nil, fmt.Errorf("error getting parameter info: %w", err)
			}

			val, err := stringAndTypeToVal(rec[idx], info.datatype)
			if err != nil {
				return nil, fmt.Errorf("error converting value: %w", err)
			}

			vals[i][info.pos] = val
		}
	}

	// now we need to fill in the named parameters
	for i, name := range namedVals {
		info, ok := actionParamTypeMap[name]
		if !ok {
			return nil, fmt.Errorf(`action does not have a parameter named "%s"`, name)
		}

		for j := range vals {
			vals[j][info.pos] = values[i]
		}
	}

	return vals, nil
}

// splitMapping takes a list of strings of the form "csv_column:action_param" and returns the two parts.
func splitMapping(mapping []string) (map[string]string, error) {
	m := make(map[string]string)
	for _, s := range mapping {
		parts := strings.Split(s, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid mapping: %s", s)
		}

		m[parts[0]] = parts[1]
	}

	return m, nil
}

// getNamedParams gets the named parameters.
// It returns the values, their positions in the action, and an error if any.
func getNamedParams(actionNamedParams []NamedParameter, unparsedNamedValues []string) (names []string, values []any, positions []int, err error) {
	parsedParams, err := parseParams(unparsedNamedValues)
	if err != nil {
		return nil, nil, nil, err
	}

	actionParams := actionParamInfoMap(actionNamedParams)

	for name, val := range parsedParams {
		act, ok := actionParams[name]
		if !ok {
			return nil, nil, nil, fmt.Errorf(`action does not have a parameter named "%s"`, name)
		}

		names = append(names, name)
		values = append(values, val)
		positions = append(positions, act.pos)
	}

	return names, values, positions, nil
}

// parseTypedParam takes a string of form type:value and returns the value as the correct type.
func parseTypedParam(param string) (datatype *types.DataType, val any, err error) {
	if param == NullLiteral {
		return types.NullType.Copy(), nil, nil
	}

	parts := strings.SplitN(param, ":", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf(`invalid parameter format: "%s"; parameters must be of format type:value (e.g. text:"Hello World!")`, param)
	}

	datatype, err = types.ParseDataType(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf(`invalid parameter type: "%s"; error: %w`, parts[0], err)
	}

	val, err = stringAndTypeToVal(parts[1], datatype)
	if err != nil {
		return nil, nil, fmt.Errorf(`invalid parameter value: "%s"; error: %w`, parts[1], err)
	}

	return datatype, val, nil
}

// GetParamList returns the list of parameters for an action in a namespace.
func GetParamList(ctx context.Context,
	query func(ctx context.Context, query string, args map[string]any) (*types.QueryResult, error),
	namespace, action string) ([]NamedParameter, error) {
	if namespace == "" {
		namespace = engine.DefaultNamespace
	}

	res, err := query(ctx, "{info}SELECT parameter_names, parameter_types FROM actions WHERE namespace = $namespace AND name = $action", map[string]any{
		"namespace": namespace,
		"action":    action,
	})
	if err != nil {
		return nil, err
	}

	if len(res.Values) == 0 {
		return nil, fmt.Errorf(`action "%s" not found in namespace "%s"`, action, namespace)
	}
	if len(res.Values) > 1 {
		return nil, fmt.Errorf(`action "%s" is ambiguous in namespace "%s"`, action, namespace)
	}

	var paramNames []string
	var paramTypes []*types.DataType
	switch res.Values[0][0].(type) {
	case nil:
		return nil, nil // no inputs
	case []string:
		paramNames = res.Values[0][0].([]string)
		typs := res.Values[0][1].([]string)
		for _, t := range typs {
			dt, err := types.ParseDataType(t)
			if err != nil {
				return nil, err
			}
			paramTypes = append(paramTypes, dt)
		}
	case []any:
		for _, v := range res.Values[0][0].([]any) {
			paramNames = append(paramNames, v.(string))
		}

		for _, v := range res.Values[0][1].([]any) {
			dt, err := types.ParseDataType(v.(string))
			if err != nil {
				return nil, err
			}
			paramTypes = append(paramTypes, dt)
		}
	default:
		return nil, fmt.Errorf("unexpected type %T when querying action parameters. this is a bug", res.Values[0][0])
	}

	if len(paramNames) != len(paramTypes) {
		return nil, errors.New("mismatched parameter names and types")
	}

	params := make([]NamedParameter, len(paramNames))
	for i, name := range paramNames {
		params[i] = NamedParameter{
			Name: name,
			Type: paramTypes[i],
		}
	}

	return params, nil
}

type NamedParameter struct {
	Name string
	Type *types.DataType
}
