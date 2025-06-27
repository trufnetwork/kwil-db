package database

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"

	"github.com/spf13/cobra"
)

var (
	callLong = `Call a ` + "`view`" + ` action, returning the result.

` + "`view`" + ` actions are read-only actions that do not require gas to execute.  They are
the primary way to query the state of a database. The ` + "`call`" + ` command is used to call
a ` + "`view`" + ` action on a database.  It takes the action name as the first positional
argument, and the action inputs as all subsequent arguments.

To specify a action input, you first need to specify the input name, then the input value, delimited by a colon.
For example, for action ` + "`get_user($username)`" + `, you would specify the action as follows:

` + "`call get_user username:satoshi`" + `

You specify the database namespace in which to execute this with the ` + "`--namespace` flag. " + `

If you are interacting with a Kwil gateway, you can also pass the ` + "`--authenticate`" + ` flag to authenticate the call with your private key.`

	callExample = `# Calling the ` + "`get_user($username)`" + ` action on the "somedb" namespace
kwil-cli database call get_user --namespace somedb username:satoshi

# Calling the ` + "`get_user($username)`" + ` action on a database using a namespace, authenticating with a private key
kwil-cli database call get_user --namespace somedb username:satoshi --authenticate`
)

func callCmd() *cobra.Command {
	var gwAuth, logs bool

	cmd := &cobra.Command{
		Use:        "call <action> <parameter_1:value_1> <parameter_2:value_2> ...",
		Short:      "Call a 'view' action, returning the result.",
		Long:       callLong,
		Example:    callExample,
		Deprecated: `Use "kwil-cli call-action" instead.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// AuthenticatedCalls specifies that the call should be authenticated with the private key
			// if the call is made to the Kwild node with private mode enabled. Else, no authentication is required.
			dialFlags := client.AuthenticatedCalls
			if gwAuth {
				// If the call is made to a gateway, the call should be authenticated with the private key.
				dialFlags = client.UsingGateway
			}

			return client.DialClient(cmd.Context(), cmd, dialFlags, func(ctx context.Context, clnt clientType.Client, conf *config.KwilCliConfig) error {
				namespace, _, err := getSelectedNamespace(cmd)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error getting selected namespace from CLI flags: %w", err))
				}

				action, args, err := getSelectedAction(cmd, args)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error getting selected action: %w", err))
				}

				inputs, err := parseInputs(args)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error getting inputs: %w", err))
				}

				tuples, err := buildExecutionInputs(ctx, clnt, namespace, action, []map[string]string{inputs})
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error creating action inputs: %w", err))
				}

				if len(tuples) == 0 {
					tuples = append(tuples, []any{})
				}
				if len(tuples) > 1 {
					return display.PrintErr(cmd, errors.New("only one set of inputs can be provided to call"))
				}

				data, err := clnt.Call(ctx, namespace, action, tuples[0])
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("error calling action: %w", err))
				}

				if data == nil {
					data = &types.CallResult{}
				}

				return display.PrintCmd(cmd, &respCall{
					Data:      data,
					PrintLogs: logs,
				})
			})
		},
	}

	bindFlagsTargetingAction(cmd) // --namespace/-n , --action/-a
	cmd.Flags().BoolVar(&gwAuth, "authenticate", false, "authenticate signals that the call is being made to a gateway and should be authenticated with the private key")
	cmd.Flags().BoolVar(&logs, "logs", false, "result will include logs from notices raised during the call")
	return cmd
}

type respCall struct {
	Data      *types.CallResult
	PrintLogs bool
}

func (r *respCall) MarshalJSON() ([]byte, error) {
	if !r.PrintLogs {
		return json.Marshal(r.Data.QueryResult) // this is for backwards compatibility
	}

	bts, err := json.Marshal(r.Data)
	if err != nil {
		return nil, err
	}

	return bts, nil
}

func (r *respCall) MarshalText() (text []byte, err error) {
	if !r.PrintLogs {
		return recordsToTable(r.Data.QueryResult.ExportToStringMap(), nil), nil
	}

	bts := recordsToTable(r.Data.QueryResult.ExportToStringMap(), nil)

	if len(r.Data.Logs) > 0 {
		bts = append(bts, []byte("\n\nLogs:")...)
		bts = append(bts, []byte(r.Data.Logs)...)
	}

	return bts, nil
}

// buildExecutionInputs will build the inputs for an action execution/call.
func buildExecutionInputs(ctx context.Context, client clientType.Client, namespace string, action string, inputs []map[string]string) ([][]any, error) {
	params, err := GetParamList(ctx, func(ctx context.Context, query string, args map[string]any) (*types.QueryResult, error) {
		return client.Query(ctx, query, args, false)
	}, namespace, action)
	if err != nil {
		return nil, err
	}

	var results [][]any
	for _, in := range inputs {
		var tuple []any
		for _, p := range params {
			val, ok := in[p.Name]
			if !ok {
				tuple = append(tuple, nil)
				continue
			}

			encoded, err := encodeBasedOnType(p.Type, val)
			if err != nil {
				return nil, err
			}

			tuple = append(tuple, encoded)
		}

		results = append(results, tuple)
	}

	return results, nil
}

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

// decodeMany attempts to parse command-line inputs as base64 encoded values.
func decodeMany(inputs []string) ([][]byte, bool) {
	b64Arr := [][]byte{}
	b64Ok := true
	for _, s := range inputs {
		// in the CLI, if data has suffix ;b64, it is base64 encoded
		if strings.HasSuffix(s, "#b64") {
			s = strings.TrimSuffix(s, "#b64")
		} else {
			b64Ok = false
			break
		}

		bts, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			b64Ok = false
			break
		}
		b64Arr = append(b64Arr, bts)
	}

	return b64Arr, b64Ok
}

// FormatByteEncoding formats bytes to be read on the CLI.
func FormatByteEncoding(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// encodeBasedOnType will encode the input value based on the type of the input.
// If it is an array, it will properly split the input value by commas.
// If the input value is base64 encoded, it will decode it.
func encodeBasedOnType(t *types.DataType, v string) (any, error) {
	if t.IsArray {
		split, err := splitIgnoringQuotedCommas(v)
		if err != nil {
			return nil, err
		}

		// attempt to decode base64 encoded values
		b64Arr, b64Ok := decodeMany(split)
		if b64Ok {
			return b64Arr, nil
		}

		return split, nil
	}

	// attempt to decode base64 encoded values
	bts, ok := decodeMany([]string{v})
	if ok {
		return bts[0], nil
	}

	// otherwise, just keep it as string and let the server handle it
	return v, nil
}

// splitIgnoringQuotedCommas splits a string by commas, but ignores commas that are inside single or double quotes.
// It will return an error if there are unclosed quotes.
func splitIgnoringQuotedCommas(input string) ([]string, error) {
	var result []string
	var currentToken []rune
	inSingleQuote := false
	inDoubleQuote := false

	for _, char := range input {
		switch char {
		case '\'':
			if !inDoubleQuote { // Toggle single quote flag if not inside double quotes
				inSingleQuote = !inSingleQuote
				continue // Skip appending this quote character to token
			}
			currentToken = append(currentToken, char)
		case '"':
			if !inSingleQuote { // Toggle double quote flag if not inside single quotes
				inDoubleQuote = !inDoubleQuote
				continue // Skip appending this quote character to token
			}
			currentToken = append(currentToken, char)
		case ',':
			if inSingleQuote || inDoubleQuote { // If inside quotes, treat comma as a normal character
				currentToken = append(currentToken, char)
			} else { // Otherwise, it's a delimiter
				result = append(result, string(currentToken))
				currentToken = []rune{}
			}
		default:
			currentToken = append(currentToken, char)
		}
	}

	// Append the last token
	result = append(result, string(currentToken))

	if inSingleQuote || inDoubleQuote {
		return nil, errors.New("unclosed quote in array inputs")
	}

	return result, nil
}
