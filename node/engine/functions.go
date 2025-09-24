package engine

import (
	"fmt"
	"strings"

	"github.com/trufnetwork/kwil-db/core/types"
)

var (
	Functions = map[string]FunctionDefinition{
		"abs": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.IntType) && args[0].Name != types.NumericStr {
					return nil, fmt.Errorf("%w: expected argument to be int or decimal, got %s", ErrType, args[0].String())
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("abs"),
		},
		"error": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				// technically error returns nothing, but to allow it to be used in the query planner
				// we have it return text. It doesn't really matter because it will cancel action execution.
				return types.TextType, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				def, err := defaultFormat("error")(inputs)
				if err != nil {
					return "", err
				}

				return def + "::text", nil
			},
		},
		"parse_unix_timestamp": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// two args, both text
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				if !args[1].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[1])
				}

				return decimal16_6, nil
			},
			PGFormatFunc: defaultFormat("parse_unix_timestamp"),
		},
		"format_unix_timestamp": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// first arg must be decimal(16, 6), second arg must be text
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[0].Equals(decimal16_6) {
					return nil, wrapErrArgumentType(decimal16_6, args[0])
				}

				if !args[1].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[1])
				}

				return types.TextType, nil
			},
			PGFormatFunc: defaultFormat("format_unix_timestamp"),
		},
		"notice": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				// technically error returns nothing, but for backwards compatibility with SELECT CASE we return null.
				// It doesn't really matter, since error will cancel execution anyways.
				return types.NullType, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				return "", fmt.Errorf(`%w: "notice" cannot be used in SQL statements`, ErrIllegalFunctionUsage)
			},
		},
		"uuid_generate_v5": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// first argument must be a uuid, second argument must be text
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[0].Equals(types.UUIDType) {
					return nil, wrapErrArgumentType(types.UUIDType, args[0])
				}

				if !args[1].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[1])
				}

				return types.UUIDType, nil
			},
			PGFormatFunc: defaultFormat("uuid_generate_v5"),
		},
		// a special function that generates a UUID using a fixed namespace
		"uuid_generate_kwil": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// 1 argument, must be text
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.UUIDType, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				return "uuid_generate_v5('a247cac1-d817-4949-bac7-dc4b1dc41d09'::uuid," + inputs[0] + ")", nil
			},
		},
		"encode": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// first must be blob, second must be text
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[0].Equals(types.ByteaType) {
					return nil, wrapErrArgumentType(types.ByteaType, args[0])
				}

				if !args[1].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[1])
				}

				return types.TextType, nil
			},
			PGFormatFunc: defaultFormat("encode"),
		},
		"decode": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// first must be text, second must be text
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				if !args[1].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[1])
				}

				return types.ByteaType, nil
			},
			PGFormatFunc: defaultFormat("decode"),
		},
		"digest": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// first must be either text or blob, second must be text
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[0].Equals(types.TextType) && !args[0].Equals(types.ByteaType) {
					return nil, fmt.Errorf("%w: expected first argument to be text or blob, got %s", ErrType, args[0].String())
				}

				if !args[1].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[1])
				}

				return types.ByteaType, nil
			},
			PGFormatFunc: defaultFormat("digest"),
		},
		// array functions
		"array_append": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[0].IsArray {
					return nil, fmt.Errorf("%w: expected first argument to be an array, got %s", ErrType, args[0].String())
				}

				if args[1].IsArray {
					return nil, fmt.Errorf("%w: expected second argument to be a scalar, got %s", ErrType, args[1].String())
				}

				if !strings.EqualFold(args[0].Name, args[1].Name) {
					return nil, fmt.Errorf("%w: append type must be equal to scalar array type. array type: %s append type: %s", ErrType, args[0].Name, args[1].Name)
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("array_append"),
		},
		"array_prepend": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if args[0].IsArray {
					return nil, fmt.Errorf("%w: expected first argument to be a scalar, got %s", ErrType, args[0].String())
				}

				if !args[1].IsArray {
					return nil, fmt.Errorf("%w: expected second argument to be an array, got %s", ErrType, args[1].String())
				}

				if !strings.EqualFold(args[0].Name, args[1].Name) {
					return nil, fmt.Errorf("%w: prepend type must be equal to scalar array type. array type: %s prepend type: %s", ErrType, args[1].Name, args[0].Name)
				}

				return args[1], nil
			},
			PGFormatFunc: defaultFormat("array_prepend"),
		},
		"array_cat": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[0].IsArray {
					return nil, fmt.Errorf("%w: expected first argument to be an array, got %s", ErrType, args[0].String())
				}

				if !args[1].IsArray {
					return nil, fmt.Errorf("%w: expected second argument to be an array, got %s", ErrType, args[1].String())
				}

				if !strings.EqualFold(args[0].Name, args[1].Name) {
					return nil, fmt.Errorf("%w: expected both arrays to be of the same scalar type, got %s and %s", ErrType, args[0].Name, args[1].Name)
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("array_cat"),
		},
		"array_length": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) < 1 || len(args) > 2 {
					return nil, fmt.Errorf("invalid number of arguments: expected 1 or 2, got %d", len(args))
				}

				if !args[0].IsArray {
					return nil, fmt.Errorf("%w: expected argument to be an array, got %s", ErrType, args[0].String())
				}

				if len(args) == 2 && !args[1].Equals(types.IntType) {
					return nil, wrapErrArgumentType(types.IntType, args[1])
				}

				return types.IntType, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				if len(inputs) == 1 {
					return fmt.Sprintf("array_length(%s, 1)", inputs[0]), nil
				}
				return fmt.Sprintf("array_length(%s, %s)", inputs[0], inputs[1]), nil
			},
		},
		"array_remove": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[0].IsArray {
					return nil, fmt.Errorf("%w: expected first argument to be an array, got %s", ErrType, args[0].String())
				}

				if args[1].IsArray {
					return nil, fmt.Errorf("%w: expected second argument to be a scalar, got %s", ErrType, args[1].String())
				}

				if !strings.EqualFold(args[0].Name, args[1].Name) {
					return nil, fmt.Errorf("%w: remove type must be equal to scalar array type. array type: %s remove type: %s", ErrType, args[0].Name, args[1].Name)
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("array_remove"),
		},
		// string functions
		// the main SQL string functions defined here: https://www.postgresql.org/docs/16.1/functions-string.html
		"bit_length": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.IntType, nil
			},
			PGFormatFunc: defaultFormat("bit_length"),
		},
		"char_length": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.IntType, nil
			},
			PGFormatFunc: defaultFormat("char_length"),
		},
		"character_length": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.IntType, nil
			},
			PGFormatFunc: defaultFormat("character_length"),
		},
		"length": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.IntType, nil
			},
			PGFormatFunc: defaultFormat("length"),
		},
		"lower": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.TextType, nil
			},
			PGFormatFunc: defaultFormat("lower"),
		},
		"lpad": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				//can have 2-3 args. 1 and 3 must be text, 2 must be int
				if len(args) < 2 || len(args) > 3 {
					return nil, fmt.Errorf("invalid number of arguments: expected 2 or 3, got %d", len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				if !args[1].Equals(types.IntType) {
					return nil, wrapErrArgumentType(types.IntType, args[1])
				}

				if len(args) == 3 && !args[2].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[2])
				}

				return types.TextType, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				str := strings.Builder{}
				str.WriteString("lpad(")
				str.WriteString(inputs[0])
				str.WriteString(", ")
				str.WriteString(inputs[1])
				str.WriteString("::INT4")
				if len(inputs) == 3 {
					str.WriteString(", ")
					str.WriteString(inputs[2])
				}
				str.WriteString(")")

				return str.String(), nil
			},
		},
		"ltrim": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				//can have 1 or 2 args. both must be text
				if len(args) < 1 || len(args) > 2 {
					return nil, fmt.Errorf("invalid number of arguments: expected 1 or 2, got %d", len(args))
				}

				for _, arg := range args {
					if !arg.Equals(types.TextType) {
						return nil, wrapErrArgumentType(types.TextType, arg)
					}
				}

				return types.TextType, nil
			},
			PGFormatFunc: defaultFormat("ltrim"),
		},
		"octet_length": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.IntType, nil
			},
			PGFormatFunc: defaultFormat("octet_length"),
		},
		"overlay": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// 3-4 arguments. 1 and 2 must be text, 3 must be int, 4 must be int
				if len(args) < 3 || len(args) > 4 {
					return nil, fmt.Errorf("invalid number of arguments: expected 3 or 4, got %d", len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				if !args[1].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[1])
				}

				if !args[2].Equals(types.IntType) {
					return nil, wrapErrArgumentType(types.IntType, args[2])
				}

				if len(args) == 4 && !args[3].Equals(types.IntType) {
					return nil, wrapErrArgumentType(types.IntType, args[3])
				}

				return types.TextType, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				str := strings.Builder{}
				str.WriteString("overlay(")
				str.WriteString(inputs[0])
				str.WriteString(" placing ")
				str.WriteString(inputs[1])
				str.WriteString(" from ")
				str.WriteString(inputs[2])
				str.WriteString("::INT4")
				if len(inputs) == 4 {
					str.WriteString(" for ")
					str.WriteString(inputs[3])
					str.WriteString("::INT4")
				}
				str.WriteString(")")

				return str.String(), nil
			},
		},
		"position": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// 2 arguments. both must be text
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				for _, arg := range args {
					if !arg.Equals(types.TextType) {
						return nil, wrapErrArgumentType(types.TextType, arg)
					}
				}

				return types.IntType, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				return fmt.Sprintf("position(%s in %s)", inputs[0], inputs[1]), nil
			},
		},
		"rpad": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// 2-3 args, 1 and 3 must be text, 2 must be int
				if len(args) < 2 || len(args) > 3 {
					return nil, fmt.Errorf("invalid number of arguments: expected 2 or 3, got %d", len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				if !args[1].Equals(types.IntType) {
					return nil, wrapErrArgumentType(types.IntType, args[1])
				}

				if len(args) == 3 && !args[2].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[2])
				}

				return types.TextType, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				str := strings.Builder{}
				str.WriteString("rpad(")
				str.WriteString(inputs[0])
				str.WriteString(", ")
				str.WriteString(inputs[1])
				str.WriteString("::INT4")
				if len(inputs) == 3 {
					str.WriteString(", ")
					str.WriteString(inputs[2])
				}
				str.WriteString(")")

				return str.String(), nil
			},
		},
		"rtrim": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// 1-2 args, both must be text
				if len(args) < 1 || len(args) > 2 {
					return nil, fmt.Errorf("invalid number of arguments: expected 1 or 2, got %d", len(args))
				}

				for _, arg := range args {
					if !arg.Equals(types.TextType) {
						return nil, wrapErrArgumentType(types.TextType, arg)
					}
				}

				return types.TextType, nil
			},
			PGFormatFunc: defaultFormat("rtrim"),
		},
		"substring": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// 2-3 args, 1 must be text, 2 and 3 must be int
				// Postgres supports several different usages of substring, however Kwil only supports 1.
				// In Postgres, substring can be used to both impose a string over a range, or to perform
				// regex matching. Kwil only supports the former, as regex matching is not supported.
				// Therefore, the second and third arguments must be integers.
				if len(args) < 2 || len(args) > 3 {
					return nil, fmt.Errorf("invalid number of arguments: expected 2 or 3, got %d", len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				if !args[1].Equals(types.IntType) {
					return nil, wrapErrArgumentType(types.IntType, args[1])
				}

				if len(args) == 3 && !args[2].Equals(types.IntType) {
					return nil, wrapErrArgumentType(types.IntType, args[2])
				}

				return types.TextType, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				str := strings.Builder{}
				str.WriteString("substring(")
				str.WriteString(inputs[0])
				str.WriteString(" from ")
				str.WriteString(inputs[1])
				str.WriteString("::INT4")
				if len(inputs) == 3 {
					str.WriteString(" for ")
					str.WriteString(inputs[2])
					str.WriteString("::INT4")
				}
				str.WriteString(")")

				return str.String(), nil
			},
		},
		"trim": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// 1-2 args, both must be text
				if len(args) < 1 || len(args) > 2 {
					return nil, fmt.Errorf("invalid number of arguments: expected 1 or 2, got %d", len(args))
				}

				for _, arg := range args {
					if !arg.Equals(types.TextType) {
						return nil, wrapErrArgumentType(types.TextType, arg)
					}
				}

				return types.TextType, nil
			},
			PGFormatFunc: defaultFormat("trim"),
		},
		"upper": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.TextType, nil
			},
			PGFormatFunc: defaultFormat("upper"),
		},
		"format": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) < 1 {
					return nil, fmt.Errorf("invalid number of arguments: expected at least 1, got %d", len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.TextType, nil
			},
			PGFormatFunc: defaultFormat("format"),
		},
		"coalesce": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) < 1 {
					return nil, fmt.Errorf("invalid number of arguments: expected at least 1, got %d", len(args))
				}

				firstType := args[0]
				// all arguments must be the same type
				for i, arg := range args {
					if !firstType.Equals(arg) {
						return nil, fmt.Errorf("%w: all arguments must be the same type, but argument %d is %s and argument 1 is %s", ErrType, i+1, arg.String(), firstType.String())
					}
				}

				return firstType, nil
			},
			PGFormatFunc: defaultFormat("coalesce"),
		},
		"greatest": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) < 2 {
					return nil, fmt.Errorf("invalid number of arguments: expected at least 2, got %d", len(args))
				}

				if !args[0].IsNumeric() || !args[1].IsNumeric() {
					return nil, fmt.Errorf("%w: expected both arguments to be numeric, got %s and %s", ErrType, args[0].String(), args[1].String())
				}

				// all arguments must be the same type
				for i, arg := range args {
					if !args[0].Equals(arg) {
						return nil, fmt.Errorf("%w: all arguments must be the same type, but argument %d is %s and argument 1 is %s", ErrType, i+1, arg.String(), args[0].String())
					}
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("greatest"),
		},
		"least": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) < 2 {
					return nil, fmt.Errorf("invalid number of arguments: expected at least 2, got %d", len(args))
				}

				if !args[0].IsNumeric() || !args[1].IsNumeric() {
					return nil, fmt.Errorf("%w: expected both arguments to be numeric, got %s and %s", ErrType, args[0].String(), args[1].String())
				}

				// all arguments must be the same type
				for i, arg := range args {
					if !args[0].Equals(arg) {
						return nil, fmt.Errorf("%w: all arguments must be the same type, but argument %d is %s and argument 1 is %s", ErrType, i+1, arg.String(), args[0].String())
					}
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("least"),
		},
		"nullif": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 2 {
					return nil, fmt.Errorf("invalid number of arguments: expected 2, got %d", len(args))
				}

				if !args[0].Equals(args[1]) {
					return nil, fmt.Errorf("%w: both arguments must be the same type, but got %s and %s", ErrType, args[0].String(), args[1].String())
				}

				if args[0].EqualsStrict(types.NullType) && args[1].EqualsStrict(types.NullType) {
					return nil, fmt.Errorf("%w: both arguments to NULLIF cannot be null", ErrType)
				}

				// the return type is the first type that is not null
				if args[0].EqualsStrict(types.NullType) {
					return args[1], nil
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("nullif"),
		},
		// Aggregate functions
		"count": &AggregateFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) > 1 {
					return nil, fmt.Errorf("invalid number of arguments: expected at most 1, got %d", len(args))
				}

				return types.IntType, nil
			},
			PGFormatFunc: func(inputs []string, distinct bool) (string, error) {
				if len(inputs) == 0 {
					if distinct {
						return "", fmt.Errorf("count(DISTINCT *) is not supported")
					}
					return "count(*)", nil
				}
				if distinct {
					return fmt.Sprintf("count(DISTINCT %s)", inputs[0]), nil
				}

				return fmt.Sprintf("count(%s)", inputs[0]), nil
			},
		},
		"sum": &AggregateFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// per https://www.postgresql.org/docs/current/datatype-numeric.html#DATATYPE-NUMERIC-TABLE
				// the result of sum will be made a decimal(1000, 0)
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].IsNumeric() {
					return nil, fmt.Errorf("%w: expected argument to be numeric, got %s", ErrType, args[0].String())
				}

				var retType *types.DataType
				switch {
				case args[0].Equals(types.IntType):
					retType = decimal1000.Copy()
				case args[0].Name == types.NumericStr:
					retType = args[0].Copy()
					retType.Metadata[0] = 1000 // max precision
				default:
					panic(fmt.Sprintf("unexpected numeric type: %s", args[0].String()))
				}

				return retType, nil
			},
			PGFormatFunc: func(inputs []string, distinct bool) (string, error) {
				if distinct {
					return fmt.Sprintf("sum(DISTINCT %s)", inputs[0]), nil
				}
				return fmt.Sprintf("sum(%s)", inputs[0]), nil
			},
		},
		"min": &AggregateFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// as per postgres docs, min can take any numeric or string type: https://www.postgresql.org/docs/8.0/functions-aggregate.html
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].IsNumeric() && !args[0].Equals(types.TextType) {
					return nil, fmt.Errorf("%w: expected argument to be numeric or text, got %s", ErrType, args[0].String())
				}

				return args[0], nil
			},
			PGFormatFunc: func(inputs []string, distinct bool) (string, error) {
				if distinct {
					return fmt.Sprintf("min(DISTINCT %s)", inputs[0]), nil
				}
				return fmt.Sprintf("min(%s)", inputs[0]), nil
			},
		},
		"max": &AggregateFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// as per postgres docs, max can take any numeric or string type: https://www.postgresql.org/docs/8.0/functions-aggregate.html
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].IsNumeric() && !args[0].Equals(types.TextType) {
					return nil, fmt.Errorf("%w: expected argument to be numeric or text, got %s", ErrType, args[0].String())
				}

				return args[0], nil
			},
			PGFormatFunc: func(inputs []string, distinct bool) (string, error) {
				if distinct {
					return fmt.Sprintf("max(DISTINCT %s)", inputs[0]), nil
				}
				return fmt.Sprintf("max(%s)", inputs[0]), nil
			},
		},
		"array_agg": &AggregateFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if args[0].IsArray {
					return nil, fmt.Errorf("%w: expected argument to be a scalar, got %s", ErrType, args[0].String())
				}

				a2 := args[0].Copy()
				a2.IsArray = true
				return a2, nil
			},
			PGFormatFunc: func(inputs []string, distinct bool) (string, error) {
				if distinct {
					return fmt.Sprintf("array_agg(DISTINCT %s)", inputs[0]), nil
				}
				return fmt.Sprintf("array_agg(%s ORDER BY %s)", inputs[0], inputs[0]), nil
			},
		},
		"avg": &AggregateFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// Postgres supports any numeric type for average, but we will enforce that it is numeric
				// to guarantee determinism.
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !strings.EqualFold(args[0].Name, types.NumericStr) {
					return nil, fmt.Errorf("%w: expected argument to be numeric, got %s", ErrType, args[0].String())
				}

				return args[0], nil
			},
			PGFormatFunc: func(inputs []string, distinct bool) (string, error) {
				if distinct {
					return fmt.Sprintf("avg(DISTINCT %s)", inputs[0]), nil
				}
				return fmt.Sprintf("avg(%s)", inputs[0]), nil
			},
		},
		// Window functions
		"lag": &WindowFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// LAG(value_expression [, offset [, default_value]])
				if len(args) < 1 || len(args) > 3 {
					return nil, fmt.Errorf("invalid number of arguments: expected 1-3, got %d", len(args))
				}

				if len(args) >= 2 {
					if !args[1].Equals(types.IntType) {
						return nil, wrapErrArgumentType(types.IntType, args[1])
					}
				}

				if len(args) == 3 {
					if !args[2].Equals(args[0]) {
						return nil, fmt.Errorf("%w: expected default value to be the same type as the value expression: %s != %s", ErrType, args[0].String(), args[2].String())
					}
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("lag"),
		},
		"lead": &WindowFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// LEAD(value_expression [, offset [, default_value]])
				if len(args) < 1 || len(args) > 3 {
					return nil, fmt.Errorf("invalid number of arguments: expected 1-3, got %d", len(args))
				}

				if len(args) >= 2 {
					if !args[1].Equals(types.IntType) {
						return nil, wrapErrArgumentType(types.IntType, args[1])
					}
				}

				if len(args) == 3 {
					if !args[2].Equals(args[0]) {
						return nil, fmt.Errorf("%w: expected default value to be the same type as the value expression: %s != %s", ErrType, args[0].String(), args[2].String())
					}
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("lead"),
		},
		"first_value": &WindowFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// FIRST_VALUE(value_expression) OVER (...)
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("first_value"),
		},
		"last_value": &WindowFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// LAST_VALUE(value_expression) OVER (...)
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("last_value"),
		},
		"nth_value": &WindowFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// NTH_VALUE(value_expression, nth) OVER (...)
				if len(args) != 2 {
					return nil, wrapErrArgumentNumber(2, len(args))
				}

				if !args[1].Equals(types.IntType) {
					return nil, wrapErrArgumentType(types.IntType, args[1])
				}

				return args[0], nil
			},
			PGFormatFunc: defaultFormat("nth_value"),
		},
		"row_number": &WindowFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				// ROW_NUMBER() OVER (...)
				if len(args) != 0 {
					return nil, wrapErrArgumentNumber(0, len(args))
				}

				return types.IntType, nil
			},
			PGFormatFunc: defaultFormat("row_number"),
		},
		// PostgreSQL database size functions
		"pg_database_size": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.IntType, nil
			},
			PGFormatFunc: defaultFormat("pg_database_size"),
		},
		"pg_total_relation_size": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.IntType, nil
			},
			PGFormatFunc: defaultFormat("pg_total_relation_size"),
		},
		"pg_relation_size": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.TextType) {
					return nil, wrapErrArgumentType(types.TextType, args[0])
				}

				return types.IntType, nil
			},
			PGFormatFunc: defaultFormat("pg_relation_size"),
		},
		"pg_size_pretty": &ScalarFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) (*types.DataType, error) {
				if len(args) != 1 {
					return nil, wrapErrArgumentNumber(1, len(args))
				}

				if !args[0].Equals(types.IntType) {
					return nil, wrapErrArgumentType(types.IntType, args[0])
				}

				return types.TextType, nil
			},
			PGFormatFunc: defaultFormat("pg_size_pretty"),
		},
		// Table-valued functions
		"unnest": &TableValuedFunctionDefinition{
			ValidateArgsFunc: func(args []*types.DataType) ([]*NamedType, error) {
				if len(args) == 0 {
					return nil, fmt.Errorf("unnest requires at least 1 argument, got %d", len(args))
				}

				var fields []*NamedType
				for i, arg := range args {
					if !arg.IsArray {
						return nil, fmt.Errorf("%w: argument %d must be array type, got %s",
							ErrType, i+1, arg.String())
					}

					// Create column from array element type
					elementType := arg.Copy()
					elementType.IsArray = false

					// Generate default column name
					columnName := fmt.Sprintf("unnest_%d", i+1)
					if len(args) == 1 {
						columnName = "unnest" // Single array gets simple name
					}

					fields = append(fields, &NamedType{
						Name: columnName,
						Type: elementType,
					})
				}

				return fields, nil
			},
			PGFormatFunc: func(inputs []string) (string, error) {
				return fmt.Sprintf("UNNEST(%s)", strings.Join(inputs, ", ")), nil
			},
		},
	}
)

// defaultFormat is the default PGFormat function for functions that do not have a custom one.
func defaultFormat(name string) func(inputs []string) (string, error) {
	return func(inputs []string) (string, error) {
		return fmt.Sprintf("%s(%s)", name, strings.Join(inputs, ", ")), nil
	}
}

var (
	// decimal1000 is a decimal type with a precision of 1000.
	decimal1000 *types.DataType
	// decimal16_6 is a decimal type with a precision of 16 and a scale of 6.
	// it is used to represent UNIX timestamps, allowing microsecond precision.
	// see internal/sql/pg/sql.go/sqlCreateParseUnixTimestampFunc for more info
	decimal16_6 *types.DataType
)

func init() {
	var err error
	decimal1000, err = types.NewNumericType(1000, 0)
	if err != nil {
		panic(fmt.Sprintf("failed to create decimal type: 1000, 0: %v", err))
	}

	decimal16_6, err = types.NewNumericType(16, 6)
	if err != nil {
		panic(fmt.Sprintf("failed to create decimal type: 16, 6: %v", err))
	}
}

// FunctionDefinition if a definition of a function.
// It has two implementations: ScalarFuncDef and AggregateFuncDef.
type FunctionDefinition interface {
	// ValidateArgs is a function that checks the arguments passed to the function.
	// It can check the argument type and amount of arguments.
	// It returns the expected return type based on the arguments.
	ValidateArgs(args []*types.DataType) (*types.DataType, error)
	funcdef()
}

// ScalarFunctionDefinition is a definition of a scalar function.
type ScalarFunctionDefinition struct {
	ValidateArgsFunc func(args []*types.DataType) (*types.DataType, error)
	PGFormatFunc     func(inputs []string) (string, error)
}

func (s *ScalarFunctionDefinition) ValidateArgs(args []*types.DataType) (*types.DataType, error) {
	return s.ValidateArgsFunc(args)
}

func (s *ScalarFunctionDefinition) funcdef() {}

// AggregateFunctionDefinition is a definition of an aggregate function.
type AggregateFunctionDefinition struct {
	// ValidateArgs is a function that checks the arguments passed to the function.
	// It can check the argument type and amount of arguments.
	ValidateArgsFunc func(args []*types.DataType) (*types.DataType, error)
	// PGFormat is a function that formats the inputs to the function in Postgres format.
	// For example, the function `sum` would format the inputs as `sum($1)`.
	// It can also format the inputs with DISTINCT. If no inputs are given, it is a *.
	PGFormatFunc func(inputs []string, distinct bool) (string, error)
	// We currently don't need to evaluate aggregates since they are handled by the engine.
}

func (a *AggregateFunctionDefinition) ValidateArgs(args []*types.DataType) (*types.DataType, error) {
	return a.ValidateArgsFunc(args)
}

func (a *AggregateFunctionDefinition) funcdef() {}

type WindowFunctionDefinition struct {
	// ValidateArgs is a function that checks the arguments passed to the function.
	// It can check the argument type and amount of arguments.
	ValidateArgsFunc func(args []*types.DataType) (*types.DataType, error)
	// PGFormat is a function that formats the inputs to the function in Postgres format.
	// For example, the function `sum` would format the inputs as `sum($1)`.
	// It can also format the inputs with DISTINCT. If no inputs are given, it is a *.
	PGFormatFunc func(inputs []string) (string, error)
}

func (w *WindowFunctionDefinition) ValidateArgs(args []*types.DataType) (*types.DataType, error) {
	return w.ValidateArgsFunc(args)
}

func (w *WindowFunctionDefinition) funcdef() {}

// TableValuedFunctionDefinition is a definition of a table-valued function.
// Table-valued functions return a table (multiple rows and columns) rather than a scalar value.
type TableValuedFunctionDefinition struct {
	// ValidateArgsFunc validates the arguments and returns the table schema.
	ValidateArgsFunc func(args []*types.DataType) ([]*NamedType, error)
	// PGFormatFunc formats the function call for PostgreSQL.
	PGFormatFunc func(inputs []string) (string, error)
}

func (t *TableValuedFunctionDefinition) ValidateArgs(args []*types.DataType) (*types.DataType, error) {
	// For table-valued functions, we don't return a single type but validate args
	// The actual schema validation is handled separately
	_, err := t.ValidateArgsFunc(args)
	return nil, err
}

func (t *TableValuedFunctionDefinition) ValidateTableSchema(args []*types.DataType) ([]*NamedType, error) {
	return t.ValidateArgsFunc(args)
}

func (t *TableValuedFunctionDefinition) funcdef() {}

// FormatFunc is a function that formats a string of inputs for a SQL function.
type FormatFunc func(inputs []string) (string, error)

func wrapErrArgumentNumber(expected, got int) error {
	return fmt.Errorf("expected %d, got %d", expected, got)
}

func wrapErrArgumentType(expected, got *types.DataType) error {
	return fmt.Errorf("%w: expected %s, got %s", ErrType, expected.String(), got.String())
}
