package cmds

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/trufnetwork/kwil-db/core/types"
)

// parseParams parses the arguments into a map of name to value.
// it expects the arguments to be in the form of name:type=value
func parseParams(args []string) (map[string]any, error) {
	params := make(map[string]any)

	for _, arg := range args {
		// trim off any leading '$'
		arg = strings.TrimPrefix(arg, "$")

		// split the arg into name and value.  only split on the first '='
		split := strings.SplitN(arg, "=", 2)
		if len(split) != 2 {
			return nil, fmt.Errorf("invalid argument: %s.  argument must be in the form of name:type=value, received", arg)
		}

		// it is now split into name:type and value
		nameAndType := strings.SplitN(split[0], ":", 2)
		if len(nameAndType) != 2 {
			return nil, fmt.Errorf("invalid argument: %s.  argument must be in the form of name:type=value", arg)
		}

		dt, err := types.ParseDataType(nameAndType[1])
		if err != nil {
			return nil, fmt.Errorf("invalid data type: %s", nameAndType[1])
		}

		val, err := stringAndTypeToVal(split[1], dt)
		if err != nil {
			return nil, fmt.Errorf("error parsing value: %w", err)
		}

		params[nameAndType[0]] = val
	}

	return params, nil
}

// stringAndTypeToVal converts a string and type to a value.
// The string is the value, and the type is the data type.
// e.g. 5 and int8, or "satoshi" and text.
// we should probably refactor this since its sort've a mess, but its unexported
// and the tests are pretty good so its ok for now.
func stringAndTypeToVal(s string, dt *types.DataType) (v any, err error) {
	// before checking the type (which sometimes leads to trimming),
	// we should see if it is the NullLiteral
	if s == NullLiteral {
		return nil, nil
	}

	// decode is a function that is used if the data type is bytea or bytea[]
	var decode decodeFunc

	var trimmed bool

	// scan is the value that should be scanned into
	// It should be a pointer
	var scan any
	switch *dt {
	case *types.TextType:
		// special case: we should remove quotes from the string.
		s, trimmed = trimQuotes(s)
		scan = new(string)
	case *types.BoolType:
		scan = new(bool)
	case *types.IntType:
		scan = new(int64)
	case *types.ByteaType:
		scan = new([]byte)
		s, decode = trimDecodeParam(s)
	case *types.UUIDType:
		scan = new(types.UUID)
	case *types.TextArrayType:
		scan = new([]*string)
	case *types.BoolArrayType:
		scan = new([]*bool)
	case *types.IntArrayType:
		scan = new([]*int64)
	case *types.ByteaArrayType:
		scan = new([]*[]byte)
		s, decode = trimDecodeParam(s)
	case *types.UUIDArrayType:
		scan = new([]*types.UUID)
	default:
		// numerics have metadata so they cannot be type switched on
		if dt.Name == types.NumericStr {
			if dt.IsArray {
				arr := new([]*types.Decimal)
				scan = arr
				defer func() {
					for _, dec := range *arr {
						if dec == nil {
							continue
						}
						err2 := dec.SetPrecisionAndScale(dt.Metadata[0], dt.Metadata[1])
						if err != nil {
							v = nil
							err = fmt.Errorf("error setting precision and scale: %w", err2)
							return
						}
					}
				}()
			} else {
				d := new(types.Decimal)
				scan = d
				defer func() {
					err2 := d.SetPrecisionAndScale(dt.Metadata[0], dt.Metadata[1])
					if err2 != nil {
						v = nil
						err = fmt.Errorf("error setting precision and scale: %w", err2)
					}
				}()
			}
		} else {
			return nil, fmt.Errorf("unsupported data type: %s", dt.Name)
		}
	}

	if dt.IsArray {
		// if it is an array, it might be wrapped in []
		if len(s) >= 2 {
			if s[0] == '[' && s[len(s)-1] == ']' {
				s = s[1 : len(s)-1]
			}
		}
	}

	// if an array is an empty string, it is a zero-length array.
	// scalar values that are empty strings should be rejected
	if s == "" {
		if dt.IsArray {
			// we call scan here to ensure it is properly set to a 0-length array
			err := types.ScanTo([]any{[]string{}}, scan)
			if err != nil {
				return nil, err
			}

			return scan, nil
		}

		// if the string was trimmed, it was a quoted empty string, so it is valid
		if !trimmed {
			return nil, fmt.Errorf(`empty string is not a valid value for a scalar type. use "null" to represent a null value`)
		}
	}

	var from any
	if dt.IsArray {
		split, err := splitByCommas(s)
		if err != nil {
			return nil, err
		}

		// if there is a decode function, we should decode each element
		if decode != nil {
			bts := make([][]byte, len(split))
			for i, v := range split {
				if v != nil {
					b, err := decode(*v)
					if err != nil {
						return nil, err
					}
					bts[i] = b
				}
			}
			from = bts
		} else {
			from = split
		}
	} else {
		if decode != nil {
			b, err := decode(s)
			if err != nil {
				return nil, err
			}
			from = b
		} else {
			from = s
		}
	}

	err = types.ScanTo([]any{from}, scan)
	if err != nil {
		return nil, err
	}

	return scan, nil
}

type decodeFunc func(string) ([]byte, error)

// trimDecodeParam searches the end of a string for encode/decode instructions and returns the
// trimmed string and the decode function. If none is found, it returns base64.
// It should only be used for bytea and bytea[].
func trimDecodeParam(s string) (trimmed string, decode decodeFunc) {
	if b, ok := strings.CutSuffix(s, ";hex"); ok {
		return b, hex.DecodeString
	}
	if b, ok := strings.CutSuffix(s, ";base64"); ok {
		return b, base64.StdEncoding.DecodeString
	}
	if b, ok := strings.CutSuffix(s, ";b64"); ok {
		return b, base64.StdEncoding.DecodeString
	}

	// default to base64
	return s, base64.StdEncoding.DecodeString
}

// trimQuotes trims the quotes from a string if they exist.
func trimQuotes(s string) (string, bool) {
	if len(s) < 2 {
		return s, false
	}

	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1], true
	}

	if s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1], true
	}

	return s, false
}

// NullLiteral is the string representation of a null value.
const NullLiteral = "null"

// splitByCommas splits a string by commas, but ignores commas that are
// inside single or double quotes (with backslash escapes). It distinguishes:
//   - consecutive commas => nil
//   - quoted empty => ""
//   - unquoted null literal => nil
//   - partial quoting => error
//   - unclosed quotes => error
func splitByCommas(input string) ([]*string, error) {
	var result []*string
	var currentToken []rune

	inSingleQuote := false
	inDoubleQuote := false
	sawQuote := false        // encountered a quote in the current token
	justClosedQuote := false // helps detect partial quoting (e.g. 'b'c)
	escaped := false         // are we currently escaping the next character?

	finalizeToken := func() {
		curTok := string(currentToken)

		switch {
		case len(curTok) == 0 && !sawQuote:
			// If nothing accumulated and no quotes => nil
			result = append(result, nil)
		case strings.TrimSpace(curTok) == NullLiteral && !sawQuote:
			// If token is exactly "null" (ignoring whitespace) and unquoted => nil
			result = append(result, nil)
		case len(curTok) == 0 && sawQuote:
			// If nothing accumulated but we did see quotes => ""
			empty := ""
			result = append(result, &empty)
		case !sawQuote:
			// if we did not see quotes, trim whitespace
			trimmed := strings.TrimSpace(curTok)
			result = append(result, &trimmed)
		default:
			// Else normal token
			result = append(result, &curTok)
		}

		// Reset for the next token
		currentToken = []rune{}
		sawQuote = false
		justClosedQuote = false
	}

	for i, char := range input {
		if escaped {
			currentToken = append(currentToken, char)
			escaped = false
			justClosedQuote = false
			continue
		}

		// If we had just closed a quote, anything other than a comma is an error
		if justClosedQuote && char != ',' {
			return nil, fmt.Errorf("invalid partial quote usage near index %d (char '%c')", i, char)
		}

		switch char {
		case '\\':
			escaped = true

		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
				if inSingleQuote {
					sawQuote = true
					justClosedQuote = false
				} else {
					justClosedQuote = true
				}
			} else {
				// literal if in double quotes
				currentToken = append(currentToken, char)
				justClosedQuote = false
			}

		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
				if inDoubleQuote {
					sawQuote = true
					justClosedQuote = false
				} else {
					justClosedQuote = true
				}
			} else {
				// literal if in single quotes
				currentToken = append(currentToken, char)
				justClosedQuote = false
			}

		case ',':
			if inSingleQuote || inDoubleQuote {
				// literal comma
				currentToken = append(currentToken, char)
				justClosedQuote = false
			} else {
				// finalize token
				finalizeToken()
			}

		default:
			if !inSingleQuote && !inDoubleQuote && unicode.IsSpace(char) && len(currentToken) == 0 {
				// Skip leading spaces outside of quotes
				continue
			}
			currentToken = append(currentToken, char)
			justClosedQuote = false
		}
	}

	// Finalize the last token
	finalizeToken()

	// If quotes were left unclosed, it's an error
	if inSingleQuote || inDoubleQuote {
		return nil, fmt.Errorf("unclosed quote in array inputs")
	}

	return result, nil
}
