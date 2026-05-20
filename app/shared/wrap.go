package shared

import (
	"os"
	"strings"

	"github.com/spf13/pflag"
	"golang.org/x/term"
)

// wrapTextToTerminalWidth wraps text by detecting the current
// terminal width (columns) and using that as the wrap limit.
// If it can't get the terminal width, it will wrap it to 80
func wrapTextToTerminalWidth(text string) string {
	// Get the terminal size from standard output.
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		width = 80
	}

	return WrapText(text, width)
}

// WrapText wraps text by the specified width
func WrapText(text string, width int) string {
	return wrapText(text, width-2) // for safety, sometimes terminal still doesn't wrap properly
}

// wrapFlags wraps all flag descriptions. It does this by accounting for the characters
// that are to the left of the flag description, as well as the terminal width.
// If the width can't be determined, it won't wrap the flags.
func wrapFlags(f *pflag.FlagSet) {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return
	}

	/* example unwrapped output:
	Flags:
	      --csv string                CSV file containing the parameters to pass to the action
	  -m, --csv-mapping stringArray   mapping of CSV columns to action parameters. format: "csv_column:action_param_name" OR "csv_column:action_param_position"
	  -h, --help                      help for exec-action
	  -n, --namespace string          namespace to execute the action in
	  -N, --nonce int                 nonce override (-1 means request from server) (default -1)
	  -p, --param stringArray         named parameters that will override any positional or CSV parameters. format: "name:type=value"
	      --sync                      synchronous broadcast (wait for it to be included in a block)

	Global Flags:
	  -Y, --assume-yes           Assume yes for all prompts
	      --chain-id string      the expected/intended Kwil Chain ID
	  -c, --config string        the path to the Kwil CLI persistent global settings file (default "/Users/brennanlamey/.kwil-cli/config.json")
	      --output string        the format for command output - either 'text' or 'json' (default "text")
	      --private-key string   the private key of the wallet that will be used for signing
	      --provider string      the Kwil provider RPC endpoint (default "http://127.0.0.1:8484")
	  -S, --silence              Silence logs
	*/

	// we first find the widest flag (shorthand, long, and type).
	// Cobra adjusts the width of all flags to the widest flag.
	var widest int
	f.VisitAll(func(f *pflag.Flag) {
		length := 2 // initial offset value
		if f.Shorthand != "" {
			length += 2 // -x,
		}
		if f.Shorthand != "" && f.Name != "" {
			length += 2 // account for the comma and space between: -x, --name
		}
		if f.Name != "" {
			length += len(f.Name) + 2 // --name
		}
		if f.Value.Type() != "" {
			length += len(f.Value.Type()) + 1 // type, plus the space between type and name
		}
		// an additional 3 spaces, between the end and the start of the description
		length += 3

		if length > widest {
			widest = length
		}
	})

	wrapTo := width - widest - 4
	// now we wrap the descriptions
	f.VisitAll(func(f *pflag.Flag) {
		if f.Usage == "" {
			return
		}

		str := f.Usage

		f.Usage = wrapLine(str, wrapTo)
	})
}

// wrapLine wraps a single paragraph (with no \n) to the given width.
func wrapLine(text string, width int) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}

	var sb strings.Builder
	lineLen := 0

	for i, w := range words {
		// First word on a line
		if i == 0 {
			sb.WriteString(w)
			lineLen = len(w)
			continue
		}
		// Check if adding this word + 1 space exceeds width
		if lineLen+1+len(w) > width {
			sb.WriteString("\n")
			sb.WriteString(w)
			lineLen = len(w)
		} else {
			sb.WriteString(" ")
			sb.WriteString(w)
			lineLen += 1 + len(w)
		}
	}

	return sb.String()
}

// wrapText removes single line breaks (replacing them with spaces),
// preserves double breaks (or lines starting with '-') as separators,
// and wraps each "paragraph" to the given width.
func wrapText(text string, width int) string {
	// Split the original text by lines
	lines := strings.Split(text, "\n")

	var resultParts []string
	var currentParagraph []string

	// Flush the current paragraph: join with spaces, wrap, add to results
	flushParagraph := func() {
		if len(currentParagraph) > 0 {
			joined := strings.Join(currentParagraph, " ")
			wrapped := wrapLine(joined, width)
			resultParts = append(resultParts, wrapped)
			currentParagraph = nil
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// If line is blank or starts with '-', we preserve it as-is (separator).
		if trimmed == "" || strings.HasPrefix(trimmed, "-") {
			// Flush whatever paragraph we have so far
			flushParagraph()
			// Then just keep this line as its own entry (unwrapped).
			// For blank lines, 'trimmed' == "", but we append the original line
			// so it remains a visual blank line. Or if it's "-something", keep it as is.
			resultParts = append(resultParts, line)
		} else {
			// Accumulate into our current paragraph
			currentParagraph = append(currentParagraph, trimmed)
		}
	}

	// Flush last paragraph if needed
	flushParagraph()

	// Rejoin everything with newlines
	return strings.Join(resultParts, "\n")
}
