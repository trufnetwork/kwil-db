// Package display provides interfaces and functions to format the command
// line output and print.
package display

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/trufnetwork/kwil-db/app/shared"

	"github.com/spf13/cobra"
)

// BindOutputFormatFlag binds the output format flag to the command.
// This should be added on the root command.
func BindOutputFormatFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().String("output", defaultOutputFormat.string(), "the format for command output - either 'text' or 'json'")
}

// BindSilenceFlag binds the silence flag to the passed command.
// If bound, the command will silence logs.
// If true, display commands will not print to stdout or stderr.
// The flag will be bound to all subcommands of the given command.
func BindSilenceFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolP("silence", "S", false, "Silence logs")
}

// ShouldSilence returns the value of the silence flag
func ShouldSilence(cmd *cobra.Command) bool {
	s, _ := cmd.Flags().GetBool("silence")
	return s
}

// OutputFormat is the format for command output
// It implements the pflag.Value interface
type OutputFormat string

// String implements the Stringer interface
// NOTE: cannot use the pointer receiver here
func (o OutputFormat) string() string {
	return string(o)
}

// Valid returns true if the output format is valid.
func (o OutputFormat) valid() bool {
	switch o {
	case outputFormatText, outputFormatJSON, outputFormatSilent:
		return true
	default:
		return false
	}
}

const (
	outputFormatText   OutputFormat = "text"
	outputFormatJSON   OutputFormat = "json"
	outputFormatSilent OutputFormat = "silent"

	defaultOutputFormat = outputFormatText
)

// emptyResult is used as a placeholder for when the result is empty.
// It implements the MsgFormatter interface
type emptyResult struct{}

func (e *emptyResult) MarshalText() ([]byte, error) {
	return []byte(""), nil
}

func (e *emptyResult) MarshalJSON() ([]byte, error) {
	// an empty string will fail to unmarshal for all result types. JSON null
	// (not a string or any type at all) is better, but unmarshalling should be
	// skipped entirely if the error field of wrappedMsg is set
	return []byte(`null`), nil
}

// MsgFormatter is an interface that wraps the MarshalText and MarshalJSON
// It defines the requirements for something to be printed.
type MsgFormatter interface {
	json.Marshaler
	encoding.TextMarshaler
}

// MessageReader is a utility to help unmarshal a message from a reader.
type MessageReader[T any] struct {
	Result T      `json:"result"`
	Error  string `json:"error"`
}

type wrappedMsg struct {
	Result MsgFormatter `json:"result"`
	Error  error        `json:"error"`
}

func (w *wrappedMsg) MarshalJSON() ([]byte, error) {
	var errMsg string
	if w.Error != nil {
		errMsg = w.Error.Error()
	}
	return json.Marshal(struct {
		Result MsgFormatter `json:"result"`
		Error  string       `json:"error"`
	}{
		Result: w.Result,
		Error:  errMsg,
	})
}

// printJson prints the wrappedMsg in json format. It prints to stdout.
// The input error is never returned, only an error from printing is returned.
func (w *wrappedMsg) printJson(stdout io.Writer, _ io.Writer) error {
	msg, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}

	fmt.Fprintln(stdout, string(msg))
	return nil
}

// printText prints the wrappedMsg in text format. It prints to stdout if
// `w.Error` is empty, otherwise it prints to stderr.
// The input error is never returned, only an error from printing is returned.
func (w *wrappedMsg) printText(stdout io.Writer, stderr io.Writer) error {
	if w.Error != nil {
		fmt.Fprintln(stderr, w.Error)
		return nil
	}

	msg, err := w.Result.MarshalText()
	if err != nil {
		return err
	}

	fmt.Fprintln(stdout, string(msg))
	return nil
}

// wrapMsg wraps response and error in a wrappedMsg struct.
func wrapMsg(msg MsgFormatter, err error) *wrappedMsg {
	if err != nil {
		return &wrappedMsg{
			Result: &emptyResult{},
			Error:  err,
		}
	}

	return &wrappedMsg{
		Result: msg,
		Error:  nil,
	}
}

// prettyPrint prints the wrappedMsg in the given format. Any error in msg.Error
// is always returned, but it may be joined with any other errors related to
// printing.
func prettyPrint(msg *wrappedMsg, format OutputFormat, stdout io.Writer, stderr io.Writer) error {
	switch format {
	case outputFormatJSON:
		return msg.printJson(stdout, stderr)
	case outputFormatText:
		return msg.printText(stdout, stderr)
	case outputFormatSilent:
		return nil
	default:
		return errors.Join(msg.Error, fmt.Errorf("invalid output format: %s", format))
	}
}

// Print is a helper function to wrap and print message in given format.
// THIS SHOULD NOT BE USED IN COMMANDS. Use PrintCmd instead.
func Print(msg MsgFormatter, err error, format OutputFormat) {
	wrappedMsg := wrapMsg(msg, err)
	prettyPrint(wrappedMsg, format, os.Stdout, os.Stderr)
}

// PrintCmd prints output based on the commands output format flag.
// If not format flag is provided, it will default to text in stdout.
func PrintCmd(cmd *cobra.Command, msg MsgFormatter) error {
	wrappedMsg := &wrappedMsg{
		Result: msg,
		Error:  nil,
	}

	format, err := cmd.Flags().GetString("output")
	if err != nil || format == "" {
		format = defaultOutputFormat.string()
	}
	if !OutputFormat(format).valid() {
		// set the output format in cmd to the default output format to avoid error being thrown twice
		err := cmd.Flags().Set("output", defaultOutputFormat.string())
		if err != nil {
			return err
		}

		return fmt.Errorf("invalid output format: %s", format)
	}

	// if silencing but output is json, we should still print the json
	if ShouldSilence(cmd) && format != outputFormatJSON.string() {
		return nil
	}

	return prettyPrint(wrappedMsg, OutputFormat(format), cmd.OutOrStdout(), cmd.OutOrStderr())
}

type WrappedCmdErr struct {
	Err          error
	OutputFormat OutputFormat
}

func (wce *WrappedCmdErr) Error() string {
	var out strings.Builder
	err := prettyPrint(&wrappedMsg{
		Result: &emptyResult{},
		Error:  wce.Err,
	}, wce.OutputFormat, &out, &out)
	if err != nil {
		return errors.Join(err, wce.Err).Error()
	}
	return out.String()
}

// FormattedError returns a WrappedCmdErr with the error and output format from
// the command, which specifies the output format to use. This seemed like a
// nice idea, and it may be in the future, however, for now Cobra will always at
// least partially hijack the output, so we will keep using PrintErr, which
// swallows the error to prevent Cobra from using its printing conventions.
func FormattedError(cmd *cobra.Command, err error) error {
	if err == nil {
		return nil
	}
	outputFormat, err2 := getOutputFormat(cmd)
	if err2 != nil {
		return errors.Join(err, err2)
	}
	return &WrappedCmdErr{
		Err:          err,
		OutputFormat: outputFormat,
	}
}

// PrintErr prints the error according to the commands output format flag. The
// returned error is nil if the message it was printed successfully. Thus, this
// function must ONLY be called from within a cobra.Command's RunE function or
// or returned directly by the RunE function, NOT used to direct application
// logic since the returned error no longer pertains to the initial error. This
// also stores the error the command's Context, accessible via the
// shared.CtxKeyCmdErr key. This allows the main function to determine if a
// non-zero exit code should be returned.
func PrintErr(cmd *cobra.Command, err error) error {
	// To pull the error out in main, we will set a value in the Command's
	// context that we can check for in main. If Cobra did not prefix the error,
	// we would not have to do this to achieve non-zero exit codes to the OS.
	shared.SetCmdCtxErr(cmd, err)

	outputFormat, err2 := getOutputFormat(cmd)
	if err2 != nil {
		return err2
	}

	// if silencing but output is json, we should still print the json
	if ShouldSilence(cmd) && outputFormat != outputFormatJSON {
		return nil
	}

	return prettyPrint(&wrappedMsg{
		Result: &emptyResult{},
		Error:  err,
	}, outputFormat, cmd.OutOrStdout(), cmd.OutOrStderr())
}

// Log prints the message to stdout if the silence flag is not set.
func Log(cmd *cobra.Command, msg string) {
	if !ShouldSilence(cmd) {
		fmt.Fprintln(cmd.OutOrStdout(), msg)
	}
}

func getOutputFormat(cmd *cobra.Command) (OutputFormat, error) {
	format, err := cmd.Flags().GetString("output")
	if err != nil || format == "" {
		format = defaultOutputFormat.string()
	}
	outputFormat := OutputFormat(format)
	if !outputFormat.valid() {
		return "", fmt.Errorf("invalid output format: %s", format)
	}
	if ShouldSilence(cmd) && outputFormat != outputFormatJSON {
		outputFormat = outputFormatSilent
	}

	return outputFormat, nil
}
