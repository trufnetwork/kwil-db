package display

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type demoFormat struct {
	data []byte
}

func (d *demoFormat) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Data string `json:"name_to_whatever"`
	}{
		Data: string(d.data) + "_whatever",
	})
}

func (d *demoFormat) MarshalText() ([]byte, error) {
	return fmt.Appendf(nil, "Whatever format: %s", d.data), nil
}

func Example_wrappedMsg_text() {
	msg := wrapMsg(&demoFormat{data: []byte("demo")}, nil)
	prettyPrint(msg, "text", os.Stdout, os.Stderr)
	// Output: Whatever format: demo
}

func Test_wrappedMsg_text_withError(t *testing.T) {
	var stderr bytes.Buffer
	var stdout bytes.Buffer

	err := errors.New("an error")
	msg := wrapMsg(&demoFormat{data: []byte("demo")}, err)
	prettyPrint(msg, "text", &stdout, &stderr)

	output := stdout.Bytes()
	assert.Equal(t, "", string(output), "stdout should be empty")

	errput := stderr.Bytes()
	assert.Equal(t, "an error\n", string(errput), "stderr should contain error")
}

func Example_wrappedMsg_json() {
	msg := wrapMsg(&demoFormat{data: []byte("demo")}, nil)
	prettyPrint(msg, "json", os.Stdout, os.Stderr)
	// Output: {
	//   "result": {
	//     "name_to_whatever": "demo_whatever"
	//   },
	//   "error": ""
	// }
}

func Example_wrappedMsg_json_withError() {
	err := errors.New("an error")
	msg := wrapMsg(&demoFormat{data: []byte("demo")}, err)
	prettyPrint(msg, "json", os.Stdout, os.Stderr)
	// Output:
	// {
	//   "result": null,
	//   "error": "an error"
	// }
}

func TestOutputFormat_String(t *testing.T) {
	tests := []struct {
		name     string
		format   OutputFormat
		expected string
	}{
		{
			name:     "text format",
			format:   outputFormatText,
			expected: "text",
		},
		{
			name:     "json format",
			format:   outputFormatJSON,
			expected: "json",
		},
		{
			name:     "empty format",
			format:   "",
			expected: "",
		},
		{
			name:     "invalid format",
			format:   "invalid",
			expected: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.format.string()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOutputFormat_Valid(t *testing.T) {
	tests := []struct {
		name     string
		format   OutputFormat
		expected bool
	}{
		{
			name:     "text format",
			format:   outputFormatText,
			expected: true,
		},
		{
			name:     "json format",
			format:   outputFormatJSON,
			expected: true,
		},
		{
			name:     "empty format",
			format:   "",
			expected: false,
		},
		{
			name:     "invalid format",
			format:   "invalid",
			expected: false,
		},
		{
			name:     "case sensitive format",
			format:   "TEXT",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.format.valid()
			assert.Equal(t, tt.expected, result)
		})
	}
}
