package conf

import (
	"os"
	"testing"

	"github.com/knadh/koanf/v2"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/trufnetwork/kwil-db/config"
)

func TestPreRunBindConfigFile(t *testing.T) {
	k = koanf.New(".")

	tmpDir := t.TempDir()

	configContent := `
top_val = "a"

[section]
key = "value"
number = 42

[nested]
string_value = "nested-string"
`
	configPath := config.ConfigFilePath(tmpDir)
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	// Create test command with root flag
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("root", tmpDir, "root directory")
	rootFlag := cmd.Flag("root")
	rootFlag.Changed = true

	err = PreRunBindConfigFile(cmd, []string{})
	assert.NoError(t, err)

	// Verify config values were properly loaded
	assert.Equal(t, "a", k.String("top_val"))
	assert.Equal(t, "value", k.String("section.key"))
	assert.Equal(t, 42, k.Int("section.number"))
	assert.Equal(t, "nested-string", k.String("nested.string_value"))
}

func TestPreRunBindConfigFileNonExistent(t *testing.T) {
	k = koanf.New(".")

	// Create temporary directory without config file
	tmpDir, err := os.MkdirTemp("", "kwil-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("root", tmpDir, "root directory")

	// Should not error when config file doesn't exist
	err = PreRunBindConfigFile(cmd, []string{})
	assert.NoError(t, err)
}

func TestPreRunBindFlags(t *testing.T) {
	k = koanf.New(".")

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("test-flag", "", "test flag")
	cmd.Flags().Int("number-value", 0, "number value")

	// Set some flag values
	cmd.Flags().Set("test-flag", "test-value")
	cmd.Flags().Set("number-value", "42")

	err := PreRunBindFlags(cmd, []string{})
	assert.NoError(t, err)

	// Verify the values were properly bound (to the underscore converted versions)
	assert.Equal(t, "test-value", k.String("test_flag"))
	assert.Equal(t, 42, k.Int("number_value"))
}
