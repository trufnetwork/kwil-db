package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/testing"
)

var (
	testLong = `Runs Kuneiform JSON tests.
	
The ` + "`" + `test` + "`" + ` command executes runs tests for Kuneiform.
Custom tests for user-defined schemas can be defined using JSON.
For information on how to create JSON tests for Kuneiform schemas,
reference the Kwil docs (https://docs.kwil.com).

Paths to JSON files for tests are relative to the working directory, but
schema filepaths specified in the JSON will be accessed relative to the
respective JSON file.

Test cases can be run by specyfing the path to the JSON using the
` + "`" + `file` + "`" + ` flag. Multiple test files can be specified by simply
using the flag many times.

The tests need an active PostgreSQL instance to run against. Users can
use the ` + "`--test-container`" + ` flag to have ` + "`kwil-cli`" + ` setup
and teardown a Docker test container, if they have Docker installed locally.
Alternatively, users can specify a PostgreSQL connection using the
 ` + "`--host`, `--port`, `--user`, `--password`, and `--database` " + `flags.`

	testExample = `# Run tests with a test container
kwil-cli utils test --file ./test1.json --file ./test2.json --test-container

# Run tests against a manually set up local Postgres instance
kwil-cli utils test --file ./test1.json --host localhost --port 5432 \
--user postgres --password password --database postgres`
)

func testCmd() *cobra.Command {
	var testCases []string
	var host, port, user, pass, dbName string
	var useTestContainer bool
	cmd := &cobra.Command{
		Use:     "test",
		Short:   "Runs Kuneiform JSON tests.",
		Long:    testLong,
		Example: testExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			l := log.NewStdoutLogger()

			opts := testing.Options{
				Logger: testing.LoggerFromKwilLogger(l),
			}

			userHasSetPgConn := false
			setPgConnFlag := ""
			for _, flag := range []string{
				"database",
				"user",
				"password",
				"host",
				"port"} {
				if cmd.Flag(flag).Changed {
					userHasSetPgConn = true
					setPgConnFlag = flag
				}
			}

			// either useContainer or db flags can be set
			if useTestContainer {
				// if useTestContainer, ensure no other flags are set
				if userHasSetPgConn {
					return display.PrintErr(cmd, fmt.Errorf("cannot specify both --test-container and --%s", setPgConnFlag))
				}

				opts.UseTestContainer = true
			} else {
				if !userHasSetPgConn {
					return display.PrintErr(cmd, errors.New("must specify either postgres connection flags or --test-container"))
				}

				opts.Conn = &testing.ConnConfig{
					Host:   host,
					Port:   port,
					User:   user,
					Pass:   pass,
					DBName: dbName,
				}
			}

			opts.ReplaceExistingContainer = func() (bool, error) {
				//if common
				assumeYes, err := helpers.GetAssumeYesFlag(cmd)
				if err != nil {
					return false, err
				}

				if assumeYes {
					return true, nil
				}

				sel := promptui.Prompt{
					Label:   fmt.Sprintf(`Existing Docker contains found with name "%s". Wipe the existing container and create a new one? (y/n)`, testing.ContainerName),
					Default: "N",
				}

				res, err := sel.Run()
				if err != nil {
					return false, err
				}

				if res == "Y" || res == "y" {
					return true, nil
				}

				return false, nil
			}

			// run the tests
			for _, path := range testCases {
				_, err := expandHome(&path)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				bts, err := os.ReadFile(path)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				var schemaTest testing.SchemaTest
				if err = json.Unmarshal(bts, &schemaTest); err != nil {
					return display.PrintErr(cmd, err)
				}

				if err = makeSchemaPathsRelative(&schemaTest, path); err != nil {
					return display.PrintErr(cmd, err)
				}

				if err = schemaTest.Run(cmd.Context(), &opts); err != nil {
					return display.PrintCmd(cmd, &testsPassed{
						Passing: false,
						Reason:  err.Error(),
					})
				}
			}

			return display.PrintCmd(cmd, &testsPassed{
				Passing: true,
			})
		},
	}

	cmd.Flags().StringSliceVarP(&testCases, "file", "f", nil, "filepaths of tests to run")
	cmd.Flags().BoolVar(&useTestContainer, "test-container", false, "runs the tests with a Docker testcontainer")
	cmd.Flags().StringVar(&dbName, "database", "kwild", "name of the Postgres database to manually connect to")
	cmd.Flags().StringVar(&user, "user", "postgres", "user with administrative privileges on the database")
	cmd.Flags().StringVar(&pass, "password", "", "password for the database user")
	cmd.Flags().StringVar(&host, "host", "localhost", "host of the database")
	cmd.Flags().StringVar(&port, "port", "5432", "port of the database")
	helpers.BindAssumeYesFlag(cmd)

	return cmd
}

type testsPassed struct {
	Passing bool   `json:"passing"`
	Reason  string `json:"reason,omitempty"`
}

func (t *testsPassed) MarshalJSON() ([]byte, error) {
	type Alias testsPassed
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(t),
	})
}

func (t *testsPassed) MarshalText() (text []byte, err error) {
	if !t.Passing {
		return []byte("\nTests failed:\n" + t.Reason), nil
	}

	return []byte("\nAll tests passed successfully."), nil
}

// adjustPath expands a path relative to another path.
// relativeTo is expected to be a file, NOT a directory.
func adjustPath(path, relativeTo string) (string, error) {
	// If the path is already absolute, return it as is.
	if filepath.IsAbs(path) {
		return path, nil
	}

	changed, err := expandHome(&path)
	if err != nil {
		return "", err
	}
	// if changed, just return, since it is absolute now
	if changed {
		return path, nil
	}

	// Otherwise, treat it as relative.
	// trim off the file from the path
	return filepath.Join(filepath.Dir(relativeTo), path), nil
}

// expandHome tries to expand to a user's home directory if a path
// has a ~. If it doesn't, it does not change the input
func expandHome(s *string) (changed bool, err error) {
	if s == nil {
		return false, errors.New("input string pointer is nil")
	}

	// If the path is ~/..., expand it to the user's home directory.
	if strings.HasPrefix(*s, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return false, err
		}
		*s = filepath.Join(homeDir, (*s)[2:])

		return true, nil
	}

	return false, nil
}

// makeSchemaPathsRelative makes all schema paths relative for a test.
func makeSchemaPathsRelative(test *testing.SchemaTest, jsonFilepath string) error {
	for i, path := range test.SeedScripts {
		adjusted, err := adjustPath(path, jsonFilepath)
		if err != nil {
			return err
		}

		test.SeedScripts[i] = adjusted
	}

	return nil
}
