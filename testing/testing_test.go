//go:build pglive

package testing

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
)

// testing the testing package
func Test_Testing(t *testing.T) {
	// testing errors returned from a precompile, which are not returned
	// as part of the call result
	err := precompiles.RegisterPrecompile("kwild_testing", precompiles.Precompile{
		Methods: []precompiles.Method{
			{
				Name: "err",
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					return errors.New("extension error")
				},
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
			},
		},
	})
	require.NoError(t, err)

	RunSchemaTest(t, SchemaTest{
		Name:  "testing the testing framework",
		Owner: "0xabc",
		SeedStatements: []string{
			`USE kwild_testing AS kwild_testing;`,
			`CREATE ACTION do_err($ext bool) public {
				if $ext {
					kwild_testing.err();
				} else {
					error('built-in error'); 
				}	
			}`,
		},
		TestCases: []TestCase{
			{
				Name:   "test built-in error",
				Action: `do_err`,
				Args:   []interface{}{false},
				ErrMsg: "built-in error",
			},
			{
				Name:   "test extension error",
				Action: `do_err`,
				Args:   []interface{}{true},
				ErrMsg: "extension error",
			},
		},
		FunctionTests: []TestFunc{
			func(ctx context.Context, platform *Platform) error {
				res, err := platform.Engine.CallWithoutEngineCtx(ctx, platform.DB, "", "do_err", []any{false}, nil)
				require.NoError(t, err)

				assert.Error(t, res.Error)
				assert.Contains(t, res.Error.Error(), "built-in error")

				_, err = platform.Engine.CallWithoutEngineCtx(ctx, platform.DB, "", "do_err", []any{true}, nil)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "extension error")

				return nil
			},
		},
	}, &Options{
		Conn: &ConnConfig{
			Host:   "127.0.0.1",
			Port:   "5432",
			User:   "kwild",
			Pass:   "kwild", // would be ignored if pg_hba.conf set with trust
			DBName: "kwil_test_db",
		},
	})
}
