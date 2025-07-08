package testing

import (
	"context"
	"testing"

	"github.com/trufnetwork/kwil-db/node/engine/interpreter"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
)

// Example test showing how to use extension loading in kwilTesting framework
func TestExtensionLoadingExample(t *testing.T) {
	// First, register a test extension
	err := precompiles.RegisterPrecompile("test_extension", precompiles.Precompile{
		Methods: []precompiles.Method{
			{
				Name:            "test_method",
				AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
				Parameters:      []precompiles.PrecompileValue{},
				Returns: &precompiles.MethodReturn{
					IsTable: false,
					Fields: []precompiles.PrecompileValue{
						precompiles.NewPrecompileValue("success", types.BoolType, false),
					},
				},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					return resultFn([]any{true})
				},
			},
		},
	})
	require.NoError(t, err)

	// Configure test options with extension loading
	options := &Options{
		UseTestContainer: true,
		Extensions: []interpreter.StoredExtension{
			{
				ExtName: "test_extension",
				Alias:   "test_ext",
				Metadata: map[string]interpreter.Value{
					"test_param": func() interpreter.Value {
						value, err := interpreter.NewValue("test_value")
						if err != nil {
							panic("failed to create test_param value: " + err.Error())
						}
						return value
					}(),
				},
			},
		},
	}

	RunSchemaTest(t, SchemaTest{
		Name:  "test with extension loading",
		Owner: "0x123",
		FunctionTests: []TestFunc{
			func(ctx context.Context, platform *Platform) error {
				// Test that extension namespace is available
				var exists bool
				result, err := platform.DB.Execute(ctx, "SELECT EXISTS(SELECT 1 FROM kwild_engine.namespaces WHERE name = 'test_ext')")
				require.NoError(t, err)
				if len(result.Rows) > 0 {
					exists = result.Rows[0][0].(bool)
				}
				require.True(t, exists, "Extension namespace should exist")

				// Test that extension is registered
				var count int64
				result, err = platform.DB.Execute(ctx, "SELECT COUNT(*) FROM kwild_engine.initialized_extensions WHERE base_extension = 'test_extension'")
				require.NoError(t, err)
				if len(result.Rows) > 0 {
					count = result.Rows[0][0].(int64)
				}
				require.Equal(t, int64(1), count, "Extension should be registered")

				return nil
			},
		},
	}, options)
}
