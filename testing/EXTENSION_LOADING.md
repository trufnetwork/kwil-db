# Extension Loading Support in kwilTesting Framework

The kwilTesting framework now supports loading and testing extensions during test execution. This enables comprehensive testing of extension-dependent functionality including SQL migrations, actions, and precompile functions.

## Overview

Previously, the kwilTesting framework didn't support loading extensions, making it impossible to test:
- Extension-dependent SQL migrations
- Extension precompile functions
- Extension schemas and tables
- Cache functionality and other extension features

This enhancement adds extension loading support while maintaining full backward compatibility.

## Configuration

### ExtensionConfig

Extensions are configured using the `ExtensionConfig` struct:

```go
type ExtensionConfig struct {
    // Name is the name of the extension to load (must be registered)
    Name string
    // Alias is the namespace alias for the extension (e.g., "ext_tn_cache") 
    Alias string
    // Metadata contains initialization parameters for the extension
    Metadata map[string]any
}
```

### Options

Extensions are specified in the test `Options`:

```go
options := &testing.Options{
    UseTestContainer: true,
    Extensions: []testing.ExtensionConfig{
        {
            Name:  "ext_tn_cache",
            Alias: "ext_tn_cache", 
            Metadata: map[string]any{
                "enabled": true,
                "max_cache_size": 1000,
            },
        },
    },
}
```

## Usage Examples

### Basic Extension Loading

```go
func TestWithExtension(t *testing.T) {
    // Register extension first (usually done in init())
    err := precompiles.RegisterPrecompile("my_extension", myExtension)
    require.NoError(t, err)

    options := &testing.Options{
        UseTestContainer: true,
        Extensions: []testing.ExtensionConfig{
            {
                Name:  "my_extension",
                Alias: "my_ext",
                Metadata: map[string]any{
                    "param1": "value1",
                },
            },
        },
    }

    testing.RunSchemaTest(t, testing.SchemaTest{
        Name: "extension test",
        SeedStatements: []string{
            "CREATE ACTION test() public { my_ext.some_method(); };",
        },
        TestCases: []testing.TestCase{
            {
                Name:   "test extension method",
                Action: "test", 
                Args:   []any{},
            },
        },
    }, options)
}
```

### Testing tn_cache Extension

```go
func TestTnCache(t *testing.T) {
    options := &testing.Options{
        UseTestContainer: true,
        Extensions: []testing.ExtensionConfig{
            {
                Name:  "ext_tn_cache",
                Alias: "ext_tn_cache",
                Metadata: map[string]any{
                    "enabled": true,
                },
            },
        },
    }

    testing.RunSchemaTest(t, testing.SchemaTest{
        Name:        "cache functionality test",
        SeedScripts: []string{"migrations.sql"}, // Includes cache migration
        FunctionTests: []testing.TestFunc{
            func(ctx context.Context, platform *testing.Platform) error {
                // Test cache tables exist
                var exists bool
                err := platform.DB.Execute(ctx, 
                    "SELECT EXISTS(SELECT 1 FROM ext_tn_cache.cached_streams LIMIT 0)",
                    func(row sql.Row) error {
                        exists = true
                        return nil
                    })
                require.NoError(t, err)
                return nil
            },
        },
    }, options)
}
```

### Convenience Functions

For common testing scenarios, convenience functions are provided:

```go
// Basic test options
options := testing.GetTestOptions()

// Test options with tn_cache extension pre-configured
options := testing.GetTestOptionsWithTnCache()
```

## Extension Requirements

### Registration

Extensions must be registered before they can be loaded in tests:

```go
func init() {
    err := precompiles.RegisterPrecompile("my_extension", precompiles.Precompile{
        Methods: []precompiles.Method{
            // Method definitions...
        },
    })
    if err != nil {
        panic(err)
    }
}
```

### Extension Structure

Extensions follow the standard `precompiles.Precompile` structure:

```go
var myExtension = precompiles.Precompile{
    Methods: []precompiles.Method{
        {
            Name:            "my_method",
            AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
            Parameters: []precompiles.PrecompileValue{
                precompiles.NewPrecompileValue("param1", types.TextType, false),
            },
            Returns: &precompiles.MethodReturn{
                IsTable: false,
                Fields: []precompiles.PrecompileValue{
                    precompiles.NewPrecompileValue("result", types.BoolType, false),
                },
            },
            Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
                // Implementation...
                return resultFn([]any{true})
            },
        },
    },
}
```

## Implementation Details

### Database Schema

Extensions are registered in the test database using the same schema as production:

- `kwild_engine.namespaces` - Extension namespaces
- `kwild_engine.initialized_extensions` - Extension registrations  
- `kwild_engine.extension_initialization_parameters` - Extension metadata

### Extension Loading Process

1. **Pre-test Setup**: Extensions are registered in the database before interpreter creation
2. **Interpreter Creation**: The interpreter loads registered extensions from the database
3. **Namespace Creation**: Extension namespaces and methods become available
4. **Test Execution**: Tests can use extension functionality normally

### Metadata Handling

Extension metadata is stored and retrieved using the same mechanisms as production:

- Supports all primitive types (string, int, float, bool)
- Supports arrays of primitive types
- Automatically handles type conversion and storage

## Backward Compatibility

The extension loading functionality is fully backward compatible:

- Existing tests continue to work without modifications
- Extensions field in Options is optional
- Default behavior unchanged when no extensions specified

## Troubleshooting

### Extension Not Found Error

```
extension my_extension is not registered
```

**Solution**: Ensure the extension is registered before running tests:

```go
func init() {
    precompiles.RegisterPrecompile("my_extension", myExtension)
}
```

### Extension Method Not Available

**Solution**: Verify extension alias matches the namespace used in SQL:

```go
// Configuration
{Name: "my_extension", Alias: "my_ext"}

// Usage in SQL  
"my_ext.some_method()"  // Must match alias
```

### Database Schema Errors

**Solution**: Ensure the test database has the required kwild_engine schema. This is automatically created by the testing framework.

## Migration from Skipped Tests

To migrate existing tests that were skipped due to extension requirements:

1. Remove `t.Skip()` calls
2. Add extension configuration to test options
3. Update test options parameter in `RunSchemaTest` call

Example:

```go
// Before
func TestCacheBasic(t *testing.T) {
    t.Skip("kwilTesting framework doesn't support extensions")
    // ... test code
}

// After  
func TestCacheBasic(t *testing.T) {
    options := testing.GetTestOptionsWithTnCache()
    testing.RunSchemaTest(t, testing.SchemaTest{
        // ... test definition
    }, options)
}
```