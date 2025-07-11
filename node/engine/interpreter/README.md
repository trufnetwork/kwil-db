# Kuneiform Engine Interpreter (Engine Integration)

This directory contains the Kuneiform engine interpreter implementation, responsible for executing parsed and structured language features. This is the **Engine Integration** stage of the Kuneiform language feature development process.

## Overview

The interpreter takes the AST output from AST enhancement and implements the actual execution logic for language features. This stage focuses on:

- **Execution Logic**: Implementing runtime behavior for language constructs
- **Parameter Validation**: Validating and processing action parameters
- **Default Value Evaluation**: Executing default value expressions
- **Error Handling**: Comprehensive runtime error management

## Architecture

```
Grammar Extension → AST Enhancement → Engine Integration
                                             ↓
                                    Runtime Execution
                                             ↓
                                    Parameter Validation
                                             ↓
                                    Default Value Evaluation
                                             ↓
                                    Action Execution
```

## Key Components

### Parameter Validation (`planner.go`)

Implements enhanced parameter validation with optional parameter support:

```go
validateArgs := func(v []Value) ([]Value, error) {
    // Check for too many arguments
    if len(v) > len(act.Parameters) {
        return nil, fmt.Errorf("expected at most %d arguments, got %d", len(act.Parameters), len(v))
    }

    // Prepare result array with full parameter count
    newVal := make([]Value, len(act.Parameters))

    // Process provided arguments
    for i, arg := range v {
        if !act.Parameters[i].Type.Equals(arg.Type()) {
            return nil, fmt.Errorf("type mismatch for argument %d", i+1)
        }
        newVal[i] = arg
    }

    // Fill missing arguments with defaults
    for i := len(v); i < len(act.Parameters); i++ {
        param := act.Parameters[i]
        if param.DefaultValue == nil {
            return nil, fmt.Errorf("missing required argument %d", i+1)
        }

        // Evaluate default value
        defaultVal, err := evaluateDefaultValue(param.DefaultValue, param.Type)
        if err != nil {
            return nil, fmt.Errorf("failed to evaluate default: %w", err)
        }
        newVal[i] = defaultVal
    }

    return newVal, nil
}
```

### Default Value Evaluation (`planner.go`)

Implements comprehensive default value evaluation system:

```go
func evaluateDefaultValue(defaultValue any, expectedType *types.DataType) (Value, error) {
    defaultVal, ok := defaultValue.(*parse.DefaultValue)
    if !ok {
        return nil, fmt.Errorf("invalid default value type")
    }

    // Only handle literal values (literal-only implementation for security and performance)
    return createValueFromLiteral(defaultVal.LiteralValue, expectedType)
}
```

### Value Creation (`planner.go`)

Type-safe value creation with proper constructor usage:

```go
func createValueFromLiteral(literal any, expectedType *types.DataType) (Value, error) {
    if literal == nil {
        return makeNull(expectedType)
    }

    switch v := literal.(type) {
    case bool:
        return makeBool(v), nil
    case int64:
        return makeInt8(v), nil
    case float64:
        return NewValue(v)
    case string:
        return makeText(v), nil
    default:
        return nil, fmt.Errorf("unsupported literal type: %T", literal)
    }
}
```

### Complex Expression Evaluation (`planner.go`)

Framework for evaluating complex expressions:

```go
func evaluateExpression(expr parse.Expression, expectedType *types.DataType) (Value, error) {
    if expr == nil {
        return nil, fmt.Errorf("no expression to evaluate")
    }

    // Handle ExpressionLiteral
    if literal, ok := expr.(*parse.ExpressionLiteral); ok {
        return createValueFromLiteral(literal.Value, expectedType)
    }

    // Handle arithmetic expressions
    if arith, ok := expr.(*parse.ExpressionArithmetic); ok {
        return evaluateArithmetic(arith, expectedType)
    }

    return nil, fmt.Errorf("unsupported expression type: %T", expr)
}
```

## Implementation Example: Optional Parameters

### Engine Integration Implementation

The optional parameters feature demonstrates complete engine integration implementation:

#### 1. Enhanced Parameter Validation
- **Flexible Arguments**: Accepts fewer arguments than parameters
- **Type Validation**: Ensures type compatibility
- **Default Filling**: Fills missing arguments with evaluated defaults

#### 2. Comprehensive Default Evaluation
- **Literal Fast Path**: Pre-evaluated literals for performance
- **Expression Evaluation**: Full expression evaluation for complex defaults
- **Type Safety**: Proper Value constructor usage

#### 3. Arithmetic Operations
```go
func performAddition(left, right Value) (Value, error) {
    if left.Type().Equals(types.IntType) && right.Type().Equals(types.IntType) {
        leftInt8, ok := left.(*int8Value)
        if !ok {
            return nil, fmt.Errorf("expected int8Value, got %T", left)
        }
        rightInt8, ok := right.(*int8Value)
        if !ok {
            return nil, fmt.Errorf("expected int8Value, got %T", right)
        }
        return makeInt8(leftInt8.Int64 + rightInt8.Int64), nil
    }

    return nil, fmt.Errorf("unsupported types for addition")
}
```

## Execution Flow

### Action Execution with Optional Parameters

```
Action Call: my_action(123)
↓
Parameters: [$param1 INT, $param2 BOOL DEFAULT false]
↓
Validation: 1 argument provided, 2 parameters expected
↓
Argument Processing: $param1 = 123 (validated)
↓
Default Evaluation: $param2 = false (from DEFAULT false)
↓
Execution: action runs with [123, false]
```

### Default Value Processing

```
Default Value: "DEFAULT 10 + 20"
↓
Parse Check: DefaultValue{Expression: ExpressionArithmetic{...}, IsLiteral: false}
↓
Expression Evaluation: evaluateExpression() → evaluateArithmetic()
↓
Operand Processing: 10 → makeInt8(10), 20 → makeInt8(20)
↓
Operation: performAddition(10, 20)
↓
Result: makeInt8(30)
```

## Development Workflow

### Adding New Language Features (Engine Integration)

1. **Update Core Components**: Modify planner.go and related files
2. **Add Evaluation Logic**: Implement execution functions
3. **Add Runtime Validation**: Handle error conditions
4. **Create Integration Tests**: Test end-to-end functionality
5. **Verify Performance**: Ensure acceptable performance

### Testing

```bash
# Run all interpreter tests
go test ./node/engine/interpreter/... -v

# Run specific test suites
go test ./node/engine/interpreter/... -v -run "TestDefaultValueEvaluation"
go test ./node/engine/interpreter/... -v -run "TestCreateValueFromLiteral"

# Run integration tests
go test -run TestIntegration

# Verify end-to-end functionality
go test -run TestEndToEnd
```

### Code Quality

```bash
# Format code
gofmt -w ./node/engine/interpreter/

# Run linter
golangci-lint run ./node/engine/interpreter/

# Check compilation
go build ./node/engine/interpreter/...
```

## Performance Optimizations

### Literal Fast Path

Phase 3 implements performance optimizations for common cases:

```go
// Fast path for pre-evaluated literals
if defaultVal.IsLiteral {
    return createValueFromLiteral(defaultVal.LiteralValue, expectedType)
}

// Slow path for complex expressions
return evaluateExpression(defaultVal.Expression, expectedType)
```

### Type-Safe Operations

- **Proper Value Constructors**: Use makeInt8(), makeText(), makeBool()
- **Type Assertions**: Validate Value types before operations
- **Memory Efficiency**: Minimize allocations during execution

## Error Handling

Phase 3 includes comprehensive error handling:

### Parameter Validation Errors
- **Too Many Arguments**: When more arguments than parameters provided
- **Type Mismatches**: When argument types don't match parameter types
- **Missing Required Parameters**: When no default value is available

### Default Value Evaluation Errors
- **Invalid Default Types**: When default value has wrong type
- **Expression Evaluation Failures**: When complex expressions fail
- **Arithmetic Errors**: Division by zero, overflow, etc.

### Runtime Errors
- **Value Constructor Failures**: When Value creation fails
- **Type Assertion Failures**: When type assertions fail
- **Cast Operation Failures**: When type casts fail

## Integration Points

### AST Integration
- **AST Input**: Processes structured AST from parser
- **Default Values**: Uses DefaultValue structs from parser
- **Type Information**: Leverages type metadata from AST

### Engine Integration
- **Action Execution**: Integrates with core action execution logic
- **Value System**: Uses engine Value types and operations
- **Error Reporting**: Provides detailed error information

## File Structure

```
node/engine/interpreter/
├── planner.go              # Core execution logic
├── default_values_test.go  # Phase 3 tests
├── interpreter.go          # Main interpreter
├── values.go              # Value system
├── roles_test.go          # Role-based tests
└── *.go                   # Other interpreter components
```

## Supported Features

### Basic Optional Parameters
```sql
CREATE ACTION get_users($limit INT DEFAULT 10, $active BOOL DEFAULT true) {
    SELECT * FROM users WHERE active = $active LIMIT $limit;
};
```

### Literal-Only Defaults
```sql
CREATE ACTION process_batch(
    $data_source TEXT,
    $batch_size INT DEFAULT 100,       -- Literal values only
    $timeout INT DEFAULT 60            -- Pre-computed values
) {
    -- Action implementation
};
```

### Mixed Parameter Types
```sql
CREATE ACTION process_data(
    $data_source TEXT,                    -- Required
    $max_records INT DEFAULT 100,         -- Optional with default
    $use_cache BOOL DEFAULT true,         -- Optional with default
    $timeout INT DEFAULT 60               -- Optional with literal default
) {
    -- Process data implementation
};
```

## Runtime Usage

### Go Client Integration
```go
// Call with all parameters
result, err := client.Execute("process_data", []any{"source", 50, false, 120})

// Call with partial parameters (uses defaults)
result, err := client.Execute("process_data", []any{"source", 50})
// Uses: use_cache = true, timeout = 60

// Call with minimal parameters (uses multiple defaults)
result, err := client.Execute("process_data", []any{"source"})
// Uses: max_records = 100, use_cache = true, timeout = 60
```

## Best Practices

### Execution Logic
- **Type Safety**: Always validate Value types before operations
- **Error Handling**: Handle all possible error conditions
- **Performance**: Optimize for common cases
- **Memory Management**: Minimize allocations during execution

### Default Value Evaluation
- **Literal Optimization**: Use fast path for pre-evaluated literals
- **Expression Validation**: Validate expressions before evaluation
- **Type Compatibility**: Ensure default values match parameter types
- **Error Reporting**: Provide clear error messages for failures

### Testing
- **Unit Tests**: Test individual functions and components
- **Integration Tests**: Test complete execution flows
- **Error Scenarios**: Test all error conditions
- **Performance Tests**: Benchmark critical paths

## Future Enhancements

Engine integration provides the foundation for future execution features:

- **Advanced Expressions**: Support for more complex expression types
- **Function Calls**: Enable function calls in default expressions
- **Variable References**: Allow variable references in defaults
- **Performance Optimization**: Additional execution optimizations

For more information on language feature development, see the [Kuneiform Language Development Guide](../../docs/dev/kuneiform-language-development.md).