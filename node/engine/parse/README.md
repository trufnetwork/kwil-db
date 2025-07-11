# Kuneiform Parser (AST Enhancement)

This directory contains the Kuneiform parser implementation, responsible for converting parsed grammar into Abstract Syntax Tree (AST) data structures. This is the **AST Enhancement** stage of the Kuneiform language feature development process.

## Overview

The parser takes the output from grammar extension and creates structured data representations that can be processed by the engine. This stage focuses on:

- **AST Data Structures**: Defining Go structs to represent language constructs
- **Visitor Implementation**: Processing parsed grammar into AST nodes
- **JSON Serialization**: API integration support
- **Performance Optimization**: Efficient data representation

## Architecture

```
Grammar Extension → AST Enhancement → Engine Integration
                         ↓
                   AST Data Structures
                         ↓
                   JSON Serialization
                         ↓
                   API Integration
```

## Key Components

### AST Data Structures (`ast.go`)

Defines the core data structures for representing Kuneiform language constructs:

```go
// Example: DefaultValue represents a default value for a parameter
type DefaultValue struct {
    // Expression is the parsed AST expression for the default value
    Expression Expression `json:"expression,omitempty"`
    // LiteralValue is the pre-evaluated value for simple literals
    LiteralValue any `json:"literal_value,omitempty"`
    // IsLiteral indicates whether this is a simple literal value
    IsLiteral bool `json:"is_literal"`
}
```

**Key Features:**
- **Dual Storage**: Both expression AST and pre-evaluated literals
- **JSON Support**: Complete serialization for API integration
- **Performance**: Optimized for common use cases

### Visitor Implementation (`antlr.go`)

Implements the ANTLR visitor pattern to convert parsed grammar into AST:

```go
func (s *schemaVisitor) VisitAction_parameter(ctx *gen.Action_parameterContext) any {
    name := s.cleanStringIdent(ctx, ctx.VARIABLE().GetText())
    typ := ctx.Type_().Accept(s).(*types.DataType)

    var defaultValue any
    if ctx.DEFAULT() != nil {
        defaultValue = s.processDefaultValue(ctx.Action_expr())
    }

    return &engine.NamedType{
        Name:         name,
        Type:         typ,
        DefaultValue: defaultValue,
    }
}
```

### Test Coverage (`parse_test.go`)

Comprehensive tests for parsing functionality:

- **Syntax Validation**: Ensures grammar is parsed correctly
- **AST Structure**: Validates proper AST node creation
- **Edge Cases**: Tests boundary conditions and error scenarios
- **JSON Serialization**: Validates API integration

## Implementation Example: Optional Parameters

### AST Enhancement Implementation

The optional parameters feature demonstrates complete AST enhancement implementation:

#### 1. AST Data Structures
```go
// DefaultValue struct for storing default parameter values
type DefaultValue struct {
    Expression   Expression `json:"expression,omitempty"`
    LiteralValue any       `json:"literal_value,omitempty"`
    IsLiteral    bool      `json:"is_literal"`
}
```

#### 2. Enhanced Parameter Processing
```go
func (s *schemaVisitor) processDefaultValue(ctx gen.IAction_exprContext) *DefaultValue {
    expr := ctx.Accept(s).(Expression)

    // Optimize for simple literals
    if literal, ok := expr.(*ExpressionLiteral); ok {
        return &DefaultValue{
            Expression:   expr,
            LiteralValue: literal.Value,
            IsLiteral:    true,
        }
    }

    // Complex expression - store AST only
    return &DefaultValue{
        Expression: expr,
        IsLiteral:  false,
    }
}
```

#### 3. JSON Integration
```json
{
  "name": "$use_cache",
  "type": {"name": "bool", "is_array": false},
  "default": {
    "expression": {"type": "literal", "value": false},
    "literal_value": false,
    "is_literal": true
  }
}
```

## Development Workflow

### Adding New Language Features (AST Enhancement)

1. **Define AST Structures**: Add new structs in `ast.go`
2. **Update Visitor**: Modify `antlr.go` to process new grammar
3. **Add Processing Logic**: Implement helper functions for new constructs
4. **Create Tests**: Add comprehensive test cases
5. **Verify JSON Support**: Ensure serialization works correctly

### Testing

```bash
# Run all parser tests
go test ./node/engine/parse/... -v

# Run specific test suites
go test ./node/engine/parse/... -v -run "TestCreateActionStatements"
go test ./node/engine/parse/... -v -run "TestCreateActionStatementsWithOptionalParams"

# Test JSON serialization
go test -run TestJSONSerialization
```

### Code Quality

```bash
# Format code
gofmt -w ./node/engine/parse/

# Run linter
golangci-lint run ./node/engine/parse/

# Check compilation
go build ./node/engine/parse/...
```

## Performance Considerations

### Literal Optimization

Phase 2 implements performance optimizations for common cases:

```go
// Fast path for literals
if defaultVal.IsLiteral {
    return defaultVal.LiteralValue  // No evaluation needed
}

// Slow path for complex expressions
return evaluateExpression(defaultVal.Expression)
```

### Memory Efficiency

- **Reuse of AST nodes** where possible
- **Minimal allocation** for common patterns
- **Efficient JSON marshaling** with omitempty tags

## Error Handling

Phase 2 includes comprehensive error handling:

- **Type Validation**: Ensures proper AST node types
- **Context Validation**: Validates grammar context objects
- **JSON Errors**: Handles serialization failures
- **Memory Safety**: Prevents panics from nil pointers

## Integration Points

### Grammar Integration
- **Grammar Input**: Processes ANTLR-generated parse trees
- **Context Objects**: Uses generated context interfaces
- **Visitor Pattern**: Implements ANTLR visitor interface

### Engine Integration
- **AST Output**: Provides structured data for engine processing
- **Type Information**: Supplies type metadata for validation
- **Default Values**: Provides default value information for execution

## File Structure

```
node/engine/parse/
├── ast.go              # AST data structures
├── antlr.go            # Visitor implementation
├── parse_test.go       # Comprehensive tests
├── types.go            # Type definitions
├── position.go         # Position tracking
├── grammar/            # Phase 1: Grammar files
│   ├── README.md       # Grammar documentation
│   └── *.g4           # ANTLR grammar files
└── gen/               # Generated parser code
    └── *.go           # ANTLR-generated files
```

## Best Practices

### AST Design
- **Immutable Structures**: AST nodes should be immutable after creation
- **Type Safety**: Use strong typing throughout
- **Documentation**: Document all public structures and methods
- **JSON Support**: Include JSON tags for API integration

### Visitor Implementation
- **Error Handling**: Handle all possible error conditions
- **Type Assertions**: Validate all type assertions
- **Context Validation**: Check context objects for nil values
- **Performance**: Optimize for common cases

### Testing
- **Comprehensive Coverage**: Test all code paths
- **Edge Cases**: Test boundary conditions
- **Error Scenarios**: Test error handling
- **Performance**: Include performance benchmarks

## Future Enhancements

AST enhancement provides the foundation for future language features:

- **Advanced Expressions**: Support for more complex expression types
- **Type Inference**: Enhanced type validation and inference
- **Optimization**: Additional performance optimizations
- **Debugging Support**: Enhanced error messages and debugging information

For more information on language feature development, see the [Kuneiform Language Development Guide](../../docs/dev/kuneiform-language-development.md).