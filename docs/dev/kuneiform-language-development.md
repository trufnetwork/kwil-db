# Kuneiform Language Feature Development Guide

This guide covers the complete development workflow for adding new language features to Kuneiform (Kwil DB's SQL dialect), including grammar extension, AST enhancement, and engine integration using our proven 3-Stage Development Approach.

## Overview

Kwil DB uses ANTLR 4.13.1 to generate parsers for the Kuneiform language. New language features is recommended to be implemented using our **3-Stage Development Approach**:

### **3-Stage Development Approach**

1. **Grammar Extension** - Extend ANTLR grammar to accept new syntax
2. **AST Enhancement** - Add data structures and processing logic
3. **Engine Integration** - Implement execution logic in the engine

This approach ensures:
- **Incremental Development**: Each stage builds on the previous one
- **Comprehensive Testing**: Testing at each stage before moving to the next
- **Maintainability**: Clear separation of concerns between parsing, representation, and execution
- **Backward Compatibility**: No breaking changes to existing functionality

### **Component Architecture**

```
User Input (SQL/Kuneiform)
↓
Grammar Extension (node/engine/parse/grammar/)
↓
AST Enhancement (node/engine/parse/)
↓
Engine Integration (node/engine/interpreter/)
↓
Execution Result
```

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Grammar Extension](#grammar-extension)
- [AST Enhancement](#ast-enhancement)
- [Engine Integration](#engine-integration)
- [Complete Implementation Example: Optional Parameters](#complete-implementation-example-optional-parameters)
- [Best Practices](#best-practices)
- [Common Issues and Solutions](#common-issues-and-solutions)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Requirements](#documentation-requirements)

## Prerequisites

### Java Requirements

ANTLR 4.13.1 requires Java 11 or higher. The recommended version is Java 17 (LTS).

```bash
# Install Java 17
sudo apt update
sudo apt install openjdk-17-jdk

# Verify installation
java -version
# Should show: openjdk version "17.x.x"
```

### Go Modules

Ensure Go modules are up to date:

```bash
cd /path/to/kwil-db
go mod tidy
```

## Grammar Files Structure

```
node/engine/parse/grammar/
├── KuneiformLexer.g4      # Token definitions (keywords, operators, literals)
├── KuneiformParser.g4     # Syntax rules and structure
├── generate.sh            # ANTLR generation script
└── antlr-4.13.1-complete.jar  # ANTLR tool (auto-downloaded)
```

## Grammar Extension

Grammar extension focuses on extending the ANTLR grammar to accept new syntax without breaking existing functionality.

### **Goals**
- Make the grammar accept new syntax
- Generate parsers without errors
- Satisfy visitor interface requirements
- Maintain backward compatibility

### **Workflow**

#### 1. Backup Grammar Files

Always backup before making changes:

```bash
cd node/engine/parse/grammar
cp KuneiformParser.g4 KuneiformParser.g4.backup
cp KuneiformLexer.g4 KuneiformLexer.g4.backup
```

#### 2. Modify Grammar

Edit the `.g4` files to add new syntax. Common patterns:

**Adding New Tokens (KuneiformLexer.g4):**
```antlr
NEW_KEYWORD: 'NEW_KEYWORD';
```

**Adding New Rules (KuneiformParser.g4):**
```antlr
new_rule:
    KEYWORD_1 KEYWORD_2 LPAREN parameter_list? RPAREN
;

parameter_list:
    parameter (COMMA parameter)*
;

parameter:
    VARIABLE type (DEFAULT expr)?
;
```

#### 3. Generate Parser

```bash
cd node/engine/parse/grammar
./generate.sh
```

This script:
1. Downloads ANTLR 4.13.1 jar (if not present)
2. Runs: `antlr4 -Dlanguage=Go -visitor -no-listener -package gen -o ../gen *.g4`
3. Generates Go files in `../gen/` directory

#### 4. Update Go Visitor Interfaces

Grammar changes require updating the visitor implementation in `node/engine/parse/antlr.go`.

**Missing Visitor Methods:**
If you add a new rule `new_rule`, implement:
```go
func (s *schemaVisitor) VisitNew_rule(ctx *gen.New_ruleContext) any {
    // Phase 1: Just satisfy interface requirement
    return nil
}
```

**Context Method Changes:**
```go
// Update parsing loops to use new context methods
for i, param := range ctx.AllParameter() {
    paramCtx := param.(*gen.ParameterContext)
    // Process parameter
}
```

#### 5. Add Test Cases

Add test cases in `node/engine/parse/parse_test.go`:

```go
{
    name:  "Test new syntax",
    input: "NEW_KEYWORD example($param1 int, $param2 bool DEFAULT false);",
    expect: &ExpectedStatement{
        // Expected AST structure
    },
},
```

#### 6. Verify Phase 1 Completion

```bash
# Run all parser tests
go test ./node/engine/parse/... -v

# Check for compilation errors
go build ./node/engine/parse/...
```

**Grammar extension is complete when:**
- ✅ Grammar accepts new syntax
- ✅ Parser generates without errors
- ✅ All existing tests pass
- ✅ New test cases for syntax acceptance pass

### **Documentation**: See `node/engine/parse/grammar/README.md`

---

## AST Enhancement

AST enhancement focuses on adding data structures and processing logic to properly store and represent new language features.

### **Goals**
- Add data structures to store new language constructs
- Update visitor implementation to process new syntax
- Add JSON serialization support
- Implement performance optimizations

### **Workflow**

#### 1. Add AST Data Structures

Add new structs in `node/engine/parse/ast.go`:

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

#### 2. Update Existing Structures

Extend existing structures to include new fields:

```go
type NamedType struct {
    Name         string     `json:"name"`
    Type         *DataType  `json:"type"`
    DefaultValue any        `json:"default,omitempty"`  // Added this field
}
```

#### 3. Update Visitor Implementation

Modify `node/engine/parse/antlr.go` to process new constructs:

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

#### 4. Add Processing Logic

Implement helper functions for new constructs:

```go
func (s *schemaVisitor) processDefaultValue(ctx gen.IAction_exprContext) *DefaultValue {
    expr := ctx.Accept(s).(Expression)

    // Check if it's a simple literal
    if literal, ok := expr.(*ExpressionLiteral); ok {
        return &DefaultValue{
            Expression:   expr,
            LiteralValue: literal.Value,
            IsLiteral:    true,
        }
    }

    // Complex expression - store only the AST
    return &DefaultValue{
        Expression: expr,
        IsLiteral:  false,
    }
}
```

#### 5. Add Comprehensive Tests

Create Phase 2 specific tests:

```go
func TestCreateActionStatementsPhase2(t *testing.T) {
    tests := []struct {
        name   string
        input  string
        expect func(*testing.T, *CreateActionStatement)
    }{
        {
            name:  "Boolean default parameter",
            input: "CREATE ACTION test($param BOOL DEFAULT false) public {};",
            expect: func(t *testing.T, stmt *CreateActionStatement) {
                defaultVal := stmt.Parameters[0].DefaultValue.(*DefaultValue)
                assert.True(t, defaultVal.IsLiteral)
                assert.Equal(t, false, defaultVal.LiteralValue)
            },
        },
    }
}
```

#### 6. Verify Phase 2 Completion

```bash
# Run all tests
go test ./node/engine/parse/... -v

# Test JSON serialization
go test -run TestJSONSerialization
```

**AST enhancement is complete when:**
- ✅ AST structures store new language constructs
- ✅ Visitor implementation processes new syntax
- ✅ JSON serialization works correctly
- ✅ All existing tests pass
- ✅ New AST tests pass

### **Documentation**: See `node/engine/parse/README.md`

---

## Engine Integration

Engine integration focuses on implementing execution logic in the engine to enable actual use of new language features.

### **Goals**
- Implement execution logic for new language features
- Add runtime validation and error handling
- Update core engine components
- Enable end-to-end functionality

### **Workflow**

#### 1. Update Engine Components

Modify core engine files like `node/engine/interpreter/planner.go`:

```go
// Example: Enhanced parameter validation
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

#### 2. Add Evaluation Logic

Implement functions to evaluate new language constructs:

```go
func evaluateDefaultValue(defaultValue any, expectedType *types.DataType) (Value, error) {
    defaultVal, ok := defaultValue.(*parse.DefaultValue)
    if !ok {
        return nil, fmt.Errorf("invalid default value type")
    }

    // For literals, use the pre-evaluated value
    if defaultVal.IsLiteral {
        return createValueFromLiteral(defaultVal.LiteralValue, expectedType)
    }

    // For complex expressions, evaluate the expression
    return evaluateExpression(defaultVal.Expression, expectedType)
}
```

#### 3. Add Runtime Validation

Implement comprehensive error handling:

```go
func createValueFromLiteral(literal any, expectedType *types.DataType) (Value, error) {
    switch v := literal.(type) {
    case bool:
        return makeBool(v), nil
    case int64:
        return makeInt8(v), nil
    case string:
        return makeText(v), nil
    case nil:
        return makeNull(expectedType)
    default:
        return nil, fmt.Errorf("unsupported literal type: %T", literal)
    }
}
```

#### 4. Add Integration Tests

Create comprehensive tests for the complete feature:

```go
func TestDefaultValueEvaluation(t *testing.T) {
    tests := []struct {
        name         string
        defaultValue *parse.DefaultValue
        expectedType *types.DataType
        expectError  bool
    }{
        {
            name: "Boolean literal default",
            defaultValue: &parse.DefaultValue{
                IsLiteral:    true,
                LiteralValue: true,
            },
            expectedType: types.BoolType,
            expectError:  false,
        },
    }
}
```

#### 5. Verify Phase 3 Completion

```bash
# Run all engine tests
go test ./node/engine/... -v

# Run integration tests
go test -run TestIntegration

# Verify end-to-end functionality
go test -run TestEndToEnd
```

**Engine integration is complete when:**
- ✅ Engine can execute new language features
- ✅ Runtime validation works correctly
- ✅ Error handling is comprehensive
- ✅ All existing tests pass
- ✅ New engine tests pass
- ✅ End-to-end functionality works

### **Documentation**: See `node/engine/interpreter/README.md`

## ANTLR Key Concepts

### Context Objects

Each grammar rule creates a context object with methods to access child elements:

```go
// Grammar rule: parameter: VARIABLE type (DEFAULT expr)?
// Creates: ParameterContext with methods:
// - VARIABLE() -> variable token
// - Type_() -> type context
// - DEFAULT() -> default token (nil if not present)
// - Expr() -> expression context (nil if not present)
```

### Visitor Pattern

Implement `KuneiformParserVisitor` interface:

```go
type schemaVisitor struct {
    antlr.BaseParseTreeVisitor
    errs   *errorListener
    stream *antlr.InputStream
}

func (s *schemaVisitor) VisitParameter(ctx *gen.ParameterContext) any {
    name := ctx.VARIABLE().GetText()
    typ := ctx.Type_().Accept(s).(*types.DataType)

    // Handle optional DEFAULT
    var defaultValue *DefaultValue
    if ctx.DEFAULT() != nil {
        defaultValue = ctx.Expr().Accept(s).(*DefaultValue)
    }

    return &Parameter{
        Name:    name,
        Type:    typ,
        Default: defaultValue,
    }
}
```

### Context Method Patterns

- **Single item**: `Type_()` returns `ITypeContext`
- **Multiple items**: `AllType_()` returns `[]ITypeContext`
- **Tokens**: `VARIABLE()` returns `antlr.TerminalNode`
- **Optional items**: Returns `nil` if not present

## Common Issues and Solutions

### Java Version Error
```
java.lang.UnsupportedClassVersionError: org/antlr/v4/Tool has been compiled by a more recent version
```
**Solution**: Upgrade to Java 17+

### Missing Visitor Method
```
*schemaVisitor does not implement gen.KuneiformParserVisitor (missing method VisitXXX)
```
**Solution**: Add the missing method to `antlr.go`

### Context Method Undefined
```
ctx.Method undefined
```
**Solution**: Check generated parser for correct method names (often `AllMethod()` vs `Method()`)

### Test Failures After Grammar Changes
**Solution**:
1. Verify grammar syntax
2. Update visitor implementation
3. Update test expectations if AST structure changed

## Debugging Tips

### Verify Grammar Generation
```bash
# Check generated files timestamps
ls -la node/engine/parse/gen/

# Look for ANTLR errors in output
cd node/engine/parse/grammar
./generate.sh 2>&1 | grep -i error
```

### Check Compilation
```bash
# Build parser package
go build ./node/engine/parse/...

# Check for import issues
go mod tidy
```

### Test Specific Changes
```bash
# Run targeted tests
go test ./node/engine/parse/... -v -run "TestCreateAction"

# Check git diff
git diff node/engine/parse/
```

## Example: Adding DEFAULT Parameter Support

This example shows how Phase 1 of optional parameters was implemented.

### 1. Grammar Changes

**KuneiformParser.g4** - Modified `create_action_statement`:
```antlr
create_action_statement:
    CREATE (OR REPLACE)? ACTION (IF NOT EXISTS)? identifier
    LPAREN (action_parameter (COMMA action_parameter)*)? RPAREN
    identifier*
    action_return?
    LBRACE action_statement* RBRACE
;

action_parameter:
    VARIABLE type (DEFAULT action_expr)?
;
```

### 2. Visitor Updates

**antlr.go** - Updated parameter parsing:
```go
// Updated parameter count
Parameters: arr[*engine.NamedType](len(ctx.AllAction_parameter())),

// Updated parsing loop
for i, param := range ctx.AllAction_parameter() {
    paramCtx := param.(*gen.Action_parameterContext)
    name := s.cleanStringIdent(ctx, paramCtx.VARIABLE().GetText())
    typ := paramCtx.Type_().Accept(s).(*types.DataType)
    cas.Parameters[i] = &engine.NamedType{Name: name, Type: typ}
}

// Added required visitor method
func (s *schemaVisitor) VisitAction_parameter(ctx *gen.Action_parameterContext) any {
    return nil // Phase 1: Just satisfy interface
}
```

### 3. Test Cases

**parse_test.go** - Added comprehensive tests:
```go
{
    name:  "Create action with default parameter (boolean)",
    input: "CREATE ACTION my_action($param1 int, $use_cache bool DEFAULT false) public {};",
    expect: &CreateActionStatement{
        Name:      "my_action",
        Modifiers: []string{"public"},
        Parameters: []*engine.NamedType{
            {Name: "$param1", Type: types.IntType},
            {Name: "$use_cache", Type: types.BoolType},
        },
        Returns: nil,
    },
},
```

## Best Practices

### Grammar Design
- Use descriptive rule names
- Group related rules together
- Add comments for complex rules
- Follow existing naming conventions

### Testing Strategy
- Add tests for new syntax variations
- Test edge cases and error conditions
- Ensure existing tests still pass
- Use descriptive test names

### Error Handling
- Validate grammar syntax before committing
- Handle optional elements gracefully
- Provide clear error messages
- Test error scenarios

### Version Control
- Backup original files before changes
- Commit grammar and generated files together
- Document breaking changes
- Tag major grammar changes

## Integration with Kwil DB

Grammar changes integrate with the broader Kwil DB system:

1. **AST Types** (`node/engine/parse/types.go`) - Define Go structures for AST nodes
2. **Engine Validation** (`node/engine/interpreter/`) - Validate and execute parsed code
3. **SQL Generation** - Convert AST to SQL for database operations
4. **Client SDKs** - May need updates for new syntax features

## Future Development

When extending grammar:

1. **Phase 1**: Grammar accepts new syntax (parsing only)
2. **Phase 2**: AST stores new information (data structures)
3. **Phase 3**: Engine processes new features (execution logic)
4. **Phase 4**: Update client SDKs and documentation

This phased approach allows for incremental development and testing.

## Complete Implementation Example: Optional Parameters

### Grammar Extension (Completed)

Extended grammar to support DEFAULT parameter syntax:

```antlr
action_parameter:
    VARIABLE type (DEFAULT action_expr)?
;
```

**Results**: Grammar accepts `DEFAULT false`, `DEFAULT null`, `DEFAULT 30`, `DEFAULT 10 + 20`

### AST Enhancement (Completed)

Added DefaultValue struct to store default value information:

```go
type DefaultValue struct {
    Expression   Expression `json:"expression,omitempty"`
    LiteralValue any       `json:"literal_value,omitempty"`
    IsLiteral    bool      `json:"is_literal"`
}
```

Extended NamedType to include default values:

```go
type NamedType struct {
    Name         string     `json:"name"`
    Type         *DataType  `json:"type"`
    DefaultValue any        `json:"default,omitempty"`
}
```

**Key Features**:
- **Dual Storage**: Both expression AST and pre-evaluated literals
- **Optimization**: Direct literal access for performance
- **JSON Support**: Complete serialization for API integration

**Test Coverage**:
- Boolean defaults: `DEFAULT false`
- Null defaults: `DEFAULT null`
- Integer defaults: `DEFAULT 42`
- Complex expressions: `DEFAULT 10 + 20`
- Mixed parameters: Required and optional in same action

### Engine Integration (✅ COMPLETED)

Implemented parameter validation with default value injection:

```go
func evaluateDefaultValue(defaultValue any, expectedType *types.DataType) (Value, error) {
    defaultVal, ok := defaultValue.(*parse.DefaultValue)
    if !ok {
        return nil, fmt.Errorf("invalid default value type: %T", defaultValue)
    }

    // For literals, use the pre-evaluated value
    if defaultVal.IsLiteral {
        return createValueFromLiteral(defaultVal.LiteralValue, expectedType)
    }

    // For complex expressions, evaluate the expression
    return evaluateExpression(defaultVal.Expression, expectedType)
}
```

**Key Features Implemented:**
- **Parameter Validation**: Enhanced `validateArgs` function handles fewer arguments than parameters
- **Default Value Evaluation**: Complete system for literal and complex expression evaluation
- **Arithmetic Operations**: Support for +, -, *, / in default expressions
- **Type Safety**: Proper Value constructor usage and type assertions
- **Error Handling**: Comprehensive error reporting for invalid defaults

**Test Coverage:**
- Unit tests for default value evaluation (`default_values_test.go`)
- Integration tests with complete action execution
- Regression tests ensuring backward compatibility

**Usage Examples:**
```sql
-- Basic optional parameters
CREATE ACTION get_users($limit INT DEFAULT 10, $active BOOL DEFAULT true) {
    SELECT * FROM users WHERE active = $active LIMIT $limit;
};

-- Complex expression defaults
CREATE ACTION process_batch(
    $data_source TEXT,
    $batch_size INT DEFAULT 50 * 2,    -- Evaluates to 100
    $timeout INT DEFAULT 30 + 30       -- Evaluates to 60
) {
    -- Action implementation
};
```

**Files Modified:**
- `node/engine/interpreter/planner.go` - Core parameter validation and evaluation
- `node/engine/interpreter/default_values_test.go` - Comprehensive test coverage

### Future Enhancements

Optional parameters functionality can be extended with:

```sql
-- Enhanced expressions and function calls
CREATE ACTION get_record($data_provider TEXT, $stream_id TEXT, $use_cache BOOL DEFAULT false) public {
    -- $use_cache defaults to false when not provided
};
```

This demonstrates the complete language feature development lifecycle from parsing through execution.

## Documentation Requirements

When implementing new language features, ensure comprehensive documentation is created:

### Component Documentation

#### Grammar Extension
- **Location**: `node/engine/parse/grammar/README.md`
- **Content**: Grammar rules, token definitions, generation process
- **Audience**: Developers modifying grammar files

#### AST Enhancement
- **Location**: `node/engine/parse/README.md`
- **Content**: AST structures, visitor implementation, JSON serialization
- **Audience**: Developers working with parser and AST

#### Engine Integration
- **Location**: `node/engine/interpreter/README.md`
- **Content**: Execution logic, validation, runtime behavior
- **Audience**: Developers implementing execution features

### Implementation Guides

Create detailed implementation guides for each development stage:

- **Grammar extension guide** - Grammar extension details
- **AST enhancement guide** - AST enhancement details
- **Engine integration guide** - Engine integration details

### Summary Documentation

- **`kwil-db-optional-parameters-implementation-summary.md`** - Complete feature overview
- **Update `CONTRIBUTING.md`** - Include 3-Stage Development Approach
- **Update this guide** - Document the complete implementation

### Testing Documentation

Document testing strategies for each development stage:

```markdown
#### Grammar Testing
- Grammar acceptance tests
- Parser generation verification
- Syntax error handling

#### AST Testing
- AST structure validation
- JSON serialization tests
- Visitor implementation tests

#### Engine Testing
- Execution logic tests
- Integration tests
- Performance benchmarks
```

### Code Documentation

Ensure comprehensive code documentation:

```go
// Example: Comprehensive function documentation
// evaluateDefaultValue evaluates a default value from the AST and returns a Value.
// It handles both literal values (for performance) and complex expressions.
//
// Parameters:
//   - defaultValue: The default value from the AST (must be *parse.DefaultValue)
//   - expectedType: The expected data type for validation
//
// Returns:
//   - Value: The evaluated default value
//   - error: Any error that occurred during evaluation
//
// Performance Note: Literal values use a fast path for better performance.
func evaluateDefaultValue(defaultValue any, expectedType *types.DataType) (Value, error) {
    // Implementation...
}
```

## Testing Guidelines

### Stage-Specific Testing

#### Grammar Testing
```bash
# Test grammar accepts new syntax
go test ./node/engine/parse/... -v -run "TestGrammar"

# Test parser generation
cd node/engine/parse/grammar && ./generate.sh

# Test syntax error handling
go test ./node/engine/parse/... -v -run "TestSyntaxErrors"
```

#### AST Testing
```bash
# Test AST structure creation
go test ./node/engine/parse/... -v -run "TestAST"

# Test JSON serialization
go test ./node/engine/parse/... -v -run "TestJSON"

# Test visitor implementation
go test ./node/engine/parse/... -v -run "TestVisitor"
```

#### Engine Testing
```bash
# Test execution logic
go test ./node/engine/interpreter/... -v -run "TestExecution"

# Test integration scenarios
go test ./node/engine/interpreter/... -v -run "TestIntegration"

# Test performance
go test ./node/engine/interpreter/... -v -run "TestPerformance" -bench=.
```

### Comprehensive Testing Strategy

1. **Unit Tests**: Test individual functions and components
2. **Integration Tests**: Test complete feature workflows
3. **Regression Tests**: Ensure existing functionality is preserved
4. **Performance Tests**: Validate performance requirements
5. **Error Handling Tests**: Test all error scenarios

### Test Coverage Requirements

- **Grammar**: Grammar acceptance, parser generation, syntax errors
- **AST**: AST creation, JSON serialization, visitor processing
- **Engine**: Execution logic, validation, integration scenarios

## Best Practices Summary

### Development Approach
1. **Incremental Implementation**: Complete each stage before moving to the next
2. **Comprehensive Testing**: Test thoroughly at each stage
3. **Documentation**: Document each stage and component
4. **Backward Compatibility**: Ensure existing functionality is preserved

### Code Quality
1. **Type Safety**: Use strong typing throughout
2. **Error Handling**: Handle all possible error conditions
3. **Performance**: Optimize for common use cases
4. **Documentation**: Document all public APIs and complex logic

### Testing Strategy
1. **Stage-Specific Tests**: Target tests for each development stage
2. **Integration Tests**: Test complete workflows
3. **Error Scenarios**: Test all error conditions
4. **Performance**: Benchmark critical paths

This comprehensive approach ensures high-quality, maintainable, and well-documented language features in Kwil DB.