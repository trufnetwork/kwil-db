# Grammar Development Guide

This guide covers the development workflow for modifying Kuneiform grammar in Kwil DB, including ANTLR parser generation, Go visitor implementation, and testing.

## Overview

Kwil DB uses ANTLR 4.13.1 to generate parsers for the Kuneiform language. The grammar files define the syntax rules, and ANTLR generates Go code that parses Kuneiform into an Abstract Syntax Tree (AST).

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

## Development Workflow

### 1. Backup Grammar Files

Always backup before making changes:

```bash
cd node/engine/parse/grammar
cp KuneiformParser.g4 KuneiformParser.g4.backup
cp KuneiformLexer.g4 KuneiformLexer.g4.backup
```

### 2. Modify Grammar

Edit the `.g4` files to add new syntax. Common patterns:

#### Adding New Tokens (KuneiformLexer.g4)
```antlr
NEW_KEYWORD: 'NEW_KEYWORD';
```

#### Adding New Rules (KuneiformParser.g4)
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

### 3. Generate Parser

```bash
cd node/engine/parse/grammar
./generate.sh
```

This script:
1. Downloads ANTLR 4.13.1 jar (if not present)
2. Runs: `antlr4 -Dlanguage=Go -visitor -no-listener -package gen -o ../gen *.g4`
3. Generates Go files in `../gen/` directory

### 4. Update Go Visitor Implementation

Grammar changes often require updating the visitor implementation in `node/engine/parse/antlr.go`.

#### Common Updates Required

**Missing Visitor Methods:**
If you add a new rule `new_rule`, implement:
```go
func (s *schemaVisitor) VisitNew_rule(ctx *gen.New_ruleContext) any {
    // Implementation here
    return nil
}
```

**Context Method Changes:**
Grammar changes affect context object methods:
```go
// Old: ctx.AllType_()
// New: ctx.AllParameter()

// Update loops accordingly:
for i, param := range ctx.AllParameter() {
    paramCtx := param.(*gen.ParameterContext)
    // Process parameter
}
```

### 5. Add Test Cases

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

### 6. Run Tests

```bash
# Run all parser tests
go test ./node/engine/parse/... -v

# Run specific test suite
go test ./node/engine/parse/... -v -run "TestNewSyntax"

# Check for compilation errors
go build ./node/engine/parse/...
```

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

### Phase 1: Grammar Extension (Completed)

Extended grammar to support DEFAULT parameter syntax:

```antlr
action_parameter:
    VARIABLE type (DEFAULT action_expr)?
;
```

**Results**: Grammar accepts `DEFAULT false`, `DEFAULT null`, `DEFAULT 30`, `DEFAULT 10 + 20`

### Phase 2: AST Enhancement (Completed)

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

### Phase 3: Engine Integration (Planned)

Will implement parameter validation with default value injection:

```go
func validateAndFillDefaults(args []Value, params []*NamedType) ([]Value, error) {
    // Fill missing arguments with defaults
    for i := len(args); i < len(params); i++ {
        if params[i].DefaultValue == nil {
            return nil, fmt.Errorf("missing required argument %d", i+1)
        }
        
        defaultVal, err := evaluateDefault(params[i].DefaultValue)
        if err != nil {
            return nil, fmt.Errorf("default evaluation failed: %v", err)
        }
        
        result[i] = defaultVal
    }
    
    return result, nil
}
```

### Phase 4: SQL Action Updates (Planned)

Will update existing SQL actions to use new DEFAULT syntax:

```sql
-- Before
CREATE ACTION get_record($data_provider TEXT, $stream_id TEXT, $use_cache BOOL) public {
    -- Must pass explicit null for $use_cache
};

-- After  
CREATE ACTION get_record($data_provider TEXT, $stream_id TEXT, $use_cache BOOL DEFAULT false) public {
    -- $use_cache defaults to false when not provided
};
```

This demonstrates the complete grammar extension lifecycle from parsing through execution.