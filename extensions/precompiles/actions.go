// package actions allows custom actions to be registered with the
// engine.
package precompiles

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// Initializer is a function that creates a new instance of an extension.
// It is called:
// - Each time an extension is instantiated using `USE ... AS ...`
// - Once for every instantiated extension on node startup
// It should be used for reading values into memory, creating
// connections, and other setup that should only be done once per
// extension instance.
type Initializer func(ctx context.Context, service *common.Service, db sql.DB, alias string, metadata map[string]any) (Precompile, error)

// Precompile holds the methods and lifecycle hooks for a precompile extension.
type Precompile struct {
	// OnStart is called when the node starts, or when the extension is first used
	OnStart func(ctx context.Context, app *common.App) error
	// OnUse is called when a `USE ... AS ...` statement is executed
	OnUse func(ctx *common.EngineContext, app *common.App) error
	// Methods is a map of method names to method implementations.
	Methods []Method
	// OnUnuse is called when a `UNUSE ...` statement is executed
	OnUnuse func(ctx *common.EngineContext, app *common.App) error
	// Cache is a snapshot of the in-memory state of the extension.
	// It is used to save and restore the state of the extension.
	Cache Cache
}

// Cache is a snapshot of the in-memory state of a precompile extension.
type Cache interface {
	// Copy creates a deep copy of the cache.
	Copy() Cache
	// Apply applies a previously created deep copy of the cache.
	// The value passed from Apply will never be changed by the engine,
	// so there is no need to copy it.
	Apply(cache Cache)
}

type emptyCache struct{}

func (e *emptyCache) Apply(cache Cache) {}

func (e *emptyCache) Copy() Cache { return &emptyCache{} }

// CleanExtension verifies that the extension is correctly set up.
// It does not need to be called by extension authors, as it is called
// automatically by kwild.
func CleanPrecompile(e *Precompile) error {
	methodNames := make(map[string]struct{})
	for _, method := range e.Methods {
		err := method.verify()
		if err != nil {
			return fmt.Errorf("method %s: %w", method.Name, err)
		}

		if _, ok := methodNames[method.Name]; ok {
			return fmt.Errorf("duplicate method %s", method.Name)
		}

		methodNames[method.Name] = struct{}{}
	}

	if e.OnStart == nil {
		e.OnStart = func(ctx context.Context, app *common.App) error { return nil }
	}
	if e.OnUse == nil {
		e.OnUse = func(ctx *common.EngineContext, app *common.App) error { return nil }
	}
	if e.OnUnuse == nil {
		e.OnUnuse = func(ctx *common.EngineContext, app *common.App) error { return nil }
	}

	if e.Cache == nil {
		e.Cache = &emptyCache{}
	}

	return nil
}

// Method is a method that can be called on a precompile extension.
type Method struct {
	// Name is the name of the method.
	// It is case-insensitive, and should be unique within the extension.
	Name string
	// AccessModifiers is a list of access modifiers for the method.
	// It must have exactly one of PUBLIC, PRIVATE, or SYSTEM,
	// and can have any number of other modifiers.
	AccessModifiers []Modifier
	// Parameters is a list of parameters.
	// The engine will enforce that anything calling the method
	// provides the correct number of parameters, and in the correct
	// types.
	Parameters []PrecompileValue
	// Returns specifies the return structure of the method.
	// If nil, the method does not return anything.
	Returns *MethodReturn
	// Handler is the function that is called when the method is invoked.
	Handler HandlerFunc
}

type HandlerFunc func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error

// Copy deep-copies a method.
func (m *Method) Copy() *Method {
	m2 := &Method{
		Name:            m.Name,
		AccessModifiers: slices.Clone(m.AccessModifiers),
		Parameters:      copyParams(m.Parameters),
		Handler:         m.Handler,
	}

	if m.Returns != nil {
		m2.Returns = &MethodReturn{
			IsTable: m.Returns.IsTable,
			Fields:  copyParams(m.Returns.Fields),
		}
	}

	return m2
}

func copyParams(params []PrecompileValue) []PrecompileValue {
	params2 := make([]PrecompileValue, len(params))
	for i, param := range params {
		params2[i] = param.Copy()
	}
	return params2
}

func (m *Method) verify() error {
	if strings.ToLower(m.Name) != m.Name {
		return fmt.Errorf("method name %s must be lowercase", m.Name)
	}

	if len(m.Name) == 0 {
		return fmt.Errorf("method name must not be empty")
	}

	if len(m.AccessModifiers) == 0 {
		return fmt.Errorf("method %s has no access modifiers", m.Name)
	}

	found := 0
	for _, mod := range m.AccessModifiers {
		if mod == PUBLIC || mod == PRIVATE || mod == SYSTEM {
			found++
		}
	}

	if found != 1 {
		return fmt.Errorf("method %s must have exactly one of PUBLIC, PRIVATE, or SYSTEM", m.Name)
	}

	if err := uniqueFieldNames(m.Parameters); err != nil {
		return fmt.Errorf("method %s: %w", m.Name, err)
	}

	if m.Returns != nil {
		if len(m.Returns.Fields) == 0 {
			return fmt.Errorf("method %s has no return types", m.Name)
		}

		if err := uniqueFieldNames(m.Returns.Fields); err != nil {
			return fmt.Errorf("method %s: %w", m.Name, err)
		}
	}

	return nil
}

func uniqueFieldNames(fields []PrecompileValue) error {
	fieldNames := make(map[string]struct{})
	for _, field := range fields {
		if _, ok := fieldNames[field.Name]; ok {
			return fmt.Errorf("duplicate field name %s", field.Name)
		}
		fieldNames[field.Name] = struct{}{}
	}

	return nil
}

// MethodReturn specifies the return structure of a method.
type MethodReturn struct {
	// If true, then the method returns any number of rows.
	// If false, then the method returns exactly one row.
	IsTable bool
	// Fields is a list of column types.
	// It is required. If the extension returns types that are
	// not matching the column types, the engine will return an error.
	Fields []PrecompileValue
}

// Modifier modifies the access to an action.
type Modifier string

const (
	// PUBLIC means that the action is public.
	PUBLIC Modifier = "PUBLIC"
	// PRIVATE means that the action is private.
	PRIVATE Modifier = "PRIVATE"
	// SYSTEM means that the action can only be called by the system.
	SYSTEM Modifier = "SYSTEM"
	// View means that an action does not modify the database.
	VIEW Modifier = "VIEW"

	// Owner requires that the caller is the owner of the database.
	OWNER Modifier = "OWNER"
)

type Modifiers []Modifier

func (m Modifiers) Has(mod Modifier) bool {
	return slices.Contains(m, mod)
}

// PrecompileValue specifies the type and nullability of a value passed to or returned from
// a precompile method.
type PrecompileValue struct {
	// Name is the name of the value.
	Name string
	// Type is the type of the value.
	Type *types.DataType
	// Nullable is true if the value can be null.
	Nullable bool
}

func (p *PrecompileValue) Copy() PrecompileValue {
	return PrecompileValue{
		Name:     p.Name,
		Type:     p.Type.Copy(),
		Nullable: p.Nullable,
	}
}

// NewPrecompileValue creates a new precompile value.
// TODO: update this signature to include name
func NewPrecompileValue(name string, t *types.DataType, nullable bool) PrecompileValue {
	return PrecompileValue{
		Name:     name,
		Type:     t,
		Nullable: nullable,
	}
}

var registeredPrecompiles = make(map[string]Initializer)

func RegisteredPrecompiles() map[string]Initializer {
	return registeredPrecompiles
}

// RegisterPrecompile registers a precompile extension with the engine.
// It is a more user-friendly way to register precompiles than RegisterInitializer.
func RegisterPrecompile(name string, ext Precompile) error {
	name = strings.ToLower(name)
	if _, ok := registeredPrecompiles[name]; ok {
		return fmt.Errorf("precompile of same name already registered:%s ", name)
	}

	err := CleanPrecompile(&ext)
	if err != nil {
		return err
	}

	return RegisterInitializer(name, func(ctx context.Context, service *common.Service, db sql.DB, alias string, metadata map[string]any) (Precompile, error) {
		return ext, nil
	})
}

// RegisterInitializer registers an initializer for a precompile extension.
// It is more flexible than RegisterPrecompile, as it allows extension interfaces to
// change dynamically based on initialization. Unless you need this flexibility,
// use RegisterPrecompile instead.

func RegisterInitializer(name string, init Initializer) error {
	name = strings.ToLower(name)
	if _, ok := registeredPrecompiles[name]; ok {
		return fmt.Errorf("precompile of same name already registered:%s ", name)
	}

	registeredPrecompiles[name] = init
	return nil
}
