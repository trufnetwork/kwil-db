package interpreter

import (
	"context"
	"fmt"
	"strings"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// initializeExtension initializes an extension.
func initializeExtension(ctx context.Context, svc *common.Service, db sql.DB, i precompiles.Initializer, alias string,
	metadata map[string]value) (*namespace, *precompiles.Precompile, error) {

	convMetadata := make(map[string]any)
	for k, v := range metadata {
		convMetadata[k] = v.RawValue()
	}

	inst, err := i(ctx, svc, db, alias, convMetadata)
	if err != nil {
		return nil, nil, err
	}
	err = precompiles.CleanPrecompile(&inst)
	if err != nil {
		return nil, nil, err
	}

	// we construct a map of executables
	executables := copyBuiltinExecutables()
	methods := make(map[string]precompileExecutable)
	for _, method := range inst.Methods {
		lowerName := strings.ToLower(method.Name)

		expectedArgs := make([]*types.DataType, len(method.Parameters))
		for i, p := range method.Parameters {
			expectedArgs[i] = p.Type
		}

		exec := &executable{
			Name:         lowerName,
			ExpectedArgs: &expectedArgs,
			Func: func(exec *executionContext, args []value, fn resultFunc) error {
				if err := exec.canExecute(alias, lowerName, method.AccessModifiers); err != nil {
					return err
				}

				if len(args) != len(method.Parameters) {
					return fmt.Errorf(`%w: extension method "%s" expected %d arguments, but got %d`, engine.ErrExtensionImplementation, lowerName, len(method.Parameters), len(args))
				}

				argVals := make([]any, len(args))
				for i, arg := range args {
					argVals[i] = arg.RawValue()

					// ensure the argument types match
					if !method.Parameters[i].Type.Equals(arg.Type()) {
						return fmt.Errorf(`%w: extension method "%s" expected argument %d to be of type %s, but got %s`, engine.ErrExtensionImplementation, lowerName, i+1, method.Parameters[i].Type, arg.Type())
					}

					// the above will be ok if the argument is nil
					// we therefore check for nullability here
					if !method.Parameters[i].Nullable && arg.Null() {
						return fmt.Errorf(`%w: extension method "%s" expected argument %d to be non-null, but got null`, engine.ErrExtensionImplementation, lowerName, i+1)
					}
				}

				exec2 := exec.subscope(alias)

				return method.Handler(exec2.engineCtx, exec2.app(), argVals, func(a []any) error {
					// if no return is specified for this method, then the callback should never be called
					if method.Returns == nil {
						return fmt.Errorf(`%w: method "%s"."%s" returned no value, but expected one`, engine.ErrExtensionImplementation, alias, lowerName)
					}

					colNames := make([]string, len(a))
					returnVals := make([]value, len(a))

					if len(method.Returns.Fields) != len(a) {
						return fmt.Errorf("%w: method %s returned %d values, but expected %d", engine.ErrExtensionImplementation, lowerName, len(a), len(method.Returns.Fields))
					}

					for i, v := range a {
						newVal, ok, err := newValueWithSoftCast(v, method.Returns.Fields[i].Type)
						if err != nil {
							return err
						}
						if !ok {
							return fmt.Errorf(`%w: method "%s"."%s" returned a value of type %s, but expected %s. column: "%s"`, engine.ErrExtensionImplementation, alias, lowerName, newVal.Type(), method.Returns.Fields[i].Type, method.Returns.Fields[i].Name)
						}

						if !method.Returns.Fields[i].Nullable && newVal.Null() {
							return fmt.Errorf(`%w: method "%s"."%s" returned a null value for a non-nullable column. column: "%s"`, engine.ErrExtensionImplementation, alias, lowerName, method.Returns.Fields[i].Name)
						}

						returnVals[i] = newVal
						colNames[i] = method.Returns.Fields[i].Name
					}

					return fn(&row{
						columns: colNames, // it is ok if this is nil
						Values:  returnVals,
					})
				})
			},
			Type: executableTypePrecompile,
		}

		executables[lowerName] = exec
		methods[lowerName] = precompileExecutable{
			method: &method,
			exec:   exec,
		}
	}

	return &namespace{
		availableFunctions: executables,
		tables:             make(map[string]*engine.Table),
		onDeploy: func(ctx *executionContext) error {
			return inst.OnUse(ctx.engineCtx, ctx.app())
		},
		onUndeploy: func(ctx *executionContext) error {
			return inst.OnUnuse(ctx.engineCtx, ctx.app())
		},
		namespaceType: namespaceTypeExtension,
		methods:       methods,
		extCache:      inst.Cache,
	}, &inst, nil
}

type precompileExecutable struct {
	method *precompiles.Method
	exec   *executable
}

// copy deep copies the precompileExecutable.
func (p *precompileExecutable) copy() *precompileExecutable {
	e := *p.exec
	return &precompileExecutable{
		method: p.method.Copy(),
		exec:   &e,
	}
}
