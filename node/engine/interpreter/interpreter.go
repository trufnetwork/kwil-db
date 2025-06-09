package interpreter

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/decred/dcrd/container/lru"

	"github.com/kwilteam/kwil-db/common"
	"github.com/kwilteam/kwil-db/core/types"
	"github.com/kwilteam/kwil-db/core/types/validation"
	"github.com/kwilteam/kwil-db/core/utils/order"
	"github.com/kwilteam/kwil-db/extensions/hooks"
	"github.com/kwilteam/kwil-db/extensions/precompiles"
	"github.com/kwilteam/kwil-db/node/engine"
	"github.com/kwilteam/kwil-db/node/engine/parse"
	"github.com/kwilteam/kwil-db/node/pg"
	"github.com/kwilteam/kwil-db/node/types/sql"
)

// ThreadSafeInterpreter is a thread-safe interpreter.
// It is defined as a separate struct because there are time where
// the interpreter recursively calls itself, and we need to avoid
// deadlocks.
type ThreadSafeInterpreter struct {
	mu sync.RWMutex
	i  *baseInterpreter
}

// lock locks the interpreter with either a read or write lock, depending on the access mode of the database.
func (t *ThreadSafeInterpreter) lock(db sql.DB) (unlock func(), err error) {
	am, ok := db.(sql.AccessModer)
	if !ok {
		return nil, fmt.Errorf("database does not implement AccessModer")
	}

	if am.AccessMode() == sql.ReadOnly {
		t.mu.RLock()
		return t.mu.RUnlock, nil
	}

	t.mu.Lock()
	return t.mu.Unlock, nil
}

func (t *ThreadSafeInterpreter) Call(ctx *common.EngineContext, db sql.DB, namespace string, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error) {
	unlock, err := t.lock(db)
	if err != nil {
		return nil, err
	}
	defer unlock()

	return t.i.call(ctx, db, namespace, action, args, resultFn, true)
}

func (t *ThreadSafeInterpreter) CallWithoutEngineCtx(ctx context.Context, db sql.DB, namespace string, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error) {
	return t.Call(newInvalidEngineCtx(ctx), db, namespace, action, args, resultFn)
}

func (t *ThreadSafeInterpreter) Execute(ctx *common.EngineContext, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error) error {
	unlock, err := t.lock(db)
	if err != nil {
		return err
	}
	defer unlock()

	return t.i.execute(ctx, db, statement, params, fn, true)
}

func (t *ThreadSafeInterpreter) ExecuteWithoutEngineCtx(ctx context.Context, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error) error {
	return t.Execute(newInvalidEngineCtx(ctx), db, statement, params, fn)
}

// recursiveInterpreter is an interpreter that can call itself.
// It is used for extensions that need to call back into the interpreter.
type recursiveInterpreter struct {
	i *baseInterpreter
	// logs is the slice of logs that the interpreter has written.
	// It references the slice that will be returned to the caller.
	logs *[]string
}

func (r *recursiveInterpreter) Call(ctx *common.EngineContext, db sql.DB, namespace string, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error) {
	res, err := r.i.call(ctx, db, namespace, action, args, resultFn, false)
	if err != nil {
		return nil, err
	}

	*r.logs = append(*r.logs, res.Logs...)
	return res, nil
}

func (r *recursiveInterpreter) CallWithoutEngineCtx(ctx context.Context, db sql.DB, namespace string, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error) {
	return r.Call(newInvalidEngineCtx(ctx), db, namespace, action, args, resultFn)
}

func (r *recursiveInterpreter) Execute(ctx *common.EngineContext, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error) error {
	return r.i.execute(ctx, db, statement, params, fn, false)
}

func (r *recursiveInterpreter) ExecuteWithoutEngineCtx(ctx context.Context, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error) error {
	return r.Execute(newInvalidEngineCtx(ctx), db, statement, params, fn)
}

// newInvalidEngineCtx creates a new engine context that is invalid.
// It is used with ExecuteWithoutEngineCtx to allow extensions to interact with the engine
// without being in a transaction.
func newInvalidEngineCtx(ctx context.Context) *common.EngineContext {
	return &common.EngineContext{
		TxContext: &common.TxContext{
			Ctx: ctx,
			BlockContext: &common.BlockContext{
				ChainContext: &common.ChainContext{
					NetworkParameters: &common.NetworkParameters{},
					MigrationParams:   &common.MigrationContext{},
				},
			},
		},
		OverrideAuthz: true,
		InvalidTxCtx:  true,
	}
}

// a namespace is a collection of tables and actions.
// It is conceptually equivalent to Postgres's schema, but is given a
// different name to avoid confusion.
type namespace struct {
	// availableFunctions is a map of both built-in functions and user-defined PL/pgSQL functions.
	// When the interpreter planner is created, it will be populated with all built-in functions,
	// and then it will be updated with user-defined functions, effectively allowing users to override
	// some function name with their own implementation. This allows Kwil to add new built-in
	// functions without worrying about breaking user schemas.
	// This will not include aggregate and window functions, as those can only be used in SQL.
	// availableFunctions maps local action names to their execution func.
	availableFunctions map[string]*executable
	tables             map[string]*engine.Table

	// onDeploy is called exactly once when the namespace is deployed.
	// It is used to set up the namespace.
	onDeploy func(ctx *executionContext) error
	// onUndeploy is called exactly once when the namespace is undeployed.
	// It is used to clean up the namespace.
	onUndeploy func(ctx *executionContext) error

	// namespaceType is the type of namespace.
	// It can be user-created, built-in, or extension.
	namespaceType namespaceType
	// methods is a map of methods that are available if the namespace is an extension.
	methods map[string]precompileExecutable
	// extensionCache is a cache of in-memory state for an extension.
	// It can be nil if the namespace does not have an extension.
	extCache precompiles.Cache
}

// copy creates a deep copy of the namespace.
func (n *namespace) copy() *namespace {
	n2 := &namespace{
		availableFunctions: maps.Clone(n.availableFunctions),
		tables:             make(map[string]*engine.Table), // we need to copy the tables as well, so shallow copy is not enough
		onDeploy:           n.onDeploy,
		onUndeploy:         n.onUndeploy,
		namespaceType:      n.namespaceType,
		methods:            make(map[string]precompileExecutable), // we need to copy the methods as well, so shallow copy is not enough
	}

	if n.extCache != nil {
		n2.extCache = n.extCache.Copy()
	}

	for tblName, tbl := range n.tables {
		n2.tables[tblName] = tbl.Copy()
	}

	for k, v := range n.methods {
		n2.methods[k] = *v.copy()
	}

	return n2
}

// apply applies a previously created deep copy of the namespace.
// The value passed from Apply will never be changed by the engine,
func (n *namespace) apply(n2 *namespace) {
	n.availableFunctions = n2.availableFunctions
	n.tables = n2.tables
	n.onDeploy = n2.onDeploy
	n.onUndeploy = n2.onUndeploy
	n.namespaceType = n2.namespaceType
	n.methods = n2.methods

	if n.extCache != nil {
		n.extCache.Apply(n2.extCache)
	}
}

type namespaceType string

const (
	namespaceTypeUser      namespaceType = "USER"
	namespaceTypeSystem    namespaceType = "SYSTEM"
	namespaceTypeExtension namespaceType = "EXTENSION"
)

func (n namespaceType) valid() bool {
	switch n {
	case namespaceTypeUser, namespaceTypeSystem, namespaceTypeExtension:
		return true
	default:
		return false
	}
}

type nilNamespaceRegister struct{}

func (n nilNamespaceRegister) RegisterNamespace(ns string) {}

func (n nilNamespaceRegister) UnregisterAllNamespaces() {}

func (n nilNamespaceRegister) Lock() {}

func (n nilNamespaceRegister) Unlock() {}

// NewInterpreter creates a new interpreter.
// It reads currently stored namespaces and loads them into memory.
func NewInterpreter(ctx context.Context, db sql.DB, service *common.Service, accounts common.Accounts, validators common.Validators, nsr engine.NamespaceRegister) (*ThreadSafeInterpreter, error) {
	if nsr == nil {
		nsr = nilNamespaceRegister{}
	}

	err := initSQLIfNotInitialized(ctx, db)
	if err != nil {
		return nil, err
	}

	interpreter := &baseInterpreter{
		namespaces:        make(map[string]*namespace),
		service:           service,
		validators:        validators,
		accounts:          accounts,
		namespaceRegister: nsr,
	}

	namespaces, err := listNamespaces(ctx, db)
	if err != nil {
		return nil, err
	}

	for _, ns := range namespaces {
		tables, err := listTablesInNamespace(ctx, db, ns.Name)
		if err != nil {
			return nil, err
		}

		tblMap := make(map[string]*engine.Table)
		for _, tbl := range tables {
			tblMap[tbl.Name] = tbl
		}

		actions, err := listActionsInBuiltInNamespace(ctx, db, ns.Name)
		if err != nil {
			return nil, err
		}

		// now, we override the built-in functions with the actions
		namespaceFunctions := copyBuiltinExecutables()
		for _, action := range actions {
			exec := makeActionToExecutable(ns.Name, action)
			namespaceFunctions[exec.Name] = exec
		}

		interpreter.namespaces[ns.Name] = &namespace{
			tables:             tblMap,
			availableFunctions: namespaceFunctions,
			namespaceType:      ns.Type,
			onDeploy:           func(ctx *executionContext) error { return nil },
			onUndeploy:         func(ctx *executionContext) error { return nil },
		}
	}

	// we need to add the tables of the info schema manually, since they are not stored in the database

	// get and initialize all used extensions
	storedExts, err := getExtensionInitializationMetadata(ctx, db)
	if err != nil {
		return nil, err
	}

	systemExtensions := precompiles.RegisteredPrecompiles()
	var instances []*precompiles.Precompile // we must call OnStart after all instances have been initialized
	for _, ext := range storedExts {
		sysExt, ok := systemExtensions[ext.ExtName]
		if !ok {
			return nil, fmt.Errorf("the database has an extension in use that is unknown to the system: %s", ext.ExtName)
		}

		namespace, inst, err := initializeExtension(ctx, service, db, sysExt, ext.Alias, ext.Metadata)
		if err != nil {
			return nil, err
		}
		instances = append(instances, inst)

		// in case the extension implementation was changed, we need to update the stored method info
		err = ensureMethodsRegistered(ctx, db, ext.Alias, inst.Methods)
		if err != nil {
			return nil, err
		}

		// if a namespace already exists, we should use it instead, since it might have been read earlier, and contain
		// kuneiform actions and tables
		if existing, ok := interpreter.namespaces[ext.Alias]; ok {
			// kuneiform actions should overwrite methods,
			// so any actions already read should just overwrite the methods
			for k, v := range existing.availableFunctions {
				namespace.availableFunctions[k] = v
			}

			namespace.tables = existing.tables
		}

		interpreter.namespaces[ext.Alias] = namespace
	}

	interpreter.accessController, err = newAccessController(ctx, db)
	if err != nil {
		return nil, err
	}

	threadSafe := &ThreadSafeInterpreter{i: interpreter}

	app := &common.App{
		Service:    service,
		DB:         db,
		Engine:     threadSafe,
		Accounts:   accounts,
		Validators: validators,
	}

	for _, inst := range instances {
		err = inst.OnStart(ctx, app)
		if err != nil {
			return nil, err
		}
	}

	interpreter.syncNamespaceManager()

	for _, hook := range hooks.ListEngineReadyHooks() {
		err = hook(ctx, app)
		if err != nil {
			return nil, err
		}
	}

	return threadSafe, nil
}

// initSQLIfNotInitialized initializes the SQL database if it is not already initialized.
func initSQLIfNotInitialized(ctx context.Context, db sql.DB) error {
	var exists bool
	count := 0
	// we need to check if it is initialized. We will do this by checking if the schema kwild_engine exists
	err := queryRowFunc(ctx, db, "SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'kwild_engine')", []any{&exists}, func() error {
		count++
		return nil
	})
	if err != nil {
		return err
	}

	switch count {
	case 0:
		return fmt.Errorf("could not determine if the database is initialized")
	case 1:
		if !exists {
			err = pg.Exec(ctx, db, schemaInitSQL)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected number of rows returned")
	}

	return nil
}

// newUserDefinedErr makes an error that was returned from user-defined code using the ERROR function.
func newUserDefinedErr(e error) error {
	return &userDefinedErr{err: e}
}

type userDefinedErr struct {
	err error
}

func (u *userDefinedErr) Error() string {
	return u.err.Error()
}

// unwrapExecutionErr unwraps an error that was returned from user-defined code using the ERROR function, or an error
// that is the result of user logic / data (e.g. a Postgres primary key violation).
// The error can either come from an action call to ERROR() or from Kwil's custom ERROR() postgres function.
// It returns the error, and whether it was a user logic error or something more serious.
// If it is a user-defined error, it will be unwrapped and returned as the error.
func unwrapExecutionErr(e error) (err error, isUserLogicErr bool) {
	if e == nil {
		return nil, false
	}
	as := new(userDefinedErr)
	if errors.As(e, &as) {
		return e, true
	}

	// if it is a SQL error, it might be a basic integrity constraint violation,
	// which we should leave as-is but mark as a user logic error.
	if allowedSQLSTATEErrRegex.MatchString(e.Error()) {
		return e, true
	}

	return e, false
}

// checks for 22xxx and 23xxx SQLSTATE errors, or P0001 (raise_exception)
// https://www.postgresql.org/docs/current/errcodes-appendix.html
var allowedSQLSTATEErrRegex = regexp.MustCompile(`\(SQLSTATE ((23|22)\d{3}\)|P0001)`)

// baseInterpreter interprets Kwil SQL statements.
type baseInterpreter struct {
	namespaces map[string]*namespace
	// accessController is used to check if a user has access to a namespace
	accessController *accessController
	// service is the base application
	service *common.Service
	// validators is the validator manager for the application
	validators common.Validators
	// accounts is the account manager for the application
	accounts common.Accounts
	// namespaceRegister is used to register and unregister namespaces
	namespaceRegister engine.NamespaceRegister
}

// copy deep copies the state of the interpreter.
// It is used to ensure transactionality by providing
// a state that can be rolled back to.
func (i *baseInterpreter) copy() *baseInterpreter {
	namespaces := make(map[string]*namespace)
	for k, v := range i.namespaces {
		namespaces[k] = v.copy()
	}

	return &baseInterpreter{
		namespaces:       namespaces,
		accessController: i.accessController.copy(),
		// service, validators, and accounts should have no need to be copied
		service:    i.service,
		validators: i.validators,
		accounts:   i.accounts,
	}
}

// apply applies a previously copied state to the interpreter.
// It is used to roll back the interpreter to a previous state.
func (i *baseInterpreter) apply(copied *baseInterpreter) {
	newNamespaces := make(map[string]*namespace)
	for k, v := range copied.namespaces {
		// if a namespace already exists, we need to call
		// the apply function. If it is new, we just add it.
		toSet, ok := i.namespaces[k]
		if ok {
			toSet.apply(v)
		} else {
			toSet = v
		}

		newNamespaces[k] = toSet
	}
	i.namespaces = newNamespaces

	i.accessController = copied.accessController
	i.service = copied.service
	i.validators = copied.validators
	i.accounts = copied.accounts
}

// adhocParseCache is an lru cache for statements that are parsed ad-hoc.
var adhocParseCache = lru.NewMap[string, []parse.TopLevelStatement](100)

// parseAdhoc parses an ad-hoc Kwil SQL statement.
// It uses an LRU cache to avoid re-parsing the same statement if it is commonly used
// (e.g. in extensions).
func parseAdhoc(statement string) ([]parse.TopLevelStatement, error) {
	res, ok := adhocParseCache.Get(statement)
	if ok {
		return res, nil
	}

	ast, err := parse.Parse(statement)
	if err != nil {
		return nil, err
	}

	adhocParseCache.Put(statement, ast)

	return ast, nil
}

// Execute executes a statement against the database.
func (i *baseInterpreter) execute(ctx *common.EngineContext, db sql.DB, statement string, params map[string]any, fn func(*common.Row) error, toplevel bool) (err error) {
	copied := i.copy()
	defer func() {
		noErrOrPanic := true
		if err != nil {
			// rollback the interpreter
			noErrOrPanic = false
		}
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			noErrOrPanic = false
		}

		if noErrOrPanic {
			i.syncNamespaceManager()
		} else {
			// rollback
			i.apply(copied)
		}
	}()

	err = ctx.Valid()
	if err != nil {
		return err
	}

	if fn == nil {
		fn = func(*common.Row) error { return nil }
	}

	// parse the statement
	ast, err := parseAdhoc(statement)
	if err != nil {
		return fmt.Errorf("%w: error in top-level statement %s: %w", engine.ErrParse, statement, err)
	}

	if len(ast) == 0 {
		return fmt.Errorf("no valid statements provided: %s", statement)
	}

	execCtx, err := i.newExecCtx(ctx, db, engine.DefaultNamespace, toplevel)
	if err != nil {
		return err
	}

	// we convert each param (which is a key-value pair) to a value
	// and set it as a variable in the execution context.
	// We use the order package to ensure that we iterate over the
	// variables in a deterministic order. This is important because if
	// there is an error thrown due to two or more variables, nodes might
	// execute them in different orders, yielding different error messages.
	for _, param := range order.OrderMap(params) {
		val, err := newValue(param.Value)
		if err != nil {
			return err
		}

		name := strings.ToLower(param.Key)
		if !strings.HasPrefix(name, "$") {
			name = "$" + name
		}
		if err := isValidVarName(name); err != nil {
			return err
		}

		err = execCtx.setVariable(name, val)
		if err != nil {
			return err
		}
	}

	interpPlanner := interpreterPlanner{}

	for _, stmt := range ast {
		err = stmt.Accept(&interpPlanner).(stmtFunc)(execCtx, func(row *row) error {
			return fn(rowToCommonRow(row))
		})
		if err != nil {
			return err
		}
	}

	return nil
}

var identRegexp = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// isValidVarName checks if a string is a valid variable name.
func isValidVarName(s string) error {
	if !strings.HasPrefix(s, "$") {
		return fmt.Errorf("variable name must start with $")
	}

	if !identRegexp.MatchString(s[1:]) {
		return fmt.Errorf("variable name must only contain letters, numbers, and underscores")
	}

	// we ignore the $ as part of the "name"
	if len(s[1:]) > validation.MAX_IDENT_NAME_LENGTH {
		return fmt.Errorf("variable name cannot be longer than %d characters, received %s", validation.MAX_IDENT_NAME_LENGTH, s)
	}

	return nil
}

// Call executes an action against the database.
// The resultFn is called with the result of the action, if any.
func (i *baseInterpreter) call(ctx *common.EngineContext, db sql.DB, namespace, action string, args []any, resultFn func(*common.Row) error, toplevel bool) (callRes *common.CallResult, err error) {
	copied := i.copy()
	defer func() {
		// if there is either an error or a panic, then we need
		// to rollback the interpreter to its previous state.
		// The database will rollback automatically, but there
		// might be state that was changed in-memory that needs to be rolled back.
		noErrOrPanic := true
		if err != nil {
			// rollback the interpreter
			noErrOrPanic = false
		}
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			noErrOrPanic = false
		}
		if callRes != nil && callRes.Error != nil {
			noErrOrPanic = false
		}

		if noErrOrPanic {
			i.syncNamespaceManager()
		} else {
			// rollback
			i.apply(copied)
		}
	}()

	err = ctx.Valid()
	if err != nil {
		return nil, err
	}
	if resultFn == nil {
		resultFn = func(*common.Row) error { return nil }
	}

	if namespace == "" {
		namespace = engine.DefaultNamespace
	}
	namespace = strings.ToLower(namespace)
	action = strings.ToLower(action)

	execCtx, err := i.newExecCtx(ctx, db, namespace, toplevel)
	if err != nil {
		return nil, err
	}

	ns, ok := i.namespaces[namespace]
	if !ok {
		return nil, fmt.Errorf(`namespace "%s" does not exist`, namespace)
	}

	// now we can call the executable. The executable checks that the caller is allowed to call the action
	// (e.g. in case of a private action or owner action)
	exec, ok := ns.availableFunctions[action]
	if !ok {
		return nil, fmt.Errorf(`%w: action "%s" does not exist in namespace "%s"`, engine.ErrUnknownAction, action, namespace)
	}

	switch exec.Type {
	case executableTypeFunction:
		return nil, fmt.Errorf(`action "%s" is a built-in function and cannot be called directly`, action)
	case executableTypeAction, executableTypePrecompile:
		// do nothing, this is what we want
	default:
		return nil, fmt.Errorf(`node bug: unknown executable type "%s"`, exec.Type)
	}

	argVals := make([]value, len(args))

	if exec.ExpectedArgs != nil {
		expect := *exec.ExpectedArgs
		if len(expect) != len(args) {
			return nil, fmt.Errorf(`%w: action "%s" expected %d arguments, but got %d`, engine.ErrActionInvocation, action, len(expect), len(args))
		}

		for i, arg := range args {
			val, ok, err := newValueWithSoftCast(arg, expect[i])
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf(`%w: action "%s" expected argument %d to be of type %s, but got %s`, engine.ErrType, action, i+1, expect[i], val.Type())
			}

			argVals[i] = val
		}
	} else {
		for i, arg := range args {
			val, err := newValue(arg)
			if err != nil {
				return nil, err
			}

			argVals[i] = val
		}
	}

	err = exec.Func(execCtx, argVals, func(row *row) error {
		return resultFn(rowToCommonRow(row))
	})

	// if the error is an execution error,
	// then it should be part of the CallResult,
	// and not returned as a top-level error.
	err, ok = unwrapExecutionErr(err)
	if ok {
		// Add profiling results to logs if profiling is enabled
		logs := *execCtx.logs
		if execCtx.EnableProfiling && len(*execCtx.profileRecords) > 0 {
			logs = append(logs, "=== PROFILING RESULTS ===")
			for _, record := range *execCtx.profileRecords {
				logs = append(logs, record.String())
			}
			logs = append(logs, "=== END PROFILING ===")
		}

		return &common.CallResult{
			Logs:  logs,
			Error: err,
		}, nil
	}

	// Add profiling results to logs if profiling is enabled
	logs := *execCtx.logs
	if execCtx.EnableProfiling && len(*execCtx.profileRecords) > 0 {
		logs = append(logs, "=== PROFILING RESULTS ===")
		for _, record := range *execCtx.profileRecords {
			logs = append(logs, record.String())
		}
		logs = append(logs, "=== END PROFILING ===")
	}

	return &common.CallResult{
		Logs: logs,
	}, err
}

// rowToCommonRow converts a row to a common.Row.
func rowToCommonRow(row *row) *common.Row {
	// convert the results to any
	convertedResults := make([]any, len(row.Values))
	dataTypes := make([]*types.DataType, len(row.Values))
	for i, result := range row.Values {
		convertedResults[i] = result.RawValue()
		dataTypes[i] = result.Type()
	}

	return &common.Row{
		ColumnNames: row.Columns(),
		ColumnTypes: dataTypes,
		Values:      convertedResults,
	}
}

// newExecCtx creates a new execution context.
func (i *baseInterpreter) newExecCtx(txCtx *common.EngineContext, db sql.DB, namespace string, toplevel bool) (*executionContext, error) {
	am, ok := db.(sql.AccessModer)
	if !ok {
		return nil, fmt.Errorf("database does not implement AccessModer")
	}

	logs := make([]string, 0)

	// Check if profiling is enabled via transaction context
	enableProfiling := false
	if profilingValue, ok := txCtx.TxContext.Value("enable_profiling"); ok {
		if enabled, ok := profilingValue.(bool); ok {
			enableProfiling = enabled
		}
	}

	var profileRecords *[]ProfileRecord
	if enableProfiling {
		records := make([]ProfileRecord, 0)
		profileRecords = &records
	}

	e := &executionContext{
		engineCtx:       txCtx,
		scope:           newScope(namespace),
		canMutateState:  am.AccessMode() == sql.ReadWrite,
		db:              db,
		interpreter:     i,
		logs:            &logs,
		EnableProfiling: enableProfiling,
		profileRecords:  profileRecords,
	}
	e.scope.isTopLevel = toplevel

	return e, nil
}

// syncNamespaceManager syncs all current namespaces with the namespace manager.
func (i *baseInterpreter) syncNamespaceManager() {
	i.namespaceRegister.Lock()
	defer i.namespaceRegister.Unlock()
	i.namespaceRegister.UnregisterAllNamespaces()
	for ns := range i.namespaces {
		if ns == engine.InfoNamespace {
			continue
		}
		i.namespaceRegister.RegisterNamespace(ns)
	}
}

var builtInExecutables = func() map[string]*executable {
	execs := make(map[string]*executable)
	for funcName, impl := range engine.Functions {
		if scalarImpl, ok := impl.(*engine.ScalarFunctionDefinition); ok {
			execs[funcName] = funcDefToExecutable(funcName, scalarImpl)
		}
	}

	return execs
}()

// copyBuiltinExecutables returns a map of built-in functions to their executables.
func copyBuiltinExecutables() map[string]*executable {
	b := make(map[string]*executable)
	for k, v := range builtInExecutables {
		b[k] = v
	}

	return b
}

// funcDefToExecutable converts a Postgres function definition to an executable.
// This allows built-in Postgres functions to be used within the interpreter.
// This inconveniently requires a roundtrip to the database, but it is necessary
// to ensure that the function is executed correctly. In the future, we can replicate
// the functionality of the function in Go to avoid the roundtrip. I initially tried
// to do this, however it get's extroadinarily complex when getting to string formatting.
func funcDefToExecutable(funcName string, funcDef *engine.ScalarFunctionDefinition) *executable {
	return &executable{
		Name: funcName,
		Func: func(e *executionContext, args []value, fn resultFunc) error {
			//convert args to any
			params := make([]string, len(args))
			argTypes := make([]*types.DataType, len(args))
			for i, arg := range args {
				pgType, err := engine.MakeTypeCast(arg.Type())
				if err != nil {
					return err
				}
				params[i] = "$" + strconv.Itoa(i+1) + pgType
				argTypes[i] = arg.Type()
			}

			// get the expected return type
			retTyp, err := funcDef.ValidateArgsFunc(argTypes)
			if err != nil {
				return err
			}

			// if the function name is notice, then we need to get write the notice to our logs locally,
			// instead of executing a query. This is the functional equivalent of Kwil's console.log().
			if funcName == "notice" {
				var log string
				if !args[0].Null() {
					log = args[0].RawValue().(string)
				}
				*e.logs = append(*e.logs, log)
				return nil
			}

			if funcName == "error" {
				var msg string
				if !args[0].Null() {
					msg = args[0].RawValue().(string)
				}
				return newUserDefinedErr(errors.New(msg))
			}

			builtIn, ok := builtInScalarFuncs[funcName]
			if ok {
				res, err := builtIn(args)
				if err != nil {
					return err
				}

				return fn(&row{
					columns: []string{funcName},
					Values:  []value{res},
				})
			}
			// we cannot recursively call Postgres, so if a query is active and we don't
			// have a Go implementation, we need to error out.
			if e.queryActive {
				return fmt.Errorf(`%w: cannot execute function "%s" while a query is active`, engine.ErrQueryActive, funcName)
			}

			zeroVal, err := newZeroValue(retTyp)
			if err != nil {
				return err
			}

			// format the function
			pgFormat, err := funcDef.PGFormatFunc(params)
			if err != nil {
				return err
			}

			// execute the query
			// We could avoid a roundtrip here by having a go implementation of the function.
			// Since for now we are more concerned about expanding functionality than scalability,
			// we will use the roundtrip.
			iters := 0
			err = query(e.engineCtx.TxContext.Ctx, e.db, "SELECT "+pgFormat+";", []any{zeroVal}, func() error {
				iters++
				return nil
			}, args)
			if err != nil {
				return err
			}
			if iters != 1 {
				return fmt.Errorf("expected 1 row, got %d", iters)
			}

			return fn(&row{
				columns: []string{funcName},
				Values:  []value{zeroVal},
			})
		},
		Type: executableTypeFunction,
	}
}

// scalarFuncImpl is a function that implements a scalar function.
// It allows us to replicate Postgres functions in Go.
type scalarFuncImpl func([]value) (value, error)

// builtInScalarFuncs is a map of built-in scalar functions to their implementations.
var builtInScalarFuncs = map[string]scalarFuncImpl{
	// for now, we are only implementing Kwil's supported array functions.
	// This is because there are logical things that are quite hard / impossible
	// to implement without being able to reference these functions within
	// FOR loop over a set of rows.
	// In the future, we can implement more functions.
	"array_length": func(args []value) (value, error) {
		if args[0].Null() {
			return makeNull(types.IntType)
		}

		arr, ok := args[0].(arrayValue)
		if !ok {
			return nil, fmt.Errorf("expected array, got %s", args[0].Type())
		}

		return newValue(int64(arr.Len()))
	},
	"array_append": func(args []value) (value, error) {
		if args[0].Null() {
			return oneLengthArray(args[1])
		}

		arr, ok := args[0].(arrayValue)
		if !ok {
			return nil, fmt.Errorf("expected array, got %s", args[0].Type())
		}

		scal, ok := args[1].(scalarValue)
		if !ok {
			return nil, fmt.Errorf("expected scalar, got %s", args[1].Type())
		}

		// copy as to not mutate the original array
		arr2, err := copyVal(arr)
		if err != nil {
			return nil, err
		}

		// 1-based indexing
		err = arr2.Set(arr2.Len()+1, scal)
		if err != nil {
			return nil, err
		}

		return arr2, nil
	},
	"array_prepend": func(args []value) (value, error) {
		if args[0].Null() {
			return oneLengthArray(args[1])
		}

		arr, ok := args[0].(arrayValue)
		if !ok {
			return nil, fmt.Errorf("expected array, got %s", args[0].Type())
		}

		scal, ok := args[1].(scalarValue)
		if !ok {
			return nil, fmt.Errorf("expected scalar, got %s", args[1].Type())
		}

		// we will make a zero-value of the array and then set the first value to the scalar
		newVal, err := newZeroValue(arr.Type())
		if err != nil {
			return nil, err
		}

		arrVal, ok := newVal.(arrayValue)
		if !ok {
			return nil, fmt.Errorf("expected array, got %s", newVal.Type())
		}

		err = arrVal.Set(1, scal)
		if err != nil {
			return nil, err
		}

		for i := int32(1); i <= arr.Len(); i++ {
			val, err := arr.Get(i)
			if err != nil {
				return nil, err
			}

			err = arrVal.Set(i+1, val)
			if err != nil {
				return nil, err
			}
		}

		return arrVal, nil
	},
	"array_cat": func(args []value) (value, error) {
		if args[0].Null() {
			return args[1], nil
		}

		if args[1].Null() {
			return args[0], nil
		}

		arr1, ok := args[0].(arrayValue)
		if !ok {
			return nil, fmt.Errorf("expected array, got %s", args[0].Type())
		}

		arr2, ok := args[1].(arrayValue)
		if !ok {
			return nil, fmt.Errorf("expected array, got %s", args[1].Type())
		}

		// we will make a zero-value of the array and then set the first value to the scalar
		newVal, err := newZeroValue(arr1.Type())
		if err != nil {
			return nil, err
		}

		arrVal, ok := newVal.(arrayValue)
		if !ok {
			return nil, fmt.Errorf("expected array, got %s", newVal.Type())
		}

		for i := int32(1); i <= arr1.Len(); i++ {
			val, err := arr1.Get(i)
			if err != nil {
				return nil, err
			}

			err = arrVal.Set(i, val)
			if err != nil {
				return nil, err
			}
		}

		for i := int32(1); i <= arr2.Len(); i++ {
			val, err := arr2.Get(i)
			if err != nil {
				return nil, err
			}

			err = arrVal.Set(i+arr1.Len(), val)
			if err != nil {
				return nil, err
			}
		}

		return arrVal, nil
	},
	"array_remove": func(args []value) (value, error) {
		if args[0].Null() {
			return args[0], nil
		}

		arr, ok := args[0].(arrayValue)
		if !ok {
			return nil, fmt.Errorf("expected array, got %s", args[0].Type())
		}

		scal, ok := args[1].(scalarValue)
		if !ok {
			return nil, fmt.Errorf("expected scalar, got %s", args[1].Type())
		}

		expectedScal := arr.Type().Copy()
		expectedScal.IsArray = false
		if !expectedScal.Equals(scal.Type()) {
			return nil, fmt.Errorf("expected scalar of type %s, got %s", expectedScal, scal.Type())
		}

		// we will make a new array and copy all values except the one we want to remove
		newVal, err := newZeroValue(arr.Type())
		if err != nil {
			return nil, err
		}

		arrVal, ok := newVal.(arrayValue)
		if !ok {
			return nil, fmt.Errorf("expected array, got %s", newVal.Type())
		}

		// we will iterate over the array and copy all values except the one we want to remove
		for i := int32(1); i <= arr.Len(); i++ {
			val, err := arr.Get(i)
			if err != nil {
				return nil, err
			}

			isEq, err := val.Compare(scal, _EQUAL)
			if err != nil {
				return nil, err
			}

			if isEq.Bool.Bool {
				continue
			}

			err = arrVal.Set(arrVal.Len()+1, val)
			if err != nil {
				return nil, err
			}
		}

		return arrVal, nil
	},
}

// oneLengthArray makes an array with one element.
// The arg must be a scalar.
func oneLengthArray(v value) (arrayValue, error) {
	scal, ok := v.(scalarValue)
	if !ok {
		return nil, fmt.Errorf("expected scalar, got %s", v.Type())
	}

	dt := v.Type().Copy()
	dt.IsArray = true

	newVal, err := newZeroValue(dt)
	if err != nil {
		return nil, err
	}

	arrVal, ok := newVal.(arrayValue)
	if !ok {
		return nil, fmt.Errorf("expected array, got %s", newVal.Type())
	}

	err = arrVal.Set(1, scal)
	if err != nil {
		return nil, err
	}

	return arrVal, nil
}
