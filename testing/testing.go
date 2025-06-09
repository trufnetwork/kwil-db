// package testing provides tools for testing Kuneiform schemas.
// It is meant to be used by consumers of Kwil to easily test schemas
// in a fully synchronous environment.
package testing

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kwilteam/kwil-db/common"
	"github.com/kwilteam/kwil-db/config"
	"github.com/kwilteam/kwil-db/core/log"
	"github.com/kwilteam/kwil-db/node/accounts"
	"github.com/kwilteam/kwil-db/node/engine/interpreter"
	"github.com/kwilteam/kwil-db/node/pg"
	"github.com/kwilteam/kwil-db/node/types/sql"
	"github.com/kwilteam/kwil-db/node/voting"
	"github.com/stretchr/testify/assert"
)

// RunSchemaTest runs a SchemaTest.
// It is meant to be used with Go's testing package.
func RunSchemaTest(t *testing.T, s SchemaTest, options *Options) {
	if options == nil {
		options = &Options{
			UseTestContainer: true,
			Logger:           t,
		}
	}
	if options.Logger == nil {
		options.Logger = t
	}

	if s.Owner == "" {
		s.Owner = string(deployer)
	}

	err := s.Run(context.Background(), options)
	if err != nil {
		t.Fatalf("test failed: %s", err.Error())
	}
}

// RunSchemaTestWithProfiling runs a SchemaTest with profiling enabled and logs all profiling results.
// This automatically enables profiling and logs detailed execution timings.
func RunSchemaTestWithProfiling(t *testing.T, s SchemaTest, options *Options) {
	if options == nil {
		options = &Options{
			UseTestContainer: true,
			Logger:           t,
		}
	}
	if options.Logger == nil {
		options.Logger = t
	}

	if s.Owner == "" {
		s.Owner = string(deployer)
	}

	// Force enable profiling and logging
	options.EnableProfiling = true
	options.LogProfiling = true

	err := s.Run(context.Background(), options)
	if err != nil {
		t.Fatalf("test failed: %s", err.Error())
	}
}

// TestResults contains the results of running a schema test, including profiling data.
type TestResults struct {
	// TestCaseResults contains the results for each test case execution
	TestCaseResults []TestCaseResult `json:"test_case_results"`
	// FunctionResults contains the results for each custom function test
	FunctionResults []FunctionResult `json:"function_results"`
	// Success indicates whether all tests passed
	Success bool `json:"success"`
	// Error contains any error that occurred during test execution
	Error string `json:"error,omitempty"`
}

// TestCaseResult contains the results of a single test case execution
type TestCaseResult struct {
	// Name is the name of the test case
	Name string `json:"name"`
	// Namespace is the database namespace
	Namespace string `json:"namespace"`
	// Action is the action that was executed
	Action string `json:"action"`
	// Success indicates whether the test passed
	Success bool `json:"success"`
	// Error contains any error that occurred
	Error string `json:"error,omitempty"`
	// Logs contains all logs from the execution, including profiling results
	Logs []string `json:"logs"`
	// ProfilingResults contains parsed profiling data (if profiling was enabled)
	ProfilingResults []ProfilingResult `json:"profiling_results,omitempty"`
}

// FunctionResult contains the results of a custom function test
type FunctionResult struct {
	// Name is the identifier of the function test
	Name string `json:"name"`
	// Success indicates whether the test passed
	Success bool `json:"success"`
	// Error contains any error that occurred
	Error string `json:"error,omitempty"`
	// Logs contains any logs captured during execution
	Logs []string `json:"logs"`
}

// ProfilingResult contains parsed profiling data for easier consumption
type ProfilingResult struct {
	// NodeType is the type of AST node (e.g., "SQL_PREPARE", "ACTION_CALL")
	NodeType string `json:"node_type"`
	// Identifier is a human-readable description of what was executed
	Identifier string `json:"identifier"`
	// Duration is the execution time in nanoseconds
	Duration int64 `json:"duration"`
	// DurationStr is a human-readable duration string
	DurationStr string `json:"duration_str"`
}

// SchemaTest allows for testing schemas against a live database.
// It allows for several ways of specifying schemas to deploy, as well
// as functions that can be run against the schemas, and expected results.
type SchemaTest struct {
	// Name is the name of the test case.
	Name string `json:"name"`
	// Owner is a public identifier of the user that owns the database.
	// If empty, a pre-defined deployer will be used.
	Owner string `json:"owner"`
	// SeedScripts are paths to the files containing SQL
	// scripts that are run before each test to seed the database
	SeedScripts []string `json:"seed_scripts"`
	// SeedStatements are SQL statements run before each test that are
	// meant to seed the database with data. They are run after the
	// SeedScripts.
	SeedStatements []string `json:"seed_statements"`
	// TestCases execute actions against the database
	// engine, taking certain inputs and expecting certain outputs or
	// errors. These run separately from the functions, and separately
	// from each other. They are the easiest way to test the database
	// engine, but if more nuanced tests are needed (e.g. to simulate
	// several different wallets), the FunctionTests field should be used
	// instead. All schemas will be redeployed and all seed data re-applied
	// between executing each TestCase.
	TestCases []TestCase `json:"test_cases"`
	// FunctionTests are arbitrary functions that can be used to
	// execute any logic against the schemas.
	// All schemas will be reset before each function is run.
	// FunctionTests are more cumbersome to use than TestCases, but
	// they allow for more nuanced testing and flexibility.
	// All functions and testcases are run against fresh schemas.
	FunctionTests []TestFunc `json:"-"`
}

// Run runs the test case.
// If opts is nil, the test set up and teardown create a Docker
// testcontainer to run the test.
func (tc SchemaTest) Run(ctx context.Context, opts *Options) error {
	if opts == nil {
		opts = &Options{}

		// doing this here since doing it outside
		// of the nil check would make it impossible to tell if
		// there was a user config error, or if we just need defaults.
		opts.UseTestContainer = true
	}

	if opts.Logger == nil {
		l := log.New(log.WithLevel(log.LevelInfo))
		opts.Logger = &kwilLoggerWrapper{
			Logger: l,
		}
	}

	err := opts.valid()
	if err != nil {
		return fmt.Errorf("test configuration error: %w", err)
	}

	// we read in the scripts of seed statements
	seedStmts := []string{}
	for _, schemaFile := range tc.SeedScripts {
		bts, err := os.ReadFile(schemaFile)
		if err != nil {
			return err
		}

		opts.Logger.Logf(`reading seed script "%s"`, schemaFile)

		seedStmts = append(seedStmts, string(bts))
	}
	// once we read in the scripts, we need to add the adhoc seed statements
	seedStmts = append(seedStmts, tc.SeedStatements...)

	// connect to Postgres, and run each test case in its
	// own transaction that is rolled back.
	return runWithPostgres(ctx, opts, func(ctx context.Context, d *pg.DB, logger Logger) error {
		testFns := tc.FunctionTests
		var testFnIdentifiers []string // tracks an identifier for each sub test
		var testNames []string         // tracks the names of each sub test

		// identify the functions
		for i := range tc.FunctionTests {
			testFnIdentifiers = append(testFnIdentifiers, fmt.Sprintf("TestCase.Function-%d", i))
			testNames = append(testNames, fmt.Sprintf("Function-%d", i))
		}

		// identify the executions
		for _, tc := range tc.TestCases {
			tc2 := tc // copy to avoid loop variable capture
			testFns = append(testFns, tc2.runExecution)
			testFnIdentifiers = append(testFnIdentifiers, "TestCase.Execution: "+tc2.Name)
			testNames = append(testNames, tc2.Name)
		}

		var errs []error

		for i, testFn := range testFns {
			// each test case is named after the index it is for its type.
			// It is run in a function to allow defers
			err := func() error {
				logger.Logf(`running test %s`, testFnIdentifiers[i])

				// setup a tx and execution engine
				outerTx, err := d.BeginPreparedTx(ctx)
				if err != nil {
					return err
				}
				// always rollback the outer transaction to reset the database
				defer outerTx.Rollback(ctx)

				var logger log.Logger
				// if this is a kwil logger, we can keep using it.
				// If it is from testing.T, we should make a Kwil logger.
				if wrapped, ok := opts.Logger.(*kwilLoggerWrapper); ok {
					logger = wrapped.Logger
				} else {
					logger = log.New(log.WithLevel(log.LevelInfo))
				}

				accs, err := accounts.InitializeAccountStore(ctx, outerTx, logger)
				if err != nil {
					return err
				}

				votes, err := voting.InitializeVoteStore(ctx, outerTx)
				if err != nil {
					return err
				}

				interp, err := interpreter.NewInterpreter(ctx, outerTx, &common.Service{
					Logger:      logger,
					LocalConfig: &config.Config{},
					Identity:    []byte("node"),
				}, accs, votes, nil)
				if err != nil {
					return err
				}

				// Create transaction context for ownership transfer
				ownershipTxCtx := &common.TxContext{
					Ctx:    ctx,
					Signer: deployer,
					Caller: string(deployer),
					TxID:   "txid",
					BlockContext: &common.BlockContext{
						Height: 0,
					},
				}

				// Enable profiling for ownership transfer if requested globally
				if opts.EnableProfiling {
					ownershipTxCtx.SetValue("enable_profiling", true)
				}

				err = interp.Execute(&common.EngineContext{
					TxContext:     ownershipTxCtx,
					OverrideAuthz: true,
				}, outerTx, "TRANSFER OWNERSHIP TO $user", map[string]any{
					"user": tc.Owner,
				}, func(r *common.Row) error {
					return nil
				})
				if err != nil {
					return err
				}

				tx2, err := outerTx.BeginTx(ctx)
				if err != nil {
					return err
				}
				defer tx2.Rollback(ctx)

				platform := &Platform{
					Engine:   interp,
					DB:       tx2,
					Deployer: deployer,
					Logger:   opts.Logger,
					Options:  opts,
				}

				// deploy schemas
				for _, stmt := range seedStmts {
					// Create transaction context for seed statements
					seedTxCtx := &common.TxContext{
						Ctx:    ctx,
						Signer: deployer,
						Caller: string(deployer),
						TxID:   platform.Txid(),
						BlockContext: &common.BlockContext{
							Height: 0,
						},
					}

					// Enable profiling for seed statements if requested globally
					if opts.EnableProfiling {
						seedTxCtx.SetValue("enable_profiling", true)
					}

					err = interp.Execute(&common.EngineContext{
						TxContext:     seedTxCtx,
						OverrideAuthz: true,
					}, tx2, stmt, nil, func(r *common.Row) error {
						// do nothing
						return nil
					})
					if err != nil {
						return err
					}
				}

				// run test function
				err = testFn(ctx, platform)
				if err != nil {
					return fmt.Errorf(`test "%s" failed: %w`, testNames[i], err)
				}
				return nil
			}()
			if err != nil {
				errs = append(errs, err)
			}
		}

		if len(errs) == 0 {
			return nil
		}
		return errors.Join(errs...)
	})
}

var deployer = []byte("deployer")

// TestFunc is a function that can be run against the database engine.
// A returned error signals a failed test.
type TestFunc func(ctx context.Context, platform *Platform) error

// TestCase executes an action against the database engine.
// It can be given inputs, expected outputs, expected error types,
// and expected error messages.
type TestCase struct {
	// Name is a name that the test will be identified by if it fails.
	Name string `json:"name"`
	// Namespace is the name of the database schema to execute the
	// action against.
	Namespace string `json:"namespace"`
	// Action is the name of the action.
	Action string `json:"action"`
	// Args are the inputs to the action.
	// If the action takes no parameters, this should be nil.
	Args []any `json:"args"`
	// Returns are the expected outputs of the action.
	// It takes a two-dimensional array to model the output of a table.
	// If the action has no outputs, this should be nil.
	Returns [][]any `json:"returns"`
	// Err is the expected error type. If no error is expected, this
	// should be nil.
	Err error `json:"-"`
	// ErrMsg will search the error returned by the action for
	// the given substring. If no error is expected, this should be an
	// empty string.
	ErrMsg string `json:"error"`
	// Signer sets the @caller, and the bytes will be used as the @signer.
	// If empty, the test case schema deployer will be used.
	Caller string `json:"caller"`
	// BlockHeight sets the blockheight for the test, accessible by
	// the @height variable. If not set, it will default to 0.
	Height int64 `json:"height"`
	// EnableProfiling specifies whether profiling should be enabled for the test
	EnableProfiling bool `json:"enable_profiling"`
	// LogProfiling specifies whether profiling results should be logged for the test
	LogProfiling bool `json:"log_profiling"`
}

// run runs the Execution as a TestFunc
func (e *TestCase) runExecution(ctx context.Context, platform *Platform) error {
	caller := string(deployer)
	if e.Caller != "" {
		caller = e.Caller
	}

	// log to help users debug failed tests
	platform.Logger.Logf(`executing action "%s" against namespace "%s"`, e.Action, e.Namespace)

	var results [][]any

	// Create transaction context and set profiling configuration
	txCtx := &common.TxContext{
		Ctx:    ctx,
		Signer: []byte(caller),
		Caller: caller,
		TxID:   platform.Txid(),
		BlockContext: &common.BlockContext{
			Height: e.Height,
			ChainContext: &common.ChainContext{
				MigrationParams:   &common.MigrationContext{},
				NetworkParameters: &common.NetworkParameters{},
			},
		},
	}

	// Enable profiling if requested (either per test case or globally)
	// Test case setting takes precedence over global setting
	if e.EnableProfiling || (platform.Options != nil && platform.Options.EnableProfiling) {
		txCtx.SetValue("enable_profiling", true)
	}

	res, err := platform.Engine.Call(&common.EngineContext{
		TxContext:     txCtx,
		OverrideAuthz: true,
	}, platform.DB, e.Namespace, e.Action, e.Args, func(r *common.Row) error {
		results = append(results, r.Values)
		return nil
	})

	// the received error will usually be returns as part of res,
	// but there are times where it might be returned as a separate error
	// (e.g. in case of an extension erroring).
	// Therefore, we need to check both.

	var (
		receivedErr    error
		expectsErr     bool
		expectsErrText string
	)

	if err != nil {
		receivedErr = err
	} else if res.Error != nil {
		receivedErr = res.Error
	}

	if e.Err != nil {
		expectsErr = true
		expectsErrText = e.Err.Error()
	} else if e.ErrMsg != "" {
		expectsErr = true
		expectsErrText = e.ErrMsg
	}
	// check for an execution error
	if receivedErr != nil {
		// if error is not nil, the test should only pass if either
		// Err or ErrMsg or both is set
		if e.Err != nil {
			errTypeName := reflect.TypeOf(e.Err).Elem().Name()
			if !errors.Is(receivedErr, e.Err) {
				return fmt.Errorf(`expected error of type "%s", received error: %w`, errTypeName, receivedErr)
			}
		}
		if e.ErrMsg != "" {
			if !strings.Contains(receivedErr.Error(), e.ErrMsg) {
				return fmt.Errorf(`expected error message to contain substring "%s", received error: %w`, e.ErrMsg, receivedErr)
			}
		}

		if !expectsErr {
			return fmt.Errorf(`unexpected error: %w`, receivedErr)
		}

		return nil
	}

	if expectsErr {
		return fmt.Errorf(`expected error message to contain substring "%s", but the error didn't happen`, expectsErrText)
	}

	if len(results) != len(e.Returns) {
		return fmt.Errorf("expected %d rows to be returned, received %d", len(e.Returns), len(results))
	}

	for i, row := range results {
		if len(row) != len(e.Returns[i]) {
			return fmt.Errorf("expected %d columns to be returned, received %d", len(e.Returns[i]), len(row))
		}

		for j, col := range row {
			if !assert.ObjectsAreEqualValues(e.Returns[i][j], col) {
				// add 1 to row and column index since they are 0 indexed.
				return fmt.Errorf(`incorrect value for expected result: row %d, column %d. expected "%v", received "%v"`, i+1, j+1, e.Returns[i][j], col)
			}
		}
	}

	// Capture profiling data if available
	platform.AddProfilingData(res.Logs)

	// Log profiling results if requested (either per test case or globally)
	shouldLogProfiling := e.LogProfiling || e.EnableProfiling ||
		(platform.Options != nil && (platform.Options.LogProfiling || platform.Options.EnableProfiling))

	if shouldLogProfiling && len(res.Logs) > 0 {
		platform.Logger.Logf("Action logs for %s.%s:", e.Namespace, e.Action)
		for _, log := range res.Logs {
			platform.Logger.Logf("  %s", log)
		}
	}

	return nil
}

// Platform provides utilities and info for usage in test functions.
// It allows users to access the database engine, get information about the
// schema deployers, control transactions, or even directly access PostgreSQL.
type Platform struct {
	// Engine is the Kuneiform engine that can deploy schemas, execute actions,
	// execute adhoc SQL, and more. It should be the primary way to interact with the database.
	Engine common.Engine
	// DB is the database engine that the test case is running against.
	// It provides access directly to Postgres, and has superuser access
	// to the underlying database. If users want to execute ad-hoc queries,
	// they should prefer to use the Engine, which parses Kwil's SQL standard,
	// and guarantees determinism.
	DB sql.DB
	// Deployer is the public identifier of the user that deployed the schemas
	// during test setup. It can be used to execute owner-only actions.
	// To execute owner-only actions, set the Deployer to be the
	// *common.ExecutionData.TransactionData.Signer field when executing the
	// action.
	Deployer []byte

	// Logger is for logging information during execution of the test.
	Logger Logger

	// Options contains the test configuration options
	Options *Options

	// lastTxid is the last transaction ID that was used.
	lastTxid []byte

	// ProfilingData collects profiling results from all executions if profiling is enabled
	ProfilingData []ProfilingResult
}

// Txid returns a new, unused transaction ID.
// It is deterministic, making tests repeatable.
func (p *Platform) Txid() string {
	if len(p.lastTxid) == 0 {
		b := sha256.Sum256([]byte("first txid"))
		p.lastTxid = b[:]
		return hex.EncodeToString(b[:])
	}

	b := sha256.Sum256(p.lastTxid)
	p.lastTxid = b[:]
	return hex.EncodeToString(b[:])
}

// NewTxContext creates a new transaction context for custom test functions.
// If enableProfiling is true, profiling will be enabled for this context.
// If enableProfiling is false, it will use the global profiling setting from Options.
func (p *Platform) NewTxContext(ctx context.Context, caller string, enableProfiling *bool) *common.TxContext {
	if caller == "" {
		caller = string(p.Deployer)
	}

	txCtx := &common.TxContext{
		Ctx:    ctx,
		Signer: []byte(caller),
		Caller: caller,
		TxID:   p.Txid(),
		BlockContext: &common.BlockContext{
			Height: 0,
		},
	}

	// Determine if profiling should be enabled
	shouldEnableProfiling := false
	if enableProfiling != nil {
		// Explicit override
		shouldEnableProfiling = *enableProfiling
	} else if p.Options != nil {
		// Use global setting
		shouldEnableProfiling = p.Options.EnableProfiling
	}

	if shouldEnableProfiling {
		txCtx.SetValue("enable_profiling", true)
	}

	return txCtx
}

// CallWithProfiling is a convenience method for custom test functions to call actions with profiling control.
func (p *Platform) CallWithProfiling(ctx context.Context, caller, namespace, action string, args []any, enableProfiling *bool, resultFn func(*common.Row) error) (*common.CallResult, error) {
	txCtx := p.NewTxContext(ctx, caller, enableProfiling)

	res, err := p.Engine.Call(&common.EngineContext{
		TxContext:     txCtx,
		OverrideAuthz: true,
	}, p.DB, namespace, action, args, resultFn)

	// Capture profiling data if available
	if res != nil {
		p.AddProfilingData(res.Logs)
	}

	return res, err
}

// ExecuteWithProfiling is a convenience method for custom test functions to execute SQL with profiling control.
func (p *Platform) ExecuteWithProfiling(ctx context.Context, caller, statement string, params map[string]any, enableProfiling *bool, resultFn func(*common.Row) error) error {
	txCtx := p.NewTxContext(ctx, caller, enableProfiling)

	return p.Engine.Execute(&common.EngineContext{
		TxContext:     txCtx,
		OverrideAuthz: true,
	}, p.DB, statement, params, resultFn)
}

// parseProfilingFromLogs extracts profiling results from log strings
func (p *Platform) parseProfilingFromLogs(logs []string) []ProfilingResult {
	var results []ProfilingResult
	inProfiling := false

	for _, log := range logs {
		if log == "=== PROFILING RESULTS ===" {
			inProfiling = true
			continue
		}
		if log == "=== END PROFILING ===" {
			inProfiling = false
			continue
		}
		if inProfiling && log != "" {
			// Parse log format: "NodeType: Identifier (Duration)"
			// Example: "SQL_PREPARE: SELECT * FROM users (1.234ms)"
			if parts := strings.Split(log, ": "); len(parts) >= 2 {
				nodeType := parts[0]
				rest := strings.Join(parts[1:], ": ")

				// Extract duration from parentheses
				if idx := strings.LastIndex(rest, "("); idx != -1 {
					identifier := strings.TrimSpace(rest[:idx])
					durationStr := strings.Trim(rest[idx+1:], "() ")

					// Parse duration
					if duration, err := time.ParseDuration(durationStr); err == nil {
						results = append(results, ProfilingResult{
							NodeType:    nodeType,
							Identifier:  identifier,
							Duration:    duration.Nanoseconds(),
							DurationStr: durationStr,
						})
					}
				}
			}
		}
	}
	return results
}

// AddProfilingData adds profiling results to the platform's collection
func (p *Platform) AddProfilingData(logs []string) {
	if p.Options != nil && (p.Options.EnableProfiling || p.Options.LogProfiling) {
		p.ProfilingData = append(p.ProfilingData, p.parseProfilingFromLogs(logs)...)
	}
}

// runWithPostgres runs the callback function with a postgres container.
func runWithPostgres(ctx context.Context, opts *Options, fn func(context.Context, *pg.DB, Logger) error) (err error) {
	if !opts.UseTestContainer {
		db, err := pg.NewDB(ctx, &pg.DBConfig{
			PoolConfig: pg.PoolConfig{
				MaxConns: 11,
				ConnConfig: pg.ConnConfig{
					Host:   opts.Conn.Host,
					Port:   opts.Conn.Port,
					User:   opts.Conn.User,
					Pass:   opts.Conn.Pass,
					DBName: opts.Conn.DBName,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("error setting up database: %w", err)
		}

		defer db.Close()

		return fn(ctx, db, opts.Logger)
	}

	port := "52853" // random port

	// Run the container
	cmd := exec.CommandContext(ctx, "docker", dockerStartArgs(port)...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get output from container: %w", err)
	}
	switch {
	case err == nil:
		// do nothing
	case strings.Contains(err.Error(), "command not found"):
		{
			return fmt.Errorf("docker not found. Please ensure Docker is installed and running")
		}
	case strings.Contains(err.Error(), "Conflict. The container name") && opts.ReplaceExistingContainer != nil:
		// check if the container is in use
		use, err := opts.ReplaceExistingContainer()
		if err != nil {
			return err
		}

		if !use {
			return fmt.Errorf(`cannot create test-container: conflicting container name: "%s"`, ContainerName)
		}

		cmdStop := exec.CommandContext(ctx, "docker", "rm", "-f", ContainerName)
		err = cmdStop.Run()
		if err != nil {
			return fmt.Errorf("error removing conflicting container: %w", err)
		}

		cmd = exec.CommandContext(ctx, "docker", dockerStartArgs(port)...)
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("error running test container: %w", err)
		}
	default:
		return fmt.Errorf("error running test container: %w", err)
	}

	defer func() {
		cmdStop := exec.CommandContext(ctx, "docker", "rm", "-f", ContainerName)
		err2 := cmdStop.Run()
		if err2 != nil {
			if err == nil {
				err = err2
			} else {
				err = errors.Join(err, err2)
			}
		}
	}()

	err = waitForLogs(ctx, ContainerName, "database system is ready to accept connections", "database system is shut down", "PostgreSQL init process complete; ready for start up")
	if err != nil {
		return fmt.Errorf("error waiting for logs: %w", err)
	}

	opts.Logger.Logf("running test container: %s", string(out))

	db, err := connectWithRetry(ctx, port, 10) // might take a while to start up on slower machines
	if err != nil {
		return fmt.Errorf("error connecting to database: %w", err)
	}

	defer db.Close()

	return fn(ctx, db, opts.Logger)
}

// waitForLogs waits for the logs to be received from the container.
// The logs must be received in order.
func waitForLogs(ctx context.Context, containerName string, logs ...string) error {
	logsCmd := exec.CommandContext(ctx, "docker", "logs", "--follow", containerName)

	stdout, err := logsCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to attach to logs: %w", err)
	}

	if err := logsCmd.Start(); err != nil {
		return fmt.Errorf("failed to start logs command: %w", err)
	}
	defer logsCmd.Process.Kill() // Ensure the logs process is terminated

	scanner := bufio.NewScanner(stdout)
	logCh := make(chan string)
	errCh := make(chan error, 1)
	defer close(errCh)
	defer stdout.Close()

	// Goroutine to scan logs
	go func() {
		defer close(logCh)
		for scanner.Scan() {
			logCh <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			errCh <- fmt.Errorf("error reading logs: %w", err)
		}
	}()

	i := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case line, ok := <-logCh:
			if !ok {
				return fmt.Errorf("log message not found")
			}

			if strings.Contains(line, logs[i]) {
				i++
			}

			if i == len(logs) {
				return nil
			}
		}
	}
}

// ContainerName is the name of the test container
const ContainerName = "kwil-testing-postgres"

// dockerStartArgs returns the docker start command args
func dockerStartArgs(port string) (args []string) {
	return []string{"run", "-d", "-p", port + ":5432", "--name", ContainerName,
		"-e", "POSTGRES_HOST_AUTH_METHOD=trust", "kwildb/postgres:16.8-1"}
}

// connectWithRetry tries to connect to Postgres, and will retry n times at
// 1 second intervals if it fails.
func connectWithRetry(ctx context.Context, port string, n int) (*pg.DB, error) {
	var db *pg.DB
	var err error

	for range n {
		db, err = pg.NewDB(ctx, &pg.DBConfig{
			PoolConfig: pg.PoolConfig{
				MaxConns: 11,
				ConnConfig: pg.ConnConfig{
					Host:   "localhost",
					Port:   port,
					User:   "kwild",
					Pass:   "kwild", // would be ignored if pg_hba.conf set with trust
					DBName: "kwil_test_db",
				},
			},
		})
		if err == nil {
			return db, nil
		}
		if !strings.Contains(err.Error(), "failed to connect to") {
			return nil, err
		}

		time.Sleep(time.Second)
	}

	return nil, err
}

// Options configures optional parameters for running the test.
// Either UseTestContainer should be true, or a valid
// PostgreSQL connection should be specified.
type Options struct {
	// UseTestContainer specifies whether the test should setup and
	// teardown a test container.
	UseTestContainer bool
	// Conn specifies a manually setup Postgres connection that the
	// test can connect to.
	Conn *ConnConfig
	// Logger is a logger to be used in the test
	Logger Logger
	// ReplaceExistingContainer is a callback function that is called when
	// a conflicting container name is already in use. If it returns
	// true, then the container will be removed and recreated. If it
	// returns false, then the test will fail.
	ReplaceExistingContainer func() (bool, error)
	// EnableProfiling specifies whether profiling should be enabled for the test
	EnableProfiling bool
	// LogProfiling specifies whether profiling results should be logged for the test
	LogProfiling bool
}

// ConnConfig groups the basic connection settings used to construct the DSN
// "connection string" used to open a new connection to a postgres host.
type ConnConfig struct {
	// Host, Port, User, Pass, and DBName are used verbatim to create a
	// connection string in DSN format.
	// https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
	Host, Port string
	User, Pass string
	DBName     string
}

func (d *Options) valid() error {
	if d.UseTestContainer && d.Conn != nil {
		return fmt.Errorf("test cannot both use a test container and specify a Postgres connection")
	}

	if !d.UseTestContainer && d.Conn == nil {
		return fmt.Errorf("test must either use a test container or specify a Postgres connection")
	}

	return nil
}

// Logger is a logger that the tests use while running.
// It can be made to fit both Kwil's Logger interface,
// as well as Go's stdlib test package
type Logger interface {
	Logf(string, ...any)
}

// LoggerFromKwilLogger wraps the Kwil standard logger so
// so that it can be used in tests
func LoggerFromKwilLogger(log log.Logger) Logger {
	return &kwilLoggerWrapper{
		Logger: log,
	}
}

type kwilLoggerWrapper struct {
	log.Logger
}

func (k *kwilLoggerWrapper) Logf(s string, a ...any) {
	k.Logger.Logf(log.LevelInfo /*fix*/, s, a...)
}
