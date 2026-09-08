package interpreter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

func TestSQLVerbTableUsesDeterministicKeys(t *testing.T) {
	t.Parallel()

	require.Equal(t, "insert:preliminary_credentials", sqlVerbTable(
		"INSERT INTO preliminary_credentials (id, user_id) VALUES ($request_id, $caller_user_id)",
	))
	require.Equal(t, "select:credentials", sqlVerbTable(
		"SELECT 1 FROM credentials WHERE id = $id",
	))
	require.Equal(t, "select:preliminary_credentials", sqlVerbTable(
		"SELECT 1 FROM preliminary_credentials WHERE original_id = $id OR copy_id = $id",
	))
	require.Equal(t, "update:wallets", sqlVerbTable("UPDATE wallets SET address = $a WHERE id = $id"))
	require.Equal(t, "delete:preliminary_credentials", sqlVerbTable(
		"DELETE FROM preliminary_credentials WHERE id = $preliminary_id",
	))
	require.Equal(t, "select", sqlVerbTable("SELECT 1"))
	require.Equal(t, "insert:credentials", sqlVerbTable("-- note\nINSERT INTO main.credentials VALUES (1)"))
	require.Equal(t, "sql", sqlVerbTable("   "))
}

func TestObserveExecutableSkipsBuiltinsAndNilTrace(t *testing.T) {
	t.Parallel()

	exec := &executionContext{
		engineCtx: &common.EngineContext{},
		scope:     newScope("main"),
	}
	called := false
	def := &executable{
		Name: "notice",
		Type: executableTypeFunction,
		Func: func(_ *executionContext, _ []Value, _ resultFunc) error {
			called = true
			return nil
		},
	}
	require.NoError(t, observeExecutable(exec, "main", def, nil, nil))
	require.True(t, called)
}

// no t.Parallel: AllocsPerRun pins GOMAXPROCS and must not race other tests.
func TestObserveSQLSkipsNameBuildingWithoutTrace(t *testing.T) {
	exec := &executionContext{
		engineCtx: &common.EngineContext{},
		scope:     newScope("main"),
	}
	stmt := "INSERT INTO preliminary_credentials (id, user_id) VALUES ($request_id, $caller_user_id)"

	allocs := testing.AllocsPerRun(100, func() {
		observeSQL(exec, stmt)()
	})
	require.Zero(t, allocs)
}

func TestObserveExecutableRecordsErrorPath(t *testing.T) {
	t.Parallel()

	tr := common.NewEngineTrace()
	exec := &executionContext{
		engineCtx: &common.EngineContext{
			TxContext: &common.TxContext{EngineTrace: tr},
		},
		scope: newScope("main"),
	}
	def := &executable{
		Name: "credential_id_in_use",
		Type: executableTypeAction,
		Func: func(_ *executionContext, _ []Value, _ resultFunc) error {
			return errors.New("boom")
		},
	}

	err := observeExecutable(exec, "main", def, nil, nil)
	require.EqualError(t, err, "boom")

	stages := tr.Stages()
	require.Len(t, stages, 1)
	require.Equal(t, "action", stages[0].Kind)
	require.Equal(t, "main", stages[0].Namespace)
	require.Equal(t, "credential_id_in_use", stages[0].Name)
	require.Equal(t, 1, stages[0].Count)
}

func TestInterpreterWriteLockWaitIsTraced(t *testing.T) {
	tr := common.NewEngineTrace()
	engineCtx := &common.EngineContext{
		TxContext: &common.TxContext{EngineTrace: tr},
	}
	interp := &ThreadSafeInterpreter{}
	db := traceLockDB{mode: sql.ReadWrite}

	interp.mu.RLock()
	started := make(chan struct{})
	result := make(chan lockResult, 1)
	go func() {
		close(started)
		unlock, err := interp.lock(engineCtx, db)
		result <- lockResult{unlock: unlock, err: err}
	}()
	<-started
	time.Sleep(20 * time.Millisecond)
	interp.mu.RUnlock()

	got := <-result
	require.NoError(t, got.err)
	got.unlock()

	stages := tr.Stages()
	require.Len(t, stages, 1)
	require.Equal(t, common.EngineTraceKindRuntime, stages[0].Kind)
	require.Equal(t, "interpreter_write_lock_wait", stages[0].Name)
	require.GreaterOrEqual(t, stages[0].ExclusiveMs, int64(10))
}

type lockResult struct {
	unlock func()
	err    error
}

type traceLockDB struct {
	mode sql.AccessMode
}

func (d traceLockDB) AccessMode() sql.AccessMode {
	return d.mode
}

func (traceLockDB) Execute(context.Context, string, ...any) (*sql.ResultSet, error) {
	panic("not used")
}

func (traceLockDB) BeginTx(context.Context) (sql.Tx, error) {
	panic("not used")
}
