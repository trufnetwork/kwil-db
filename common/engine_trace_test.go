package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEngineTraceNilIsNoop(t *testing.T) {
	t.Parallel()

	var tr *EngineTrace
	done := tr.Start(EngineTraceKindAction, "main", "create_preliminary_credential", "")
	require.NotPanics(t, done)
	require.Nil(t, tr.Stages())
	require.Equal(t, "", tr.ParentName())
}

func TestEngineTraceExclusiveTimeIsSummable(t *testing.T) {
	t.Parallel()

	tr := NewEngineTrace()
	parentDone := tr.Start(EngineTraceKindAction, "main", "create_preliminary_credential", "")
	require.Equal(t, "create_preliminary_credential", tr.ParentName())

	childDone := tr.Start(EngineTraceKindAction, "main", "credential_id_in_use", tr.ParentName())
	time.Sleep(25 * time.Millisecond)
	childDone()

	sqlDone := tr.Start(EngineTraceKindSQL, "", "insert:preliminary_credentials", tr.ParentName())
	time.Sleep(15 * time.Millisecond)
	sqlDone()

	time.Sleep(10 * time.Millisecond)
	parentDone()

	stages := tr.Stages()
	require.Len(t, stages, 3)

	byName := map[string]EngineTraceStage{}
	var exclusiveSum int64
	for _, stage := range stages {
		byName[stage.Name] = stage
		exclusiveSum += stage.ExclusiveMs
		require.GreaterOrEqual(t, stage.TotalMs, stage.ExclusiveMs)
	}

	parent := byName["create_preliminary_credential"]
	child := byName["credential_id_in_use"]
	sql := byName["insert:preliminary_credentials"]
	require.Equal(t, EngineTraceKindAction, parent.Kind)
	require.Equal(t, "", parent.Parent)
	require.Equal(t, "create_preliminary_credential", child.Parent)
	require.Equal(t, "create_preliminary_credential", sql.Parent)
	require.GreaterOrEqual(t, child.ExclusiveMs, int64(15))
	require.GreaterOrEqual(t, sql.ExclusiveMs, int64(10))
	require.Less(t, parent.ExclusiveMs, parent.TotalMs)
	require.InDelta(t, float64(parent.TotalMs), float64(exclusiveSum), 1)
}

func TestEngineTraceRecordsErrorPath(t *testing.T) {
	t.Parallel()

	tr := NewEngineTrace()
	func() {
		done := tr.Start(EngineTraceKindPrecompile, "idos", "assert_credential_signatures", "create_preliminary_credential")
		defer done()
		time.Sleep(5 * time.Millisecond)
	}()

	stages := tr.Stages()
	require.Len(t, stages, 1)
	require.Equal(t, 1, stages[0].Count)
	require.Equal(t, "idos", stages[0].Namespace)
	require.Equal(t, EngineTraceKindPrecompile, stages[0].Kind)
	require.GreaterOrEqual(t, stages[0].ExclusiveMs, int64(1))
}
