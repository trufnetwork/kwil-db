package blockprocessor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
)

func TestBlockExecutionProfileAggregatesActionsAndSlowTransactions(t *testing.T) {
	t.Parallel()

	executeTx := executionProfileTestActionTx(t, "idos", "finalize_credentials_as_gateway", 2)
	transferTx := &ktypes.Transaction{
		Body: &ktypes.TransactionBody{PayloadType: ktypes.PayloadTypeTransfer},
	}
	profile := newBlockExecutionProfile()
	profile.record(
		executeTx,
		ktypes.HashBytes([]byte("execute-1")),
		uint32(ktypes.CodeOk),
		300*time.Millisecond,
		250*time.Millisecond,
		[]common.EngineTraceStage{
			{
				Kind:        common.EngineTraceKindAction,
				Namespace:   "idos",
				Name:        "finalize_credentials_as_gateway",
				Count:       1,
				TotalMs:     250,
				ExclusiveMs: 200,
				MaxMs:       200,
			},
			{
				Kind:        common.EngineTraceKindSQL,
				Name:        "delete:preliminary_credentials",
				Parent:      "finalize_credentials_as_gateway",
				Count:       1,
				TotalMs:     50,
				ExclusiveMs: 50,
				MaxMs:       50,
			},
		},
	)
	profile.record(
		executeTx,
		ktypes.HashBytes([]byte("execute-2")),
		1,
		700*time.Millisecond,
		600*time.Millisecond,
		[]common.EngineTraceStage{
			{
				Kind:        common.EngineTraceKindAction,
				Namespace:   "idos",
				Name:        "finalize_credentials_as_gateway",
				Count:       1,
				TotalMs:     600,
				ExclusiveMs: 500,
				MaxMs:       500,
			},
			{
				Kind:        common.EngineTraceKindSQL,
				Name:        "delete:preliminary_credentials",
				Parent:      "finalize_credentials_as_gateway",
				Count:       1,
				TotalMs:     100,
				ExclusiveMs: 100,
				MaxMs:       100,
			},
		},
	)
	profile.record(
		transferTx,
		ktypes.HashBytes([]byte("transfer")),
		uint32(ktypes.CodeOk),
		2*time.Second,
		1500*time.Millisecond,
		nil,
	)

	require.True(t, profile.shouldLog())
	require.Equal(t, 3*time.Second, profile.total)
	require.Equal(t, []actionExecutionProfile{
		{
			PayloadType:   "transfer",
			Transactions:  1,
			Calls:         1,
			TotalMs:       2_000,
			MaxMs:         2_000,
			PayloadMs:     1_500,
			MaxPayloadMs:  1_500,
			OverheadMs:    500,
			MaxOverheadMs: 500,
		},
		{
			PayloadType:   "execute",
			Namespace:     "idos",
			Action:        "finalize_credentials_as_gateway",
			Transactions:  2,
			Calls:         4,
			Failures:      1,
			TotalMs:       1_000,
			MaxMs:         700,
			PayloadMs:     850,
			MaxPayloadMs:  600,
			OverheadMs:    150,
			MaxOverheadMs: 100,
			Stages: []engineStageProfile{
				{
					Kind:        common.EngineTraceKindAction,
					Namespace:   "idos",
					Name:        "finalize_credentials_as_gateway",
					Count:       2,
					TotalMs:     850,
					ExclusiveMs: 700,
					MaxMs:       500,
				},
				{
					Kind:        common.EngineTraceKindSQL,
					Name:        "delete:preliminary_credentials",
					Parent:      "finalize_credentials_as_gateway",
					Count:       2,
					TotalMs:     150,
					ExclusiveMs: 150,
					MaxMs:       100,
				},
			},
		},
	}, profile.actionProfiles())

	slowTxs := profile.slowTransactions()
	require.Len(t, slowTxs, 1)
	require.Equal(t, "transfer", slowTxs[0].PayloadType)
	require.Equal(t, int64(2_000), slowTxs[0].DurationMs)
	require.Equal(t, int64(1_500), slowTxs[0].PayloadMs)
	require.Equal(t, int64(500), slowTxs[0].OverheadMs)
	require.Equal(t, int64(0), slowTxs[0].TracedMs)
	require.Equal(t, int64(1_500), slowTxs[0].UntracedMs)
}

func TestBlockExecutionProfileLogsCumulativeSlowBlock(t *testing.T) {
	t.Parallel()

	tx := executionProfileTestActionTx(t, "idos", "create_preliminary_credential", 1)
	profile := newBlockExecutionProfile()
	// no single transaction crosses the per-tx threshold, so only the
	// cumulative block total can trigger the log.
	for i := range 4 {
		profile.record(
			tx,
			ktypes.HashBytes([]byte{byte(i)}),
			uint32(ktypes.CodeOk),
			500*time.Millisecond,
			400*time.Millisecond,
			nil,
		)
		if i < 3 {
			require.False(t, profile.shouldLog())
		}
	}

	require.True(t, profile.shouldLog())
	require.Empty(t, profile.slowTransactions())
	require.Equal(t, int64(2_000), profile.actionProfiles()[0].TotalMs)
	require.Equal(t, int64(1_600), profile.actionProfiles()[0].PayloadMs)
	require.Equal(t, int64(400), profile.actionProfiles()[0].OverheadMs)
}

func TestBlockExecutionProfileOmitsEmptyStages(t *testing.T) {
	t.Parallel()

	tx := executionProfileTestActionTx(t, "idos", "create_preliminary_credential", 1)
	profile := newBlockExecutionProfile()
	profile.record(
		tx,
		ktypes.HashBytes([]byte{1}),
		uint32(ktypes.CodeOk),
		2*time.Second,
		1800*time.Millisecond,
		nil,
	)

	profiles := profile.actionProfiles()
	require.Len(t, profiles, 1)
	require.Nil(t, profiles[0].Stages)
	require.True(t, profile.shouldLog())
}

func TestBlockExecutionProfileReportsTracedAndUntracedPayloadTime(t *testing.T) {
	t.Parallel()

	tx := executionProfileTestActionTx(t, "idos", "upsert_wallet_as_inserter", 1)
	profile := newBlockExecutionProfile()
	profile.record(
		tx,
		ktypes.HashBytes([]byte("slow-upsert")),
		uint32(ktypes.CodeOk),
		1200*time.Millisecond,
		time.Second,
		[]common.EngineTraceStage{
			{
				Kind:        common.EngineTraceKindRuntime,
				Name:        "interpreter_write_lock_wait",
				Count:       1,
				TotalMs:     700,
				ExclusiveMs: 700,
				MaxMs:       700,
			},
			{
				Kind:        common.EngineTraceKindAction,
				Namespace:   "idos",
				Name:        "upsert_wallet_as_inserter",
				Count:       1,
				TotalMs:     250,
				ExclusiveMs: 250,
				MaxMs:       250,
			},
		},
	)

	slowTxs := profile.slowTransactions()
	require.Len(t, slowTxs, 1)
	require.Equal(t, int64(950), slowTxs[0].TracedMs)
	require.Equal(t, int64(50), slowTxs[0].UntracedMs)
}

func TestBlockExecutionProfileCapsLoggedSlowTransactions(t *testing.T) {
	t.Parallel()

	tx := executionProfileTestActionTx(t, "idos", "create_preliminary_credential", 1)
	profile := newBlockExecutionProfile()
	for i := range maxSlowTransactionsLogged + 5 {
		profile.record(
			tx,
			ktypes.HashBytes([]byte{byte(i)}),
			uint32(ktypes.CodeOk),
			time.Duration(1_000+i)*time.Millisecond,
			time.Second,
			nil,
		)
	}

	slowTxs := profile.slowTransactions()
	require.Len(t, slowTxs, maxSlowTransactionsLogged)
	// the cap keeps the worst offenders, not the first ones recorded.
	require.Equal(t, int64(1_014), slowTxs[0].DurationMs)
	require.Equal(t, int64(1_005), slowTxs[maxSlowTransactionsLogged-1].DurationMs)
}

func executionProfileTestActionTx(
	t *testing.T,
	namespace string,
	action string,
	calls int,
) *ktypes.Transaction {
	t.Helper()
	payload, err := (&ktypes.ActionExecution{
		Namespace: namespace,
		Action:    action,
		Arguments: make([][]*ktypes.EncodedValue, calls),
	}).MarshalBinary()
	require.NoError(t, err)
	return &ktypes.Transaction{
		Body: &ktypes.TransactionBody{
			PayloadType: ktypes.PayloadTypeExecute,
			Payload:     payload,
		},
	}
}
