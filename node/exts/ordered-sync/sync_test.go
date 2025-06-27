//go:build pglive

package orderedsync

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/node/engine/interpreter"
	"github.com/trufnetwork/kwil-db/node/pg"
)

// Helper to create an int64 pointer
func i64Ptr(i int64) *int64 {
	return &i
}

func TestResolutionMessageRoundTrip(t *testing.T) {
	testCases := []struct {
		name  string
		input ResolutionMessage
	}{
		{
			name: "Nil PreviousPointInTime",
			input: ResolutionMessage{
				Topic:               "testTopic1",
				PreviousPointInTime: nil,
				PointInTime:         12345,
				Data:                []byte("some data 1"),
			},
		},
		{
			name: "With PreviousPointInTime",
			input: ResolutionMessage{
				Topic:               "testTopic2",
				PreviousPointInTime: i64Ptr(9999999999),
				PointInTime:         -42,
				Data:                []byte("some data 2"),
			},
		},
		{
			name: "Empty Data",
			input: ResolutionMessage{
				Topic:               "testTopic3",
				PreviousPointInTime: i64Ptr(-1234),
				PointInTime:         98765,
				Data:                []byte{},
			},
		},
		{
			name: "Empty Topic",
			input: ResolutionMessage{
				Topic:               "",
				PreviousPointInTime: nil,
				PointInTime:         0,
				Data:                []byte("non-empty data"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Marshal the input struct
			b, err := tc.input.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() failed: %v", err)
			}

			// Unmarshal into a new struct
			var got ResolutionMessage
			if err := got.UnmarshalBinary(b); err != nil {
				t.Fatalf("UnmarshalBinary() failed: %v", err)
			}

			// Verify each field
			if got.Topic != tc.input.Topic {
				t.Errorf("Topic mismatch: got %v, want %v", got.Topic, tc.input.Topic)
			}

			switch {
			case got.PreviousPointInTime == nil && tc.input.PreviousPointInTime != nil:
				t.Errorf("PreviousPointInTime mismatch: got nil, want %v", *tc.input.PreviousPointInTime)
			case got.PreviousPointInTime != nil && tc.input.PreviousPointInTime == nil:
				t.Errorf("PreviousPointInTime mismatch: got %v, want nil", *got.PreviousPointInTime)
			case got.PreviousPointInTime != nil && tc.input.PreviousPointInTime != nil:
				if *got.PreviousPointInTime != *tc.input.PreviousPointInTime {
					t.Errorf("PreviousPointInTime mismatch: got %v, want %v",
						*got.PreviousPointInTime, *tc.input.PreviousPointInTime)
				}
			}

			if got.PointInTime != tc.input.PointInTime {
				t.Errorf("PointInTime mismatch: got %v, want %v", got.PointInTime, tc.input.PointInTime)
			}

			if !bytes.Equal(got.Data, tc.input.Data) {
				t.Errorf("Data mismatch: got %v, want %v", got.Data, tc.input.Data)
			}
		})
	}
}

// Tests that the logic that determines what is finalized works as expected.
// It's sort've ugly that this needs to import the interpreter, but since we are trying
// to test SQL against the engine, not much we can do about it.
func Test_Finalization(t *testing.T) {
	topic1 := "topic1"
	topic2 := "topic2"

	type testcase struct {
		name               string
		startingTopic1Time int64
		startingTopic2Time int64
		// in
		in []*ResolutionMessage
		// expected
		want []*ResolutionMessage
	}

	testcases := []testcase{
		{
			name: "No data",
			in:   nil,
			want: nil,
		},
		{
			name: "Single topic, single data point",
			in: []*ResolutionMessage{
				{
					Topic:               topic1,
					PreviousPointInTime: nil,
					PointInTime:         1,
					Data:                []byte("data1"),
				},
			},
			want: []*ResolutionMessage{
				{
					Topic:               topic1,
					PreviousPointInTime: nil,
					PointInTime:         1,
					Data:                []byte("data1"),
				},
			},
		},
		{
			name: "many topics, many data points, out of order",
			in: []*ResolutionMessage{
				{
					Topic:               topic1,
					PreviousPointInTime: i64Ptr(4),
					PointInTime:         8,
					Data:                []byte("data5"),
				},
				{
					Topic:               topic2,
					PreviousPointInTime: i64Ptr(3),
					PointInTime:         7,
					Data:                []byte("data4"),
				},
				{
					Topic:               topic1,
					PreviousPointInTime: i64Ptr(2),
					PointInTime:         4,
					Data:                []byte("data3"),
				},
				{
					Topic:               topic2,
					PreviousPointInTime: nil,
					PointInTime:         3,
					Data:                []byte("data2"),
				},
				{
					Topic:               topic1,
					PreviousPointInTime: nil,
					PointInTime:         2,
					Data:                []byte("data1"),
				},
			},
			want: []*ResolutionMessage{
				{
					Topic:               topic1,
					PreviousPointInTime: nil,
					PointInTime:         2,
					Data:                []byte("data1"),
				},
				{
					Topic:               topic1,
					PreviousPointInTime: i64Ptr(2),
					PointInTime:         4,
					Data:                []byte("data3"),
				},
				{
					Topic:               topic1,
					PreviousPointInTime: i64Ptr(4),
					PointInTime:         8,
					Data:                []byte("data5"),
				},
				{
					Topic:               topic2,
					PreviousPointInTime: nil,
					PointInTime:         3,
					Data:                []byte("data2"),
				},
				{
					Topic:               topic2,
					PreviousPointInTime: i64Ptr(3),
					PointInTime:         7,
					Data:                []byte("data4"),
				},
			},
		},
		{
			name:               "starting with some data",
			startingTopic1Time: 3,
			in: []*ResolutionMessage{
				{
					Topic:               topic1,
					PreviousPointInTime: i64Ptr(3),
					PointInTime:         4,
					Data:                []byte("data4"),
				},
				{
					Topic:               topic1,
					PreviousPointInTime: i64Ptr(4),
					PointInTime:         5,
					Data:                []byte("data5"),
				},
			},
			want: []*ResolutionMessage{
				{
					Topic:               topic1,
					PreviousPointInTime: i64Ptr(3),
					PointInTime:         4,
					Data:                []byte("data4"),
				},
				{
					Topic:               topic1,
					PreviousPointInTime: i64Ptr(4),
					PointInTime:         5,
					Data:                []byte("data5"),
				},
			},
		},
		{
			name:               "invalid previous point in time",
			startingTopic1Time: 3,
			in: []*ResolutionMessage{
				{
					Topic:               topic1,
					PreviousPointInTime: i64Ptr(2),
					PointInTime:         4,
					Data:                []byte("data4"),
				},
			},
			want: nil,
		},
	}

	ctx := context.Background()

	db, err := pg.NewDB(ctx, &pg.DBConfig{
		PoolConfig: pg.PoolConfig{
			ConnConfig: pg.ConnConfig{
				Host:   "127.0.0.1",
				Port:   "5432",
				User:   "kwild",
				Pass:   "kwild", // would be ignored if pg_hba.conf set with trust
				DBName: "kwil_test_db",
			},
			MaxConns: 11,
		},
	})
	require.NoError(t, err)
	defer db.Close()

	resolveFn := "a"
	RegisterResolveFunc(resolveFn, func(ctx context.Context, app *common.App, block *common.BlockContext, res *ResolutionMessage) error {
		return nil
	})

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			defer Synchronizer.reset()
			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx) // always rollback to avoid cleanup

			interp, err := interpreter.NewInterpreter(ctx, tx, &common.Service{}, nil, nil, nil)
			require.NoError(t, err)

			err = createNamespace(ctx, tx, interp)
			require.NoError(t, err)

			err = registerTopic(ctx, tx, interp, topic1, resolveFn)
			require.NoError(t, err)
			err = registerTopic(ctx, tx, interp, topic2, resolveFn)
			require.NoError(t, err)

			if tc.startingTopic1Time != 0 {
				err = setLatestPointInTime(ctx, tx, interp, topic1, tc.startingTopic1Time)
				require.NoError(t, err)
			}
			if tc.startingTopic2Time != 0 {
				err = setLatestPointInTime(ctx, tx, interp, topic2, tc.startingTopic2Time)
				require.NoError(t, err)
			}

			for _, msg := range tc.in {
				err = storeDataPoint(ctx, tx, interp, msg)
				require.NoError(t, err)
			}

			// Now we have stored all the data points, we can check the finalization
			finalized, err := getFinalizedDataPoints(ctx, tx, interp)
			require.NoError(t, err)

			require.EqualValues(t, tc.want, finalized)
		})
	}
}
