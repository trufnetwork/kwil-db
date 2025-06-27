//go:build pglive

package voting_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
	dbtest "github.com/trufnetwork/kwil-db/node/pg/test"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"

	"github.com/stretchr/testify/require"
)

func Test_EventStore(t *testing.T) {
	type testcase struct {
		name string
		// We are testing event store methods that use a dedicated DB
		// connection, and package-level functions that use the consensus conn.
		fn func(t *testing.T, e *voting.EventStore, consensusTx sql.DB)
	}
	tests := []testcase{
		{
			name: "standard storage and retrieval",
			fn: func(t *testing.T, e *voting.EventStore, db sql.DB) {
				ctx := context.Background()

				err := e.Store(ctx, []byte("hello"), "test")
				require.NoError(t, err)

				events, err := voting.GetEvents(ctx, db)
				require.NoError(t, err)

				require.Len(t, events, 1)
				require.Equal(t, []byte("hello"), events[0].Body)
				require.Equal(t, "test", events[0].Type)

				err = voting.DeleteEvent(ctx, db, events[0].ID())
				require.NoError(t, err)

				events, err = voting.GetEvents(ctx, db)
				require.NoError(t, err)

				require.Len(t, events, 0)
			},
		},
		{
			name: "idempotent storage",
			fn: func(t *testing.T, e *voting.EventStore, db sql.DB) {
				ctx := context.Background()

				err := e.Store(ctx, []byte("hello"), "test")
				require.NoError(t, err)

				err = e.Store(ctx, []byte("hello"), "test")
				require.NoError(t, err)

				events, err := voting.GetEvents(ctx, db)
				require.NoError(t, err)

				require.Len(t, events, 1)
			},
		},
		{
			name: "deleting non-existent event",
			fn: func(t *testing.T, e *voting.EventStore, db sql.DB) {
				ctx := context.Background()

				err := voting.DeleteEvent(ctx, db, types.NewUUIDV5([]byte("hello")))
				require.NoError(t, err)
			},
		},
		{
			name: "using kv scoping",
			fn: func(t *testing.T, e *voting.EventStore, db sql.DB) {
				ctx := context.Background()

				kv := e.KV([]byte("hello"))
				kvCopy := e.KV([]byte("hello"))
				kv2 := e.KV([]byte("hello2"))

				err := kv.Set(ctx, []byte("key"), []byte("value"))
				require.NoError(t, err)

				value, err := kv.Get(ctx, []byte("key"))
				require.NoError(t, err)
				require.Equal(t, []byte("value"), value)

				value, err = kvCopy.Get(ctx, []byte("key"))
				require.NoError(t, err)
				require.Equal(t, []byte("value"), value)

				value, err = kv2.Get(ctx, []byte("key"))
				require.NoError(t, err)
				require.Nil(t, value)
			},
		},
		{
			name: "marking broadcasted",
			fn: func(t *testing.T, e *voting.EventStore, db sql.DB) {
				ctx := context.Background()

				tx, err := db.BeginTx(ctx)
				require.NoError(t, err)
				defer tx.Rollback(ctx)

				event := &types.VotableEvent{
					Body: []byte("hello"),
					Type: "test",
				}
				id := event.ID()

				err = e.Store(ctx, event.Body, event.Type)
				require.NoError(t, err)

				// Mark event as broadcasted
				err = e.MarkBroadcasted(ctx, []*types.UUID{id})
				require.NoError(t, err)

				err = tx.Commit(ctx)
				require.NoError(t, err)

				tx2, err := db.BeginTx(ctx)
				require.NoError(t, err)
				defer tx2.Rollback(ctx)

				// GetEvents should still return the event
				events, err := voting.GetEvents(ctx, tx2)
				require.NoError(t, err)
				require.Len(t, events, 1)

				err = e.MarkRebroadcast(ctx, []*types.UUID{id})
				require.NoError(t, err)

				err = tx2.Commit(ctx)
				require.NoError(t, err)

				// GetEvents should still return the event
				events, err = voting.GetEvents(ctx, db)
				require.NoError(t, err)
				require.Len(t, events, 1)
			},
		},
		{
			name: "get events which has no resolutions",
			fn: func(t *testing.T, e *voting.EventStore, db sql.DB) {
				ctx := context.Background()

				// create 3 events
				for i := range 3 {
					data := fmt.Sprintf("test%d", i)
					err := e.Store(ctx, []byte(data), "test")
					require.NoError(t, err)
				}

				// Get events which have no resolutions
				events, err := voting.GetEvents(ctx, db)
				require.NoError(t, err)
				require.Len(t, events, 3)

				// create resolutions for 1 events
				err = voting.CreateResolution(ctx, db, events[0], 10, []byte("a"), crypto.KeyTypeEd25519)
				require.NoError(t, err)

				// Get events which have no resolutions
				events, err = voting.GetEvents(ctx, db)
				require.NoError(t, err)
				require.Len(t, events, 2)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			db, cleanup, err := dbtest.NewTestPool(ctx, []string{"kwild_events", "kwild_voting"}) // db is the event store specific connection
			require.NoError(t, err)
			defer cleanup()

			e, _, err := voting.NewResolutionStore(ctx, db)
			require.NoError(t, err)

			// create a second db connection to emulate the consensus db
			consensusDB, cleanup2, err := dbtest.NewTestPool(ctx, nil) // don't need to delete schema since we will never commit
			require.NoError(t, err)
			defer cleanup2()

			consensusTx, err := consensusDB.BeginTx(ctx)
			require.NoError(t, err)
			defer consensusTx.Rollback(ctx) // always rollback, to clean up

			tt.fn(t, e, consensusDB)
		})
	}
}
