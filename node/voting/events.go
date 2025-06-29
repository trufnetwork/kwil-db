// package events is used to track events that need to be included in a Kwil block.
// It contains an event store that is outside of consensus.  The event store's primary
// purpose is to store events that are heard from other chains, and delete them once the
// node can verify that their event vote has been included in a block.
package voting

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/versioning"
)

// Life cycle of an event:
// 1. Events received from an external source is stored in the event store.
// 2. Block proposer will create resolutions for the events observed.
// Resolution is a proposal based on an event, to which the network will vote on
// to get processed and applied.
// 3. Other voters vote on the existing resolutions if they witnessed the event.
// 4. Once the resolution meets required threshold votes, the resolution gets
// approved and processed.
// 5. Events are deleted from the event store when the votes are processed or
// threshold is met or when expired.

/*
	Final schema after all the upgrades:

	events:
	- id: uuid
	- data: bytea
	- event_type: text
	- broadcasted: boolean

	kv:
	- key: bytea
	- value: bytea

*/

const (
	schemaName = `kwild_events`

	eventStoreVersion = 1

	// eventsTable is the SQL table definition for the events table.
	// All the events in this table exist in one of the below states.
	// "received" and "broadcasted" fields are used to track the state of the event:
	// broadcasted: true if the event has been broadcasted by the validator.
	// It may or may not have been received by the network.
	eventsTable = `CREATE TABLE IF NOT EXISTS ` + schemaName + `.events (
		id BYTEA PRIMARY KEY, -- uuid
		data BYTEA NOT NULL,
		event_type TEXT NOT NULL,
		received BOOLEAN NOT NULL DEFAULT FALSE, -- received is set to true if the network has received the vote for this event
		broadcasted BOOLEAN NOT NULL DEFAULT FALSE -- broadcasted is set to true if the event has been broadcasted by the validator. It may or may not have been received by the network
	);`

	insertEventIdempotent = `INSERT INTO ` + schemaName + `.events (id, data, event_type) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;`

	deleteEvent = `DELETE FROM ` + schemaName + `.events WHERE id = $1;`

	deleteEvents = `DELETE FROM ` + schemaName + `.events WHERE id =ANY($1);`

	// getNewEvents returns the list of events observed by the validator to which resolutions does not exist.
	getNewEvents = `SELECT e.data, e.event_type
	FROM ` + schemaName + `.events AS e
	LEFT JOIN ` + votingSchemaName + `.resolutions AS r ON e.id = r.id
	WHERE r.id IS NULL;`

	// eventsToBroadcast returns the list of the resolutionIDs observed by the validator that are not previously broadcasted.
	// It will only search for votes from which resolutions exist (it achieves this by inner joining against the existing resolutions,
	// effectively filtering out events that do not have resolutions yet).
	eventsToBroadcast = `SELECT e.id
	FROM ` + votingSchemaName + `.resolutions AS r
	INNER JOIN ` + schemaName + `.events AS e ON r.id = e.id
	WHERE NOT e.broadcasted;`

	// mark list of events as broadcasted.
	markBroadcasted = `UPDATE ` + schemaName + `.events SET broadcasted = TRUE WHERE id =ANY($1);`

	// mark list of events as not broadcasted and ready to broadcast.
	markRebroadcast = `UPDATE ` + schemaName + `.events SET broadcasted = FALSE WHERE id =ANY($1);`

	// KV sql
	kvTableName     = schemaName + `.kv`
	createKvTblStmt = `
	CREATE TABLE IF NOT EXISTS ` + kvTableName + ` (
		key BYTEA PRIMARY KEY,
		value BYTEA NOT NULL
	);`
	upsertKvStmt = `
		INSERT INTO ` + kvTableName + ` (key, value)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = $2;
	`
	selectKvStmt = `
		SELECT value
		FROM ` + kvTableName + `
		WHERE key = $1;
	`
	deleteKvStmt = `
		DELETE FROM ` + kvTableName + `
		WHERE key = $1;
	`

	// V0 to V1 migration
	dropReceivedColumn = `ALTER TABLE ` + schemaName + `.events DROP COLUMN received;`
)

// DB is a database connection.
type DB interface {
	sql.ReadTxMaker // i.e. outer! cannot be the consensus connection
	sql.DB          // make txns, and run bare execute
}

// EventStore stores events from external sources.
// Kwil uses the event store to track received events, and ensure that they are
// broadcasted to the network.
// It follows an at-least-once semantic, and so each event body should be unique.
// Events can be added idempotently; calling StoreEvent for an event that has already
// been stored or processed will incur some computational overhead, but will not
// cause any issues.
// Voters would then create resolutions for these events, and vote on them.
type EventStore struct {
	// eventWriter is a database used for writing events.
	// It holds a separate connection to the database, since
	// events are written outside of the consensus process.
	// Events are deleted during consensus and need to be atomic
	// with consensus, so these two cannot be managed with the same
	// connection.
	eventWriter DB

	// protects eventWriter, not applicable to read-only operations
	// also protects access to the numEvents
	writerMtx sync.Mutex

	// numEvents tracks the count of events added by the listeners
	// which doesn't have resolutions yet.
	numEvents int64
}

// NewEventStore will initialize the event and vote store with the provided DB
// connection, which is retained by the EventStore. This must not be the writer
// connection used to update state by the consensus application. Updates that
// are to be performed in the same transaction that updates state are done in
// functions that are passed the consensus DB connection.
func NewResolutionStore(ctx context.Context, eventWriterDB DB) (*EventStore, *VoteStore, error) {
	// Initialize the vote store with the consensus database connection.
	vs, err := InitializeVoteStore(ctx, eventWriterDB) // doesn't keep the db instance
	if err != nil {
		return nil, nil, err
	}

	// Initialize the event store with the events database connection.
	ev, err := initializeEventStore(ctx, eventWriterDB)
	if err != nil {
		return nil, nil, err
	}

	return ev, vs, nil
}

// NewEventStore creates a new event store. It takes a database connection to
// write events to. WARNING: This DB type is capable of creating read-only
// (outer) transactions, thus this connection cannot be the same connection used
// for consensus updates by txapp.
func initializeEventStore(ctx context.Context, writerDB DB) (*EventStore, error) {
	upgradeFns := map[int64]versioning.UpgradeFunc{
		0: initEventsTables,
		1: upgradeV0ToV1,
	}

	// NOTE: Upgrade runs the upgrades in a transaction (atomic)
	err := versioning.Upgrade(ctx, writerDB, schemaName, upgradeFns, eventStoreVersion)
	if err != nil {
		return nil, err
	}

	return &EventStore{
		eventWriter: writerDB,
	}, nil
}

func initEventsTables(ctx context.Context, tx sql.DB) error {
	// Create the events and kv table if it does not exist.
	if _, err := tx.Execute(ctx, eventsTable); err != nil {
		return err
	}
	_, err := tx.Execute(ctx, createKvTblStmt)
	return err
}

func upgradeV0ToV1(ctx context.Context, db sql.DB) error {
	// Drop the received column from the events table.
	_, err := db.Execute(ctx, dropReceivedColumn)
	return err
}

// Store stores an event in the event store. It uses the local connection to the
// event store, instead of the consensus connection. It only stores unprocessed
// events. If an event is already processed.
func (e *EventStore) Store(ctx context.Context, data []byte, eventType string) error {
	e.writerMtx.Lock()
	defer e.writerMtx.Unlock()

	_, err := resolutions.GetResolution(eventType) // check if the event type is valid
	if err != nil {
		return err
	}

	tx, err := e.eventWriter.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	id := (&types.VotableEvent{
		Body: data,
		Type: eventType,
	}).ID()

	// If event already processed do not insert the event since we do not want
	// to broadcast a vote transaction.
	processed, err := IsProcessed(ctx, tx, id)
	if err != nil {
		return err
	}
	if processed {
		// fmt.Printf("existing or already-processed event NOT INSERTED: %v\n", id)
		return nil // on changes, just rollback
	}

	_, err = tx.Execute(ctx, insertEventIdempotent, id[:], data, eventType)
	if err != nil {
		return err
	}
	// fmt.Printf("inserted event new event: type %v, id %v\n", eventType, id)

	e.numEvents++
	return tx.Commit(ctx)
}

// GetUnbroadcastedEvents filters out the events observed by the validator that are not previously broadcasted.
func (e *EventStore) GetUnbroadcastedEvents(ctx context.Context) ([]*types.UUID, error) {
	readTx, err := e.eventWriter.BeginReadTx(ctx)
	if err != nil {
		return nil, err
	}
	defer readTx.Rollback(ctx) // only reading, so we can always rollback

	res, err := readTx.Execute(ctx, eventsToBroadcast)
	if err != nil {
		return nil, err
	}

	var ids []*types.UUID
	for _, row := range res.Rows {
		if len(row) != 1 {
			return nil, fmt.Errorf("expected 1 column, got %d", len(row))
		}

		id, ok := row[0].([]byte)
		if !ok {
			return nil, fmt.Errorf("expected id to be types.UUID, got %T", row[0])
		}
		uid := types.UUID(slices.Clone(id))
		ids = append(ids, &uid)
	}

	return ids, nil
}

// MarkBroadcasted marks the event as broadcasted.
func (e *EventStore) MarkBroadcasted(ctx context.Context, ids []*types.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	e.writerMtx.Lock()
	defer e.writerMtx.Unlock()

	_, err := e.eventWriter.Execute(ctx, markBroadcasted, types.UUIDArray(ids).Bytes())
	return err
}

// MarkRebroadcast marks the event to be rebroadcasted. Usually in scenarios where
// the transaction was rejected by mempool due to invalid nonces.
func (e *EventStore) MarkRebroadcast(ctx context.Context, ids []*types.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	e.writerMtx.Lock()
	defer e.writerMtx.Unlock()

	_, err := e.eventWriter.Execute(ctx, markRebroadcast, types.UUIDArray(ids).Bytes())
	return err
}

// GetEvents gets all events in the event store to which resolutions have not yet been created.
func GetEvents(ctx context.Context, db sql.Executor) ([]*types.VotableEvent, error) {
	res, err := db.Execute(ctx, getNewEvents)
	if err != nil {
		return nil, err
	}

	var events []*types.VotableEvent
	if len(res.Columns) != 2 {
		return nil, errors.New("expected 2 columns getting events. this is an internal bug")
	}
	for _, row := range res.Rows {
		// rows[0] is the raw data of the event
		// rows[1] is the event type
		data, ok := row[0].([]byte)
		if !ok {
			return nil, fmt.Errorf("expected data to be []byte, got %T", row[0])
		}
		eventType, ok := row[1].(string)
		if !ok {
			return nil, fmt.Errorf("expected event type to be string, got %T", row[1])
		}

		events = append(events, &types.VotableEvent{
			Body: slices.Clone(data),
			Type: eventType,
		})
	}

	return events, nil
}

// DeleteEvent deletes an event from the event store.
// It is idempotent. If the event does not exist, it will not return an error.
func DeleteEvent(ctx context.Context, db sql.Executor, id *types.UUID) error {
	_, err := db.Execute(ctx, deleteEvent, id[:])
	return err
}

// DeleteEvents deletes a list of events from the event store.
// It is idempotent. If the event does not exist, it will not return an error.
func DeleteEvents(ctx context.Context, db sql.DB, ids ...*types.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	_, err := db.Execute(ctx, deleteEvents, types.UUIDArray(ids).Bytes())
	return err
}

func (e *EventStore) UpdateStats(deletedEvts int64) {
	e.writerMtx.Lock()
	defer e.writerMtx.Unlock()

	if e.numEvents > deletedEvts {
		e.numEvents -= deletedEvts
	} else {
		e.numEvents = 0
	}
}

func (e *EventStore) HasEvents() bool {
	e.writerMtx.Lock()
	defer e.writerMtx.Unlock()

	return e.numEvents > 0
}

// KV returns a kv store that is scoped to the given prefix.
// It allows the user to define their own semantics
// for tracking committed data. For example, it can be used to
// track the latest block number of some other chain.
// This allows users to implement complex logic for efficient
// restart, to avoid re-processing events. Key uniqueness is
// scoped to the event type.
func (e *EventStore) KV(prefix []byte) *KV {
	return &KV{
		prefix: prefix,
		es:     e,
	}
}

// KV is a KVStore that is scoped to an event type.
type KV struct {
	prefix []byte
	es     *EventStore
}

func (s *KV) Get(ctx context.Context, key []byte) ([]byte, error) {
	tx, err := s.es.eventWriter.BeginReadTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) // only reading, so we can always rollback

	res, err := tx.Execute(ctx, selectKvStmt, append(s.prefix, key...))
	if err != nil {
		return nil, err
	}

	if len(res.Rows) == 0 {
		return nil, nil
	}

	if len(res.Rows) > 1 {
		return nil, fmt.Errorf("expected 1 row, got %d", len(res.Rows))
	}

	data, ok := res.Rows[0][0].([]byte)
	if !ok {
		return nil, fmt.Errorf("expected data to be []byte, got %T", res.Rows[0][0])
	}

	return slices.Clone(data), nil
}

func (s *KV) Set(ctx context.Context, key, value []byte) error {
	s.es.writerMtx.Lock()
	defer s.es.writerMtx.Unlock()

	tx, err := s.es.eventWriter.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Execute(ctx, upsertKvStmt, append(s.prefix, key...), value)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *KV) Delete(ctx context.Context, key []byte) error {
	s.es.writerMtx.Lock()
	defer s.es.writerMtx.Unlock()

	tx, err := s.es.eventWriter.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Execute(ctx, deleteKvStmt, append(s.prefix, key...))
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}
