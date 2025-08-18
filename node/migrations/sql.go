package migrations

import (
	"context"
	"fmt"

	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// InitializeMigrationSchema initializes the migration schema in the database.
func initializeMigrationSchema(ctx context.Context, db sql.DB) error {
	// Tables used by the old node in the migration process.
	_, err := db.Execute(ctx, tableMigrationsSQL)
	if err != nil {
		return err
	}

	_, err = db.Execute(ctx, tableLastStoredChangesetSQL)
	if err != nil {
		return err
	}

	// Tables used by the new node in the migration process.
	_, err = db.Execute(ctx, tableChangesetsMetadataSQL)
	if err != nil {
		return err
	}

	_, err = db.Execute(ctx, tableChangesetsSQL)
	if err != nil {
		return err
	}

	_, err = db.Execute(ctx, tableLastChangesetSQL)
	if err != nil {
		return err
	}

	return err
}

const (
	migrationsSchemaName   = `kwild_migrations`
	migrationSchemaVersion = 0
)

var (
	// tableMigrationsSQL is the sql table used to store the current migration state.
	// Only one migration can be active at a time.
	// Primary key should always be 1, to help us ensure there are no bugs in the code.
	tableMigrationsSQL = `CREATE TABLE IF NOT EXISTS ` + migrationsSchemaName + `.migration (
		id INT PRIMARY KEY,
		start_height INT8 NOT NULL,
		end_height INT8 NOT NULL
	)`

	// getMigrationSQL is the sql query used to get the current migration.
	getMigrationSQL = `SELECT start_height, end_height FROM ` + migrationsSchemaName + `.migration;`
	// migrationIsActiveSQL is the sql query used  to check if a migration is active.
	migrationIsActiveSQL = `SELECT EXISTS(SELECT 1 FROM ` + migrationsSchemaName + `.migration);`
	// createMigrationSQL is the sql query used to create a new migration.
	createMigrationSQL = `INSERT INTO ` + migrationsSchemaName + `.migration (id, start_height, end_height) VALUES ($1, $2, $3);`

	lastStoreChangeset = `last_stored_changeset`

	// tableLastChangesetSQL is the table that tracks last stored changeset. It is a single row table with the row name as "last_stored_changeset".
	tableLastStoredChangesetSQL = `CREATE TABLE IF NOT EXISTS ` + migrationsSchemaName + `.last_stored_changeset (
			name TEXT PRIMARY KEY,
			height INT8 -- height of the last stored changeset
		)`

	// upsertLastChangesetSQL is the sql query used to set the last changeset.
	upsertLastStoredChangesetSQL = `INSERT INTO ` + migrationsSchemaName + `.last_stored_changeset (name, height) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET height = $2;`

	// getLastChangesetSQL is the sql query used to get the last changeset.
	getLastStoredChangesetSQL = `SELECT height FROM ` + migrationsSchemaName + `.last_stored_changeset WHERE name = $1;`
)

// getMigrationState gets the current migration state from the database.
func getMigrationState(ctx context.Context, db sql.Executor) (*activeMigration, error) {
	res, err := db.Execute(ctx, getMigrationSQL)
	if err != nil {
		return nil, err
	}

	if len(res.Rows) == 0 {
		return nil, nil
	}

	if len(res.Rows) != 1 {
		// should never happen
		return nil, fmt.Errorf("internal bug: expected one row for migrations, got %d", len(res.Rows))
	}

	// parse the migration declaration
	md := &activeMigration{}

	row := res.Rows[0]
	var ok bool
	md.StartHeight, ok = row[0].(int64)
	if !ok {
		return nil, fmt.Errorf("internal bug: activation period is not an int64")
	}

	md.EndHeight, ok = row[1].(int64)
	if !ok {
		return nil, fmt.Errorf("internal bug: duration is not an int64")
	}

	return md, nil
}

// migrationActive checks if a migration is active.
func migrationActive(ctx context.Context, db sql.Executor) (bool, error) {
	res, err := db.Execute(ctx, migrationIsActiveSQL)
	if err != nil {
		return false, err
	}

	if len(res.Rows) != 1 {
		// should never happen
		return false, fmt.Errorf("internal bug: expected one row for migrations, got %d", len(res.Rows))
	}

	row := res.Rows[0]
	active, ok := row[0].(bool)
	if !ok {
		return false, fmt.Errorf("internal bug: migration active is not a bool")
	}

	return active, nil
}

// createMigration creates a new migration state in the database.
func createMigration(ctx context.Context, db sql.Executor, md *activeMigration) error {
	_, err := db.Execute(ctx, createMigrationSQL, 1, md.StartHeight, md.EndHeight)
	return err
}

// setLastStoredChangeset sets the last changeset in the database.
func setLastStoredChangeset(ctx context.Context, db sql.Executor, height int64) error {
	_, err := db.Execute(ctx, upsertLastStoredChangesetSQL, lastStoreChangeset, height)
	return err
}

// getLastStoredChangeset gets the last changeset from the database.
func getLastStoredChangeset(ctx context.Context, db sql.Executor) (int64, error) {
	res, err := db.Execute(ctx, getLastStoredChangesetSQL, lastStoreChangeset)
	if err != nil {
		return -1, err
	}

	if len(res.Rows) == 0 {
		return -1, nil
	}

	if len(res.Rows) != 1 {
		// should never happen
		return -1, fmt.Errorf("internal bug: expected one row for last changeset, got %d", len(res.Rows))
	}

	row := res.Rows[0]
	height, ok := row[0].(int64)
	if !ok {
		return -1, fmt.Errorf("internal bug: last changeset height is not an int64")
	}

	return height, nil
}

// Changeset Resolutions
var (
	// Tables concerning migrating changesets from old chain to new chain.
	defaultRowName = `height`

	// tableLastChangesetSQL is the table that tracks last applied changeset. It is a single row table with the row name as "last_changeset".
	tableLastChangesetSQL = `CREATE TABLE IF NOT EXISTS ` + migrationsSchemaName + `.last_changeset (
		name TEXT PRIMARY KEY, -- name of the row, should always be "height"
		height INT8
	)`

	// upsertLastChangesetSQL is the sql query used to set the last changeset.
	upsertLastChangesetSQL = `INSERT INTO ` + migrationsSchemaName + `.last_changeset (name, height) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET height = $2;`

	// getLastChangesetSQL is the sql query used to get the last changeset.
	getLastChangesetSQL = `SELECT height FROM ` + migrationsSchemaName + `.last_changeset WHERE name = $1;`

	// tableChangesetMetadataSQL is the table that stores changesets.
	tableChangesetsMetadataSQL = `CREATE TABLE IF NOT EXISTS ` + migrationsSchemaName + `.changesets_metadata (
		height INT8 PRIMARY KEY,
		total_chunks INT, -- total number of chunks in the changeset
		received INT, -- number of chunks received
		prev_height INT8 -- height of the previous changeset
	)`

	// tableChangesetsSQL is the table that stores changeset chunks. These are identified by height and index.
	tableChangesetsSQL = `CREATE TABLE IF NOT EXISTS ` + migrationsSchemaName + `.changesets (
		height INT8,
		index INT,
		changeset BYTEA,
		FOREIGN KEY (height) REFERENCES ` + migrationsSchemaName + `.changesets_metadata(height) ON DELETE CASCADE,
		PRIMARY KEY (height, index)
	)`

	// insertChangesetMetadataSQL is the sql query used to insert changeset metadata.
	insertChangesetMetadataSQL = `INSERT INTO ` + migrationsSchemaName + `.changesets_metadata (height, total_chunks, received, prev_height) VALUES ($1, $2, $3, $4) ON CONFLICT (height) DO NOTHING;`

	// updateChangesetMetadataSQL is the sql query used to update changeset metadata.
	updateChangesetMetadataSQL = `UPDATE ` + migrationsSchemaName + `.changesets_metadata SET received = received + 1 WHERE height = $1;`

	// deleteChangesetMetadataSQL is the sql query used to delete changeset metadata.
	deleteChangesetMetadataSQL = `DELETE FROM ` + migrationsSchemaName + `.changesets_metadata WHERE height = $1;`

	// getChangesetMetadataSQL is the sql query used to get changeset metadata.
	// getChangesetMetadataSQL = `SELECT total_chunks, received, prev_height FROM ` + migrationsSchemaName + `.changesets_metadata WHERE height = $1;`

	// get the metadata for the earliest changeset.
	getEarliestChangesetMetadataSQL = `SELECT height, total_chunks, received, prev_height FROM ` + migrationsSchemaName + `.changesets_metadata ORDER BY height ASC LIMIT 1;`

	// insertChangesetSQL is the sql query used to insert changeset.
	insertChangesetSQL = `INSERT INTO ` + migrationsSchemaName + `.changesets (height, index, changeset) VALUES ($1, $2, $3) ON CONFLICT (height, index) DO NOTHING;`

	// getChangesetsSQL is the sql query used to get changeset.
	getChangesetsSQL = `SELECT changeset FROM ` + migrationsSchemaName + `.changesets WHERE height = $1 AND index = $2;`

	// changesetExistsSQL is the sql query used to check if a changeset exists.
	changesetExistsSQL = `SELECT 1 FROM ` + migrationsSchemaName + `.changesets WHERE height = $1 AND index = $2;`
)

// setLastChangeset sets the last changeset in the database.
func setLastChangeset(ctx context.Context, db sql.Executor, height int64) error {
	_, err := db.Execute(ctx, upsertLastChangesetSQL, defaultRowName, height)
	return err
}

// getLastChangeset gets the last changeset from the database.
func getLastChangeset(ctx context.Context, db sql.Executor) (int64, error) {
	res, err := db.Execute(ctx, getLastChangesetSQL, defaultRowName)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return -1, err
	}

	if len(res.Rows) == 0 {
		return -1, nil
	}

	if len(res.Rows) != 1 {
		// should never happen
		return -1, fmt.Errorf("internal bug: expected one row for last changeset, got %d", len(res.Rows))
	}

	row := res.Rows[0]
	height, ok := row[0].(int64)
	if !ok {
		return -1, fmt.Errorf("internal bug: last changeset height is not an int64")
	}

	return height, nil
}

// insertChangesetMetadata inserts the changeset metadata into the database.
func insertChangesetMetadata(ctx context.Context, db sql.Executor, height int64, totalChunks int64, prev_height int64) error {
	_, err := db.Execute(ctx, insertChangesetMetadataSQL, height, totalChunks, 0, prev_height)
	return err
}

// deleteChangesets deletes the changesets from the database for a given height.
func deleteChangesets(ctx context.Context, db sql.Executor, height int64) error {
	// This should delete all changesets as well due to foreign key (delete on cascade) condition
	_, err := db.Execute(ctx, deleteChangesetMetadataSQL, height)
	return err
}

// insertChangesetChunk inserts a changeset chunk of index into the database.
func insertChangesetChunk(ctx context.Context, db sql.Executor, height int64, index int64, changeset []byte) error {
	_, err := db.Execute(ctx, insertChangesetSQL, height, index, changeset)
	return err
}

// getEarliestChangesetMetadata gets the changeset metadata from the database for the earliest changeset received.
func getEarliestChangesetMetadata(ctx context.Context, db sql.Executor) (height int64, prevHeight int64, totalChunks int64, chunksReceived int64, err error) {
	res, err := db.Execute(ctx, getEarliestChangesetMetadataSQL)
	if err != nil {
		return -1, -1, 0, 0, err
	}

	// row doesnt exist.
	if len(res.Rows) == 0 {
		return -1, -1, -1, -1, nil
	}

	if len(res.Rows) != 1 {
		// should never happen
		return -1, -1, 0, 0, fmt.Errorf("internal bug: expected one row for changeset metadata, got %d", len(res.Rows))
	}

	if len(res.Rows[0]) != 4 {
		// should never happen
		return -1, -1, 0, 0, fmt.Errorf("internal bug: expected four columns for changeset metadata, got %d", len(res.Rows[0]))
	}

	row := res.Rows[0]
	var ok bool
	height, ok = row[0].(int64)
	if !ok {
		return -1, -1, 0, 0, fmt.Errorf("internal bug: height is not an int64")
	}

	// total_chunks is INT column, now correctly decodes to int32
	if totalChunksInt32, ok := row[1].(int32); ok {
		if totalChunksInt32 < 0 {
			return -1, -1, 0, 0, fmt.Errorf("internal bug: total_chunks cannot be negative: %d", totalChunksInt32)
		}
		totalChunks = int64(totalChunksInt32)
	} else {
		return -1, -1, 0, 0, fmt.Errorf("internal bug: total_chunks is not an int32")
	}

	// received is INT column, now correctly decodes to int32
	if receivedInt32, ok := row[2].(int32); ok {
		if receivedInt32 < 0 {
			return -1, -1, 0, 0, fmt.Errorf("internal bug: received cannot be negative: %d", receivedInt32)
		}
		chunksReceived = int64(receivedInt32)
		if chunksReceived > totalChunks {
			return -1, -1, 0, 0, fmt.Errorf("internal bug: received exceeds total_chunks (%d > %d)", receivedInt32, int32(totalChunks))
		}
	} else {
		return -1, -1, 0, 0, fmt.Errorf("internal bug: received is not an int32")
	}

	prevHeight, ok = row[3].(int64)
	if !ok {
		return -1, -1, 0, 0, fmt.Errorf("internal bug: prev height is not an int64")
	}

	return height, prevHeight, totalChunks, chunksReceived, nil
}

// changesetChunkExists checks if a changeset chunk already exists in the database.
func changesetChunkExists(ctx context.Context, db sql.Executor, height int64, index int64) (bool, error) {
	res, err := db.Execute(ctx, changesetExistsSQL, height, index)
	if err != nil {
		return false, err
	}

	return len(res.Rows) == 1, nil
}

// getChangeset gets the changeset corresponding to a given height and index from the database.
func getChangeset(ctx context.Context, db sql.Executor, height int64, index int64) ([]byte, error) {
	res, err := db.Execute(ctx, getChangesetsSQL, height, index)
	if err != nil {
		return nil, err
	}

	if len(res.Rows) == 0 {
		return nil, ErrChangesetNotFound
	}

	if len(res.Rows) != 1 {
		// should never happen
		return nil, fmt.Errorf("internal bug: expected one row for changeset, got %d", len(res.Rows))
	}

	if len(res.Rows[0]) != 1 {
		return nil, fmt.Errorf("internal bug: expected one column for changeset, got %d", len(res.Rows[0]))
	}

	row := res.Rows[0]
	changeset, ok := row[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("internal bug: changeset is not a byte slice")
	}

	return changeset, nil
}
