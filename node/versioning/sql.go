package versioning

import (
	"context"
	"errors"
	"fmt"

	"github.com/trufnetwork/kwil-db/node/types/sql"
)

var (
	sqlCreateSchema = `CREATE SCHEMA IF NOT EXISTS %s;`

	// sqlVersionTable is a table that stores the version of the account store.
	// This is a single row table with a name and version column. The name is always 'version'.
	sqlVersionTable = `CREATE TABLE IF NOT EXISTS %s._kwil_version (
		name TEXT NOT NULL PRIMARY KEY, -- name: 'version'
		version INT NOT NULL
	);`

	// sqlEnsureVersionExists is a query that ensures that the version table has a row with the name 'version'.
	// If the row does not exist, it will be inserted with a version of 0.
	sqlEnsureVersionExists = `INSERT INTO %s._kwil_version (name, version) VALUES ('version', $1) ON CONFLICT (name) DO NOTHING;`

	// sqlCurrentVersion is a query that returns the current version of the database.
	sqlCurrentVersion = `SELECT version FROM %s._kwil_version WHERE name = 'version';`

	// sqlUpdateVersion is a query that updates the version of the database.
	sqlUpdateVersion = `UPDATE %s._kwil_version SET version = $1 WHERE name = 'version';`
)

// getCurrentVersion returns the current version of the database.
func getCurrentVersion(ctx context.Context, db sql.Executor, schema string) (int64, error) {
	res, err := db.Execute(ctx, fmt.Sprintf(sqlCurrentVersion, schema))
	if err != nil {
		return 0, err
	}

	if len(res.Rows) == 0 {
		return 0, errors.New("version table has no rows")
	}

	if len(res.Rows[0]) > 1 {
		return 0, errors.New("version table has more than one row")
	}

	val, ok := sql.Int64(res.Rows[0][0])
	if !ok {
		return 0, errors.New("version table has invalid version")
	}

	return val, nil
}
