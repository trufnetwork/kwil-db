// package versioning provides standard schema versioning for Kwil databases.
package versioning

import (
	"context"
	"fmt"

	"github.com/trufnetwork/kwil-db/node/types/sql"
)

var (
	ErrTargetVersionTooLow = fmt.Errorf("target version is lower than current version")
)

const (
	// preVersion is the value inserted into a fresh version table with
	// sqlEnsureVersionExists. This is used to ensure that the "upgrade" to
	// version 0, which is usually just schema table initialization, defined
	// per-store is executed.
	preVersion = -1
)

// ensureVersionTableExists ensures that the version table exists in the
// database. If the table does not exist, it will be created, and the first
// version will be set to -1.
func ensureVersionTableExists(ctx context.Context, db sql.TxMaker, schema string) error {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Create the schema if it does not exist
	if _, err := tx.Execute(ctx, fmt.Sprintf(sqlCreateSchema, schema)); err != nil {
		return err
	}

	// Create the version table if it does not exist
	if _, err = tx.Execute(ctx, fmt.Sprintf(sqlVersionTable, schema)); err != nil {
		return err
	}

	// Ensure that the version exists. If it does not, insert it with the target version.
	if _, err = tx.Execute(ctx, fmt.Sprintf(sqlEnsureVersionExists, schema), preVersion); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// Upgrade upgrades the database to the specified version.
// It will return an error if the database has already surpassed the specified version,
// or if it is not possible to upgrade to the specified version.
// All versions must be given as integers (e.g. 1, 2, 3, 4, 5, etc.), and are expected to be
// sequential. A missing version will cause an error.
// All upgrades will be transactional, and will be rolled back if an error occurs.
// All versions should start at 0.
// If the database is fresh, the schema will be initialized to the target version.
// Raw initialization at the target version can be done by providing a function for versions -1.
func Upgrade(ctx context.Context, db sql.TxMaker, schema string, versions map[int64]UpgradeFunc, targetVersion int64) error {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	err = ensureVersionTableExists(ctx, tx, schema)
	if err != nil {
		return err
	}

	current, err := getCurrentVersion(ctx, tx, schema)
	if err != nil {
		return err
	}

	if current > targetVersion {
		return fmt.Errorf(`%w: current version: %d, target version: %d`, ErrTargetVersionTooLow, current, targetVersion)
	}

	// Schema on past versions, incremental upgrade to the latest version
	for current < targetVersion {
		current++
		fn, ok := versions[current]
		if !ok {
			return fmt.Errorf("missing upgrade function for version %d", current)
		}

		if err := fn(ctx, tx); err != nil {
			return fmt.Errorf("failed to upgrade to version %d: %w", current, err)
		}
	}

	// Persist the new version
	_, err = tx.Execute(ctx, fmt.Sprintf(sqlUpdateVersion, schema), current)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// UpgradeFunc is a function that can be used to upgrade a database to a specific version.
type UpgradeFunc func(ctx context.Context, db sql.DB) error
