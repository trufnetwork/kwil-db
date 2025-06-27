// Package meta defines a chain metadata store for the ABCI application. Prior
// to using the methods, the tables should be initialized and updated to the
// latest schema version with InitializeMetaStore.
package meta

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/versioning"
)

const (
	chainSchemaName = `kwild_chain`

	chainStoreVersion = 0

	// chain state table

	initChainTable = `CREATE TABLE IF NOT EXISTS ` + chainSchemaName + `.chain (
		height INT8 NOT NULL,
		app_hash BYTEA,
		dirty BOOLEAN DEFAULT FALSE
	);` // no primary key, only one row

	insertChainState = `INSERT INTO ` + chainSchemaName + `.chain(height, app_hash, dirty) ` +
		`VALUES ($1, $2, $3);`

	setChainState = `UPDATE ` + chainSchemaName + `.chain ` +
		`SET height = $1, app_hash = $2, dirty = $3;`

	getChainState = `SELECT height, app_hash, dirty FROM ` + chainSchemaName + `.chain;`

	// network parameters table (TODO: combine with chain table)

	initParamsTable = `CREATE TABLE IF NOT EXISTS ` + chainSchemaName + `.params (
		params BYTEA
	);` // no primary key, only one row

	insertParams = `INSERT INTO ` + chainSchemaName + `.params VALUES ($1);`

	setParams = `UPDATE ` + chainSchemaName + `.params SET params = $1;`

	getParams = `SELECT params FROM ` + chainSchemaName + `.params;`
)

func initTables(ctx context.Context, tx sql.DB) error {
	_, err := tx.Execute(ctx, initChainTable)
	if err != nil {
		return err
	}
	_, err = tx.Execute(ctx, initParamsTable)
	return err
}

// InitializeMetaStore initializes the chain metadata store schema.
func InitializeMetaStore(ctx context.Context, db sql.DB) error {
	upgradeFns := map[int64]versioning.UpgradeFunc{
		0: initTables,
	}

	return versioning.Upgrade(ctx, db, chainSchemaName, upgradeFns, chainStoreVersion)
}

// GetChainState returns height and app hash from the chain state store.
// If there is no recorded data, height will be -1 and app hash nil.
func GetChainState(ctx context.Context, db sql.Executor) (height int64, appHash []byte, dirty bool, err error) {
	var res *sql.ResultSet
	res, err = db.Execute(ctx, getChainState)
	if err != nil {
		return 0, nil, false, err
	}

	switch n := len(res.Rows); n {
	case 0:
		return -1, nil, false, nil // fresh DB
	case 1:
	default:
		return 0, nil, false, fmt.Errorf("expected at most one row, got %d", n)
	}

	row := res.Rows[0]
	if len(row) != 3 {
		return 0, nil, false, fmt.Errorf("expected 3 columns, got %d", len(row))
	}

	var ok bool
	height, ok = sql.Int64(row[0])
	if !ok {
		return 0, nil, false, fmt.Errorf("invalid type for height (%T)", res.Rows[0][0])
	}

	if row[1] != nil {
		appHash, ok = row[1].([]byte)
		if !ok {
			return 0, nil, false, fmt.Errorf("expected bytes for apphash, got %T", row[1])
		}
	}

	dirty, ok = row[2].(bool)
	if !ok {
		return 0, nil, false, fmt.Errorf("expected bool for dirty, got %T", row[2])
	}

	return height, slices.Clone(appHash), dirty, nil
}

// SetChainState will update the current height and app hash.
func SetChainState(ctx context.Context, db sql.TxMaker, height int64, appHash []byte, dirty bool) error {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// attempt UPDATE
	res, err := tx.Execute(ctx, setChainState, height, appHash, dirty)
	if err != nil {
		return err
	}

	// If no rows updated, meaning empty table, do INSERT
	if res.Status.RowsAffected == 0 {
		_, err = tx.Execute(ctx, insertChainState, height, appHash, dirty)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// StoreParams stores the current consensus params in the store.
func StoreParams(ctx context.Context, db sql.TxMaker, params *types.NetworkParameters) error {
	paramBts, err := params.MarshalBinary()
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// attempt UPDATE
	res, err := tx.Execute(ctx, setParams, paramBts)
	if err != nil {
		return err
	}

	// If no rows updated, meaning empty table, do INSERT
	if res.Status.RowsAffected == 0 {
		_, err = tx.Execute(ctx, insertParams, paramBts)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

var ErrParamsNotFound = errors.New("params not found")

// LoadParams loads the consensus params from the store.
func LoadParams(ctx context.Context, db sql.Executor) (*types.NetworkParameters, error) {
	res, err := db.Execute(ctx, getParams)
	if err != nil {
		return nil, err
	}

	switch n := len(res.Rows); n {
	case 0:
		return nil, ErrParamsNotFound
	case 1:
	default:
		return nil, fmt.Errorf("expected at most one row, got %d", n)
	}

	params := &types.NetworkParameters{}
	row := res.Rows[0]
	if len(row) != 1 {
		return nil, fmt.Errorf("expected one column, got %d", len(row))
	}

	paramsBts, ok := row[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("expected BYTEA for params, got %T", row[0])
	}

	err = params.UnmarshalBinary(paramsBts)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal params: %w", err)
	}

	return params, nil
}
