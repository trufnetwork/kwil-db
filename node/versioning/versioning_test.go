//go:build pglive

package versioning_test

import (
	"context"
	"testing"

	"github.com/trufnetwork/kwil-db/node/types/sql"

	dbtest "github.com/trufnetwork/kwil-db/node/pg/test"
	"github.com/trufnetwork/kwil-db/node/versioning"

	"github.com/stretchr/testify/require"
)

const testSchema = "test_versioning"

func Test_Versioning(t *testing.T) {
	ctx := context.Background()

	upgradeFns := map[int64]versioning.UpgradeFunc{
		0: initTableV0,
		1: upgradeSchemaV0ToV1,
		2: upgradeSchemaV1ToV2,
	}
	db := dbtest.NewTestDB(t, nil)

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	defer tx.Rollback(ctx) // always rollback, to clean up the test database

	err = versioning.Upgrade(ctx, tx, testSchema, upgradeFns, 0)
	require.NoError(t, err)

	err = versioning.Upgrade(ctx, tx, testSchema, upgradeFns, 1)
	require.NoError(t, err)

	err = versioning.Upgrade(ctx, tx, testSchema, upgradeFns, 2)
	require.NoError(t, err)

	_, err = db.Execute(ctx, `INSERT INTO `+testSchema+`.test (id, name, age) VALUES (3, 'test', 30);`)
	require.NoError(t, err)
}

func initTableV0(ctx context.Context, db sql.DB) error {
	_, err := db.Execute(ctx, `CREATE TABLE IF NOT EXISTS `+testSchema+`.test (id INT PRIMARY KEY);`)
	return err
}

func upgradeSchemaV0ToV1(ctx context.Context, db sql.DB) error {
	_, err := db.Execute(ctx, `ALTER TABLE `+testSchema+`.test ADD COLUMN name TEXT;`)
	return err
}

func upgradeSchemaV1ToV2(ctx context.Context, db sql.DB) error {
	_, err := db.Execute(ctx, `ALTER TABLE `+testSchema+`.test ADD COLUMN age INT;`)
	return err
}
