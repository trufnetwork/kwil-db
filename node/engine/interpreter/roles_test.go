package interpreter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

func Test_Roles(t *testing.T) {
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

	setup := func(t *testing.T) (*accessController, sql.DB, func()) {
		tx, err := db.BeginTx(ctx)
		require.NoError(t, err)

		err = initSQLIfNotInitialized(ctx, tx)
		require.NoError(t, err)

		ac, err := newAccessController(ctx, tx)
		if err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}

		return ac, tx, func() {
			tx.Rollback(ctx)
		}
	}

	handleErr := func(t *testing.T, err error, fn func()) {
		if err != nil {
			fn()
			t.Fatal(err)
		}
	}

	t.Run("Removing SELECT from default role and restarting DB", func(t *testing.T) {
		// I test two cases: global revocation and namespace revocation.
		// There have been cases where the global revocation worked but the namespace revocation didn't.
		for _, namespace := range []*string{&mainNamespace, nil} {
			ac, db, done := setup(t)

			err = ac.RevokePrivileges(ctx, db, defaultRole, []privilege{_SELECT_PRIVILEGE}, namespace, false)
			handleErr(t, err, done)

			if ac.HasPrivilege(defaultRole, namespace, _SELECT_PRIVILEGE) {
				done()
				if namespace == nil {
					t.Fatal("expected SELECT privilege to be removed globally")
				} else {
					t.Fatal("expected SELECT privilege to be removed from namespace " + *namespace)
				}
			}

			// we make a new access controller to simulate a fresh interpreter starting
			// with state in the DB
			ac2, err := newAccessController(ctx, db)
			handleErr(t, err, done)

			if ac2.HasPrivilege("some_user", namespace, _SELECT_PRIVILEGE) {
				done()
				if namespace == nil {
					t.Fatal("AFTER RESTART: expected SELECT privilege to be removed globally")
				} else {
					t.Fatal("AFTER RESTART: expected SELECT privilege to be removed from namespace " + *namespace)
				}
			}

			done()
		}
	})

	t.Run("Adding INSERT to default role and restarting DB", func(t *testing.T) {
		for _, namespace := range []*string{&mainNamespace, nil} {
			ac, db, done := setup(t)

			err = ac.GrantPrivileges(ctx, db, defaultRole, []privilege{_INSERT_PRIVILEGE}, namespace, false)
			handleErr(t, err, done)

			if !ac.HasPrivilege(defaultRole, namespace, _INSERT_PRIVILEGE) {
				done()
				if namespace == nil {
					t.Fatal("expected INSERT privilege to be added globally")
				} else {
					t.Fatal("expected INSERT privilege to be added for namespace " + *namespace)
				}
			}

			// we make a new access controller to simulate a fresh interpreter starting
			// with state in the DB
			ac2, err := newAccessController(ctx, db)
			handleErr(t, err, done)

			if !ac2.HasPrivilege(defaultRole, namespace, _INSERT_PRIVILEGE) {
				done()
				if namespace == nil {
					t.Fatal("AFTER RESTART: expected INSERT privilege to be added globally")
				} else {
					t.Fatal("AFTER RESTART: expected INSERT privilege to be added for namespace " + *namespace)
				}
			}

			done()
		}
	})
}

var mainNamespace = "main"
