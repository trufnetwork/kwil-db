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

	t.Run("global grant keeps an explicit namespace denial", func(t *testing.T) {
		ac, db, done := setup(t)

		const role = "analyst"
		const user = "alice"
		err = ac.CreateRole(ctx, db, role)
		handleErr(t, err, done)
		err = ac.AssignRole(ctx, db, role, user, false)
		handleErr(t, err, done)

		// Namespace grant then revoke leaves granted=false and no global row.
		err = ac.GrantPrivileges(ctx, db, role, []privilege{_INSERT_PRIVILEGE}, &mainNamespace, false)
		handleErr(t, err, done)
		err = ac.RevokePrivileges(ctx, db, role, []privilege{_INSERT_PRIVILEGE}, &mainNamespace, false)
		handleErr(t, err, done)
		err = ac.GrantPrivileges(ctx, db, role, []privilege{_INSERT_PRIVILEGE}, nil, false)
		handleErr(t, err, done)

		info := "info"
		assertLiveMatchesReload := func() {
			t.Helper()
			ac2, err := newAccessController(ctx, db)
			handleErr(t, err, done)
			for _, ns := range []*string{&mainNamespace, &info} {
				live := ac.HasPrivilege(user, ns, _INSERT_PRIVILEGE)
				reloaded := ac2.HasPrivilege(user, ns, _INSERT_PRIVILEGE)
				if live != reloaded {
					done()
					t.Fatalf("live HasPrivilege(%s) = %v, reload = %v", *ns, live, reloaded)
				}
			}
		}

		if ac.HasPrivilege(user, &mainNamespace, _INSERT_PRIVILEGE) {
			done()
			t.Fatal("live cache allowed INSERT on a namespace with an explicit denial")
		}
		if !ac.HasPrivilege(user, &info, _INSERT_PRIVILEGE) {
			done()
			t.Fatal("live cache dropped the global INSERT grant on a namespace without a denial")
		}
		assertLiveMatchesReload()

		// Global revoke deletes the denial row. A later global grant applies to every namespace.
		err = ac.RevokePrivileges(ctx, db, role, []privilege{_INSERT_PRIVILEGE}, nil, false)
		handleErr(t, err, done)
		err = ac.GrantPrivileges(ctx, db, role, []privilege{_INSERT_PRIVILEGE}, nil, false)
		handleErr(t, err, done)
		if !ac.HasPrivilege(user, &mainNamespace, _INSERT_PRIVILEGE) {
			done()
			t.Fatal("global revoke should clear the namespace denial")
		}
		assertLiveMatchesReload()
		done()
	})
}

func Test_globalGrantPreservesNamespaceDenial(t *testing.T) {
	const (
		victim = "victim"
		other  = "other"
	)
	ac := &accessController{
		roles:           map[string]*perms{},
		knownNamespaces: map[string]struct{}{victim: {}, other: {}},
	}
	role := ac.newPerm()
	ac.roles["r"] = role

	victimNS := victim
	otherNS := other

	role.grant(&victimNS, _SELECT_PRIVILEGE)
	role.revoke(&victimNS, _SELECT_PRIVILEGE)
	role.grant(nil, _SELECT_PRIVILEGE)

	if role.canDo(_SELECT_PRIVILEGE, &victimNS) {
		t.Fatal("global grant overwrote an explicit denial")
	}
	if !role.canDo(_SELECT_PRIVILEGE, &otherNS) {
		t.Fatal("global grant should apply to a namespace without a denial")
	}
	if !role.canDo(_SELECT_PRIVILEGE, nil) {
		t.Fatal("global grant should set the global privilege")
	}

	copied := role.copy()
	copied.grant(nil, _SELECT_PRIVILEGE)
	if copied.canDo(_SELECT_PRIVILEGE, &victimNS) {
		t.Fatal("copied role lost the namespace denial")
	}

	// An explicit grant on the namespace clears the denial.
	role.grant(&victimNS, _SELECT_PRIVILEGE)
	if _, stillDenied := role.namespaceDenials[victim][_SELECT_PRIVILEGE]; stillDenied {
		t.Fatal("namespace grant should clear an explicit denial")
	}

	role.revoke(&victimNS, _SELECT_PRIVILEGE)
	role.revoke(nil, _SELECT_PRIVILEGE)
	role.grant(nil, _SELECT_PRIVILEGE)
	if !role.canDo(_SELECT_PRIVILEGE, &victimNS) {
		t.Fatal("global revoke should clear namespace denials")
	}

	role.revoke(&victimNS, _SELECT_PRIVILEGE)
	ac.unregisterNamespace(victim)
	ac.registerNamespace(victim)
	if !ac.roles["r"].canDo(_SELECT_PRIVILEGE, &victimNS) {
		t.Fatal("recreated namespace should inherit the global privilege")
	}
}

var mainNamespace = "main"
