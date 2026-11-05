package pg

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/trufnetwork/kwil-db/node/types/sql"
)

const (
	notifChannel       = "kwild_internal_notif"
	sqlCreateFuncError = `CREATE OR REPLACE FUNCTION error(msg text)
		RETURNS void AS $$` + sqlFuncErrorBody + `$$ LANGUAGE plpgsql;`

	// sqlFuncErrorBody, and the other function bodies below, are as Postgres
	// keeps them in pg_proc.prosrc.
	sqlFuncErrorBody = `
		BEGIN
			RAISE EXCEPTION '%', msg;
		END;
		`

	sqlCreateFuncNotice = `CREATE OR REPLACE FUNCTION notice(payload text)
		RETURNS void AS $$` + sqlFuncNoticeBody + `$$ LANGUAGE plpgsql;`

	sqlFuncNoticeBody = `
		DECLARE txid bigint;
		BEGIN
			SELECT txid_current() INTO txid;
			raise notice 'pgtx:% %', txid, payload;
		END;
		`

	sqlCreateFuncEndNotices = `CREATE OR REPLACE FUNCTION end_notices(txid bigint)
		RETURNS void AS $$` + sqlFuncEndNoticesBody + `$$ LANGUAGE plpgsql;`

	sqlFuncEndNoticesBody = `
		BEGIN
			raise notice 'pgtx:fin:%', txid;
		END;
		`

	// sqlCheckHelperFunc reads the function with the name and argument types
	// $1 in the schema where CREATE FUNCTION puts a function by default: its
	// name with its schema and arguments, its owner, whether the current role
	// has the owner's privileges, which Postgres requires to replace a
	// function, and whether the function is as kwild creates it. kwild gives
	// each function only its arguments, a result, LANGUAGE plpgsql and a body,
	// so the function must have the body $2, the arguments $3 and the result
	// $4, and every other option at its default. These are compared as Postgres
	// stores or prints them, rather than comparing pg_get_functiondef with
	// kwild's statement, whose text differs in layout even when the function is
	// the same. The body must match byte for byte.
	sqlCheckHelperFunc = `SELECT quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' ||
			pg_get_function_identity_arguments(p.oid) || ')',
		pg_get_userbyid(p.proowner), pg_has_role(p.proowner, 'USAGE'),
		l.lanname = 'plpgsql' AND p.prosrc = $2 AND pg_get_function_arguments(p.oid) = $3 AND
			pg_get_function_result(p.oid) = $4 AND p.prokind = 'f' AND p.provolatile = 'v' AND
			p.proparallel = 'u' AND NOT (p.proisstrict OR p.prosecdef OR p.proleakproof) AND
			p.procost = 100 AND p.prorows = 0 AND p.prosupport = 0 AND p.proconfig IS NULL AND
			p.protrftypes IS NULL
	FROM pg_proc p
	JOIN pg_namespace n ON n.oid = p.pronamespace
	JOIN pg_language l ON l.oid = p.prolang
	WHERE p.oid = to_regprocedure(quote_ident(current_schema()) || '.' || $1);`

	sqlGetTxID = `SELECT txid_current();`
)

// helperFunc is a function that NewDB creates for the SQL that kwild runs.
type helperFunc struct {
	create string // the statement that creates or replaces it
	sig    string // its name and argument types, as to_regprocedure reads them
	args   string // its arguments, as pg_get_function_arguments prints them
	result string // its result, as pg_get_function_result prints it
	body   string // its body, as Postgres keeps it in pg_proc.prosrc
}

var (
	funcError      = &helperFunc{sqlCreateFuncError, "error(text)", "msg text", "void", sqlFuncErrorBody}
	funcNotice     = &helperFunc{sqlCreateFuncNotice, "notice(text)", "payload text", "void", sqlFuncNoticeBody}
	funcEndNotices = &helperFunc{sqlCreateFuncEndNotices, "end_notices(bigint)", "txid bigint", "void",
		sqlFuncEndNoticesBody}
)

// ensureHelperFunc creates or replaces fn. Postgres lets only the owner of a
// function, or a role with the owner's privileges, replace it, and owning the
// database does not give that. So for a role that is not a superuser, when fn
// exists and the role may not replace it, ensureHelperFunc leaves it as it is
// if it is as kwild creates it, and otherwise returns an error that says what
// a superuser must change.
func ensureHelperFunc(ctx context.Context, conn *pgx.Conn, superuser bool, fn *helperFunc) error {
	if !superuser {
		var name, owner string
		var mayReplace, asCreated bool
		err := conn.QueryRow(ctx, sqlCheckHelperFunc, fn.sig, fn.body, fn.args, fn.result).
			Scan(&name, &owner, &mayReplace, &asCreated)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// It does not exist, so create it.
		case err != nil:
			return fmt.Errorf("failed to read function %s: %w", fn.sig, err)
		case mayReplace:
			// Replace it, as for a superuser.
		case asCreated:
			return nil
		default:
			user := conn.Config().User
			return fmt.Errorf("function %s is not as kwild defines it, and postgres role %s may not replace it, "+
				"since only its owner, postgres role %s, or a role with that role's privileges may; a superuser "+
				"must first run ALTER FUNCTION %[1]s OWNER TO %[2]s, then start kwild again", name, user, owner)
		}
	}
	_, err := conn.Exec(ctx, fn.create)
	return err
}

func ensureErrorPLFunc(ctx context.Context, conn *pgx.Conn, superuser bool) error {
	return ensureHelperFunc(ctx, conn, superuser, funcError)
}

func ensureNoticePLFuncs(ctx context.Context, conn *pgx.Conn, superuser bool) error {
	err := ensureHelperFunc(ctx, conn, superuser, funcNotice)
	if err != nil {
		return err
	}

	return ensureHelperFunc(ctx, conn, superuser, funcEndNotices)
}

func getTxID(ctx context.Context, conn sql.Executor) (int64, error) {
	res, err := conn.Execute(ctx, sqlGetTxID)
	if err != nil {
		return 0, err
	}

	if len(res.Rows) != 1 {
		return 0, sql.ErrNoRows
	}

	intVal, ok := res.Rows[0][0].(int64)
	if !ok {
		return 0, fmt.Errorf("expected int64 for pg txid, got %T", res.Rows[0][0])
	}

	return intVal, nil
}

// containsTxid checks if a string is the proper format for a txid.
// if it is, it will return the txid, the rest of the string, and true.
// if it is not, it will return 0, "", false.
func containsTxid(notice string) (txid int64, log string, isTxid bool) {
	// trim off the txid prefix
	notice, cut := strings.CutPrefix(notice, "pgtx:")
	if !cut {
		return 0, "", false
	}

	// split from the first space
	strs := strings.SplitN(notice, " ", 2)
	if len(strs) != 2 {
		return 0, "", false
	}

	// parse the txid
	i64, err := strconv.ParseInt(strs[0], 10, 64)
	if err != nil {
		return 0, "", false
	}

	return i64, strs[1], true
}

// isFinishTxid checks if a string is logging that a txid is finished
func isFinishTxid(notice string) (txid int64, isFinish bool) {
	// trim off the txid prefix
	notice, cut := strings.CutPrefix(notice, "pgtx:fin:")
	if !cut {
		return 0, false
	}

	// parse the txid
	i64, err := strconv.ParseInt(notice, 10, 64)
	if err != nil {
		return 0, false
	}

	return i64, true
}
