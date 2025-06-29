package pg

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/trufnetwork/kwil-db/node/types/sql"
)

const (
	notifChannel       = "kwild_internal_notif"
	sqlCreateFuncError = `CREATE OR REPLACE FUNCTION error(msg text)
		RETURNS void AS $$
		BEGIN
			RAISE EXCEPTION '%', msg;
		END;
		$$ LANGUAGE plpgsql;`

	sqlCreateFuncNotice = `CREATE OR REPLACE FUNCTION notice(payload text)
		RETURNS void AS $$
		DECLARE txid bigint;
		BEGIN
			SELECT txid_current() INTO txid;
			raise notice 'pgtx:% %', txid, payload;
		END;
		$$ LANGUAGE plpgsql;`

	sqlCreateFuncEndNotices = `CREATE OR REPLACE FUNCTION end_notices(txid bigint)
		RETURNS void AS $$
		BEGIN
			raise notice 'pgtx:fin:%', txid;
		END;
		$$ LANGUAGE plpgsql;`

	sqlGetTxID = `SELECT txid_current();`
)

func ensureErrorPLFunc(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, sqlCreateFuncError)
	return err
}

func ensureNoticePLFuncs(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, sqlCreateFuncNotice)
	if err != nil {
		return err
	}

	_, err = conn.Exec(ctx, sqlCreateFuncEndNotices)
	return err
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
