package node

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/trufnetwork/kwil-db/core/crypto"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/meta"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"
)

// kwildSchemas are the schemas a snapshot restores (see the snapshot schemas
// in the block processor), less the engine's namespaces and the ds_* schemas,
// which are found at run time, plus kwild_events, kwild's local event store,
// which describes the state being replaced.
var kwildSchemas = []string{"kwild_engine", "info", "kwild_voting", "kwild_internal", "kwild_chain",
	"kwild_accts", "kwild_migrations", "kwild_events"}

// ownedSchemas splits the schemas in a node's database into the ones kwild
// owns, which a resync drops, and every other one, which it keeps: public and
// the extensions in it, pg_repack's schema, schemas that node extensions
// create for local data, and anything an operator created.
func ownedSchemas(all, namespaces []string) (owned, keep []string) {
	for _, schema := range all {
		if slices.Contains(kwildSchemas, schema) || slices.Contains(namespaces, schema) ||
			strings.HasPrefix(schema, "ds_") {
			owned = append(owned, schema)
		} else {
			keep = append(keep, schema)
		}
	}
	return owned, keep
}

// isValidator reports whether key is the genesis leader's or a validator's in
// the set the database holds.
func isValidator(key, genesisLeader crypto.PublicKey, validators []*ktypes.Validator) bool {
	if genesisLeader != nil && key.Equals(genesisLeader) {
		return true
	}
	return slices.ContainsFunc(validators, func(v *ktypes.Validator) bool {
		return v.KeyType == key.Type() && bytes.Equal(v.Identifier, key.Bytes())
	})
}

// localState is what a node's database says about itself.
type localState struct {
	height     int64
	appHash    []byte
	dirty      bool // block height was being committed when the node stopped
	validators []*ktypes.Validator
	namespaces []string
}

func (ss *StateSyncService) readLocalState(ctx context.Context) (*localState, error) {
	tx, err := ss.db.BeginReadTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var st localState
	st.height, st.appHash, st.dirty, err = meta.GetChainState(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("read the chain state: %w", err)
	}
	if st.validators, err = voting.GetValidators(ctx, tx); err != nil {
		return nil, fmt.Errorf("read the validator set: %w", err)
	}
	if st.namespaces, err = engineNamespaces(ctx, tx); err != nil {
		return nil, fmt.Errorf("read the engine namespaces: %w", err)
	}
	return &st, nil
}

func engineNamespaces(ctx context.Context, tx sql.Executor) ([]string, error) {
	res, err := tx.Execute(ctx, `SELECT name FROM kwild_engine.namespaces`)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(res.Rows))
	for _, row := range res.Rows {
		name, ok := row[0].(string)
		if !ok {
			return nil, fmt.Errorf("namespace name is a %T", row[0])
		}
		names = append(names, name)
	}
	return names, nil
}

// checkStateIsOurs returns an error unless the database's app hash is the one
// this node's block store recorded for the same block. A database that is
// ahead of the block store, or that does not match it, is not this node's.
func (ss *StateSyncService) checkStateIsOurs(st *localState) error {
	// A dirty chain state is block height part way through its commit, and it
	// still holds the app hash of the block before it.
	height := st.height
	if st.dirty {
		height--
	}
	_, _, ci, err := ss.blockStore.GetRawByHeight(height)
	if err != nil {
		return fmt.Errorf("the block store has no block %d: %w", height, err)
	}
	if !bytes.Equal(ci.AppHash[:], st.appHash) {
		return fmt.Errorf("the app hash of block %d is %x in the database and %x in the block store",
			height, st.appHash, ci.AppHash[:])
	}
	return nil
}

// ResyncIfFarBehind clears a node that has state so that it restores a newer
// snapshot instead of replaying blocks, when a trusted provider vouches for a
// snapshot that is more than resync_when_behind blocks ahead of the local
// height. It returns true when it cleared the node, and the caller then state
// syncs as a new node does.
//
// It returns false, having changed nothing, when the setting is 0, the node is
// a validator, no snapshot is far enough ahead, or a check before the wipe
// fails: the database does not match this node's block store, or something
// outside kwild's schemas depends on them. It logs which. An error means the
// wipe started and did not finish; the restore marker makes the next start
// finish it.
func (ss *StateSyncService) ResyncIfFarBehind(ctx context.Context, self, genesisLeader crypto.PublicKey) (bool, error) {
	behind := ss.cfg.ResyncWhenBehind
	if !ss.cfg.Enable || behind == 0 {
		return false, nil
	}

	st, err := ss.readLocalState(ctx)
	if err != nil {
		ss.log.Warn("Not resyncing: cannot read the local state", "error", err)
		return false, nil
	}
	if isValidator(self, genesisLeader, st.validators) {
		ss.log.Info("Not resyncing: this node is a validator, and a validator always replays", "height", st.height)
		return false, nil
	}

	snapHeight, found, err := ss.FindVerifiedSnapshot(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		ss.log.Warn("Not resyncing: snapshot discovery failed", "error", err)
		return false, nil
	}
	resync := found && st.height > 0 && snapHeight > uint64(st.height) && snapHeight-uint64(st.height) > behind
	ss.log.Info("Resync decision", "local_height", st.height, "snapshot_height", snapHeight,
		"resync_when_behind", behind, "resync", resync)
	if !resync {
		return false, nil
	}

	if err := ss.checkStateIsOurs(st); err != nil {
		ss.log.Warn("Not resyncing: the database does not match this node's block store", "error", err)
		return false, nil
	}

	conn := pgConnConfig(ss.dbConfig)
	all, err := pg.ListSchemas(ctx, conn)
	if err != nil {
		ss.log.Warn("Not resyncing: cannot list the database's schemas", "error", err)
		return false, nil
	}
	owned, keep := ownedSchemas(all, st.namespaces)
	dependents, err := pg.OutsideDependents(ctx, conn, owned)
	if err != nil {
		ss.log.Warn("Not resyncing: cannot check what depends on kwild's schemas", "error", err)
		return false, nil
	}
	if len(dependents) > 0 {
		ss.log.Warn("Not resyncing: objects outside kwild's schemas depend on them, and clearing the node would drop them",
			"objects", dependents)
		return false, nil
	}

	return true, ss.clearForResync(ctx, snapHeight, st.height, keep)
}

// clearForResync deletes kwild's state from a node so that it can restore the
// snapshot at snapHeight: every block in the block store, and every schema
// that is not in keep. It marks the restore as started first, so a node
// stopped part way finishes clearing itself at the next start.
func (ss *StateSyncService) clearForResync(ctx context.Context, snapHeight uint64, from int64, keep []string) error {
	if err := writeRestoreMarker(ss.restoreMarker, &restoreMarker{
		Height:        snapHeight,
		SchemasBefore: keep,
		ResyncFrom:    uint64(from),
	}); err != nil {
		return err
	}
	if err := ss.blockStore.Reset(); err != nil {
		return fmt.Errorf("clear the block store: %w", err)
	}
	dropped, err := pg.DropSchemasExcept(ctx, pgConnConfig(ss.dbConfig), keep)
	if err != nil {
		return fmt.Errorf("drop kwild's schemas: %w", err)
	}
	ss.log.Warn("Cleared this node to restore a newer snapshot; it no longer holds blocks before it",
		"from_height", from, "snapshot_height", snapHeight, "dropped_schemas", dropped, "kept_schemas", keep)
	return nil
}
