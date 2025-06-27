package node

import (
	"context"
	"fmt"
	"sync"

	"github.com/trufnetwork/kwil-db/core/utils/order"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

func newNamespaceManager() *namespaceManager {
	return &namespaceManager{
		namespaces: make(map[string]struct{}),
	}
}

// namespaceManager keeps track of namespaces in memory.
// It is simply used as a way for the engine to communicate the set
// of namespaces
type namespaceManager struct {
	mu sync.RWMutex
	// ready is true if the manager is ready to be used.
	// It is set after the engine has created and has read in to
	// memory the set of namespaces.
	ready      bool
	namespaces map[string]struct{}
}

// RegisterNamespace registers a namespace with the manager
func (n *namespaceManager) RegisterNamespace(ns string) {
	n.namespaces[ns] = struct{}{}
}

// UnregisterNamespace unregisters a namespace with the manager
func (n *namespaceManager) UnregisterAllNamespaces() {
	n.namespaces = make(map[string]struct{})
}

// Lock locks the manager
// It should be called before registering or unregistering namespaces
func (n *namespaceManager) Lock() {
	n.mu.Lock()
}

// Unlock unlocks the manager
func (n *namespaceManager) Unlock() {
	n.mu.Unlock()
}

// Filter returns true if the namespace containers user data.
// It will return false for internal kwild schemas (e.g. "kwild_engine")
// and for namespaces that are only views (e.g. "info")
// If it is not ready, it panics.
func (n *namespaceManager) Filter(ns string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if !n.ready {
		return false
	}
	_, ok := n.namespaces[ns]
	return ok
}

// Ready sets the manager to be ready
func (n *namespaceManager) Ready() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ready = true
}

// ListPostgresSchemasToDump returns an ordered list of postgres
// schemas that should be included when exporting database state.
func (n *namespaceManager) ListPostgresSchemasToDump() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if !n.ready {
		return nil
	}

	res := make([]string, len(n.namespaces)+2)
	res[0] = engine.InternalEnginePGSchema
	res[1] = engine.InfoNamespace
	for i, ns := range order.OrderMap(n.namespaces) {
		res[i+2] = ns.Key
	}

	return res
}

type DB interface {
	sql.ReadTxMaker
}

func UserNamespaces(ctx context.Context, db DB) ([]string, error) {
	tx, err := db.BeginReadTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	res, err := tx.Execute(ctx, "select name from kwild_engine.namespaces")
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	if len(res.Columns) != 1 {
		return nil, fmt.Errorf("unexpected number of columns: %d", len(res.Columns))
	}

	var userNamespaces []string
	for _, row := range res.Rows {
		if len(row) != 1 {
			return nil, fmt.Errorf("unexpected number of columns in row: %d", len(row))
		}

		ns, ok := row[0].(string)
		if !ok {
			return nil, fmt.Errorf("failed to convert namespace to string: %v", row[0])
		}

		userNamespaces = append(userNamespaces, ns)
	}

	return userNamespaces, nil
}
