// package listeners provides the interface and registration for custom
// event-driven listeners. Listeners are designed to be non-deterministic, and
// can be used to trigger "Resolutions" on the local network. See package
// "extensions/resolutions" to define resolutions that can be voted on by the
// network.
package listeners

import (
	"context"
	"fmt"
	"strings"

	"github.com/trufnetwork/kwil-db/common"
)

// registeredListeners is a map of all registered event listeners.
var registeredListeners = make(map[string]ListenFunc)

// ListenFunc is a function that allows custom event listeners to be built
// with Kwil. The function is called when a node has come online,
// synced with the network, and is currently a validator. The
// function is expected to run for as long as the implementer wants
// the listener to continue running. The passed context will be
// canceled when the node is shutting down, or when it is no longer
// a validator. It is expected that any resources associated with
// the listener are cleaned up when the context is canceled. The
// function can be called many times if a node's validator status
// changes (e.g. becomes a validator, is removed as a validator, then
// becomes a validator again). The function can block indefinitely,
// but all resources should be cleaned up when the context is
// canceled to prevent memory leaks.
type ListenFunc func(ctx context.Context, service *common.Service, eventstore EventStore) error

// RegisterListener registers a listener with the Kwil network.
// It should be called in the init function of the listener's package.
// The name cannot have spaces in it.
func RegisterListener(name string, listener ListenFunc) error {
	name = strings.ToLower(name)

	// we protect against spaces in the name, because the KV
	// gives each listener its own namespace. Spaces are used
	// to prevent collisions in the KV.
	for _, r := range name {
		if r == ' ' {
			return fmt.Errorf("listener name cannot have spaces")
		}
	}

	if _, ok := registeredListeners[name]; ok {
		return fmt.Errorf("listener with name %s already registered: ", name)
	}

	registeredListeners[name] = listener
	return nil
}

// RegisteredListeners returns a map of all registered listeners.
func RegisteredListeners() map[string]ListenFunc {
	return registeredListeners
}

// GetListener returns a listener by its name.
func GetListener(name string) (ListenFunc, bool) {
	listener, ok := registeredListeners[name]
	return listener, ok
}

// EventStore is an interface that allows listeners to persist events,
// and track arbitrary metadata about its external source. It should
// be used to signal to the local Kwil node that the validator has
// seen an event, and that the event should be broadcast to the
// network. Events should be broadcast to the network using the
// Broadcast method. The KV store data is never forwarded to the
// network, and is simply for the convenience of the listener
// implementer to persist metadata about the data source.
type EventStore interface {
	EventKV
	// Broadcast stores a newly observed event for broadcast to the network.
	// The eventType is a string that identifies the network
	// should interpret the data. The eventType should directly
	// correspond to a "resolution" type, implemented in the
	// resolutions package. The data argument will be passed to the
	// resolution's ResolveFunc if enough nodes vote on the resolution.
	Broadcast(ctx context.Context, eventType string, data []byte) error
}

// EventKV is a simple key-value store for listeners to use to store
// arbitrary metadata about the external data source.
// None of the data stored in the KV store is broadcast to the network.
type EventKV interface {
	// Set sets a key-value pair in the KV store. The data is scoped
	// to the local node, and is not broadcast to the network.
	Set(ctx context.Context, key []byte, value []byte) error
	// Get gets a value from the local node's KV store.
	Get(ctx context.Context, key []byte) ([]byte, error)
	// Delete deletes a value from the local node's KV store. The
	// data is scoped to the local node, and is not broadcast to the
	// network.
	Delete(ctx context.Context, key []byte) error
}
