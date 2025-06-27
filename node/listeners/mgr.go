package listeners

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	common "github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/listeners"
	"github.com/trufnetwork/kwil-db/node/voting"
)

// ListenerManager listens for any Validator state changes and node catch up status
// and starts or stops the listeners accordingly
// It starts the listeners only when the node is a validator and is caught up
// It stops the running listeners when the node loses its validator status
type ListenerManager struct {
	eventStore *voting.EventStore
	vstore     ValidatorGetter
	node       Node
	service    *common.Service
	cancel     context.CancelFunc // cancels the context for the listener manager
}

// ValidatorGetter is able to read the current validator set.
type ValidatorGetter interface {
	GetValidators() []*types.Validator
	SubscribeValidators() <-chan []*types.Validator
}

type Node interface {
	InCatchup() bool
}

func NewListenerManager(svc *common.Service, eventStore *voting.EventStore, vstore ValidatorGetter, node Node) *ListenerManager {
	return &ListenerManager{
		eventStore: eventStore,
		vstore:     vstore,
		node:       node,
		service:    svc,
	}
}

// Start starts the listener manager.
// It will block until Stop is called.
// If any one listener stops, all listeners are stopped and a non-nil error
// is returned.
func (omgr *ListenerManager) Start() (err error) {
	ctx, cancel := context.WithCancel(context.Background()) // context that will be canceled when the manager shuts down
	omgr.cancel = cancel
	defer cancel()

	// Listen for status changes
	// Start oracles if the node is a validator and is caught up
	// Stop the oracles, if the node is not a validator
	errChan := make(chan error, 1)
	var listenerInstanceCancel context.CancelFunc // nil => listeners not running
	startStop := func(isValidator bool) {
		if listenerInstanceCancel == nil && isValidator {
			// inner context to manage the listeners
			// this context will be cancelled when the node loses its validator status
			// it will also be cancelled when the listener manager is stopped
			ctx2, cancel2 := context.WithCancel(ctx)
			listenerInstanceCancel = cancel2

			omgr.service.Logger.Info("Node is a validator and caught up with the network, starting listeners")

			for name, start := range listeners.RegisteredListeners() {
				go func(start listeners.ListenFunc, name string) {
					err := start(ctx2, omgr.service.NamedLogger(name), &scopedKVEventStore{
						ev: omgr.eventStore,
						// we add a space to prevent collisions in the KV
						// oracle names cannot have spaces
						KV: omgr.eventStore.KV([]byte(name + " ")),
					})
					if err != nil {
						omgr.service.Logger.Error("==========================  Event listener stopped  ==========================",
							"listener", name, "error", err)
						if !errors.Is(err, context.Canceled) {
							errChan <- err
						}
						cancel2() // Stop other listeners
					} else {
						// Listener exited with nil, no need to stop other listeners in this case
						omgr.service.Logger.Debug("Event listener stopped (cleanly)", "listener", name)
					}
				}(start, name)

			}
		} else if listenerInstanceCancel != nil && !isValidator {
			// Stop the listeners if they are running
			omgr.service.Logger.Info("Node is no longer a validator, stopping listeners")
			listenerInstanceCancel()
			listenerInstanceCancel = nil
		}
	}

	defer func() {
		omgr.service.Logger.Info("ListenerManager stopped.", "error", err)
	}()

	containsMe := func(validators []*types.Validator) bool {
		return slices.ContainsFunc(validators, func(v *types.Validator) bool {
			return bytes.Equal(v.Identifier, omgr.service.Identity)
		})
	}

	// Tick until catch-up is complete...
	syncCheck := time.NewTicker(500 * time.Millisecond)
	defer syncCheck.Stop()
	// ...then begin receiving the current validator set at each block.
	var valChan <-chan []*types.Validator

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errChan:
			return err
		case validators := <-valChan:
			startStop(containsMe(validators))
			if syncCheck != nil {
				syncCheck.Stop() // would be no-op after first time
			}

		case <-syncCheck.C:
			// still in catch up mode, keep polling
			if omgr.node.InCatchup() {
				continue
			}

			// switch to the validators channel
			syncCheck.Stop()
			valChan = omgr.vstore.SubscribeValidators() // creates a new channel in txApp

			validators := omgr.vstore.GetValidators()
			startStop(containsMe(validators))
		}
	}
}

func (omgr *ListenerManager) Stop() {
	omgr.cancel()
}

// scopedKVEventStore is for the EventStore input of listeners.ListenFunc
var _ listeners.EventStore = (*scopedKVEventStore)(nil)

// scopedKVEventStore scopes the event store's kv store to the listener's name
type scopedKVEventStore struct {
	ev *voting.EventStore
	*voting.KV
}

// Broadcast broadcasts an event to the event store.
func (e *scopedKVEventStore) Broadcast(ctx context.Context, eventType string, data []byte) error {
	return e.ev.Store(ctx, data, eventType)
}
