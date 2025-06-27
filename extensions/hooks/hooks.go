package hooks

import (
	"context"
	"fmt"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/utils/order"
)

// GenesisHook is a function that is run exactly once, at network genesis.
// It can be used to create initial state or perform other setup tasks.
// If it returns an error, the network will immediately halt. Any state
// changed or error returned should be deterministic, as all nodes will
// run the same GenesisHooks in the same order.
type GenesisHook func(ctx context.Context, app *common.App, chain *common.ChainContext) error

// RegisterGenesisHook registers a GenesisHook to be run at network genesis.
// The name can be anything, as long as it is unique. It is used to deterministically
// order the hooks.
func RegisterGenesisHook(name string, hook GenesisHook) error {
	_, ok := genesisHooks[name]
	if ok {
		return fmt.Errorf("genesis hook with name %s already exists", name)
	}

	genesisHooks[name] = hook
	return nil
}

var genesisHooks map[string]GenesisHook

// ListGenesisHooks deterministically returns a list of all registered GenesisHooks.
func ListGenesisHooks() []struct {
	Name string
	Hook GenesisHook
} {
	hooks := make([]struct {
		Name string
		Hook GenesisHook
	}, 0, len(genesisHooks))
	for _, hook := range order.OrderMap(genesisHooks) {
		hooks = append(hooks, struct {
			Name string
			Hook GenesisHook
		}{
			Name: hook.Key,
			Hook: hook.Value,
		})
	}

	return hooks
}

// EndBlockHook is a function that is run at the end of each block, after
// all of the transactions in the block have been processed, but before the
// any state has been committed. It is meant to be used to alter state, send
// data to external services, or perform cleanup tasks for other extensions.
// An error returned will halt the local node. All state changes and errors
// should be deterministic, as all nodes will run the same EndBlockHooks in
// the same order.
type EndBlockHook func(ctx context.Context, app *common.App, block *common.BlockContext) error

// RegisterEndBlockHook registers an EndBlockHook to be run at the end of each block.
// The name can be anything, as long as it is unique. It is used to deterministically
// order the hooks.
func RegisterEndBlockHook(name string, hook EndBlockHook) error {
	_, ok := endBlockHooks[name]
	if ok {
		return fmt.Errorf("end block hook with name %s already exists", name)
	}

	endBlockHooks[name] = hook
	return nil
}

var endBlockHooks map[string]EndBlockHook

// ListEndBlockHooks deterministically returns a list of all registered EndBlockHooks.
func ListEndBlockHooks() []struct {
	Name string
	Hook EndBlockHook
} {
	var hooks []struct {
		Name string
		Hook EndBlockHook
	}
	for _, hook := range order.OrderMap(endBlockHooks) {
		hooks = append(hooks, struct {
			Name string
			Hook EndBlockHook
		}{
			Name: hook.Key,
			Hook: hook.Value,
		})
	}

	return hooks
}

// EngineReadyHook is a hook that is called on startup after the engine (and all of its extensions)
// have been initialized. It is meant to be used to perform any setup tasks that require the engine
// to be fully initialized.
type EngineReadyHook func(ctx context.Context, app *common.App) error

var engineReadyHooks map[string]EngineReadyHook // map to guarantee uniqueness and order

// RegisterEngineReadyHook registers an EngineReadyHook to be run on startup after the engine is ready.
func RegisterEngineReadyHook(name string, hook EngineReadyHook) error {
	_, ok := engineReadyHooks[name]
	if ok {
		return fmt.Errorf("engine ready hook with name %s already exists", name)
	}

	engineReadyHooks[name] = hook
	return nil
}

// ListEngineReadyHooks returns a list of all registered EngineReadyHooks.
func ListEngineReadyHooks() []EngineReadyHook {
	var hooks []EngineReadyHook
	for _, hook := range order.OrderMap(engineReadyHooks) {
		hooks = append(hooks, hook.Value)
	}

	return hooks
}

func init() {
	genesisHooks = make(map[string]GenesisHook)
	endBlockHooks = make(map[string]EndBlockHook)
	engineReadyHooks = make(map[string]EngineReadyHook)
}
