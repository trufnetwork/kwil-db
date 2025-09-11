//go:build kwiltest

package orderedsync

import (
	"context"
	"errors"
	"fmt"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/node/engine"
	kwilTesting "github.com/trufnetwork/kwil-db/testing"
)

// ForTestingEnsureNamespace creates the ordered-sync namespace and sets its version.
func ForTestingEnsureNamespace(ctx context.Context, platform *kwilTesting.Platform) error {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
	if err := createNamespace(ctx, platform.DB, platform.Engine); err != nil {
		// ignore if already exists
	}
	return setVersionToCurrent(ctx, app)
}

// ForTestingEnsureTopic ensures a topic is present in DB and in the in-memory cache without causing duplicate insert errors.
func ForTestingEnsureTopic(ctx context.Context, platform *kwilTesting.Platform, topic string, resolveFunc string) error {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
	Synchronizer.mu.Lock()
	defer Synchronizer.mu.Unlock()

	// Do not early-return on cache hit; ensure DB contains the topic row

	resolveFn, ok := registered[resolveFunc]
	if !ok {
		return fmt.Errorf("resolve function %s not registered", resolveFunc)
	}

	// Check if topic exists in DB, creating namespace/version if needed
	exists := false
	err := platform.Engine.ExecuteWithoutEngineCtx(ctx, platform.DB,
		fmt.Sprintf(`{%s}SELECT 1 FROM topics WHERE name = $name`, ExtensionName),
		map[string]any{"name": topic},
		func(r *common.Row) error {
			exists = true
			return nil
		},
	)
	if errors.Is(err, engine.ErrNamespaceNotFound) {
		if err2 := createNamespace(ctx, platform.DB, platform.Engine); err2 != nil {
			return err2
		}
		if err2 := setVersionToCurrent(ctx, app); err2 != nil {
			return err2
		}
		// retry existence check once
		err = platform.Engine.ExecuteWithoutEngineCtx(ctx, platform.DB,
			fmt.Sprintf(`{%s}SELECT 1 FROM topics WHERE name = $name`, ExtensionName),
			map[string]any{"name": topic},
			func(r *common.Row) error {
				exists = true
				return nil
			},
		)
	}
	if err != nil {
		return err
	}

	if !exists {
		if err := registerTopic(ctx, platform.DB, platform.Engine, topic, resolveFunc); err != nil {
			return err
		}
	}

	// Update in-memory cache
	Synchronizer.topics[topic] = &topicInfo{resolve: resolveFn}
	return nil
}
