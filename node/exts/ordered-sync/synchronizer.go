package orderedsync

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/utils/order"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

type ResolveFunc func(ctx context.Context, app *common.App, block *common.BlockContext, res *ResolutionMessage) error

// Synchronizer is the global instance of the ordered sync extension.
var Synchronizer = &cachedSync{
	topics: make(map[string]*topicInfo),
}

type topicInfo struct {
	resolve            ResolveFunc
	lastProcessedPoint *int64 // last processed point in time, nil if none have been processed
}

// this file holds a thread-safe in-memory cache for registering topics.
// Unlike extension registration, which happens on init, topic registration
// occurs over the life cycle of the node.

type cachedSync struct {
	// mu protects all fields in this struct
	mu sync.Mutex
	// topics is a map of topics to their suffixes
	topics      map[string]*topicInfo
	initialized bool // basic protection against double initialization in case of a bug elsewhere
}

// RegisterTopic registers a topic with a callback.
// It should be called exactly once: when a topic is made relevant (within
// consensus). This should usually be in Genesis, but it can be called at any time.
func (c *cachedSync) RegisterTopic(ctx context.Context, db sql.DB, eng common.Engine, topic string, resolveFunc string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.topics[topic]
	if ok {
		return fmt.Errorf("topic %s already registered", topic)
	}

	resolveFn, ok := registered[resolveFunc]
	if !ok {
		return fmt.Errorf("resolve function %s not registered", resolveFunc)
	}

	err := registerTopic(ctx, db, eng, topic, resolveFunc)
	if err != nil {
		return err
	}

	c.topics[topic] = &topicInfo{
		resolve: resolveFn,
	}

	return nil
}

// UnregisterTopic unregisters a topic.
// It should be called exactly once when a topic is no longer relevant.
// (e.g. within a precompile's OnUnUse method).
func (c *cachedSync) UnregisterTopic(ctx context.Context, db sql.DB, eng common.Engine, topic string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.topics[topic]
	if !ok {
		return fmt.Errorf("topic %s not registered", topic)
	}

	err := unregisterTopic(ctx, db, eng, topic)
	if err != nil {
		return err
	}

	delete(c.topics, topic)
	return nil
}

// readTopicInfoOnStartup reads the last processed point in time for each topic.
// It is meant to be called within an EngineReadyHook.
// It populates the cache with topics.
func (c *cachedSync) readTopicInfoOnStartup(ctx context.Context, app *common.App) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.initialized {
		return fmt.Errorf("already initialized, this is an internal error")
	}
	c.initialized = true

	err := app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
	{kwil_ordered_sync}SELECT name, resolve_func FROM topics
	`, nil, func(r *common.Row) error {
		if len(r.Values) != 2 {
			// this should never happen
			return fmt.Errorf("unexpected number of columns")
		}

		topic, ok := r.Values[0].(string)
		if !ok {
			return fmt.Errorf("unexpected type string for topic")
		}

		resolveFunc, ok := r.Values[1].(string)
		if !ok {
			return fmt.Errorf("unexpected type string for resolve function")
		}

		_, ok = c.topics[topic]
		if ok {
			// signals an internal bug
			return fmt.Errorf("topic %s already registered", topic)
		}

		resolveFn, ok := registered[resolveFunc]
		if !ok {
			return fmt.Errorf("resolve function %s not registered", resolveFunc)
		}

		c.topics[topic] = &topicInfo{
			resolve: resolveFn,
		}
		return nil
	})

	if errors.Is(err, engine.ErrNamespaceNotFound) {
		// if unknown namespace, this is our first run, so we just skip
		return nil
	}

	return err
}

// resolve gets all finalized data points from the engine and calls the registered callback.
func (c *cachedSync) resolve(ctx context.Context, app *common.App, block *common.BlockContext) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	res, err := getFinalizedDataPoints(ctx, app.DB, app.Engine)
	if err != nil {
		return err
	}

	// we track the last resolved point so we can
	// update the last processed point in the database
	latestPoint := make(map[string]int64)
	for _, dp := range res {
		topic, ok := c.topics[dp.Topic]
		if !ok {
			return fmt.Errorf("topic %s not registered", dp.Topic)
		}

		if err := topic.resolve(ctx, app, block, dp); err != nil {
			return err
		}

		latestPoint[dp.Topic] = dp.PointInTime
	}

	// update the last processed point in the database.
	// We do this in order to guarantee deterministic behavior
	for _, kv := range order.OrderMap(latestPoint) {
		err = setLatestPointInTime(ctx, app.DB, app.Engine, kv.Key, kv.Value)
		if err != nil {
			return err
		}

		// update the in-memory cache
		c.topics[kv.Key].lastProcessedPoint = &kv.Value
	}

	return nil
}

// storeDataPoint stores a data point in the engine.
// It ensures that the point and previous point are not less than the previous point in time.
func (c *cachedSync) storeDataPoint(ctx context.Context, app *common.App, dp *ResolutionMessage) error {
	if dp.PreviousPointInTime != nil {
		if dp.PointInTime < *dp.PreviousPointInTime {
			return fmt.Errorf("point in time must be greater than previous point in time")
		}
		if dp.PointInTime == *dp.PreviousPointInTime {
			logger := app.Service.Logger.New("orderedsync")
			logger.Info("point in time already exists, skip store", "topic", dp.Topic)
			return nil
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.topics[dp.Topic]
	if !ok {
		// if topic is not registered, we should not store the data point.
		// This is not always an error: there may be an extension that was
		// dropped and the data points are still being processed.
		// In this case, we just ignore the data point.
		logger := app.Service.Logger.New("orderedsync")
		logger.Warn("topic not registered", "topic", dp.Topic)
		return nil
	}

	return storeDataPoint(ctx, app.DB, app.Engine, dp)
}

// reset resets the cache.
// THIS SHOULD ONLY BE USED IN TESTS.
//
//lint:ignore U1000 This is only used in tests
func (c *cachedSync) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.topics = make(map[string]*topicInfo)
	c.initialized = false
}
