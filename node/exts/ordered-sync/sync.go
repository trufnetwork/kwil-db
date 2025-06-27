// package orderedsync is a general purpose extension that synchronizes data from systems where absolute
// order is guaranteed (e.g. blockchains, streaming services, or other event-based systems).
// Because Kwil's resolution system does not natively guarantee order (e.g. listeners can submit
// events in order: event1, event2, event 3, but they can be resolved in order: event2, event1, event3),
// chainsync is used to guarantee the order of events.
// It requires that all events for a single point in time be submitted in one resolution, and that they point to
// the last point in time which had events that were relevant. This effectively creates a linked list of resolutions
// that can be used to ensure that we do not process events out of order.
// When orderedsync is used, it creates a new namespace in the engine in which it stores all confirmed data.
// This makes all confirmed data (even if not all of its parent resolutions have not been confirmed) part
// of the network state.
// Within an end block, orderedsync will process all information that has not been confirmed and pass
// it to it's respective listener.
package orderedsync

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/extensions/hooks"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

var (
	//go:embed schema.sql
	schema []byte
	//go:embed finalized.sql
	getFinalizedDataPointsSQL string
)

const (
	// ExtensionName is the unique name of the extension.
	// It is used to register the resolution and to create a namespace
	// in the engine for the confirmed data.
	ExtensionName = "kwil_ordered_sync"
)

// RegisterResolveFunc registers a resolve function.
// It gives it a name which it can be identified by.
// It MUST be called in init.
func RegisterResolveFunc(s string, resolveFn ResolveFunc) {
	_, ok := registered[s]
	if ok {
		panic(fmt.Sprintf("resolve function with name %s already registered", s))
	}

	registered[s] = resolveFn
}

var registered = make(map[string]ResolveFunc)

// RegisterOrderedSync registers the ordered sync extension.
// It can be called many times, but each time must have a different suffix.
// It should be called in init.
func init() {
	err := resolutions.RegisterResolution(ExtensionName, resolutions.ModAdd, resolutions.ResolutionConfig{
		RefundThreshold:       big.NewRat(1, 3),
		ConfirmationThreshold: big.NewRat(1, 2),
		ExpirationPeriod:      1 * time.Hour,
		ResolveFunc: func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext) error {
			res := &ResolutionMessage{}
			err := res.UnmarshalBinary(resolution.Body)
			if err != nil {
				return err
			}

			return Synchronizer.storeDataPoint(ctx, app, res)
		},
	})
	if err != nil {
		panic(err)
	}

	err = hooks.RegisterEngineReadyHook(ExtensionName+"_engine_ready_hook", Synchronizer.readTopicInfoOnStartup)
	if err != nil {
		panic(err)
	}

	err = hooks.RegisterGenesisHook(ExtensionName+"_genesis_hook", func(ctx context.Context, app *common.App, chain *common.ChainContext) error {
		version, notYetSet, err := getVersion(ctx, app)
		if err != nil {
			return err
		}

		if notYetSet {
			err = createNamespace(ctx, app.DB, app.Engine)
			if err != nil {
				return err
			}

			err = setVersionToCurrent(ctx, app)
			if err != nil {
				return err
			}
		} else {
			// in the future, we may want to add migrations here
			if version != currentVersion {
				return fmt.Errorf("expected version %d, got %d", currentVersion, version)
			}
		}

		return nil
	})
	if err != nil {
		panic(err)
	}

	err = hooks.RegisterEndBlockHook(ExtensionName+"_end_block_hook", Synchronizer.resolve)
	if err != nil {
		panic(err)
	}
}

func createNamespace(ctx context.Context, db sql.DB, eng common.Engine) error {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	err = eng.ExecuteWithoutEngineCtx(ctx, tx, fmt.Sprintf(`CREATE NAMESPACE %s`, ExtensionName), nil, nil)
	if err != nil {
		return err
	}

	err = eng.ExecuteWithoutEngineCtx(ctx, tx, string(schema), nil, nil)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

type ResolutionMessage struct {
	// Topic is the topic that the resolution is for.
	Topic string
	// PreviousPointInTime is the point in time that the resolution is for.
	// It is a pointer because it can be nil if this is the first resolution.
	PreviousPointInTime *int64
	// PointInTime is the point in time that the resolution is for.
	// It is used to order the resolutions.
	PointInTime int64
	// Data is the data that is being resolved.
	Data []byte
}

func (r *ResolutionMessage) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	// 1) Write topic length and topic bytes
	topicBytes := []byte(r.Topic)
	if err := binary.Write(buf, binary.BigEndian, int32(len(topicBytes))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(topicBytes); err != nil {
		return nil, err
	}

	// 2) Write presence of PreviousPointInTime, and its value if present
	if r.PreviousPointInTime != nil {
		if err := buf.WriteByte(1); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, *r.PreviousPointInTime); err != nil {
			return nil, err
		}
	} else {
		if err := buf.WriteByte(0); err != nil {
			return nil, err
		}
	}

	// 3) Write PointInTime (8 bytes)
	if err := binary.Write(buf, binary.BigEndian, r.PointInTime); err != nil {
		return nil, err
	}

	// 4) Write data length and data
	if err := binary.Write(buf, binary.BigEndian, int32(len(r.Data))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(r.Data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (r *ResolutionMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	// 1) Read topic length and topic bytes
	var topicLen int32
	if err := binary.Read(buf, binary.BigEndian, &topicLen); err != nil {
		return err
	}
	topicBytes := make([]byte, topicLen)
	if _, err := io.ReadFull(buf, topicBytes); err != nil {
		return err
	}
	r.Topic = string(topicBytes)

	// 2) Read presence of PreviousPointInTime, and read the value if present
	presenceFlag, err := buf.ReadByte()
	if err != nil {
		return err
	}
	if presenceFlag == 1 {
		var previous int64
		if err := binary.Read(buf, binary.BigEndian, &previous); err != nil {
			return err
		}
		r.PreviousPointInTime = &previous
	} else {
		r.PreviousPointInTime = nil
	}

	// 3) Read PointInTime
	if err := binary.Read(buf, binary.BigEndian, &r.PointInTime); err != nil {
		return err
	}

	// 4) Read data length and data
	var dataLen int32
	if err := binary.Read(buf, binary.BigEndian, &dataLen); err != nil {
		return err
	}
	r.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(buf, r.Data); err != nil {
		return err
	}

	return nil
}

// registerTopic registers a topic with the engine.
// It should be called by other extensions that want to inform
// orderedsync of a new topic they will be publishing for.
// It should be called every time the engine starts.
func registerTopic(ctx context.Context, db sql.DB, eng common.Engine, topic, resolveFn string) error {
	return eng.ExecuteWithoutEngineCtx(ctx, db,
		fmt.Sprintf(`{%s}INSERT INTO topics (id, name, last_processed_point, resolve_func) VALUES (
		uuid_generate_v5('5ac60ab5-9335-4ea9-8fe5-bbfe931f276e'::uuid, $name),
		$name,
		null,
		$resolve_func
        )`, ExtensionName),
		map[string]any{
			"name":         topic,
			"resolve_func": resolveFn,
		},
		nil,
	)
}

// unregisterTopic unregisters a topic with the engine.
// It should be called by other extensions that want to inform
// orderedsync that they will no longer be publishing for a topic,
// and that orderedsync should not call any resolve functions for that topic.
// It should be called when the topic is no longer relevant.
func unregisterTopic(ctx context.Context, db sql.DB, eng common.Engine, topic string) error {
	return eng.ExecuteWithoutEngineCtx(ctx, db,
		fmt.Sprintf(`{%s}DELETE FROM topics WHERE name = $name`, ExtensionName),
		map[string]any{
			"name": topic,
		},
		nil,
	)
}

// storeDataPoint stores a data point in the engine.
func storeDataPoint(ctx context.Context, db sql.DB, eng common.Engine, dp *ResolutionMessage) error {
	return eng.ExecuteWithoutEngineCtx(ctx, db,
		fmt.Sprintf(`{%s}INSERT INTO pending_data (point, topic_id, previous_point, data) VALUES (
		$point,
		(SELECT id FROM topics WHERE name = $topic),
		$previous_point,
		$data
		)`, ExtensionName),
		map[string]any{
			"point":          dp.PointInTime,
			"topic":          dp.Topic,
			"previous_point": dp.PreviousPointInTime,
			"data":           dp.Data,
		},
		nil,
	)
}

// getFinalizedDataPoints gets all finalized data points from the engine.
// It returns them first ordered by name, then by point in time.
func getFinalizedDataPoints(ctx context.Context, db sql.DB, eng common.Engine) ([]*ResolutionMessage, error) {
	var res []*ResolutionMessage
	err := eng.ExecuteWithoutEngineCtx(ctx, db, getFinalizedDataPointsSQL, nil, func(r *common.Row) error {
		// query returns 5 rows:
		// 1) point in time (int64)
		// 2) previous point in time (int64 or nil)
		// 3) data ([]byte or nil)
		// 4) topic name (string)

		if len(r.Values) != 4 {
			return fmt.Errorf("expected 4 values, got %d", len(r.Values))
		}

		pointInTime, ok := r.Values[0].(int64)
		if !ok {
			return fmt.Errorf("expected int64, got %T", r.Values[0])
		}

		var prevPot *int64
		previousPointInTime, ok := r.Values[1].(int64)
		if !ok {
			if r.Values[1] != nil {
				return fmt.Errorf("expected int64, got %T", r.Values[1])
			}
		} else {
			prevPot = &previousPointInTime
		}

		data, ok := r.Values[2].([]byte)
		if !ok {
			if r.Values[2] == nil {
				return fmt.Errorf("expected []byte, got nil")
			}
		}

		topic, ok := r.Values[3].(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", r.Values[3])
		}

		res = append(res, &ResolutionMessage{
			Topic:               topic,
			PreviousPointInTime: prevPot,
			PointInTime:         pointInTime,
			Data:                data,
		})

		return nil
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}

// setLatestPointInTime sets the latest point in time for a topic.
func setLatestPointInTime(ctx context.Context, db sql.DB, eng common.Engine, topic string, pointInTime int64) error {
	return eng.ExecuteWithoutEngineCtx(ctx, db,
		fmt.Sprintf(`{%s}UPDATE topics SET last_processed_point = $point WHERE name = $name`, ExtensionName),
		map[string]any{
			"point": pointInTime,
			"name":  topic,
		},
		nil,
	)
}

// getVersion gets the version of the meta extension.
func getVersion(ctx context.Context, app *common.App) (version int64, notYetSet bool, err error) {
	count := 0
	err = app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
	{kwil_ordered_sync}SELECT version
	FROM meta
	`, nil, func(r *common.Row) error {
		if len(r.Values) != 1 {
			return fmt.Errorf("expected 1 value, got %d", len(r.Values))
		}
		count++
		version = r.Values[0].(int64)
		return nil
	})
	switch {
	case errors.Is(err, engine.ErrNamespaceNotFound):
		return 0, true, nil
	case err != nil:
		return 0, false, err
	}

	switch count {
	case 0:
		return 0, true, nil
	case 1:
		return version, false, nil
	default:
		return 0, false, errors.New("expected only one value for version table, got")
	}
}

var currentVersion = int64(1)

// setVersion sets the version of the meta extension.
func setVersionToCurrent(ctx context.Context, app *common.App) error {
	return app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
	{kwil_ordered_sync}INSERT INTO meta(version)
	VALUES ($version)
	ON CONFLICT (version) DO UPDATE SET version = $version
	`, map[string]any{
		"version": currentVersion,
	}, nil)
}
