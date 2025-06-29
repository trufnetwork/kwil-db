package main

import (
	"context"
	"fmt"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/extensions/listeners"
)

const ListenerName = "spammer"

func init() {
	err := listeners.RegisterListener(ListenerName, Start)
	if err != nil {
		panic(err)
	}
}

func Start(ctx context.Context, service *common.Service, eventStore listeners.EventStore) error {
	if cfg, ok := service.LocalConfig.Extensions[ListenerName]; !ok {
		return fmt.Errorf("spammer listener not configured, not starting spam oracle")
	} else if cfg["enabled"] != "true" {
		service.Logger.Info("Spam oracle is DISABLED")
		return nil
	}
	service.Logger.Info("Starting spam oracle")
	const maxSpams = 10_000
	var count int
	for {
		select {
		case <-ctx.Done(): // Properly handle context cancellation
			return nil
		default:
			err := eventStore.Broadcast(ctx, "spam-resolution", []byte(fmt.Sprintf("spam%08d", count)))
			if err != nil {
				return err
			}
			if count == maxSpams {
				return nil
			}
			count++
		}
	}
}
