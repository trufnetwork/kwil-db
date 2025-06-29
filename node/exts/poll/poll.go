// package poll implements a basic polling mechanism for Kwil event listeners
package poll

import (
	"context"
	"time"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/extensions/listeners"
)

// PollFuncConstructor is a function that constructs a PollFunc. If it returns an error,
// the node will shut down.
type PollFuncConstructor func(ctx context.Context, service *common.Service, eventstore listeners.EventStore) (PollFunc, error)

// PollFunc is a function that is called every interval to poll for events.
type PollFunc func(ctx context.Context, service *common.Service, eventstore listeners.EventStore) (stopPolling bool, err error)

// NewPoller creates a new event listener that polls for events.
// It takes a poll interval and a constructor function that constructs the poll function.
// The constructor will be called exactly once when the listener starts, while the
// poll function will be called every interval.
func NewPoller(interval time.Duration, constructor PollFuncConstructor) listeners.ListenFunc {
	return func(ctx context.Context, service *common.Service, eventstore listeners.EventStore) error {
		pollFunc, err := constructor(ctx, service, eventstore)
		if err != nil {
			return err
		}

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(interval):
				stopPolling, err := pollFunc(ctx, service, eventstore)
				if err != nil {
					return err
				}
				if stopPolling {
					return nil
				}
			}
		}
	}
}
