//go:build kwiltest

package orderedsync

import (
	"context"

	"github.com/trufnetwork/kwil-db/common"
)

// ForTestingReset clears the in-memory ordered-sync cache.
func ForTestingReset() { Synchronizer.reset() }

// ForTestingInitFromDB loads topics from DB into the in-memory cache.
func ForTestingInitFromDB(ctx context.Context, app *common.App) error {
	return Synchronizer.readTopicInfoOnStartup(ctx, app)
}
