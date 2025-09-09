//go:build kwiltest

package orderedsync

import (
	"context"

	"github.com/trufnetwork/kwil-db/common"
)

// ForTestingStoreLogs stores a resolution message using the same path as production.
func ForTestingStoreLogs(ctx context.Context, app *common.App, topic string, logsData []byte, point int64, prev *int64) error {
	msg := &ResolutionMessage{
		Topic:               topic,
		PreviousPointInTime: prev,
		PointInTime:         point,
		Data:                logsData,
	}
	return Synchronizer.storeDataPoint(ctx, app, msg)
}

// ForTestingResolve applies pending data points using the end-block resolve path.
func ForTestingResolve(ctx context.Context, app *common.App, block *common.BlockContext) error {
	return Synchronizer.resolve(ctx, app, block)
}
