//go:build kwiltest

package orderedsync

import (
	"context"

	"github.com/trufnetwork/kwil-db/common"
	kwilTesting "github.com/trufnetwork/kwil-db/testing"
)

// ForTestingStoreLogs stores a resolution message using the same path as production.
func ForTestingStoreLogs(ctx context.Context, platform *kwilTesting.Platform, topic string, logsData []byte, point int64, prev *int64) error {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
	msg := &ResolutionMessage{
		Topic:               topic,
		PreviousPointInTime: prev,
		PointInTime:         point,
		Data:                logsData,
	}
	return Synchronizer.storeDataPoint(ctx, app, msg)
}

// ForTestingResolve applies pending data points using the end-block resolve path.
func ForTestingResolve(ctx context.Context, platform *kwilTesting.Platform, block *common.BlockContext) error {
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
	return Synchronizer.resolve(ctx, app, block)
}
