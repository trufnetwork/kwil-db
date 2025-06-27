package main

import (
	"context"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
)

func init() {
	// Register a resolution
	err := resolutions.RegisterResolution("spam-resolution", resolutions.ModAdd, resolutions.ResolutionConfig{
		ResolveFunc: func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext) error {
			// This is where the resolution logic goes
			app.Service.Logger.Info("Spam resolution logic approved")
			return nil
		},
	})
	if err != nil {
		panic(err)
	}
}
