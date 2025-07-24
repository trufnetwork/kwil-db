package testing

import (
	"context"
	"fmt"
	"testing"
)

// TestMetaStoreSetup verifies that the SetupMetaStore option creates kwild_chain schema correctly
func TestMetaStoreSetup(t *testing.T) {
	options := &Options{
		UseTestContainer: true,
		SetupMetaStore:   true,
		InitialHeight:    42,
	}

	RunSchemaTest(t, SchemaTest{
		Name: "verify meta store setup",
		FunctionTests: []TestFunc{
			func(ctx context.Context, platform *Platform) error {
				// Query kwild_chain.chain table
				results, err := platform.DB.Execute(ctx,
					"SELECT height FROM kwild_chain.chain LIMIT 1")
				if err != nil {
					return err
				}

				if len(results.Rows) == 0 {
					return fmt.Errorf("no rows in chain table")
				}

				height := results.Rows[0][0].(int64)
				if height != 42 {
					return fmt.Errorf("expected height 42, got %d", height)
				}

				return nil
			},
		},
	}, options)
}