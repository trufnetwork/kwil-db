package testing

import (
	"context"
	"fmt"
	"testing"
)

// TestMetaStoreSetup verifies that the SetupMetaStore option creates kwild_chain schema correctly
func TestMetaStoreSetup(t *testing.T) {
	t.Run("custom height and app hash", func(t *testing.T) {
		customAppHash := []byte("custom-test-hash-42")
		options := &Options{
			UseTestContainer: true,
			SetupMetaStore:   true,
			InitialHeight:    42,
			InitialAppHash:   customAppHash,
		}

		RunSchemaTest(t, SchemaTest{
			Name: "verify meta store setup with custom values",
			FunctionTests: []TestFunc{
				func(ctx context.Context, platform *Platform) error {
					// Query kwild_chain.chain table for both height and app_hash
					results, err := platform.DB.Execute(ctx,
						"SELECT height, app_hash FROM kwild_chain.chain LIMIT 1")
					if err != nil {
						return err
					}

					if len(results.Rows) == 0 {
						return fmt.Errorf("no rows in chain table")
					}

					row := results.Rows[0]
					if len(row) != 2 {
						return fmt.Errorf("expected 2 columns, got %d", len(row))
					}

					// Safe type assertion for height
					height, ok := row[0].(int64)
					if !ok {
						return fmt.Errorf("expected height to be int64, got %T", row[0])
					}
					if height != 42 {
						return fmt.Errorf("expected height 42, got %d", height)
					}

					// Safe type assertion for app_hash
					appHash, ok := row[1].([]byte)
					if !ok {
						return fmt.Errorf("expected app_hash to be []byte, got %T", row[1])
					}
					if string(appHash) != string(customAppHash) {
						return fmt.Errorf("expected app_hash %q, got %q", string(customAppHash), string(appHash))
					}

					return nil
				},
			},
		}, options)
	})

	t.Run("default values", func(t *testing.T) {
		options := &Options{
			UseTestContainer: true,
			SetupMetaStore:   true,
			// No InitialHeight or InitialAppHash provided - should use defaults
		}

		RunSchemaTest(t, SchemaTest{
			Name: "verify meta store setup with default values",
			FunctionTests: []TestFunc{
				func(ctx context.Context, platform *Platform) error {
					// Query kwild_chain.chain table for both height and app_hash
					results, err := platform.DB.Execute(ctx,
						"SELECT height, app_hash FROM kwild_chain.chain LIMIT 1")
					if err != nil {
						return err
					}

					if len(results.Rows) == 0 {
						return fmt.Errorf("no rows in chain table")
					}

					row := results.Rows[0]
					if len(row) != 2 {
						return fmt.Errorf("expected 2 columns, got %d", len(row))
					}

					// Safe type assertion for height (should default to 1)
					height, ok := row[0].(int64)
					if !ok {
						return fmt.Errorf("expected height to be int64, got %T", row[0])
					}
					if height != 1 {
						return fmt.Errorf("expected default height 1, got %d", height)
					}

					// Safe type assertion for app_hash (should default to "test-genesis-hash")
					appHash, ok := row[1].([]byte)
					if !ok {
						return fmt.Errorf("expected app_hash to be []byte, got %T", row[1])
					}
					expectedDefaultHash := "test-genesis-hash"
					if string(appHash) != expectedDefaultHash {
						return fmt.Errorf("expected default app_hash %q, got %q", expectedDefaultHash, string(appHash))
					}

					return nil
				},
			},
		}, options)
	})

	t.Run("negative height should fail", func(t *testing.T) {
		options := &Options{
			UseTestContainer: true,
			SetupMetaStore:   true,
			InitialHeight:    -5, // This should cause an error in setupMetaStoreForTesting directly
		}

		// This test should fail during setup due to invalid height
		err := SchemaTest{
			Name: "verify negative height fails",
			FunctionTests: []TestFunc{
				func(ctx context.Context, platform *Platform) error {
					// This should never be reached due to setup failure
					return fmt.Errorf("setup should have failed with negative height")
				},
			},
		}.Run(context.Background(), options)

		if err == nil {
			t.Errorf("expected error with negative height, but test passed")
		} else {
			// The error might be wrapped, so check if it contains our expected message
			expectedMsg := "height must be positive, got -5"
			if !contains(err.Error(), expectedMsg) {
				t.Errorf("expected error containing %q, got %q", expectedMsg, err.Error())
			}
		}
	})
}

// contains checks if a string contains a substring (helper for error checking)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(substr) > 0 && containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
