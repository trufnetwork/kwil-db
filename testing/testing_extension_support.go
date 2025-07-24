package testing

import (
	"context"
	"fmt"
	"maps"

	"github.com/trufnetwork/kwil-db/node/engine/interpreter"

	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// setupExtensions initializes extensions in the test database.
// This function replicates the extension loading logic from production nodes.
func setupExtensions(ctx context.Context, db sql.DB, extensions []interpreter.StoredExtension) error {
	for _, ext := range extensions {
		// Check if the extension is registered
		registeredExts := precompiles.RegisteredPrecompiles()
		if _, ok := registeredExts[ext.ExtName]; !ok {
			return fmt.Errorf("extension %s is not registered", ext.ExtName)
		}

		// Register the extension initialization in the database
		metadata := make(map[string]interpreter.Value)
		maps.Copy(metadata, ext.Metadata)

		// Create namespace and register extension
		err := interpreter.RegisterExtensionInitialization(ctx, db, ext.Alias, ext.ExtName, metadata)
		if err != nil {
			return fmt.Errorf("failed to register extension %s: %w", ext.ExtName, err)
		}
	}
	return nil
}
