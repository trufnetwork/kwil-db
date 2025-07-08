package testing

import (
	"context"
	"fmt"

	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// setupExtensions initializes extensions in the test database.
// This function replicates the extension loading logic from production nodes.
func setupExtensions(ctx context.Context, db sql.DB, extensions []ExtensionConfig) error {
	for _, ext := range extensions {
		// Check if the extension is registered
		registeredExts := precompiles.RegisteredPrecompiles()
		if _, ok := registeredExts[ext.Name]; !ok {
			return fmt.Errorf("extension %s is not registered", ext.Name)
		}

		// Register the extension initialization in the database
		metadata := make(map[string]any)
		for k, v := range ext.Metadata {
			metadata[k] = v
		}

		// Create namespace and register extension
		err := registerExtensionForTesting(ctx, db, ext.Alias, ext.Name, metadata)
		if err != nil {
			return fmt.Errorf("failed to register extension %s: %w", ext.Name, err)
		}
	}
	return nil
}

// registerExtensionForTesting registers an extension in the test database.
// This replicates the database operations from the production extension loading.
func registerExtensionForTesting(ctx context.Context, db sql.DB, alias, extName string, metadata map[string]any) error {
	// Create namespace
	_, err := db.Execute(ctx, `
		INSERT INTO kwild_engine.namespaces (name, type)
		VALUES ($1, 'EXTENSION')
	`, alias)
	if err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Get namespace ID
	var namespaceID int64
	result, err := db.Execute(ctx, "SELECT id FROM kwild_engine.namespaces WHERE name = $1", alias)
	if err != nil {
		return fmt.Errorf("failed to get namespace ID: %w", err)
	}
	if len(result.Rows) == 0 {
		return fmt.Errorf("namespace not found: %s", alias)
	}
	namespaceID = result.Rows[0][0].(int64)

	// Register extension
	_, err = db.Execute(ctx, `
		INSERT INTO kwild_engine.initialized_extensions (namespace_id, base_extension)
		VALUES ($1, $2)
	`, namespaceID, extName)
	if err != nil {
		return fmt.Errorf("failed to register extension: %w", err)
	}

	// Get extension ID
	var extensionID int64
	result, err = db.Execute(ctx, "SELECT id FROM kwild_engine.initialized_extensions WHERE namespace_id = $1", namespaceID)
	if err != nil {
		return fmt.Errorf("failed to get extension ID: %w", err)
	}
	if len(result.Rows) == 0 {
		return fmt.Errorf("extension not found for namespace_id: %d", namespaceID)
	}
	extensionID = result.Rows[0][0].(int64)

	// Register metadata parameters
	if false && len(metadata) > 0 { // Temporarily disabled to focus on namespace loading
		// Clear existing parameters
		_, err = db.Execute(ctx, "DELETE FROM kwild_engine.extension_initialization_parameters WHERE extension_id = $1", extensionID)
		if err != nil {
			return fmt.Errorf("failed to clear existing parameters: %w", err)
		}

		// Insert new parameters
		for key, value := range metadata {
			scalarType, isArray := getTypeInfo(value)
			valueStr := convertToString(value)

			_, err = db.Execute(ctx, `
				INSERT INTO kwild_engine.extension_initialization_parameters
				(extension_id, key, value, scalar_type, is_array, metadata)
				VALUES ($1, $2, $3, $4, $5, $6)
			`, extensionID, key, valueStr, scalarType, isArray, nil)
			if err != nil {
				return fmt.Errorf("failed to insert parameter %s: %w", key, err)
			}
		}
	}

	return nil
}

// getTypeInfo determines the scalar type and array flag for a value
func getTypeInfo(value any) (string, bool) {
	switch value.(type) {
	case string:
		return "TEXT", false
	case int, int8, int16, int32, int64:
		return "INT8", false
	case float32, float64:
		return "NUMERIC", false
	case bool:
		return "BOOL", false
	case []string:
		return "TEXT", true
	case []int, []int8, []int16, []int32, []int64:
		return "INT8", true
	case []float32, []float64:
		return "NUMERIC", true
	case []bool:
		return "BOOL", true
	default:
		// Fallback to text for unknown types
		return "TEXT", false
	}
}

// convertToString converts a value to its string representation for storage
func convertToString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%g", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}
