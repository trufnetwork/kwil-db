package interpreter

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto"
	coreauth "github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/node/engine"
)

func TestLeaderContextualVariable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		proposer       crypto.PublicKey
		invalidTxCtx   bool
		expectedResult string
		expectError    bool
	}{
		{
			name:           "valid proposer key",
			proposer:       mustCreateEd25519Key(t),
			invalidTxCtx:   false,
			expectedResult: "", // Will be set dynamically based on actual key
			expectError:    false,
		},
		{
			name:           "nil proposer key",
			proposer:       nil,
			invalidTxCtx:   false,
			expectedResult: "",
			expectError:    false,
		},
		{
			name:           "invalid transaction context",
			proposer:       mustCreateEd25519Key(t),
			invalidTxCtx:   true,
			expectedResult: "",
			expectError:    true,
		},
		{
			name:           "secp256k1 proposer key",
			proposer:       mustCreateSecp256k1Key(t),
			invalidTxCtx:   false,
			expectedResult: "", // Will be set dynamically based on actual key
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create execution context
			blockCtx := &common.BlockContext{
				Height:    100,
				Timestamp: 1640995200, // 2022-01-01 00:00:00 UTC
				Proposer:  tt.proposer,
			}

			txCtx := &common.TxContext{
				Ctx:          context.Background(),
				BlockContext: blockCtx,
				Caller:       "test_caller",
				TxID:         "test_tx_id",
			}

			engineCtx := &common.EngineContext{
				TxContext:    txCtx,
				InvalidTxCtx: tt.invalidTxCtx,
			}

			execCtx := &executionContext{
				engineCtx: engineCtx,
				scope:     newScope("test"),
			}

			// Test @leader variable
			result, err := execCtx.getVariable("@leader")

			if tt.expectError {
				require.Error(t, err)
				assert.Equal(t, engine.ErrInvalidTxCtx, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			// Convert result to string with type-safe assertion
			require.IsType(t, (*textValue)(nil), result)
			actualResult := result.(*textValue).String

			// For dynamic key tests, calculate expected result from the key using helper
			if tt.expectedResult == "" && tt.proposer != nil {
				assert.Equal(t, hexFromKey(tt.proposer), actualResult)
			} else {
				assert.Equal(t, tt.expectedResult, actualResult)
			}

			// Verify the result is deterministic (same input should give same output)
			result2, err2 := execCtx.getVariable("@leader")
			require.NoError(t, err2)
			require.IsType(t, (*textValue)(nil), result2)
			assert.Equal(t, actualResult, result2.(*textValue).String, "Leader variable should be deterministic")
		})
	}
}

func TestLeaderVariableConsistencyWithOtherContextualVars(t *testing.T) {
	t.Parallel()
	// Test that @leader follows the same pattern as @height and @block_timestamp
	proposerKey := mustCreateEd25519Key(t)

	blockCtx := &common.BlockContext{
		Height:    12345,
		Timestamp: 1640995200,
		Proposer:  proposerKey,
	}

	txCtx := &common.TxContext{
		Ctx:          context.Background(),
		BlockContext: blockCtx,
		Caller:       "test_caller",
		TxID:         "test_tx_id",
	}

	engineCtx := &common.EngineContext{
		TxContext: txCtx,
	}

	execCtx := &executionContext{
		engineCtx: engineCtx,
		scope:     newScope("test"),
	}

	// Test that all contextual variables are accessible
	height, err := execCtx.getVariable("@height")
	require.NoError(t, err)
	assert.NotNil(t, height)

	timestamp, err := execCtx.getVariable("@block_timestamp")
	require.NoError(t, err)
	assert.NotNil(t, timestamp)

	leader, err := execCtx.getVariable("@leader")
	require.NoError(t, err)
	assert.NotNil(t, leader)

	// Verify @leader returns expected hex-encoded proposer
	require.IsType(t, (*textValue)(nil), leader)
	expectedLeader := hexFromKey(proposerKey)
	assert.Equal(t, expectedLeader, leader.(*textValue).String)
}

func TestLeaderVariableInvalidTxContext(t *testing.T) {
	t.Parallel()
	// Test that @leader properly handles invalid transaction context
	execCtx := &executionContext{
		engineCtx: &common.EngineContext{
			InvalidTxCtx: true,
		},
		scope: newScope("test"),
	}

	// Test all contextual variables behave consistently with invalid context
	contextualVars := []string{"@height", "@block_timestamp", "@leader", "@caller"}

	for _, variable := range contextualVars {
		t.Run(variable, func(t *testing.T) {
			t.Parallel()
			_, err := execCtx.getVariable(variable)
			assert.Equalf(t, engine.ErrInvalidTxCtx, err,
				"Variable %s should return ErrInvalidTxCtx for invalid context", variable)
		})
	}
}

// Helper function to create an Ed25519 key for testing
func mustCreateEd25519Key(t *testing.T) crypto.PublicKey {
	t.Helper()
	// Generate an Ed25519 key for testing (not deterministic across runs)
	_, pubKey, err := crypto.GenerateEd25519Key(nil)
	require.NoError(t, err)
	return pubKey
}

// Helper function to create a secp256k1 key for testing
func mustCreateSecp256k1Key(t *testing.T) crypto.PublicKey {
	t.Helper()
	// Generate a secp256k1 key for testing (not deterministic across runs)
	_, pubKey, err := crypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	return pubKey
}

// TestLeaderIDContextualVariable tests the @leader_id contextual variable
func TestLeaderIDContextualVariable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		proposer       crypto.PublicKey
		authenticator  string
		invalidTxCtx   bool
		expectedResult string
		expectError    bool
	}{
		{
			name:           "valid ed25519 proposer key",
			proposer:       mustCreateEd25519Key(t),
			authenticator:  "ed25519_sha256",
			invalidTxCtx:   false,
			expectedResult: "", // Will be set dynamically based on actual key
			expectError:    false,
		},
		{
			name:           "valid secp256k1 proposer key",
			proposer:       mustCreateSecp256k1Key(t),
			authenticator:  "secp256k1",
			invalidTxCtx:   false,
			expectedResult: "", // Will be set dynamically based on actual key
			expectError:    false,
		},
		{
			name:           "nil proposer key",
			proposer:       nil,
			authenticator:  "ed25519_sha256",
			invalidTxCtx:   false,
			expectedResult: "",
			expectError:    false,
		},
		{
			name:           "invalid transaction context",
			proposer:       mustCreateEd25519Key(t),
			authenticator:  "ed25519_sha256",
			invalidTxCtx:   true,
			expectedResult: "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create execution context
			blockCtx := &common.BlockContext{
				Height:    100,
				Timestamp: 1640995200, // 2022-01-01 00:00:00 UTC
				Proposer:  tt.proposer,
			}

			txCtx := &common.TxContext{
				Ctx:           context.Background(),
				BlockContext:  blockCtx,
				Caller:        "test_caller",
				TxID:          "test_tx_id",
				Authenticator: tt.authenticator,
			}

			engineCtx := &common.EngineContext{
				TxContext:    txCtx,
				InvalidTxCtx: tt.invalidTxCtx,
			}

			execCtx := &executionContext{
				engineCtx: engineCtx,
				scope:     newScope("test"),
			}

			// Test @leader_id variable
			result, err := execCtx.getVariable("@leader_id")

			if tt.expectError {
				require.Error(t, err)
				assert.Equal(t, engine.ErrInvalidTxCtx, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			// Convert result to string with type-safe assertion
			require.IsType(t, (*textValue)(nil), result)
			actualResult := result.(*textValue).String

			// For dynamic key tests, calculate expected result from the key using helper
			if tt.expectedResult == "" && tt.proposer != nil {
				expectedID := identifierFromKey(t, tt.proposer)
				assert.Equal(t, expectedID, actualResult)
			} else {
				assert.Equal(t, tt.expectedResult, actualResult)
			}

			// Verify the result is deterministic (same input should give same output)
			result2, err2 := execCtx.getVariable("@leader_id")
			require.NoError(t, err2)
			require.IsType(t, (*textValue)(nil), result2)
			assert.Equal(t, actualResult, result2.(*textValue).String, "Leader ID variable should be deterministic")
		})
	}
}

// TestLeaderAuthorizationScenarios demonstrates how @leader is used in practice
// for authorization in multi-validator scenarios
func TestLeaderAuthorizationScenarios(t *testing.T) {
	t.Parallel()
	// Simulate a multi-validator scenario
	validator1 := mustCreateEd25519Key(t)
	validator2 := mustCreateSecp256k1Key(t)
	regularUser := "0x1234567890abcdef"

	tests := []struct {
		name         string
		caller       string
		proposer     crypto.PublicKey
		expectAccess bool
		description  string
	}{
		{
			name:         "leader_can_execute_digest",
			caller:       hexFromKey(validator1),
			proposer:     validator1,
			expectAccess: true,
			description:  "Current block leader should be able to execute leader-only operations",
		},
		{
			name:         "non_leader_validator_denied",
			caller:       hexFromKey(validator2),
			proposer:     validator1,
			expectAccess: false,
			description:  "Non-leader validator should be denied access to leader-only operations",
		},
		{
			name:         "regular_user_denied",
			caller:       regularUser,
			proposer:     validator1,
			expectAccess: false,
			description:  "Regular users should be denied access to leader-only operations",
		},
		{
			name:         "secp256k1_leader_allowed",
			caller:       hexFromKey(validator2),
			proposer:     validator2,
			expectAccess: true,
			description:  "Secp256k1 validators should work as leaders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create execution context with the test scenario
			blockCtx := &common.BlockContext{
				Height:    100,
				Timestamp: 1640995200,
				Proposer:  tt.proposer,
			}

			txCtx := &common.TxContext{
				Ctx:          context.Background(),
				BlockContext: blockCtx,
				Caller:       tt.caller,
				TxID:         "test_tx",
			}

			engineCtx := &common.EngineContext{
				TxContext: txCtx,
			}

			execCtx := &executionContext{
				engineCtx: engineCtx,
				scope:     newScope("test"),
			}

			// Get @caller and @leader variables
			caller, err := execCtx.getVariable("@caller")
			require.NoError(t, err)
			require.IsType(t, (*textValue)(nil), caller)
			callerText := caller.(*textValue).String

			leader, err := execCtx.getVariable("@leader")
			require.NoError(t, err)
			require.IsType(t, (*textValue)(nil), leader)
			leaderText := leader.(*textValue).String

			// Simulate leader-only authorization check (with hex normalization)
			// NOTE: We set TxContext.Caller to the hex-encoded public key here
			// to match @leader's raw pubkey hex. In production, @caller is
			// derived via the Authenticator (e.g. Ethereum 0x… address)
			// and will not equal the raw public key hex string.
			isAuthorized := normalizeHex(callerText) == normalizeHex(leaderText)

			// Verify the authorization result matches expectation
			assert.Equal(t, tt.expectAccess, isAuthorized, tt.description)

			// Log the scenario for clarity
			t.Logf("Scenario: %s", tt.description)
			t.Logf("  Caller: %s", callerText)
			t.Logf("  Leader: %s", leaderText)
			t.Logf("  Access Granted: %v", isAuthorized)
		})
	}
}

// TestLeaderDeterminism ensures @leader is deterministic within block execution
func TestLeaderDeterminism(t *testing.T) {
	t.Parallel()
	proposer := mustCreateEd25519Key(t)

	blockCtx := &common.BlockContext{
		Height:    42,
		Timestamp: 1640995200,
		Proposer:  proposer,
	}

	txCtx := &common.TxContext{
		Ctx:          context.Background(),
		BlockContext: blockCtx,
		Caller:       "test_caller",
		TxID:         "test_tx",
	}

	engineCtx := &common.EngineContext{
		TxContext: txCtx,
	}

	// Create multiple execution contexts with same block context
	execCtx1 := &executionContext{
		engineCtx: engineCtx,
		scope:     newScope("test1"),
	}

	execCtx2 := &executionContext{
		engineCtx: engineCtx,
		scope:     newScope("test2"),
	}

	// Get @leader from both contexts
	leader1, err1 := execCtx1.getVariable("@leader")
	require.NoError(t, err1)

	leader2, err2 := execCtx2.getVariable("@leader")
	require.NoError(t, err2)

	// Should be identical
	require.IsType(t, (*textValue)(nil), leader1)
	require.IsType(t, (*textValue)(nil), leader2)
	leaderText1 := leader1.(*textValue).String
	leaderText2 := leader2.(*textValue).String

	assert.Equal(t, leaderText1, leaderText2, "@leader should be deterministic within same block")

	// Should match the expected hex encoding
	expectedHex := hexFromKey(proposer)
	assert.Equal(t, expectedHex, leaderText1, "@leader should match proposer hex encoding")
}

// Helper function to convert crypto.PublicKey to hex string (matches @leader implementation)
func hexFromKey(key crypto.PublicKey) string {
	if key == nil {
		return ""
	}
	// This matches the actual implementation in context.go
	return hex.EncodeToString(key.Bytes())
}

// Helper function to get identifier from crypto.PublicKey using core auth (matches @leader_id implementation)
func identifierFromKey(t *testing.T, key crypto.PublicKey) string {
	t.Helper()
	if key == nil {
		return ""
	}
	// This matches the actual implementation in context.go
	id, err := coreauth.GetNodeIdentifier(key)
	if err != nil {
		// Return empty string on error (matches implementation behavior)
		return ""
	}
	return id
}

// Helper function to normalize hex strings for comparison (handles 0x prefix and case differences)
func normalizeHex(hexStr string) string {
	// Remove 0x prefix if present and convert to lowercase
	normalized := strings.ToLower(hexStr)
	return strings.TrimPrefix(normalized, "0x")
}
