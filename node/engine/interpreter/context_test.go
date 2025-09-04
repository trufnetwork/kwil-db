package interpreter

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto"
	coreauth "github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
	extauth "github.com/trufnetwork/kwil-db/extensions/auth"
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
			normalizeHex := func(hexStr string) string {
				normalized := strings.ToLower(hexStr)
				return strings.TrimPrefix(normalized, "0x")
			}
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

// ProductionAlignedBlockContextFactory creates block contexts that match production scenarios
// This factory helps create more realistic test scenarios that align with production node behavior
type ProductionAlignedBlockContextFactory struct {
	// Track validator set for leader rotation scenarios
	validators []crypto.PublicKey
	// Current leader index for rotation
	currentLeaderIdx int
	// Base timestamp for realistic block timing
	baseTimestamp time.Time
	// Current block height
	currentHeight int64
}

// NewProductionAlignedBlockContextFactory creates a new factory with realistic defaults
func NewProductionAlignedBlockContextFactory() *ProductionAlignedBlockContextFactory {
	// Create a realistic validator set with mixed key types
	validators := []crypto.PublicKey{
		mustCreateSecp256k1Key(&testing.T{}), // Primary validator (secp256k1)
		mustCreateEd25519Key(&testing.T{}),   // Secondary validator (ed25519)
		mustCreateSecp256k1Key(&testing.T{}), // Third validator (secp256k1)
	}

	return &ProductionAlignedBlockContextFactory{
		validators:       validators,
		currentLeaderIdx: 0,
		baseTimestamp:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		currentHeight:    1,
	}
}

// CreateBlockContext creates a block context that simulates production scenarios
func (f *ProductionAlignedBlockContextFactory) CreateBlockContext(scenario string, customProposer crypto.PublicKey) *common.BlockContext {
	var proposer crypto.PublicKey
	var height int64
	var timestamp int64

	switch scenario {
	case "normal_block":
		// Normal block with current leader
		proposer = f.validators[f.currentLeaderIdx]
		height = f.currentHeight
		timestamp = f.baseTimestamp.Add(time.Duration(f.currentHeight) * time.Second).Unix()

	case "leader_rotation":
		// Simulate leader rotation to next validator
		f.currentLeaderIdx = (f.currentLeaderIdx + 1) % len(f.validators)
		proposer = f.validators[f.currentLeaderIdx]
		height = f.currentHeight
		timestamp = f.baseTimestamp.Add(time.Duration(f.currentHeight) * time.Second).Unix()

	case "genesis_block":
		// Genesis block scenario
		proposer = f.validators[0]
		height = 1
		timestamp = f.baseTimestamp.Unix()

	case "custom_proposer":
		// Use custom proposer for specific test scenarios
		if customProposer != nil {
			proposer = customProposer
		} else {
			proposer = f.validators[0]
		}
		height = f.currentHeight
		timestamp = f.baseTimestamp.Add(time.Duration(f.currentHeight) * time.Second).Unix()

	case "nil_proposer":
		// Edge case: nil proposer (should not happen in production but test robustness)
		proposer = nil
		height = f.currentHeight
		timestamp = f.baseTimestamp.Add(time.Duration(f.currentHeight) * time.Second).Unix()

	default:
		// Default to normal block
		proposer = f.validators[f.currentLeaderIdx]
		height = f.currentHeight
		timestamp = f.baseTimestamp.Add(time.Duration(f.currentHeight) * time.Second).Unix()
	}

	// Increment height for next call
	f.currentHeight++

	return &common.BlockContext{
		Height:    height,
		Timestamp: timestamp,
		Proposer:  proposer,
		ChainContext: &common.ChainContext{
			ChainID: "test-chain",
			NetworkParameters: &types.NetworkParameters{
				MaxBlockSize: 1024 * 1024, // 1MB
			},
		},
	}
}

// CreateTxContext creates a transaction context with realistic production-aligned data
func (f *ProductionAlignedBlockContextFactory) CreateTxContext(blockCtx *common.BlockContext, authenticator string, signerBytes []byte) *common.TxContext {
	caller := ""
	if signerBytes != nil {
		if ident, err := extauth.GetIdentifier(authenticator, signerBytes); err == nil {
			caller = ident
		}
	}

	txID := "test_tx_nil"
	if len(signerBytes) > 0 {
		txID = "test_tx_" + hex.EncodeToString(signerBytes)[:8]
	}

	return &common.TxContext{
		Ctx:           context.Background(),
		BlockContext:  blockCtx,
		Signer:        signerBytes,
		Caller:        caller,
		TxID:          txID,
		Authenticator: authenticator,
	}
}

// CreateExecutionContext creates a full execution context for testing
func (f *ProductionAlignedBlockContextFactory) CreateExecutionContext(blockCtx *common.BlockContext, txCtx *common.TxContext) *executionContext {
	engineCtx := &common.EngineContext{
		TxContext: txCtx,
	}

	return &executionContext{
		engineCtx: engineCtx,
		scope:     newScope("test_namespace"),
	}
}

// TestLeaderSenderContextualVariable tests the @leader_sender variable
func TestLeaderSenderContextualVariable(t *testing.T) {
	t.Parallel()

	// Test cases for different auth types and proposer scenarios
	tests := []struct {
		name           string
		proposer       crypto.PublicKey
		authenticator  string
		invalidTxCtx   bool
		expectedSender interface{} // nil for NULL, or expected bytes
	}{
		{
			name:           "secp256k1 proposer with eth personal auth",
			proposer:       mustCreateSecp256k1Key(t),
			authenticator:  coreauth.EthPersonalSignAuth,
			invalidTxCtx:   false,
			expectedSender: []byte{}, // Not NULL - contains Ethereum address bytes
		},
		{
			name:           "secp256k1 proposer with secp256k1 auth",
			proposer:       mustCreateSecp256k1Key(t),
			authenticator:  coreauth.Secp256k1Auth,
			invalidTxCtx:   false,
			expectedSender: []byte{}, // Not NULL - contains compressed pubkey bytes
		},
		{
			name:           "ed25519 proposer with ed25519 auth",
			proposer:       mustCreateEd25519Key(t),
			authenticator:  coreauth.Ed25519Auth,
			invalidTxCtx:   false,
			expectedSender: []byte{}, // Not NULL - contains pubkey bytes
		},
		{
			name:           "ed25519 proposer with eth personal auth (mismatch)",
			proposer:       mustCreateEd25519Key(t),
			authenticator:  coreauth.EthPersonalSignAuth,
			invalidTxCtx:   false,
			expectedSender: nil, // Should be NULL due to mismatch
		},
		{
			name:           "nil proposer",
			proposer:       nil,
			authenticator:  coreauth.EthPersonalSignAuth,
			invalidTxCtx:   false,
			expectedSender: nil, // Should be NULL
		},
		{
			name:           "invalid transaction context",
			proposer:       mustCreateSecp256k1Key(t),
			authenticator:  coreauth.EthPersonalSignAuth,
			invalidTxCtx:   true,
			expectedSender: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test transaction context
			blockCtx := &common.BlockContext{
				Height:    100,
				Timestamp: 1640995200,
				Proposer:  tt.proposer,
			}

			// Create a signer for this test - we'll use the proposer as the signer
			// to test the case where they match (leader scenario)
			var signerBytes []byte
			var caller string
			if tt.proposer != nil {
				// For matching cases, create signer bytes that will match leader_sender
				// For mismatch cases, create valid signer bytes that won't match NULL leader_sender
				if getSignerBytesForAuth(tt.proposer, tt.authenticator) != nil {
					// Auth type is compatible with proposer key - use the auth format
					signerBytes = getSignerBytesForAuth(tt.proposer, tt.authenticator)
				} else {
					// Auth type is incompatible - use the key's native format
					signerBytes = getSignerBytesForKeyType(tt.proposer)
				}
				// Get caller string representation using the transaction's auth type
				if ident, err := extauth.GetIdentifier(tt.authenticator, signerBytes); err == nil {
					caller = ident
				}
			}

			txCtx := &common.TxContext{
				Ctx:           context.Background(),
				BlockContext:  blockCtx,
				Signer:        signerBytes,
				Caller:        caller,
				TxID:          "test_tx",
				Authenticator: tt.authenticator,
			}

			engineCtx := &common.EngineContext{
				TxContext: txCtx,
			}

			if tt.invalidTxCtx {
				engineCtx.InvalidTxCtx = true
			}

			execCtx := &executionContext{
				engineCtx: engineCtx,
				scope:     newScope("test"),
			}

			// Test @leader_sender variable
			leaderSenderResult, err := execCtx.getVariable("@leader_sender")
			if tt.invalidTxCtx {
				require.Error(t, err)
				assert.Equal(t, engine.ErrInvalidTxCtx, err)
				return
			}
			require.NoError(t, err)
			require.IsType(t, (*blobValue)(nil), leaderSenderResult)
			leaderSenderBlob := leaderSenderResult.(*blobValue)

			// Validate results
			if tt.expectedSender == nil {
				// Should be NULL when proposer is nil or auth type mismatch
				assert.True(t, leaderSenderBlob.Null(), "@leader_sender should be NULL")
			} else {
				assert.False(t, leaderSenderBlob.Null(), "@leader_sender should not be NULL")
				// In our test setup, leader_sender should equal signer for valid cases
				if tt.proposer != nil {
					expectedBytes := getSignerBytesForAuth(tt.proposer, tt.authenticator)
					if expectedBytes != nil {
						assert.Equal(t, expectedBytes, leaderSenderBlob.bts,
							"@leader_sender should match expected signer bytes")
					}
				}
			}

			// Direct sender comparison for is-leader expectation with explicit expected/computed match
			expectedBytes := getSignerBytesForAuth(tt.proposer, tt.authenticator)
			expectedIsLeader := expectedBytes != nil && txCtx.Signer != nil && bytes.Equal(expectedBytes, txCtx.Signer)
			computedIsLeader := !leaderSenderBlob.Null() && txCtx.Signer != nil && bytes.Equal(leaderSenderBlob.bts, txCtx.Signer)
			assert.Equal(t, expectedIsLeader, computedIsLeader, "computed is-leader should match expected signer vs leader_sender equality")

			t.Logf("Test: %s", tt.name)
			t.Logf("  Authenticator: %s", tt.authenticator)
			t.Logf("  Leader Sender NULL: %v", leaderSenderBlob.Null())
		})
	}
}

// getSignerBytesForKeyType returns signer bytes in the format based on the key type
func getSignerBytesForKeyType(key crypto.PublicKey) []byte {
	if key == nil {
		return nil
	}
	switch key.Type() {
	case crypto.KeyTypeSecp256k1:
		// For secp256k1 keys, always return the Ethereum address format
		// (this is what the EthPersonalSigner does)
		if pk, ok := key.(*crypto.Secp256k1PublicKey); ok {
			return crypto.EthereumAddressFromPubKey(pk)
		}
	case crypto.KeyTypeEd25519:
		// For Ed25519 keys, return the public key bytes
		if pk, ok := key.(*crypto.Ed25519PublicKey); ok {
			return pk.Bytes()
		}
	}
	return nil
}

// getSignerBytesForAuth returns signer bytes in the format expected by the given auth type
func getSignerBytesForAuth(key crypto.PublicKey, authType string) []byte {
	if key == nil {
		return nil
	}
	switch authType {
	case coreauth.EthPersonalSignAuth:
		if pk, ok := key.(*crypto.Secp256k1PublicKey); ok {
			return crypto.EthereumAddressFromPubKey(pk)
		}
	case coreauth.Secp256k1Auth:
		if pk, ok := key.(*crypto.Secp256k1PublicKey); ok {
			return pk.Bytes()
		}
	case coreauth.Ed25519Auth:
		if pk, ok := key.(*crypto.Ed25519PublicKey); ok {
			return pk.Bytes()
		}
	}
	return nil
}

// TestProductionAlignedLeaderSenderScenarios tests @leader_sender in scenarios that match production
// This test is designed to catch mismatches that might not be caught by simpler unit tests
func TestProductionAlignedLeaderSenderScenarios(t *testing.T) {
	t.Parallel()

	factory := NewProductionAlignedBlockContextFactory()

	tests := []struct {
		name                     string
		scenario                 string
		authenticator            string
		expectedLeaderSenderNull bool
		description              string
	}{
		{
			name:                     "normal_block_secp256k1_auth",
			scenario:                 "normal_block",
			authenticator:            coreauth.Secp256k1Auth,
			expectedLeaderSenderNull: false,
			description:              "Normal block with secp256k1 proposer and matching auth",
		},
		{
			name:                     "leader_rotation_ed25519_auth",
			scenario:                 "leader_rotation",
			authenticator:            coreauth.Ed25519Auth,
			expectedLeaderSenderNull: true,
			description:              "Leader rotation to next validator with Ed25519 auth",
		},
		{
			name:                     "genesis_block_eth_personal_auth",
			scenario:                 "genesis_block",
			authenticator:            coreauth.EthPersonalSignAuth,
			expectedLeaderSenderNull: false,
			description:              "Genesis block with secp256k1 proposer and eth personal auth",
		},
		{
			name:                     "normal_block_ed25519_mismatch",
			scenario:                 "normal_block",
			authenticator:            coreauth.Ed25519Auth,
			expectedLeaderSenderNull: true,
			description:              "Normal block with secp256k1 proposer but Ed25519 auth (mismatch)",
		},
		{
			name:                     "leader_rotation_secp256k1_auth",
			scenario:                 "leader_rotation",
			authenticator:            coreauth.Secp256k1Auth,
			expectedLeaderSenderNull: true,
			description:              "Leader rotation to next validator with secp256k1 auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create production-aligned block context
			blockCtx := factory.CreateBlockContext(tt.scenario, nil)

			// Create signer bytes based on the block proposer and auth type
			var signerBytes []byte
			if blockCtx.Proposer != nil {
				signerBytes = getSignerBytesForAuth(blockCtx.Proposer, tt.authenticator)
			}

			// Create transaction context
			txCtx := factory.CreateTxContext(blockCtx, tt.authenticator, signerBytes)

			// Create execution context
			execCtx := factory.CreateExecutionContext(blockCtx, txCtx)

			// Test @leader_sender variable
			leaderSenderResult, err := execCtx.getVariable("@leader_sender")
			require.NoError(t, err)
			require.IsType(t, (*blobValue)(nil), leaderSenderResult)

			leaderSenderBlob := leaderSenderResult.(*blobValue)

			// Verify expectation matches actual result
			if tt.expectedLeaderSenderNull {
				assert.True(t, leaderSenderBlob.Null(),
					"@leader_sender should be NULL for %s", tt.description)
			} else {
				assert.False(t, leaderSenderBlob.Null(),
					"@leader_sender should NOT be NULL for %s", tt.description)

				// For non-null cases, verify leader_sender equals signer (when they match)
				if signerBytes != nil && !leaderSenderBlob.Null() {
					assert.Equal(t, signerBytes, leaderSenderBlob.bts,
						"@leader_sender should equal signer for %s", tt.description)
				}
			}

			// Log debug information for troubleshooting
			t.Logf("Scenario: %s", tt.description)
			t.Logf("  Block Height: %d", blockCtx.Height)
			t.Logf("  Proposer: %T (%p)", blockCtx.Proposer, blockCtx.Proposer)
			t.Logf("  Authenticator: %s", tt.authenticator)
			t.Logf("  Leader Sender NULL: %v", leaderSenderBlob.Null())
			if !leaderSenderBlob.Null() {
				t.Logf("  Leader Sender: %x", leaderSenderBlob.bts)
			}
			if signerBytes != nil {
				t.Logf("  Signer: %x", signerBytes)
			}
		})
	}
}

// TestProductionAlignedLeaderElectionScenarios tests leader election scenarios
// This test simulates production leader changes and verifies contextual variables behave correctly
func TestProductionAlignedLeaderElectionScenarios(t *testing.T) {
	t.Parallel()

	factory := NewProductionAlignedBlockContextFactory()

	// Simulate a sequence of blocks with leader changes
	scenarios := []struct {
		blockNum      int
		scenario      string
		authenticator string
		description   string
	}{
		{1, "genesis_block", coreauth.EthPersonalSignAuth, "Genesis block with validator 0"},
		{2, "normal_block", coreauth.Secp256k1Auth, "Normal block with validator 0"},
		{3, "leader_rotation", coreauth.Ed25519Auth, "Leader rotation to validator 1"},
		{4, "normal_block", coreauth.Ed25519Auth, "Normal block with validator 1"},
		{5, "leader_rotation", coreauth.EthPersonalSignAuth, "Leader rotation to validator 2"},
		{6, "normal_block", coreauth.Secp256k1Auth, "Normal block with validator 2"},
	}

	var previousProposer crypto.PublicKey

	for _, scenario := range scenarios {
		t.Run(fmt.Sprintf("block_%d_%s", scenario.blockNum, scenario.scenario), func(t *testing.T) {
			// Create production-aligned block context
			blockCtx := factory.CreateBlockContext(scenario.scenario, nil)

			// Verify height progression
			assert.Equal(t, int64(scenario.blockNum), blockCtx.Height,
				"Block height should match scenario block number")

			// Create signer bytes based on the block proposer
			var signerBytes []byte
			if blockCtx.Proposer != nil {
				signerBytes = getSignerBytesForAuth(blockCtx.Proposer, scenario.authenticator)
			}

			// Create transaction context
			txCtx := factory.CreateTxContext(blockCtx, scenario.authenticator, signerBytes)

			// Create execution context
			execCtx := factory.CreateExecutionContext(blockCtx, txCtx)

			// Test @leader variable
			leaderResult, err := execCtx.getVariable("@leader")
			require.NoError(t, err)
			require.IsType(t, (*textValue)(nil), leaderResult)
			leaderText := leaderResult.(*textValue).String

			// Verify @leader matches proposer
			if blockCtx.Proposer != nil {
				expectedLeaderHex := hexFromKey(blockCtx.Proposer)
				assert.Equal(t, expectedLeaderHex, leaderText,
					"@leader should match proposer hex encoding")
			} else {
				assert.Equal(t, "", leaderText, "@leader should be empty for nil proposer")
			}

			// Test @leader_sender variable
			leaderSenderResult, err := execCtx.getVariable("@leader_sender")
			require.NoError(t, err)
			require.IsType(t, (*blobValue)(nil), leaderSenderResult)
			leaderSenderBlob := leaderSenderResult.(*blobValue)

			// For leader election scenarios, leader_sender should be non-null when auth matches proposer type
			expectedNull := signerBytes == nil
			if expectedNull {
				assert.True(t, leaderSenderBlob.Null(),
					"@leader_sender should be NULL when signer bytes are nil")
			} else {
				assert.False(t, leaderSenderBlob.Null(),
					"@leader_sender should NOT be NULL when signer bytes exist")
				assert.Equal(t, signerBytes, leaderSenderBlob.bts,
					"@leader_sender should equal signer bytes")
			}

			// Verify leader change detection
			if previousProposer != nil && blockCtx.Proposer != nil {
				leaderChanged := !bytes.Equal(previousProposer.Bytes(), blockCtx.Proposer.Bytes())
				if leaderChanged {
					t.Logf("Leader change detected at block %d", scenario.blockNum)
					t.Logf("  Previous: %x", previousProposer.Bytes())
					t.Logf("  Current:  %x", blockCtx.Proposer.Bytes())
				}
			}

			// Update previous proposer for next iteration
			previousProposer = blockCtx.Proposer

			// Log scenario details for debugging
			t.Logf("Block %d: %s", scenario.blockNum, scenario.description)
			t.Logf("  Height: %d", blockCtx.Height)
			t.Logf("  Timestamp: %d", blockCtx.Timestamp)
			t.Logf("  Leader: %s", leaderText)
			t.Logf("  Leader Sender NULL: %v", leaderSenderBlob.Null())
		})
	}
}
