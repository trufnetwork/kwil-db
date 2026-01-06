//go:build kwiltest

package erc20

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

// signMessage is a test helper that signs a message hash using standard Ethereum EIP-191 format.
// This replaces the old signMessage function that was removed during the ValidatorSigner refactoring.
func signMessage(messageHash []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Add Ethereum signed message prefix to match contract expectation
	prefix := []byte(EthereumSignedMessagePrefix)
	ethSignedMessageHash := crypto.Keccak256(append(prefix, messageHash...))

	// Use standard Ethereum signature format (V=27/28) for OpenZeppelin compatibility
	return utils.EthStandardSignDigest(ethSignedMessageHash, privateKey)
}

// testDBPoolAdapter adapts app.DB (transaction) to DelayedReadTxMaker for tests.
// In tests, we're already in a transaction context, so we return a wrapper
// that provides the existing transaction instead of creating new ones.
type testDBPoolAdapter struct {
	db sql.DB
}

func (t *testDBPoolAdapter) BeginDelayedReadTx() sql.OuterReadTx {
	// In tests, return a wrapper around the existing transaction
	return &testReadTxWrapper{db: t.db}
}

// testReadTxWrapper wraps app.DB to implement OuterReadTx for tests
type testReadTxWrapper struct {
	db sql.DB
}

func (t *testReadTxWrapper) Execute(ctx context.Context, query string, args ...interface{}) (*sql.ResultSet, error) {
	return t.db.Execute(ctx, query, args...)
}

func (t *testReadTxWrapper) BeginTx(ctx context.Context) (sql.Tx, error) {
	return t.db.BeginTx(ctx)
}

func (t *testReadTxWrapper) Rollback(ctx context.Context) error {
	// No-op for test wrapper since we don't want to rollback the main test transaction
	return nil
}

func (t *testReadTxWrapper) Commit(ctx context.Context) error {
	// No-op for test wrapper since we don't want to commit the main test transaction
	return nil
}

func (t *testReadTxWrapper) Subscribe(ctx context.Context) (<-chan string, func(context.Context) error, error) {
	// For tests, return a no-op subscription since ValidatorSigner doesn't use it
	ch := make(chan string)
	close(ch) // Close immediately as we don't send any notices in tests
	done := func(context.Context) error { return nil }
	return ch, done, nil
}

// NewValidatorSigner is a test helper that creates a ValidatorSigner for testing.
// This provides backward compatibility for existing tests.
func NewValidatorSigner(app *common.App, instanceID *types.UUID, privateKey *ecdsa.PrivateKey) *ValidatorSigner {
	// Convert ECDSA key to Ethereum address
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	// For tests, we bypass the ValidatorSigner interface and use the private key directly
	// This is acceptable in tests but would be a security issue in production
	logger := app.Service.Logger
	logger.Infof("[TEST] Creating validator signer for instance %s", instanceID)

	// Use the Service's DBPool if available, otherwise adapt app.DB for tests
	var dbPool sql.DelayedReadTxMaker
	if app.Service != nil && app.Service.DBPool != nil {
		dbPool = app.Service.DBPool
	} else {
		// In tests, adapt app.DB to provide a DelayedReadTxMaker interface
		dbPool = &testDBPoolAdapter{db: app.DB}
	}

	return &ValidatorSigner{
		app:        app,
		dbPool:     dbPool,
		instanceID: instanceID,
		// For tests, create a mock ValidatorSigner that uses the private key directly
		validatorSigner: &testValidatorSignerImpl{privateKey: privateKey},
		address:         address,
		logger:          logger,
		votedEpochs:     make(map[string]bool),
	}
}

// testValidatorSignerImpl is a mock implementation of common.ValidatorSigner for testing.
// It directly uses an ECDSA private key without the security restrictions of the production implementation.
type testValidatorSignerImpl struct {
	privateKey *ecdsa.PrivateKey
}

func (t *testValidatorSignerImpl) Sign(ctx context.Context, messageHash []byte, purpose string) ([]byte, error) {
	// For tests, we don't validate purpose - sign anything
	// Use standard Ethereum signatures (V=27/28) for OpenZeppelin compatibility
	return utils.EthStandardSignDigest(messageHash, t.privateKey)
}

func (t *testValidatorSignerImpl) EthereumAddress() ([]byte, error) {
	address := crypto.PubkeyToAddress(t.privateKey.PublicKey)
	return address.Bytes(), nil
}

func (t *testValidatorSignerImpl) CreateSecp256k1Signer() (auth.Signer, error) {
	// Convert ECDSA key to Kwil Secp256k1 key
	privKeyBytes := crypto.FromECDSA(t.privateKey)
	kwilPrivKey, err := kwilcrypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %w", err)
	}
	return &auth.EthPersonalSigner{Key: *kwilPrivKey}, nil
}

func (t *testValidatorSignerImpl) Identity() []byte {
	return crypto.FromECDSAPub(&t.privateKey.PublicKey)
}
