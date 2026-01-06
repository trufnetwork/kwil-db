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

// signMessage is a test helper that signs a message hash using Gnosis Safe EIP-191 format.
// This replaces the old signMessage function that was removed during the ValidatorSigner refactoring.
func signMessage(messageHash []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Use the same Gnosis Safe signature format as the production code
	return utils.EthGnosisSignDigest(messageHash, privateKey)
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

	// Use the Service's DBPool if available
	var dbPool sql.DelayedReadTxMaker
	if app.Service != nil && app.Service.DBPool != nil {
		dbPool = app.Service.DBPool
	} else {
		// In tests without a Service, dbPool will be nil - tests should set it up properly
		dbPool = nil
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
	return utils.EthGnosisSignDigest(messageHash, t.privateKey)
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
