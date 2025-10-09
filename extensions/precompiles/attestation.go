package precompiles

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
)

const (
	AttestationPrecompileName = "tn_attestation"
)

// AttestationQueue is a thread-safe queue for managing attestation hashes that need signing.
// It is shared between the queue_for_signing() precompile and the leader signing extension.
type AttestationQueue struct {
	mu     sync.RWMutex
	hashes map[string]struct{} // Using map for O(1) deduplication
}

// NewAttestationQueue creates a new attestation queue.
func NewAttestationQueue() *AttestationQueue {
	return &AttestationQueue{
		hashes: make(map[string]struct{}),
	}
}

// Enqueue adds an attestation hash to the queue if it doesn't already exist.
// Returns true if the hash was added, false if it already existed.
func (q *AttestationQueue) Enqueue(hash string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if _, exists := q.hashes[hash]; exists {
		return false
	}

	q.hashes[hash] = struct{}{}
	return true
}

// DequeueAll removes and returns all attestation hashes from the queue.
func (q *AttestationQueue) DequeueAll() []string {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.hashes) == 0 {
		return nil
	}

	hashes := make([]string, 0, len(q.hashes))
	for hash := range q.hashes {
		hashes = append(hashes, hash)
	}

	// Clear the queue
	q.hashes = make(map[string]struct{})

	return hashes
}

// Len returns the current number of hashes in the queue.
func (q *AttestationQueue) Len() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.hashes)
}

// Clear removes all hashes from the queue.
func (q *AttestationQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.hashes = make(map[string]struct{})
}

// Copy creates a deep copy of the queue.
func (q *AttestationQueue) Copy() *AttestationQueue {
	q.mu.RLock()
	defer q.mu.RUnlock()

	newQueue := NewAttestationQueue()
	for hash := range q.hashes {
		newQueue.hashes[hash] = struct{}{}
	}
	return newQueue
}

// attestationQueueSingleton is the global queue shared between precompile and extension.
// This will be accessed by both queue_for_signing() precompile and the leader signing extension.
var attestationQueueSingleton *AttestationQueue
var queueOnce sync.Once

// GetAttestationQueue returns the global attestation queue singleton.
// This function is exported so the leader signing extension can access it.
func GetAttestationQueue() *AttestationQueue {
	queueOnce.Do(func() {
		attestationQueueSingleton = NewAttestationQueue()
	})
	return attestationQueueSingleton
}

// ValidatorSigner wraps the validator's private key for signing attestations.
// This is only used by authorized extensions (not user actions).
type ValidatorSigner struct {
	privateKey *ecdsa.PrivateKey
	mu         sync.RWMutex
}

// NewValidatorSigner creates a new validator signer from a secp256k1 private key.
func NewValidatorSigner(privKey kwilcrypto.PrivateKey) (*ValidatorSigner, error) {
	secp256k1Key, ok := privKey.(*kwilcrypto.Secp256k1PrivateKey)
	if !ok {
		return nil, errors.New("validator key must be secp256k1 for EVM compatibility")
	}

	// Convert to ecdsa.PrivateKey for Ethereum signing
	// Use go-ethereum's crypto to convert from raw bytes
	privKeyBytes := secp256k1Key.Bytes()
	ecdsaKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert secp256k1 key to ECDSA: %w", err)
	}

	return &ValidatorSigner{
		privateKey: ecdsaKey,
	}, nil
}

// SignKeccak256 signs a keccak256 hash of the payload and returns a 65-byte signature.
// This is compatible with Ethereum's ecrecover function.
func (v *ValidatorSigner) SignKeccak256(payload []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.privateKey == nil {
		return nil, errors.New("validator signer not initialized")
	}

	// Compute keccak256 hash
	hash := crypto.Keccak256(payload)

	// Sign the hash (returns 65-byte signature in [R || S || V] format)
	signature, err := crypto.Sign(hash, v.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	return signature, nil
}

// PublicKeyBytes returns the validator's public key bytes (compressed secp256k1).
func (v *ValidatorSigner) PublicKeyBytes() []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.privateKey == nil {
		return nil
	}

	return crypto.CompressPubkey(&v.privateKey.PublicKey)
}

// EthereumAddress returns the Ethereum address derived from the validator's public key.
func (v *ValidatorSigner) EthereumAddress() []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.privateKey == nil {
		return nil
	}

	return crypto.PubkeyToAddress(v.privateKey.PublicKey).Bytes()
}

// validatorSignerSingleton is the global validator signer.
// It must be initialized with SetValidatorSigner before use.
var validatorSignerSingleton *ValidatorSigner
var signerOnce sync.Once
var signerMu sync.RWMutex

// SetValidatorSigner sets the global validator signer.
// This should be called once during node initialization.
// It returns an error if the signer is already set.
func SetValidatorSigner(privKey kwilcrypto.PrivateKey) error {
	signerMu.Lock()
	defer signerMu.Unlock()

	if validatorSignerSingleton != nil {
		return errors.New("validator signer already initialized")
	}

	signer, err := NewValidatorSigner(privKey)
	if err != nil {
		return fmt.Errorf("failed to create validator signer: %w", err)
	}

	validatorSignerSingleton = signer
	return nil
}

// GetValidatorSigner returns the global validator signer.
// Returns nil if not initialized.
func GetValidatorSigner() *ValidatorSigner {
	signerMu.RLock()
	defer signerMu.RUnlock()
	return validatorSignerSingleton
}

// attestationCache implements the precompiles.Cache interface.
// It maintains a snapshot of the queue state for consensus determinism.
type attestationCache struct {
	queue *AttestationQueue
}

// Copy creates a deep copy of the cache.
func (c *attestationCache) Copy() Cache {
	return &attestationCache{
		queue: c.queue.Copy(),
	}
}

// Apply applies a previously created deep copy of the cache.
func (c *attestationCache) Apply(cache Cache) {
	other := cache.(*attestationCache)
	c.queue = other.queue
}

func init() {
	err := RegisterPrecompile(AttestationPrecompileName, Precompile{
		Cache: &attestationCache{
			queue: GetAttestationQueue(),
		},
		Methods: []Method{
			{
				Name: "queue_for_signing",
				Parameters: []PrecompileValue{
					NewPrecompileValue("attestation_hash", types.TextType, false),
				},
				AccessModifiers: []Modifier{SYSTEM},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					attestationHash := inputs[0].(string)

					// Check if the current node is the leader
					// We check by comparing the proposer's public key with our own identity
					isLeader := false
					if ctx.TxContext.BlockContext.Proposer != nil && app.Service.Identity != nil {
						proposerBytes := ctx.TxContext.BlockContext.Proposer.Bytes()
						isLeader = string(proposerBytes) == string(app.Service.Identity)
					}

					// Only queue if we are the leader
					// For non-leaders, this is a no-op to maintain determinism
					if isLeader {
						queue := GetAttestationQueue()
						queue.Enqueue(attestationHash)

						app.Service.Logger.Debug("Queued attestation for signing",
							"hash", attestationHash,
							"queue_size", queue.Len())
					}

					// Always return nil (no return value) for all validators
					// This maintains determinism while only affecting leader's in-memory state
					return nil
				},
			},
			{
				Name: "sign_with_validator_key",
				Parameters: []PrecompileValue{
					NewPrecompileValue("payload", types.ByteaType, false),
				},
				Returns: &MethodReturn{
					Fields: []PrecompileValue{
						NewPrecompileValue("signature", types.ByteaType, false),
					},
				},
				AccessModifiers: []Modifier{SYSTEM},
				Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
					payload := inputs[0].([]byte)

					// Get the validator signer
					signer := GetValidatorSigner()
					if signer == nil {
						return errors.New("validator signer not initialized")
					}

					// Sign the payload with keccak256 hash
					signature, err := signer.SignKeccak256(payload)
					if err != nil {
						return fmt.Errorf("failed to sign payload: %w", err)
					}

					// Verify signature is 65 bytes
					if len(signature) != 65 {
						return fmt.Errorf("invalid signature length: expected 65, got %d", len(signature))
					}

					app.Service.Logger.Debug("Signed attestation payload",
						"payload_size", len(payload),
						"signature_size", len(signature))

					return resultFn([]any{signature})
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
}
