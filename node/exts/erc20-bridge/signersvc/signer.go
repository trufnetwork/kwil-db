// Package signersvc implements the SignerSvc of the Kwil reward system.
// It simply fetches the new Epoch from Kwil network and verify&sign it, then
// upload the signature back to the Kwil network. Each bridgeSigner targets one registered
// erc20 Reward instance.
package signersvc

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	ethCommon "github.com/ethereum/go-ethereum/common"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
)

// StateFilePath returns the state file.
func StateFilePath(dir string) string {
	return filepath.Join(dir, "erc20_bridge_vote.json")
}

// bridgeSigner handles the voting on one registered erc20 reward instance.
type bridgeSigner struct {
	target     string
	escrowAddr ethCommon.Address

	kwil       bridgeSignerClient
	txSigner   auth.Signer
	signerPk   *ecdsa.PrivateKey
	signerAddr ethCommon.Address
	safe       *Safe

	logger log.Logger
	state  *State
}

func newBridgeSigner(kwil bridgeSignerClient, safe *Safe, target string, txSigner auth.Signer,
	signerPk *ecdsa.PrivateKey, signerAddr ethCommon.Address, escrowAddr ethCommon.Address,
	state *State, logger log.Logger) (*bridgeSigner, error) {
	if logger == nil {
		logger = log.DiscardLogger
	}

	return &bridgeSigner{
		kwil:       kwil,
		txSigner:   txSigner,
		signerPk:   signerPk,
		signerAddr: signerAddr,
		state:      state,
		logger:     logger,
		target:     target,
		safe:       safe,
		escrowAddr: escrowAddr,
	}, nil
}

// canSkip returns true if:
// - For Safe-based bridges: signer is not one of the safe owners OR already voted with current nonce
// - For non-custodial bridges: already voted this epoch
func (s *bridgeSigner) canSkip(epoch *Epoch, safeMeta *safeMetadata) bool {
	// For Safe-based bridges, check Safe ownership
	if safeMeta != nil {
		if !slices.Contains(safeMeta.owners, s.signerAddr) {
			s.logger.Info("skip voting epoch: signer is not safe owner", "id", epoch.ID.String(),
				"signer", s.signerAddr.String(), "owners", safeMeta.owners)
			return true
		}
	}

	if epoch.Voters == nil {
		return false
	}

	// Check if already voted
	for i, voter := range epoch.Voters {
		if voter == s.signerAddr.String() {
			// For Safe-based: check nonce match
			// For non-custodial: any vote means skip (nonce is always 0)
			if safeMeta == nil || safeMeta.nonce.Cmp(big.NewInt(epoch.VoteNonces[i])) == 0 {
				s.logger.Info("skip voting epoch: already voted", "id", epoch.ID.String(),
					"nonce", epoch.VoteNonces[i], "hasSafe", safeMeta != nil)
				return true
			}
		}
	}

	return false
}

// verify verifies if the reward root is correct, and return the total amount.
func (s *bridgeSigner) verify(ctx context.Context, epoch *Epoch, escrowAddr string) (*big.Int, error) {
	rewards, err := s.kwil.GetEpochRewards(ctx, s.target, epoch.ID)
	if err != nil {
		return nil, err
	}

	recipients := make([]string, len(rewards))
	amounts := make([]*big.Int, len(rewards))

	var ok bool
	total := big.NewInt(0)
	for i, r := range rewards {
		recipients[i] = r.Recipient

		amounts[i], ok = new(big.Int).SetString(r.Amount, 10)
		if !ok {
			return nil, fmt.Errorf("parse reward amount %s failed", r.Amount)
		}

		total = total.Add(total, amounts[i])
	}

	var b32 [32]byte
	copy(b32[:], epoch.EndBlockHash)

	_, root, err := utils.GenRewardMerkleTree(recipients, amounts, escrowAddr, b32)
	if err != nil {
		return nil, err
	}

	if !slices.Equal(root, epoch.RewardRoot) {
		return nil, fmt.Errorf("reward root mismatch: %s != %s", hex.EncodeToString(root), hex.EncodeToString(epoch.RewardRoot))
	}

	s.logger.Info("verified epoch", "id", epoch.ID.String(), "rewardRoot", hex.EncodeToString(epoch.RewardRoot))
	return total, nil
}

// vote votes an epoch reward, and updates the state.
// For Safe-based bridges: generates GnosisSafe transaction and signs it
// For non-custodial bridges: signs merkle root + block hash directly
func (s *bridgeSigner) vote(ctx context.Context, epoch *Epoch, safeMeta *safeMetadata, total *big.Int) error {
	var sig []byte
	var nonce int64
	var err error

	if s.safe != nil {
		// Safe-based bridge (custodial) - use GnosisSafe transaction signing
		if safeMeta == nil {
			return fmt.Errorf("safe metadata required for custodial bridge")
		}

		safeTxData, err := utils.GenPostRewardTxData(epoch.RewardRoot, total)
		if err != nil {
			return err
		}

		// safeTxHash is the data that all signers will be signing(using personal_sign)
		_, safeTxHash, err := utils.GenGnosisSafeTx(s.escrowAddr.String(), s.safe.addr.String(),
			0, safeTxData, s.safe.chainID.Int64(), safeMeta.nonce.Int64())
		if err != nil {
			return err
		}

		sig, err = utils.EthGnosisSign(safeTxHash, s.signerPk)
		if err != nil {
			return err
		}

		nonce = safeMeta.nonce.Int64()
		s.logger.Info("signed epoch with Safe", "id", epoch.ID.String(), "nonce", nonce)
	} else {
		// Non-custodial bridge - sign merkle root + block hash directly
		//
		// This matches TrufNetworkBridge.withdraw() signature verification AND
		// the Kwil vote_epoch action verification (both expect the same format).
		//
		// Process (matching validator_signer.go:308-319 and meta_extension.go computeEpochMessageHash):
		// 1. ABI encode: packed = abi.encode(merkleRoot, blockHash)  [64 bytes]
		// 2. Hash: messageHash = keccak256(packed)  [32 bytes]
		// 3. Add prefix: "\x19Ethereum Signed Message:\n32" + messageHash
		// 4. Hash again: ethSignedMessageHash = keccak256(prefix + messageHash)
		// 5. Sign: ECDSA signature of ethSignedMessageHash
		//
		// NOTE: For bytes32 types, abi.encode() is just concatenation, but we MUST
		// hash it before signing to match the expected format.

		// Step 1: ABI encode (simple concatenation for bytes32 types)
		message := make([]byte, 64)
		copy(message[0:32], epoch.RewardRoot)
		copy(message[32:64], epoch.EndBlockHash)

		// Step 2: Hash the encoded message (CRITICAL: this was missing!)
		messageHash := ethCrypto.Keccak256(message)

		// Steps 3-5: EthZeppelinSign adds "\x19Ethereum Signed Message:\n32" prefix,
		// hashes again, and signs (this matches OpenZeppelin's ECDSA.toEthSignedMessageHash)
		sig, err = utils.EthZeppelinSign(messageHash, s.signerPk)
		if err != nil {
			return err
		}

		nonce = 0 // Non-custodial bridges don't use nonce
		s.logger.Info("signed epoch directly (non-custodial)", "id", epoch.ID.String(),
			"root", hex.EncodeToString(epoch.RewardRoot),
			"blockHash", hex.EncodeToString(epoch.EndBlockHash))
	}

	h, err := s.kwil.VoteEpoch(ctx, s.target, s.txSigner, epoch.ID, nonce, sig)
	if err != nil {
		return err
	}

	// NOTE: it's fine if s.kwil.VoteEpoch succeed, but s.state.UpdateLastVote failed,
	// as the epoch will be fetched again and skipped
	err = s.state.UpdateLastVote(s.target, &voteRecord{
		Epoch:      epoch.ID.String(),
		RewardRoot: epoch.RewardRoot,
		TxHash:     h.String(),
		SafeNonce:  uint64(nonce),
	})
	if err != nil {
		return err
	}

	s.logger.Info("vote epoch", "tx", h, "id", epoch.ID.String(), "nonce", nonce)

	return nil
}

// sync polls on newer epochs and try to vote/sign them.
// Since there could be the case that the target(namespace/or id) not exist for whatever reason,
// this function won't return Error, and also won't log at Error level.
func (s *bridgeSigner) sync(ctx context.Context) {
	s.logger.Debug("polling epochs")

	epochs, err := s.kwil.GetActiveEpochs(ctx, s.target)
	if err != nil {
		s.logger.Warn("fetch epoch", "error", err.Error())
		return
	}

	if len(epochs) == 0 {
		s.logger.Error("no epoch found")
		return
	}

	if len(epochs) == 1 {
		// Two reasons there is only one active epoches
		// 1. the very first epoch is just created
		// 2. the previous epoch is confirmed, but currently there are no rewards/issuances in the current epoch
		// In either case, we wait until there are 2 active epoches; and the 1st one(finalized) is ready to be voted.
		return
	}

	if len(epochs) != 2 {
		s.logger.Error("unexpected number of epochs", "count", len(epochs))
		return
	}

	finalizedEpoch := epochs[0]

	// Fetch Safe metadata only if this is a Safe-based bridge
	var safeMeta *safeMetadata
	if s.safe != nil {
		safeMeta, err = s.safe.latestMetadata(ctx)
		if err != nil {
			s.logger.Warn("fetch safe metadata", "error", err.Error())
			return
		}
	}

	if s.canSkip(finalizedEpoch, safeMeta) {
		return
	}

	total, err := s.verify(ctx, finalizedEpoch, s.escrowAddr.String())
	if err != nil {
		s.logger.Warn("verify epoch", "id", finalizedEpoch.ID.String(), "height", finalizedEpoch.EndHeight, "error", err.Error())
		return
	}

	err = s.vote(ctx, finalizedEpoch, safeMeta, total)
	if err != nil {
		s.logger.Warn("vote epoch", "id", finalizedEpoch.ID.String(), "height", finalizedEpoch.EndHeight, "error", err.Error())
		return
	}
}

// getSigners verifies config and returns a list of signerSvc.
func getSigners(cfg config.ERC20BridgeConfig, kwil bridgeSignerClient, state *State, rootDir string, logger log.Logger) ([]*bridgeSigner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ctx := context.Background()

	signers := make([]*bridgeSigner, 0, len(cfg.Signer))
	for target, pkPath := range cfg.Signer {
		// Auto-detect validator key if not configured or "validator" keyword is used
		// This is the default behavior - most validators sign with their validator key
		if pkPath == "" || pkPath == "validator" {
			pkPath = filepath.Join(rootDir, "nodekey.json")
			logger.Info("using validator key for bridge signer", "target", target, "path", pkPath)
		}

		// parse signer private key
		rawPkBytes, err := os.ReadFile(pkPath)
		if err != nil {
			return nil, fmt.Errorf("read private key file %s failed: %w", pkPath, err)
		}

		pkStr := strings.TrimSpace(string(rawPkBytes))

		// Try parsing as JSON first (nodekey.json format: {"key":"...", "type":"secp256k1"})
		var pkBytes []byte
		if strings.HasPrefix(pkStr, "{") {
			var nodeKey struct {
				Key  string `json:"key"`
				Type string `json:"type"`
			}
			if err := json.Unmarshal([]byte(pkStr), &nodeKey); err == nil && nodeKey.Key != "" {
				// Successfully parsed JSON - use the key field
				pkBytes, err = hex.DecodeString(nodeKey.Key)
				if err != nil {
					return nil, fmt.Errorf("parse erc20 bridge signer private key from JSON failed: %w", err)
				}
				logger.Debug("loaded private key from JSON format", "target", target, "type", nodeKey.Type)
			} else {
				return nil, fmt.Errorf("parse erc20 bridge signer private key JSON failed: %w", err)
			}
		} else {
			// Not JSON - treat as raw hex
			pkBytes, err = hex.DecodeString(pkStr)
			if err != nil {
				return nil, fmt.Errorf("parse erc20 bridge signer private key failed: %w", err)
			}
			logger.Debug("loaded private key from raw hex format", "target", target)
		}

		signerPk, err := ethCrypto.ToECDSA(pkBytes)
		if err != nil {
			return nil, fmt.Errorf("parse erc20 bridge signer private key failed: %w", err)
		}

		signerPubKey := signerPk.Public().(*ecdsa.PublicKey)
		signerAddr := ethCrypto.PubkeyToAddress(*signerPubKey)

		// derive tx signer
		key, err := crypto.UnmarshalSecp256k1PrivateKey(pkBytes)
		if err != nil {
			return nil, fmt.Errorf("parse erc20 bridge signer private key failed: %w", err)
		}

		txSigner := &auth.EthPersonalSigner{Key: *key}

		// use instance info to create safe
		instanceInfo, err := kwil.InstanceInfo(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("get reward metadata failed: %w", err)
		}

		logger.Debug("initializing bridge signer", "target", target, "chain", instanceInfo.Chain, "escrow", instanceInfo.Escrow)

		chainRpc, ok := cfg.RPC[strings.ToLower(instanceInfo.Chain)]
		if !ok {
			return nil, fmt.Errorf("target '%s' chain '%s' not found in erc20_bridge.rpc config", target, instanceInfo.Chain)
		}

		safe, err := NewSafeFromEscrow(chainRpc, instanceInfo.Escrow)
		if err != nil {
			// Check if this is a non-custodial bridge (expected for TrufNetworkBridge)
			if errors.Is(err, ErrNonCustodialBridge) {
				logger.Info("non-custodial bridge detected (direct signing)", "target", target, "chain", instanceInfo.Chain, "escrow", instanceInfo.Escrow)
				safe = nil
			} else {
				// Real error (network failure, invalid config, etc.)
				logger.Debug("safe initialization failed", "target", target, "chain", instanceInfo.Chain, "error", err.Error())
				return nil, fmt.Errorf("create safe failed: %w", err)
			}
		}

		// Validate chainID if Safe is present (custodial bridge)
		if safe != nil {
			logger.Info("custodial bridge detected (Safe-based)", "target", target, "chain", instanceInfo.Chain, "safe_addr", safe.addr.String())

			chainInfo, ok := chains.GetChainInfo(chains.Chain(instanceInfo.Chain))
			if !ok {
				return nil, fmt.Errorf("chain '%s' not found in supported chains (detected chainID: %s)", instanceInfo.Chain, safe.chainID.String())
			}

			if safe.chainID.String() != chainInfo.ID {
				return nil, fmt.Errorf("chainID mismatch: configured %s != target %s", safe.chainID.String(), chainInfo.ID)
			}
		}

		// wilRpc, target, chainRpc, strings.TrimSpace(string(pkBytes))
		svc, err := newBridgeSigner(kwil, safe, target, txSigner, signerPk, signerAddr, ethCommon.HexToAddress(instanceInfo.Escrow), state, logger.New("EVMRW."+target))
		if err != nil {
			return nil, fmt.Errorf("create erc20 bridge signer service failed: %w", err)
		}

		signers = append(signers, svc)
	}

	return signers, nil
}

// ServiceMgr manages multiple bridgeSigner instances running in parallel.
type ServiceMgr struct {
	kwil         bridgeSignerClient // will be shared among all signers
	state        *State
	bridgeCfg    config.ERC20BridgeConfig
	syncInterval time.Duration
	logger       log.Logger
	rootDir      string // node's root directory for auto-detecting validator key
}

func NewServiceMgr(
	chainID string,
	db DB,
	call engineCall,
	bcast txBcast,
	nodeApp nodeApp,
	cfg config.ERC20BridgeConfig,
	state *State,
	rootDir string,
	logger log.Logger) *ServiceMgr {
	return &ServiceMgr{
		kwil:         NewSignerClient(chainID, db, call, bcast, nodeApp),
		rootDir:      rootDir,
		state:        state,
		bridgeCfg:    cfg,
		logger:       logger,
		syncInterval: time.Minute, // default to 1m
	}
}

// Start runs all rewardSigners. It returns error if there are issues initializing the bridgeSigner;
// no errors are returned after the bridgeSigner is running.
func (m *ServiceMgr) Start(ctx context.Context) error {
	// since we need to wait on RPC running, we move the initialization logic into `init`

	var err error
	var signers []*bridgeSigner
	retryCount := 0
	// To be able to run with docker, we need to apply a retry logic, because kwild
	// won't have erc20 instance when boot
	for { // naive way to keep retrying the init, on any error
		select {
		case <-ctx.Done():
			m.logger.Info("stop initializing erc20 bridge signer")
			return nil
		default:
		}

		signers, err = getSigners(m.bridgeCfg, m.kwil, m.state, m.rootDir, m.logger)
		if err == nil {
			break
		}

		retryCount++
		// Log at debug level initially - initialization may fail during startup when bridge instances
		// are not yet registered, or when Safe metadata is temporarily unavailable.
		// Escalate to warning level after several retries to help identify persistent issues.
		// The implementation supports both Safe-based (custodial) and non-custodial bridges.
		if retryCount <= 5 {
			m.logger.Debug("failed to initialize erc20 bridge signer, will retry", "error", err.Error(), "configured_targets", len(m.bridgeCfg.Signer), "retry", retryCount)
		} else {
			m.logger.Warn("failed to initialize erc20 bridge signer after multiple retries", "error", err.Error(), "configured_targets", len(m.bridgeCfg.Signer), "retry", retryCount)
		}
		select {
		case <-time.After(time.Second * 30):
		case <-ctx.Done():
		}
	}

	wg := &sync.WaitGroup{}

	for _, s := range signers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			s.logger.Info("start watching erc20 bridge epoches")
			tick := time.NewTicker(m.syncInterval)

			for {
				s.sync(ctx)

				select {
				case <-ctx.Done():
					s.logger.Info("stop watching erc20 bridge epoches")
					return
				case <-tick.C:
				}
			}
		}()
	}

	<-ctx.Done()
	wg.Wait()

	m.logger.Infof("Erc20 bridge signer service shutting down...")

	return nil
}
