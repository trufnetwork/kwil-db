// Package signersvc implements the SignerSvc of the Kwil reward system.
// It simply fetches the new Epoch from Kwil network and verify&sign it, then
// upload the signature back to the Kwil network. Each bridgeSigner targets one registered
// erc20 Reward instance.
package signersvc

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
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
// - signer is not one of the safe owners
// - signer has voted this epoch with the same nonce as current safe nonce
func (s *bridgeSigner) canSkip(epoch *Epoch, safeMeta *safeMetadata) bool {
	if !slices.Contains(safeMeta.owners, s.signerAddr) {
		s.logger.Info("skip voting epoch: signer is not safe owner", "id", epoch.ID.String(),
			"signer", s.signerAddr.String(), "owners", safeMeta.owners)
		return true
	}

	if epoch.Voters == nil {
		return false
	}

	for i, voter := range epoch.Voters {
		if voter == s.signerAddr.String() &&
			safeMeta.nonce.Cmp(big.NewInt(epoch.VoteNonces[i])) == 0 {
			s.logger.Info("skip voting epoch: already voted", "id", epoch.ID.String(), "nonce", safeMeta.nonce)
			return true
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
// It will first fetch metadata from ETH, then generate the safeTx, then vote.
func (s *bridgeSigner) vote(ctx context.Context, epoch *Epoch, safeMeta *safeMetadata, total *big.Int) error {
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

	sig, err := utils.EthGnosisSign(safeTxHash, s.signerPk)
	if err != nil {
		return err
	}

	h, err := s.kwil.VoteEpoch(ctx, s.target, s.txSigner, epoch.ID, safeMeta.nonce.Int64(), sig)
	if err != nil {
		return err
	}

	// NOTE: it's fine if s.kwil.VoteEpoch succeed, but s.state.UpdateLastVote failed,
	// as the epoch will be fetched again and skipped
	err = s.state.UpdateLastVote(s.target, &voteRecord{
		Epoch:      epoch.ID.String(),
		RewardRoot: epoch.RewardRoot,
		TxHash:     h.String(),
		SafeNonce:  safeMeta.nonce.Uint64(),
	})
	if err != nil {
		return err
	}

	s.logger.Info("vote epoch", "tx", h, "id", epoch.ID.String(),
		"nonce", safeMeta.nonce.Int64())

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

	safeMeta, err := s.safe.latestMetadata(ctx)
	if err != nil {
		s.logger.Warn("fetch safe metadata", "error", err.Error())
		return
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
func getSigners(cfg config.ERC20BridgeConfig, kwil bridgeSignerClient, state *State, logger log.Logger) ([]*bridgeSigner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ctx := context.Background()

	signers := make([]*bridgeSigner, 0, len(cfg.Signer))
	for target, pkPath := range cfg.Signer {
		// pkPath is validated already

		// parse signer private key
		rawPkBytes, err := os.ReadFile(pkPath)
		if err != nil {
			return nil, fmt.Errorf("read private key file %s failed: %w", pkPath, err)
		}

		pkStr := strings.TrimSpace(string(rawPkBytes))
		pkBytes, err := hex.DecodeString(pkStr)
		if err != nil {
			return nil, fmt.Errorf("parse erc20 bridge signer private key failed: %w", err)
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

		chainRpc, ok := cfg.RPC[strings.ToLower(instanceInfo.Chain)]
		if !ok {
			return nil, fmt.Errorf("target '%s' chain '%s' not found in erc20_bridge.rpc config", target, instanceInfo.Chain)
		}

		safe, err := NewSafeFromEscrow(chainRpc, instanceInfo.Escrow)
		if err != nil {
			return nil, fmt.Errorf("create safe failed: %w", err)
		}

		chainInfo, ok := chains.GetChainInfo(chains.Chain(instanceInfo.Chain))
		if !ok {
			return nil, fmt.Errorf("chainID %s not supported", safe.chainID.String())
		}

		if safe.chainID.String() != chainInfo.ID {
			return nil, fmt.Errorf("chainID mismatch: configured %s != target %s", safe.chainID.String(), chainInfo.ID)
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
}

func NewServiceMgr(
	chainID string,
	db DB,
	call engineCall,
	bcast txBcast,
	nodeApp nodeApp,
	cfg config.ERC20BridgeConfig,
	state *State,
	logger log.Logger) *ServiceMgr {
	return &ServiceMgr{
		kwil:         NewSignerClient(chainID, db, call, bcast, nodeApp),
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
	// To be able to run with docker, we need to apply a retry logic, because kwild
	// won't have erc20 instance when boot
	for { // naive way to keep retrying the init, on any error
		select {
		case <-ctx.Done():
			m.logger.Info("stop initializing erc20 bridge signer")
			return nil
		default:
		}

		signers, err = getSigners(m.bridgeCfg, m.kwil, m.state, m.logger)
		if err == nil {
			break
		}

		m.logger.Warn("failed to initialize erc20 bridge signer, will retry", "error", err.Error())
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
