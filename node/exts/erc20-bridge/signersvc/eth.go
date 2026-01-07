package signersvc

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/samber/lo"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/abigen"
)

var (
	safeABI = lo.Must(abi.JSON(strings.NewReader(abigen.SafeMetaData.ABI)))

	nonceCallData     = lo.Must(safeABI.Pack("nonce"))        // nonce()
	thresholdCallData = lo.Must(safeABI.Pack("getThreshold")) // getThreshold()
	ownersCallData    = lo.Must(safeABI.Pack("getOwners"))    // getOwners()
)

type safeMetadata struct {
	threshold *big.Int
	owners    []common.Address
	nonce     *big.Int
}

type Safe struct {
	chainID *big.Int
	addr    common.Address

	safe    *abigen.Safe
	safeABI *abi.ABI
	eth     *ethclient.Client
}

// NewSafeFromEscrow attempts to initialize a Safe from an escrow contract.
// Returns nil Safe for non-custodial bridges (e.g., TrufNetworkBridge) that don't use GnosisSafe.
// Returns populated Safe for custodial bridges (e.g., RewardDistributor) that use GnosisSafe.
func NewSafeFromEscrow(rpc string, escrowAddr string) (*Safe, error) {
	client, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, fmt.Errorf("create eth client: %w", err)
	}

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("get chain ID: %w", err)
	}

	// Try to detect if this is a custodial bridge with Safe (RewardDistributor)
	// or a non-custodial bridge without Safe (TrufNetworkBridge)
	rd, err := abigen.NewRewardDistributor(common.HexToAddress(escrowAddr), client)
	if err != nil {
		return nil, fmt.Errorf("bind to escrow contract: %w", err)
	}

	// Try to get Safe address - this will fail for non-custodial bridges
	safeAddr, err := rd.Safe(nil)
	if err != nil {
		// Non-custodial bridge (e.g., TrufNetworkBridge) - no Safe needed
		// Return nil Safe to indicate direct signing should be used
		return nil, nil
	}

	// Custodial bridge (e.g., RewardDistributor) - initialize Safe
	safe, err := abigen.NewSafe(safeAddr, client)
	if err != nil {
		return nil, fmt.Errorf("create safe: %w", err)
	}

	return &Safe{
		chainID: chainID,
		addr:    safeAddr,
		safe:    safe,
		safeABI: &safeABI,
		eth:     client,
	}, nil
}

func NewSafe(rpc string, addr string) (*Safe, error) {
	client, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, fmt.Errorf("create eth cliet: %w", err)
	}

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("create eth chainID: %w", err)
	}

	safe, err := abigen.NewSafe(common.HexToAddress(addr), client)
	if err != nil {
		return nil, fmt.Errorf("create safe: %w", err)
	}

	return &Safe{
		chainID: chainID,
		addr:    common.HexToAddress(addr),
		safe:    safe,
		safeABI: &safeABI,
		eth:     client,
	}, nil
}

// height retrieves current block height.
func (s *Safe) height(ctx context.Context) (uint64, error) {
	return s.eth.BlockNumber(ctx)
}

// nonce retrieves the nonce of the Safe contract at a specified block number.
func (s *Safe) nonce(ctx context.Context, blockNumber *big.Int) (*big.Int, error) {
	callOpts := &bind.CallOpts{
		Pending:     false,
		BlockNumber: blockNumber,
		Context:     ctx,
	}
	return s.safe.Nonce(callOpts)
}

// threshold retrieves the threshold value of the Safe contract at a specified block number.
func (s *Safe) threshold(ctx context.Context, blockNumber *big.Int) (*big.Int, error) {
	callOpts := &bind.CallOpts{
		Pending:     false,
		BlockNumber: blockNumber,
		Context:     ctx,
	}
	return s.safe.GetThreshold(callOpts)
}

// owners retrieves the list of owner addresses of the Safe contract at a specified block number.
func (s *Safe) owners(ctx context.Context, blockNumber *big.Int) ([]common.Address, error) {
	callOpts := &bind.CallOpts{
		Pending:     false,
		BlockNumber: blockNumber,
		Context:     ctx,
	}
	return s.safe.GetOwners(callOpts)
}

func (s *Safe) latestMetadata(ctx context.Context) (*safeMetadata, error) {
	height, err := s.height(ctx)
	if err != nil {
		return nil, err
	}

	return s.metadata(ctx, new(big.Int).SetUint64(height))
}

func (s *Safe) metadata(ctx context.Context, blockNumber *big.Int) (*safeMetadata, error) {
	if IsMulticall3Deployed(s.chainID.String(), blockNumber) {
		return s.getSafeMetadata3(ctx, blockNumber)
	}

	return s.getSafeMetadataSeq(ctx, blockNumber)
}

// getSafeMetadataSeq retrieves safe wallet metadata in sequence
func (s *Safe) getSafeMetadataSeq(ctx context.Context, blockNumber *big.Int) (*safeMetadata, error) {
	nonce, err := s.nonce(ctx, blockNumber)
	if err != nil {
		return nil, err
	}

	threshold, err := s.threshold(ctx, blockNumber)
	if err != nil {
		return nil, err
	}

	owners, err := s.owners(ctx, blockNumber)
	if err != nil {
		return nil, err
	}

	return &safeMetadata{
		threshold: threshold,
		owners:    owners,
		nonce:     nonce,
	}, nil
}

// getSafeMetadata3 retrieves safe wallet metadata in one go, using multicall3
func (s *Safe) getSafeMetadata3(ctx context.Context, blockNumber *big.Int) (*safeMetadata, error) {
	res, err := Aggregate3(ctx, s.chainID.String(), []abigen.Multicall3Call3{
		{
			Target:       s.addr,
			AllowFailure: false,
			CallData:     nonceCallData,
		},
		{
			Target:       s.addr,
			AllowFailure: false,
			CallData:     thresholdCallData,
		},
		{
			Target:       s.addr,
			AllowFailure: false,
			CallData:     ownersCallData,
		},
	}, blockNumber, s.eth)
	if err != nil {
		return nil, err
	}

	nonce, err := safeABI.Unpack("nonce", res[0].ReturnData)
	if err != nil {
		return nil, err
	}

	threshold, err := safeABI.Unpack("getThreshold", res[1].ReturnData)
	if err != nil {
		return nil, err
	}

	owners, err := safeABI.Unpack("getOwners", res[2].ReturnData)
	if err != nil {
		return nil, err
	}

	return &safeMetadata{
		nonce:     nonce[0].(*big.Int),
		threshold: threshold[0].(*big.Int),
		owners:    owners[0].([]common.Address),
	}, nil
}
