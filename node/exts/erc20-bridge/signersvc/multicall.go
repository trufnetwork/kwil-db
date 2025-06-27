package signersvc

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/abigen"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
)

// Multicall https://github.com/mds1/multicall
// https://etherscan.io/address/0xcA11bde05977b3631167028862bE2a173976CA11

var (
	AddressMulticall3 = common.HexToAddress("0xcA11bde05977b3631167028862bE2a173976CA11")

	chainEthereum, _    = chains.GetChainInfo(chains.Ethereum)
	chainSepolia, _     = chains.GetChainInfo(chains.Sepolia)
	chainBaseSepolia, _ = chains.GetChainInfo(chains.BaseSepolia)
)

// Find multicall3 deployments on different networks: https://www.multicall3.com/deployments
var deployedAtMap = map[string]uint64{
	chainEthereum.ID:    14353601, // https://etherscan.io/tx/0x00d9fcb7848f6f6b0aae4fb709c133d69262b902156c85a473ef23faa60760bd
	chainSepolia.ID:     751532,   // https://sepolia.etherscan.io/tx/0x6313b2cee1ddd9a77a8a1edf93495a9eb3c51a4d85479f4f8fec0090ad82596b
	chainBaseSepolia.ID: 1059647,  // https://base-sepolia.blockscout.com/tx/0x07471adfe8f4ec553c1199f495be97fc8be8e0626ae307281c22534460184ed1
}

func IsMulticall3Deployed(chainID string, blockNumber *big.Int) bool {
	deployedAt, exists := deployedAtMap[chainID]
	if !exists {
		return false
	}

	if blockNumber == nil {
		return true
	}

	return deployedAt < blockNumber.Uint64()
}

// Aggregate3 aggregates multicall result.
// based on https://github.com/RSS3-Network/Node/blob/947b387f11857144c48250dd95804b5069731153/provider/ethereum/contract/multicall3/contract.go
func Aggregate3(ctx context.Context, chainID string, calls []abigen.Multicall3Call3,
	blockNumber *big.Int, contractBackend bind.ContractCaller) ([]*abigen.Multicall3Result, error) {
	if !IsMulticall3Deployed(chainID, blockNumber) {
		return nil, fmt.Errorf("multicall3 is not deployed on chainID %s yet", chainID)
	}

	abi, err := abigen.Multicall3MetaData.GetAbi()
	if err != nil {
		return nil, fmt.Errorf("load abi: %w", err)
	}

	callData, err := abi.Pack("aggregate3", calls)
	if err != nil {
		return nil, fmt.Errorf("pack data: %w", err)
	}

	message := ethereum.CallMsg{
		To:   &AddressMulticall3,
		Data: callData,
	}

	results := make([]abigen.Multicall3Result, 0, len(calls))

	data, err := contractBackend.CallContract(ctx, message, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("call contract: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("data in empty")
	}

	if err := abi.UnpackIntoInterface(&results, "aggregate3", data); err != nil {
		return nil, fmt.Errorf("unpack result: %w", err)
	}

	return ToSlicePtr(results), nil
}

func ToSlicePtr[T any](collection []T) []*T {
	result := make([]*T, len(collection))

	for i := range collection {
		result[i] = &collection[i]
	}
	return result
}
