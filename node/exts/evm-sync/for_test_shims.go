//go:build kwiltest

package evmsync

import (
	"context"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	kwilTesting "github.com/trufnetwork/kwil-db/testing"
)

// ForTestingMakeTransferLog builds a synthetic ERC20 Transfer log compatible with the parser.
func ForTestingMakeTransferLog(from, to ethcommon.Address, value [32]byte, blockNumber uint64, txIndex uint, logIndex uint, erc20Address ethcommon.Address, blockHash ethcommon.Hash, txHash ethcommon.Hash) *EthLog {
	topics := []ethcommon.Hash{
		// keccak256("Transfer(address,address,uint256)")
		ethcommon.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
		ethcommon.BytesToHash(from.Bytes()),
		ethcommon.BytesToHash(to.Bytes()),
	}

	log := &ethtypes.Log{
		Address:     erc20Address,
		Topics:      topics,
		Data:        value[:],
		BlockNumber: blockNumber,
		TxHash:      txHash,
		TxIndex:     txIndex,
		BlockHash:   blockHash,
		Index:       logIndex,
		Removed:     false,
	}

	return &EthLog{Metadata: []byte("e20trsnfr"), Log: log}
}

// ForTestingClearAllInstances performs a comprehensive cleanup of ALL EVM sync runtime components.
// This focuses on cleaning up the things that persist beyond transaction rollback:
// 1. Unregister all state pollers and transfer listeners
//
// Database cleanup is handled automatically by transaction rollback.
// This function is idempotent and safe to call multiple times.
// Use this when you want to clean up runtime state between tests.
func ForTestingClearAllInstances(ctx context.Context, platform *kwilTesting.Platform) error {
	// for each poller, unregister it
	for _, poller := range StatePoller.pollers {
		err := StatePoller.UnregisterPoll(poller.UniqueName)
		if err != nil {
			return fmt.Errorf("failed to unregister poller %s: %w", poller.UniqueName, err)
		}
	}
	// for each listener, unregister it
	for _, listener := range EventSyncer.listeners {
		err := EventSyncer.UnregisterListener(listener.uniqueName)
		if err != nil {
			return fmt.Errorf("failed to unregister listener %s: %w", listener.uniqueName, err)
		}
	}

	return nil
}
