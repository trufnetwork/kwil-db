// package ethdeposits implements an listener that listens to Ethereum events
// and triggers the creation of deposit events in Kwil.
//
// DEPRECATED: This eth_deposits listener system is deprecated.
// It has been superseded by the modern ERC20 bridge extension which provides
// better token-specific features, proper balance tracking, epochs, and merkle proof generation.
// New deployments should use the ERC20 bridge extension instead.
// For more information, see: https://github.com/trufnetwork/kwil-db/issues/1600
package ethdeposits

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/extensions/listeners"
	"github.com/trufnetwork/kwil-db/extensions/resolutions/credit"
)

const ListenerName = "eth_deposits"

// use golang's init function, which runs before main, to register the extension
// see more here: https://www.digitalocean.com/community/tutorials/understanding-init-in-go
func init() {
	// register the listener with the name "eth_deposit"
	err := listeners.RegisterListener(ListenerName, Start)
	if err != nil {
		panic(err)
	}
}

// Start starts the eth_deposit listener, which triggers the creation of deposit events in Kwil.
// It can be configured to listen to a certain smart contract address. It will listen for the EVM event signature
// "Credit(address,uint256)" and create a deposit event in Kwil when it sees a matching event. It uses the
// "credit_account" resolution, defined in extensions/resolutions/credit/credit.go, to create the deposit event.
// It will search for a local extension configuration named "eth_deposit".
//
// DEPRECATED: This function and the eth_deposits listener are deprecated.
// Use the ERC20 bridge extension instead for new integrations.
func Start(ctx context.Context, service *common.Service, eventStore listeners.EventStore) error {
	config := &EthDepositConfig{}
	listenerConfig, ok := service.LocalConfig.Extensions[ListenerName]
	if !ok {
		service.Logger.Warn("no eth_deposit configuration found, eth_deposit oracle will not start")
		return nil // no configuration, so we don't start the oracle
	}
	err := config.setConfig(listenerConfig)
	if err != nil {
		return fmt.Errorf("failed to set eth_deposit configuration: %w", err)
	}

	// we need to catch up with the ethereum chain.
	// we will get the last seen height from the kv store
	// we will either start from the last seen height, or from the configured starting height,
	// whichever is greater
	lastHeight, err := getLastStoredHeight(ctx, eventStore)
	if err != nil {
		return fmt.Errorf("failed to get last stored height: %w", err)
	}

	if config.StartingHeight > lastHeight {
		lastHeight = config.StartingHeight
	}

	client, err := newEthClient(ctx, config.RPCProvider, config.MaxRetries,
		ethcommon.HexToAddress(config.ContractAddress), service.Logger)
	if err != nil {
		return fmt.Errorf("failed to create ethereum client: %w", err)
	}
	defer client.Close()

	// get the current block height from the Ethereum client
	currentHeight, err := client.GetLatestBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current block height: %w", err)
	}
	service.Logger.Infof("ETH best block: %v", currentHeight)

	if lastHeight > currentHeight-config.RequiredConfirmations {
		return fmt.Errorf("starting height is greater than the last confirmed eth block height")
	}

	// we will now sync all logs from the starting height to the current height,
	// in chunks of config.BlockSyncChunkSize
	for {
		if lastHeight >= currentHeight-config.RequiredConfirmations {
			break
		}

		// get the next block chunk. if it is greater than the current height - required confirmations,
		// we will set it to the current height - required confirmations
		toBlock := lastHeight + config.BlockSyncChunkSize
		if toBlock > currentHeight-config.RequiredConfirmations {
			toBlock = currentHeight - config.RequiredConfirmations
		}

		err = processEvents(ctx, lastHeight, toBlock, client, eventStore, service.Logger)
		if err != nil {
			return fmt.Errorf("failed to process events: %w", err)
		}

		lastHeight = toBlock
	}

	// ListenToBlocks will listen to new blocks and process the events.
	// It only returns when the context is cancelled, or when the client cannot recover
	// from an error after the max retries.
	outerErr := client.ListenToBlocks(ctx, time.Duration(config.ReconnectionInterval)*time.Second, func(newHeight int64) error {
		newHeight = newHeight - config.RequiredConfirmations // account for required confirmations

		// it is possible to receive the same height twice
		if newHeight <= lastHeight {
			service.Logger.Info("received duplicate block height", "height", newHeight)
			return nil
		}

		service.Logger.Info("received new block height", "height", newHeight)

		// lastheight + 1 because we have already processed the last height
		err = processEvents(ctx, lastHeight+1, newHeight, client, eventStore, service.Logger)
		if err != nil {
			return fmt.Errorf("failed to process events: %w", err)
		}

		lastHeight = newHeight

		return nil
	})
	if outerErr != nil {
		return fmt.Errorf("ListenToBlocks failure: %w", outerErr)
	}

	return nil
}

// processEvents will process all events from the Ethereum client from the given
// height range. This means inserting any that have not already been processed
// for broadcast in a Kwil vote ID / approval transaction, and then storing the
// processed height.
func processEvents(ctx context.Context, from, to int64, client *ethClient, eventStore listeners.EventStore, logger log.Logger) error {
	logs, err := client.GetCreditEventLogs(ctx, from, to)
	if err != nil {
		return fmt.Errorf("failed to get credit event logs: %w", err)
	}

	for _, log := range logs {
		event, err := decodeCreditEvent(&log)
		if err != nil {
			return fmt.Errorf("failed to decode credit event: %w", err)
		}

		bts, err := event.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}

		logger.Info("Flagging new account credit event for approval (to broadcast)",
			"account", event.Account, "amount", event.Amount, "txHash", hex.EncodeToString(event.TxHash))
		err = eventStore.Broadcast(ctx, credit.CreditAccountEventType, bts)
		if err != nil {
			return fmt.Errorf("failed to mark new event for broadcast: %w", err)
		}
	}

	logger.Info("processed events", "from", from, "to", to, "events", len(logs))

	return setLastStoredHeight(ctx, eventStore, to)
}

// EthDepositConfig is the configuration for the eth_deposit listener.
// It can be read in from a map[string]string, which is passed from
// the node's local configuration.
type EthDepositConfig struct {
	// StartingHeight is the Ethereum block height it will start listening from.
	// Any events emitted before this height will be ignored.
	// If not configured, it will start from block 0.
	StartingHeight int64
	// ContractAddress is the Ethereum address of the smart contract it will listen to.
	// It is a required configuration.
	ContractAddress string
	// RequiredConfirmations is the number of Ethereum blocks that must be mined before
	// the listener will create a deposit event in Kwil. This is to protect against Ethereum
	// network reorgs / soft forks. If not configured, it will default to 12.
	// https://www.alchemy.com/overviews/what-is-a-reorg
	RequiredConfirmations int64
	// RPCProvider is the URL of the Ethereum RPC endpoint it will connect to.
	// This would likely be an Infura / Alchemy endpoint.
	// It is a required configuration.
	RPCProvider string
	// ReconnectionInterval is the amount of time in seconds that the listener
	// will wait before resubscribing for new Ethereum Blocks. Reconnects are
	// automatically handled, but a subscription may stall, in which case we
	// will make a new subscription. If the write or read on the connection to
	// the RPC provider errors, the RPC client will reconnect, and we will
	// continue to reestablish a new block subscription. If not configured, it
	// will default to 60s.
	ReconnectionInterval int64
	// MaxRetries is the total number of times the listener will attempt an RPC
	// with the provider before giving up. It will exponentially back off after
	// each try, starting at 1 second and doubling each time. If not configured,
	// it will default to 10.
	MaxRetries int64
	// BlockSyncChunkSize is the number of Ethereum blocks the listener will request from the
	// Ethereum RPC endpoint at a time while catching up to the network. If not configured,
	// it will default to 1,000,000.
	BlockSyncChunkSize int64
}

// setConfig sets the configuration for the eth_deposit listener.
// If it doesn't find a required configuration, or if it finds an invalid
// configuration, it returns an error
func (e *EthDepositConfig) setConfig(m map[string]string) error {
	startingHeight, ok := m["starting_height"]
	if !ok {
		startingHeight = "0"
	}

	var err error
	e.StartingHeight, err = strconv.ParseInt(startingHeight, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid starting_height: %s", startingHeight)
	}
	if e.StartingHeight < 0 {
		return fmt.Errorf("starting_height cannot be negative")
	}

	contractAddress, ok := m["contract_address"]
	if !ok {
		return fmt.Errorf("no contract_address provided")
	}
	e.ContractAddress = contractAddress

	requiredConfirmations, ok := m["required_confirmations"]
	if !ok {
		requiredConfirmations = "12"
	}
	e.RequiredConfirmations, err = strconv.ParseInt(requiredConfirmations, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid required_confirmations: %s", requiredConfirmations)
	}
	if e.RequiredConfirmations < 0 {
		return fmt.Errorf("required_confirmations cannot be negative")
	}

	rpc, ok := m["rpc_provider"]
	if !ok {
		return fmt.Errorf("no rpc_provider provided")
	}
	if !strings.HasPrefix(rpc, "ws") {
		return fmt.Errorf("rpc_provider must be a websocket URL")
	}
	e.RPCProvider = rpc

	reconnectionInterval, ok := m["reconnection_interval"]
	if !ok {
		reconnectionInterval = "60"
	}
	intervalInt, err := strconv.ParseInt(reconnectionInterval, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid reconnection_interval: %s", reconnectionInterval)
	}
	if intervalInt < 5 {
		return fmt.Errorf("reconnection_interval must be greater than or equal to 5")
	}
	e.ReconnectionInterval = intervalInt

	maxRetries, ok := m["max_retries"]
	if !ok {
		maxRetries = "10"
	}
	e.MaxRetries, err = strconv.ParseInt(maxRetries, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid max_retries: %s", maxRetries)
	}
	if e.MaxRetries < 0 {
		return fmt.Errorf("max_retries cannot be negative")
	}

	blockSyncChunkSize, ok := m["block_sync_chunk_size"]
	if !ok {
		blockSyncChunkSize = "1000000" // check this on goerli, it's big
	}
	e.BlockSyncChunkSize, err = strconv.ParseInt(blockSyncChunkSize, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid block_sync_chunk_size: %s", blockSyncChunkSize)
	}
	if e.BlockSyncChunkSize <= 0 {
		return fmt.Errorf("block_sync_chunk_size must be greater than 0")
	}

	return nil
}

// Map returns the configuration as a map[string]string.
// This is used for testing
func (e *EthDepositConfig) Map() map[string]string {
	return map[string]string{
		"starting_height":        strconv.FormatInt(e.StartingHeight, 10),
		"contract_address":       e.ContractAddress,
		"required_confirmations": strconv.FormatInt(e.RequiredConfirmations, 10),
		"rpc_provider":           e.RPCProvider,
		"reconnection_interval":  strconv.FormatInt(e.ReconnectionInterval, 10),
		"max_retries":            strconv.FormatInt(e.MaxRetries, 10),
		"block_sync_chunk_size":  strconv.FormatInt(e.BlockSyncChunkSize, 10),
	}
}

var (
	// lastHeightKey is the key used to store the last height processed by the listener
	lastHeightKey = []byte("lh")
)

// getLastStoredHeight gets the last height stored by the KV store
func getLastStoredHeight(ctx context.Context, eventStore listeners.EventStore) (int64, error) {
	// get the last confirmed block height processed by the listener
	lastHeight, err := eventStore.Get(ctx, lastHeightKey)
	if err != nil {
		return 0, fmt.Errorf("failed to get last block height: %w", err)
	}

	if len(lastHeight) == 0 {
		return 0, nil
	}

	return int64(binary.LittleEndian.Uint64(lastHeight)), nil
}

// setLastStoredHeight sets the last height stored by the KV store
func setLastStoredHeight(ctx context.Context, eventStore listeners.EventStore, height int64) error {
	heightBts := make([]byte, 8)
	binary.LittleEndian.PutUint64(heightBts, uint64(height))

	// set the last confirmed block height processed by the listener
	err := eventStore.Set(ctx, lastHeightKey, heightBts)
	if err != nil {
		return fmt.Errorf("failed to set last block height: %w", err)
	}
	return nil
}
