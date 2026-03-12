package evmsync

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/extensions/listeners"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

func init() {
	err := listeners.RegisterListener("evm_sync", func(ctx context.Context, service *common.Service, eventstore listeners.EventStore) error {
		syncConf, err := getSyncConfig(service.LocalConfig.Extensions)
		if err != nil {
			return fmt.Errorf("failed to get sync config: %w", err)
		}

		return EventSyncer.listen(ctx, service, eventstore, syncConf)
	})
	if err != nil {
		panic(err)
	}
}

func getSyncConfig(m map[string]map[string]string) (*syncConfig, error) {
	syncConf, ok := m["sync"]
	if !ok {
		// if not found, all syncConfig variables will be set to default
		syncConf = make(map[string]string)
	}

	conf := &syncConfig{}
	err := conf.load(syncConf)
	if err != nil {
		return nil, err
	}

	return conf, nil
}

// syncConfig is a config that is shared by all listeners.
type syncConfig struct {
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
}

func (c *syncConfig) load(m map[string]string) error {
	if v, ok := m["reconnection_interval"]; ok {
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return err
		}

		if i <= 0 {
			return errors.New("reconnection_interval must be greater than 0")
		}

		c.ReconnectionInterval = i
	} else {
		c.ReconnectionInterval = 60
	}

	if v, ok := m["max_retries"]; ok {
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return err
		}

		if i <= 0 {
			return errors.New("max_retries must be greater than 0")
		}

		c.MaxRetries = i
	} else {
		c.MaxRetries = 10
	}

	return nil
}

// getChainConf gets the chain config from the node's local configuration.
func getChainConf(cfg config.ERC20BridgeConfig, chain chains.Chain) (*chainConfig, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}

	err = chain.Valid()
	if err != nil {
		return nil, err
	}

	provider, ok := cfg.RPC[chain.String()]
	if !ok {
		return nil, fmt.Errorf("local configuration does not have an '%s' config", chain.String())
	}

	syncChunk, ok := cfg.BlockSyncChuckSize[chains.Ethereum.String()]
	if !ok {
		syncChunk = "1000000"
	}

	blockSyncChunkSize, err := strconv.ParseInt(syncChunk, 10, 64)
	if err != nil {
		return nil, err
	}

	if blockSyncChunkSize <= 0 {
		return nil, errors.New("block_sync_chunk_size must be greater than 0")
	}

	conf := &chainConfig{
		BlockSyncChunkSize: blockSyncChunkSize,
		Provider:           provider,
	}

	return conf, nil
}

// chainConfig is a config that is specific to a single chain.
type chainConfig struct {
	// BlockSyncChunkSize is the number of Ethereum blocks the listener will request from the
	// Ethereum RPC endpoint at a time while catching up to the network. If not configured,
	// it will default to 1,000,000.
	BlockSyncChunkSize int64
	// Provider is the URL of the RPC endpoint for the chain.
	// It is required.
	Provider string
}

// individualListener is a singler configured client that is responsible for listening to a single set of contracts.
// Many individual listeners can exist for a single chain.
type individualListener struct {
	chain chains.ChainInfo
	// syncConf is the configuration for the listener.
	syncConf *syncConfig
	// chainConf is the configuration for the chain.
	chainConf *chainConfig
	// client is the Ethereum client that is used to listen to the chain.
	client *ethClient
	// orderedSyncTopic is the ordered sync topic that the listener is posting to.
	orderedSyncTopic string
	// getLogsFunc gets logs for a given range of blocks.
	getLogsFunc GetBlockLogsFunc
}

// GetBlockLogsFunc is a function that provides an ethereum client and a range of blocks and returns the logs for that range.
type GetBlockLogsFunc func(ctx context.Context, client *ethclient.Client, startBlock, endBlock uint64, logger log.Logger) ([]*EthLog, error)

// listen listens for new blocks from the Ethereum chain and broadcasts them to the network.
func (i *individualListener) listen(ctx context.Context, eventstore listeners.EventStore, logger log.Logger) error {
	startBlock, err := getLastSeenHeight(ctx, eventstore, i.orderedSyncTopic)
	if err != nil {
		return fmt.Errorf("failed to get last seen height: %w", err)
	}

	currentBlock, err := i.client.GetLatestBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}

	if currentBlock < startBlock {
		return fmt.Errorf("starting height is greater than the last confirmed eth block height")
	}

	lastConfirmedBlock := currentBlock - i.chain.RequiredConfirmations
	logger.Infof(fmt.Sprintf("catching up from block %d to block %d", startBlock, lastConfirmedBlock))

	// we will now sync all logs from the starting height to the current height,
	// in chunks of config.BlockSyncChunkSize
	for {
		if startBlock >= lastConfirmedBlock {
			break
		}

		toBlock := min(startBlock+i.chainConf.BlockSyncChunkSize, lastConfirmedBlock)

		err = i.processEvents(ctx, startBlock, toBlock, eventstore, logger)
		if err != nil {
			// NOTE: this will cause the listener stops.
			return fmt.Errorf("sync up blocks failed, %w", err)
		}

		startBlock = toBlock

		// naive way to avoid reaching the RPC ratelimit, as most of them calculate limit(computing) by per second.
		// depends on network and RPC service, this loop might easily reach provided RPC ratelimit
		// for example, at the time of write, Arbitrum has 314m blocks, whereas Ethereum has 22m blocks.
		time.Sleep(time.Millisecond * 500)
	}

	logger.Info(fmt.Sprintf("synced up to block %d", lastConfirmedBlock))

	outerErr := i.client.ListenToBlocks(ctx, time.Duration(i.syncConf.ReconnectionInterval)*time.Second, func(newHeight int64) error {
		newHeight = newHeight - i.chain.RequiredConfirmations

		// it is possible to receive the same block height multiple times
		if newHeight <= startBlock {
			logger.Debug("received duplicate block height", "block", newHeight)
			return nil
		}

		logger.Info("received new block", "block", newHeight)

		// lastheight + 1 because we have already processed the last height
		err := i.processEvents(ctx, startBlock+1, newHeight, eventstore, logger)
		if err != nil {
			return err
		}

		startBlock = newHeight

		return nil
	})
	if outerErr != nil {
		return fmt.Errorf("failed to listen to blocks: %w", outerErr)
	}

	return nil
}

func (i *individualListener) processEvents(ctx context.Context, from, to int64, eventStore listeners.EventStore, logger log.Logger) error {
	// NOTE: getLogsFunc should have retry machanism on evm RPC requests!
	logs, err := i.getLogsFunc(ctx, i.client.client, uint64(from), uint64(to), logger)
	if err != nil {
		return err
	}

	if len(logs) == 0 {
		return nil
	}

	// order logs by block number
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Log.BlockNumber < logs[j].Log.BlockNumber
	})

	blocks := make(map[uint64][]*EthLog)
	blockOrder := make([]uint64, 0, len(blocks))

	for _, log := range logs {
		_, ok := blocks[log.Log.BlockNumber]
		if !ok {
			blockOrder = append(blockOrder, log.Log.BlockNumber)
		}

		blocks[log.Log.BlockNumber] = append(blocks[log.Log.BlockNumber], log)
	}

	lastUsed, err := getLastHeightWithEvent(ctx, eventStore, i.orderedSyncTopic)
	if err != nil {
		return err
	}

	var lastUsedHeight *int64
	if lastUsed != -1 {
		lastUsedHeight2 := lastUsed
		lastUsedHeight = &lastUsedHeight2
	}

	for _, blockNum := range blockOrder {
		logs := blocks[blockNum]

		// ensure we are ordered by tx index
		sort.Slice(logs, func(i, j int) bool {
			return logs[i].Log.Index < logs[j].Log.Index
		})

		serLogs, err := serializeEthLogs(logs)
		if err != nil {
			return fmt.Errorf("failed to serialize logs: %w", err)
		}

		data := orderedsync.ResolutionMessage{
			Topic:               i.orderedSyncTopic,
			PointInTime:         int64(blockNum),
			Data:                serLogs,
			PreviousPointInTime: lastUsedHeight,
		}

		bts, err := data.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal resolution message: %w", err)
		}

		err = eventStore.Broadcast(ctx, orderedsync.ExtensionName, bts)
		if err != nil {
			return fmt.Errorf("failed to broadcast resolution message: %w", err)
		}

		b2 := int64(blockNum)
		lastUsedHeight = &b2
	}

	// it is important that this is set before the last seen height is set, since it is ok
	// to resubmit the same event, but not okay to submit an event with an invalid last height
	if len(blockOrder) > 0 {
		err = setLastHeightWithEvent(ctx, eventStore, i.orderedSyncTopic, int64(blockOrder[len(blockOrder)-1]))
		if err != nil {
			return fmt.Errorf("failed to set last height with event: %w", err)
		}
	}

	logger.Info("processed events", "from", from, "to", to)

	return setLastSeenHeight(ctx, eventStore, i.orderedSyncTopic, to)
}

// serializeLog serializes an ethCommonLogCopy into a deterministic byte slice.
func serializeLog(log *ethtypes.Log) ([]byte, error) {
	buf := new(bytes.Buffer)

	// 1. Address (20 bytes)
	if _, err := buf.Write(log.Address[:]); err != nil {
		return nil, err
	}

	// 2. Number of Topics (uint32) + Topics (each 32 bytes)
	if err := binary.Write(buf, binary.BigEndian, uint32(len(log.Topics))); err != nil {
		return nil, err
	}
	for _, topic := range log.Topics {
		if _, err := buf.Write(topic[:]); err != nil {
			return nil, err
		}
	}

	// 3. Data length (uint32) + Data bytes
	if err := binary.Write(buf, binary.BigEndian, uint32(len(log.Data))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(log.Data); err != nil {
		return nil, err
	}

	// 4. BlockNumber (uint64)
	if err := binary.Write(buf, binary.BigEndian, log.BlockNumber); err != nil {
		return nil, err
	}

	// 5. TxHash (32 bytes)
	if _, err := buf.Write(log.TxHash[:]); err != nil {
		return nil, err
	}

	// 6. TxIndex (uint32)
	if err := binary.Write(buf, binary.BigEndian, uint32(log.TxIndex)); err != nil {
		return nil, err
	}

	// 7. BlockHash (32 bytes)
	if _, err := buf.Write(log.BlockHash[:]); err != nil {
		return nil, err
	}

	// 8. Index (uint32)
	if err := binary.Write(buf, binary.BigEndian, uint32(log.Index)); err != nil {
		return nil, err
	}

	// 9. Removed (1 byte: 0 or 1)
	removedByte := byte(0)
	if log.Removed {
		removedByte = 1
	}
	if err := buf.WriteByte(removedByte); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// deserializeLog deserializes the bytes back into an ethCommonLogCopy.
func deserializeLog(data []byte) (*ethtypes.Log, error) {
	log := &ethtypes.Log{}
	buf := bytes.NewReader(data)

	// 1. Address (20 bytes)
	if _, err := io.ReadFull(buf, log.Address[:]); err != nil {
		return nil, err
	}

	// 2. Number of Topics (uint32) + Topics (each 32 bytes)
	var topicCount uint32
	if err := binary.Read(buf, binary.BigEndian, &topicCount); err != nil {
		return nil, err
	}
	log.Topics = make([]ethcommon.Hash, topicCount)
	for i := range int(topicCount) {
		if _, err := io.ReadFull(buf, log.Topics[i][:]); err != nil {
			return nil, err
		}
	}

	// 3. Data length (uint32) + Data bytes
	var dataLen uint32
	if err := binary.Read(buf, binary.BigEndian, &dataLen); err != nil {
		return nil, err
	}
	log.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(buf, log.Data); err != nil {
		return nil, err
	}

	// 4. BlockNumber (uint64)
	if err := binary.Read(buf, binary.BigEndian, &log.BlockNumber); err != nil {
		return nil, err
	}

	// 5. TxHash (32 bytes)
	if _, err := io.ReadFull(buf, log.TxHash[:]); err != nil {
		return nil, err
	}

	// 6. TxIndex (uint32)
	var txIndex uint32
	if err := binary.Read(buf, binary.BigEndian, &txIndex); err != nil {
		return nil, err
	}
	log.TxIndex = uint(txIndex)

	// 7. BlockHash (32 bytes)
	if _, err := io.ReadFull(buf, log.BlockHash[:]); err != nil {
		return nil, err
	}

	// 8. Index (uint32)
	var idx uint32
	if err := binary.Read(buf, binary.BigEndian, &idx); err != nil {
		return nil, err
	}
	log.Index = uint(idx)

	// 9. Removed (1 byte: 0 or 1)
	removedByte, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	log.Removed = removedByte == 1

	return log, nil
}

var (
	// lastSeenHeightKey is the key used to store the last height processed by the listener
	lastSeenHeightKey = []byte("lh")
	// lastHeightWithEventKey is the key used to store the last height with an event processed by the listener
	lastHeightWithEventKey = []byte("lwe")
)

// getLastSeenHeight gets the last height seen on the Ethereum blockchain.
func getLastSeenHeight(ctx context.Context, eventStore listeners.EventStore, syncTopic string) (int64, error) {
	// get the last confirmed block height processed by the listener
	lastHeight, err := eventStore.Get(ctx, append(lastSeenHeightKey, []byte(syncTopic)...))
	if err != nil {
		return 0, fmt.Errorf("failed to get last seed block height: %w", err)
	}

	if len(lastHeight) == 0 {
		return 0, nil
	}

	return int64(binary.LittleEndian.Uint64(lastHeight)), nil
}

// setLastSeenHeight sets the last height seen on the Ethereum blockchain.
func setLastSeenHeight(ctx context.Context, eventStore listeners.EventStore, syncTopic string, height int64) error {
	heightBts := make([]byte, 8)
	binary.LittleEndian.PutUint64(heightBts, uint64(height))

	// set the last confirmed block height processed by the listener
	err := eventStore.Set(ctx, append(lastSeenHeightKey, []byte(syncTopic)...), heightBts)
	if err != nil {
		return fmt.Errorf("failed to set last seed block height: %w", err)
	}
	return nil
}

// getLastHeightWithEvent gets the last height that was processed by the listener and has an event.
// If this is the first one, it returns -1
func getLastHeightWithEvent(ctx context.Context, eventStore listeners.EventStore, syncTopic string) (int64, error) {
	lastHeight, err := eventStore.Get(ctx, append(lastHeightWithEventKey, []byte(syncTopic)...))
	if err != nil {
		return 0, fmt.Errorf("failed to get last used block height: %w", err)
	}

	if len(lastHeight) == 0 {
		return -1, nil
	}

	return int64(binary.LittleEndian.Uint64(lastHeight)), nil
}

// setLastHeightWithEvent sets the last height that was processed by the listener and has an event.
func setLastHeightWithEvent(ctx context.Context, eventStore listeners.EventStore, syncTopic string, height int64) error {
	heightBts := make([]byte, 8)
	binary.LittleEndian.PutUint64(heightBts, uint64(height))

	err := eventStore.Set(ctx, append(lastHeightWithEventKey, []byte(syncTopic)...), heightBts)
	if err != nil {
		return fmt.Errorf("failed to set last used block height: %w", err)
	}

	return nil
}
