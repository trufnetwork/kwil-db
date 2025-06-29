package evmsync

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
)

// ethClient is a client for interacting with the ethereum blockchain
// it handles retries and resubscribing to the blockchain in case of
// transient errors
type ethClient struct {
	maxRetries int64
	logger     log.Logger
	client     *ethclient.Client
	done       <-chan struct{}
}

// newEthClient creates a new ethereum client
func newEthClient(ctx context.Context, rpcurl string, maxRetries int64, done <-chan struct{}, logger log.Logger) (*ethClient, error) {
	var client *ethclient.Client

	// I don't set the max retries here because this only gets run on startup
	// the max retries are used for resubscribing to the blockchain
	// if we fail 3 times here, it is likely a permanent error
	count := 0
	err := utils.Retry(ctx, maxRetries, func() error {
		if count > 0 {
			logger.Warn("Retrying initial client connection", "attempt", count)
		}
		count++

		var innerErr error
		client, innerErr = ethclient.DialContext(ctx, rpcurl)
		return innerErr
	})
	if err != nil {
		return nil, err
	}

	return &ethClient{
		maxRetries: maxRetries,
		logger:     logger,
		client:     client,
		done:       done,
	}, nil
}

// GetLatestBlock gets the latest block number from the ethereum blockchain
func (ec *ethClient) GetLatestBlock(ctx context.Context) (int64, error) {
	var blockNumber int64
	err := utils.Retry(ctx, ec.maxRetries, func() error {
		block, err := ec.client.BlockNumber(ctx)
		if err != nil {
			ec.logger.Error("Failed to get latest block", "error", err)
			return err
		}
		blockNumber = int64(block)
		return nil
	})
	return blockNumber, err
}

// ListenToBlocks subscribes to new blocks on the ethereum blockchain.
// It takes a reconnectInterval, which is the amount of time it will wait
// to reconnect to the ethereum client if no new blocks are received.
// It takes a callback function that is called with the new block number.
// It can send duplicates, if that is received from the ethereum client.
// It will block until the context is cancelled, or until an error is
// returned from the callback function.
func (ec *ethClient) ListenToBlocks(ctx context.Context, reconnectInterval time.Duration, cb func(int64) error) error {
	headers := make(chan *types.Header)
	sub, err := ec.client.SubscribeNewHead(ctx, headers)
	if err != nil {
		return err
	}

	resubscribe := func() error {
		var retryCount int
		ec.logger.Warn("Resubscribing to Ethereum node", "attempt", retryCount) // anomalous
		sub.Unsubscribe()

		return utils.Retry(ctx, ec.maxRetries, func() error {
			retryCount++
			sub, err = ec.client.SubscribeNewHead(ctx, headers)
			return err
		})
	}

	reconn := time.NewTicker(reconnectInterval)
	defer reconn.Stop()

	for {
		select {
		case <-ctx.Done():
			ec.logger.Debug("Context cancelled, stopping ethereum client")
			return nil
		case <-ec.done:
			ec.logger.Debug("Done channel closed, stopping ethereum client")
			return nil
		case header := <-headers:
			ec.logger.Debug("New block", "height", header.Number.Int64())
			err := cb(header.Number.Int64())
			if err != nil {
				return err
			}

			reconn.Reset(reconnectInterval)
		case err := <-sub.Err():
			ec.logger.Error("Ethereum subscription error", "error", err)
			err = resubscribe()
			if err != nil {
				return err
			}
			reconn.Reset(reconnectInterval)
		case <-reconn.C:
			ec.logger.Warn("No new blocks received, resubscribing")
			err := resubscribe()
			if err != nil {
				return err
			}
		}
	}
}

// Close closes the ethereum client
func (ec *ethClient) Close() {
	ec.client.Close()
}
