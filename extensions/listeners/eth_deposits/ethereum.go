package ethdeposits

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jpillora/backoff"
	kcrypto "github.com/trufnetwork/kwil-db/core/crypto"

	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/extensions/resolutions/credit"
)

// file contains functionality for subscribing to ethereum and reading logs

func init() {
	// parse the contract ABI
	var err error
	eventABI, err = abi.JSON(strings.NewReader(contractABIStr))
	if err != nil {
		panic(err)
	}
}

// contractABIStr is the ABI of the smart contract the listener listens to.
// It follows the Ethereum ABI JSON format, and matches the `Credit(address,uint256)` event signature.
const contractABIStr = `[{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"_from","type":"address"},{"indexed":false,"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"Credit","type":"event"}]`

// eventABI is the abi for the Credit event
var eventABI abi.ABI

// creditEventSignature is the EVM event signature the listener listens to.
var creditEventSignature ethcommon.Hash = crypto.Keccak256Hash([]byte("Credit(address,uint256)"))

// ethClient is a client for interacting with the ethereum blockchain
// it handles retries and resubscribing to the blockchain in case of
// transient errors
type ethClient struct {
	targetAddress ethcommon.Address
	maxRetries    int64
	logger        log.Logger
	client        *ethclient.Client
}

// newEthClient creates a new ethereum client
func newEthClient(ctx context.Context, rpcurl string, maxRetries int64, targetAddress ethcommon.Address, logger log.Logger) (*ethClient, error) {
	var client *ethclient.Client

	// I don't set the max retries here because this only gets run on startup
	// the max retries are used for resubscribing to the blockchain
	// if we fail 3 times here, it is likely a permanent error
	err := retry(ctx, 3, func() error {
		var innerErr error
		client, innerErr = ethclient.DialContext(ctx, rpcurl)
		return innerErr
	})
	if err != nil {
		return nil, err
	}

	return &ethClient{
		targetAddress: targetAddress,
		maxRetries:    maxRetries,
		logger:        logger,
		client:        client,
	}, nil
}

// GetLatestBlock gets the latest block number from the ethereum blockchain
func (ec *ethClient) GetLatestBlock(ctx context.Context) (int64, error) {
	var blockNumber int64
	err := retry(ctx, ec.maxRetries, func() error {
		header, err := ec.client.HeaderByNumber(ctx, nil)
		if err != nil {
			ec.logger.Error("Failed to get latest block", "error", err)
			return err
		}
		blockNumber = header.Number.Int64()
		return nil
	})
	return blockNumber, err
}

// GetCreditEventLogs gets the logs for the credit event from the ethereum blockchain.
// It can be given a start range and an end range to filter the logs by block height.
func (ec *ethClient) GetCreditEventLogs(ctx context.Context, fromBlock, toBlock int64) ([]types.Log, error) {
	var logs []types.Log
	err := retry(ctx, ec.maxRetries, func() error {
		var err error
		logs, err = ec.client.FilterLogs(ctx, ethereum.FilterQuery{
			ToBlock:   big.NewInt(toBlock),
			FromBlock: big.NewInt(fromBlock),
			Addresses: []ethcommon.Address{ec.targetAddress},
			Topics:    [][]ethcommon.Hash{{creditEventSignature}},
		})
		if err != nil {
			ec.logger.Error("Failed to get credit event logs", "error", err)
		}

		return err
	})
	return logs, err
}

// decodeCreditEvent decodes the credit event from the ethereum log
func decodeCreditEvent(l *types.Log) (*credit.AccountCreditResolution, error) {
	data, err := eventABI.Unpack("Credit", l.Data)
	if err != nil {
		return nil, err
	}

	// the first argument is the address, the second is the amount
	address, ok := data[0].(ethcommon.Address)
	if !ok {
		return nil, fmt.Errorf("failed to parse credit event address")
	}
	amount, ok := data[1].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("failed to parse credit event amount")
	}

	return &credit.AccountCreditResolution{
		Account: address.Bytes(),
		KeyType: kcrypto.KeyTypeSecp256k1.String(),
		Amount:  amount,
		TxHash:  l.TxHash.Bytes(),
	}, nil
}

// ListenToBlocks subscribes to new blocks on the ethereum blockchain.
// It takes a reconnectInterval, which is the amount of time it will wait
// to reconnect to the ethereum client if no new blocks are received.
// It takes a callback function that is called with the new block number.
// It can send duplicates, if that is received from the ethereum client.
// It will block until the context is cancelled, or until an error is
// returned from the callback function.
func (ec *ethClient) ListenToBlocks(ctx context.Context, reconnectInterval time.Duration, cb func(int64) error) error {
	headers := make(chan *types.Header, 1)
	sub, err := ec.client.SubscribeNewHead(ctx, headers)
	if err != nil {
		return err
	}

	resubscribe := func() error {
		var retryCount int
		ec.logger.Warn("Resubscribing to Ethereum node", "attempt", retryCount) // anomalous
		sub.Unsubscribe()

		return retry(ctx, ec.maxRetries, func() error {
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

// retry will retry the function until it is successful, or reached the max retries
func retry(ctx context.Context, maxRetries int64, fn func() error) error {
	retrier := &backoff.Backoff{
		Min:    1 * time.Second,
		Max:    10 * time.Second,
		Factor: 2,
		Jitter: true,
	}

	for {
		err := fn()
		if err == nil {
			return nil
		}

		// fail after maxRetries retries
		if retrier.Attempt() > float64(maxRetries) {
			return fmt.Errorf("retry done: %w", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retrier.Duration()):
		}
	}
}
