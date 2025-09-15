package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	ethLog "github.com/ethereum/go-ethereum/log"
	"github.com/trufnetwork/kwil-db/config"
	deposits "github.com/trufnetwork/kwil-db/extensions/listeners/eth_deposits"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/log"
)

var (
	endpoint     string
	contractAddr string
)

func main() {
	flag.StringVar(&endpoint, "ep", "", "provider's http url, schema is required (env: SEPOLIA_ENDPOINT)")
	flag.StringVar(&contractAddr, "addr", "0x94e6a0aa8518b2be7abaf9e76bfbb48cab1545ad",
		"contract address with deposit events emitted (default is the address at https://sepolia.etherscan.io/address/0x94e6a0aa8518b2be7abaf9e76bfbb48cab1545ad)")
	flag.Parse()

	if endpoint == "" {
		endpoint = os.Getenv(`SEPOLIA_ENDPOINT`)
		if endpoint == "" {
			endpoint = "ws://127.0.0.1:8546"
		}
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signalChan
		cancel()
	}()

	if err := mainReal(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func mainReal(ctx context.Context) error {
	cfg := deposits.EthDepositConfig{
		ContractAddress:      contractAddr,
		RPCProvider:          endpoint,
		ReconnectionInterval: 45,
		MaxRetries:           30,
		BlockSyncChunkSize:   1_000_000,
		StartingHeight:       5_100_000,
	}
	extensionConfig := map[string]map[string]string{
		deposits.ListenerName: cfg.Map(),
	}
	svc := &common.Service{
		Logger: log.DiscardLogger,
		LocalConfig: &config.Config{
			Extensions: extensionConfig,
		},
	}
	es := &memEvtStore{svc.Logger, make(map[string][]byte)}

	rpcLogger := ethLog.NewTerminalHandlerWithLevel(os.Stdout, ethLog.LevelTrace, true)
	ethLog.SetDefault(ethLog.NewLogger(rpcLogger))

	return deposits.Start(ctx, svc, es)
}

// memEvtStore is for debugging. modify as needed.
type memEvtStore struct {
	logger log.Logger
	kv     map[string][]byte
}

func (es *memEvtStore) Broadcast(ctx context.Context, eventType string, data []byte) error {
	es.logger.Infof("mark for broadcast event %v, data %x", eventType, data)
	return nil
}

func (es *memEvtStore) Set(ctx context.Context, key []byte, value []byte) error {
	es.kv[string(key)] = value
	return nil
}

func (es *memEvtStore) Get(ctx context.Context, key []byte) ([]byte, error) {
	return es.kv[string(key)], nil
}

func (es *memEvtStore) Delete(ctx context.Context, key []byte) error {
	delete(es.kv, string(key))
	return nil
}
