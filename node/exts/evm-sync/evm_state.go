package evmsync

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/extensions/listeners"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	"github.com/trufnetwork/kwil-db/node/exts/poll"
)

// this file implements functionality for getting state from Ethereum.
// Unlike logs (which the rest of the package focuses on), state is different
// because there is no good way to get state changes per block in Ethereum.

/*
	We need some way to do periodic polling of Ethereum and call a callback
	that reads the desired state
*/

// RegisterEventResolution registers a resolution function for the EVM event listener.
// It should be called in an init function.
func RegisterStatePollResolution(name string, resolve EVMPollResolveFunc) {
	_, ok := pollFuncResolutions[name]
	if ok {
		panic(fmt.Sprintf("poll resolution with name %s already registered", name))
	}

	pollFuncResolutions[name] = resolve
}

var pollFuncResolutions = make(map[string]EVMPollResolveFunc)

func init() {
	err := listeners.RegisterListener("evm_sync_poller",
		poll.NewPoller(5*time.Second, func(ctx context.Context, service *common.Service, eventstore listeners.EventStore) (poll.PollFunc, error) {
			return func(ctx context.Context, service *common.Service, eventstore listeners.EventStore) (stopPolling bool, err error) {
				StatePoller.runPollFuncs(ctx, service, eventstore)
				return false, nil
			}, nil
		}),
	)
	if err != nil {
		panic(err)
	}

	err = resolutions.RegisterResolution(resolutionName, resolutions.ModAdd, resolutions.ResolutionConfig{
		RefundThreshold:       big.NewRat(1, 3),
		ConfirmationThreshold: big.NewRat(1, 2),
		ExpirationPeriod:      1 * time.Hour,
		ResolveFunc: func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext) error {
			p := &polledEvent{}
			if err := p.UnmarshalBinary(resolution.Body); err != nil {
				return fmt.Errorf("failed to unmarshal polled event: %v", err)
			}

			resolve, ok := pollFuncResolutions[p.ResolutionName]
			if !ok {
				return fmt.Errorf("poll resolution with name %s not found", p.UniqueName)
			}

			return resolve(ctx, app, resolution, block, p.UniqueName, p.Data)
		},
	})
	if err != nil {
		panic(err)
	}
}

const resolutionName = "evm_sync_poller_resolution"

// StatePoller is the global instance of the state poller extension,
// which allows polling for state on Ethereum. Unlike normal listeners
// (which are registered in init), StatePoller allows registration to
// be performed on-demand as part of the consensus process. It also
// provides access to an EVM client for the target chain, accessed
// via the local node's configuration.
var StatePoller = &statePoller{
	pollers: make(map[string]*PollConfig),
	clients: make(map[chains.Chain]*ethclient.Client),
}

type statePoller struct {
	// mu protects all fields in this struct
	mu sync.Mutex
	// pollers is a set of all poll functions
	pollers map[string]*PollConfig
	// clients maps chains to clients.
	// It is used as a cache, and there is no guarantee that
	// a client exists for a chain.
	clients map[chains.Chain]*ethclient.Client
}

type PollConfig struct {
	// Chain is the chain to poll
	Chain chains.Chain
	// PollFunc is the function to call to poll the chain
	PollFunc EVMPollFunc
	// UniqueName is a unique name for the poller
	UniqueName string
	// ResolutionName is the name of the registered resolution function
	ResolutionName string
}

type EVMPollFunc func(ctx context.Context, service *common.Service, eventstore listeners.EventKV, broadcast func(context.Context, []byte) error, client *ethclient.Client)
type EVMPollResolveFunc func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext, uniqueName string, decodedData []byte) error

// RegisterPoll registers a function that polls the state of Ethereum.
// The pollFunc is responsible for reading the state of Ethereum and writing
// relevant data to the event store. If the pollFunc returns true, it will
// not be called again. The resolveFunc is responsible for resolving the
// state data into the local database. It will be called once for
// each time the EventStore is written to, similar to a normal listener.
// This function should be called in an OnStart function.
func (s *statePoller) RegisterPoll(cfg PollConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.pollers[cfg.UniqueName]; ok {
		return fmt.Errorf("poller with name %s already registered", cfg.UniqueName)
	}

	s.pollers[cfg.UniqueName] = &cfg

	return nil
}

// UnregisterPoll unregisters a poller by name.
// This function should be called in an OnUnuse function.
func (s *statePoller) UnregisterPoll(uniqueName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.pollers[uniqueName]; !ok {
		return fmt.Errorf("poller with name %s not found", uniqueName)
	}

	delete(s.pollers, uniqueName)

	return nil
}

// runPollFuncs runs all poll funcs asynchronously.
func (s *statePoller) runPollFuncs(ctx context.Context, service *common.Service, eventstore listeners.EventStore) {
	wg := sync.WaitGroup{}
	s.mu.Lock()

	for _, cfg := range s.pollers {
		client, ok := s.clients[cfg.Chain]
		if !ok {
			// create a new client
			var err error
			client, err = makeNewClient(ctx, service, cfg.Chain)
			if err != nil {
				service.Logger.Error("failed to create new client", "error", err)
				continue
			}

			s.clients[cfg.Chain] = client
		} else {
			// check it is still connected, sometimes the connection can drop
			_, err := client.ChainID(ctx)
			if err != nil {
				// try to reconnect
				client, err = makeNewClient(ctx, service, cfg.Chain)
				if err != nil {
					service.Logger.Error("failed to reconnect client", "error", err)
					continue
				}

				s.clients[cfg.Chain] = client
			}
		}

		kv := makeNamespaceKV("evm.sync."+cfg.UniqueName, eventstore)

		uniqueNameCopy := cfg.UniqueName
		resolutionNameCopy := cfg.ResolutionName
		go func() {
			defer wg.Done()
			wg.Add(1)
			cfg.PollFunc(ctx, service, kv, func(ctx context.Context, data []byte) error {
				pEvent := &polledEvent{
					UniqueName:     uniqueNameCopy,
					Data:           data,
					ResolutionName: resolutionNameCopy,
				}

				bts, err := pEvent.MarshalBinary()
				if err != nil {
					return fmt.Errorf("failed to marshal polled event: %v", err)
				}

				return eventstore.Broadcast(ctx, resolutionName, bts)
			}, client)
		}()
	}

	s.mu.Unlock()
	wg.Wait()
}

func makeNewClient(ctx context.Context, service *common.Service, chain chains.Chain) (*ethclient.Client, error) {
	chainConf, err := getChainConf(service.LocalConfig.Erc20Bridge, chain)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain config for %s: %v", chain, err)
	}

	client, err := ethclient.DialContext(ctx, chainConf.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to dial ethereum client for %s: %v", chain, err)
	}

	return client, nil
}

type polledEvent struct {
	// UniqueName is the unique name of the poller
	UniqueName string
	// Data is the data that was read from the chain
	Data []byte
	// ResolutionName is the name of the resolution function
	ResolutionName string
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (p *polledEvent) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// 1. Write length of UniqueName
	nameLen := uint64(len(p.UniqueName))
	if err := binary.Write(&buf, binary.BigEndian, nameLen); err != nil {
		return nil, err
	}

	// 2. Write UniqueName bytes
	if _, err := buf.Write([]byte(p.UniqueName)); err != nil {
		return nil, err
	}

	// 3. Write length of Data
	dataLen := uint64(len(p.Data))
	if err := binary.Write(&buf, binary.BigEndian, dataLen); err != nil {
		return nil, err
	}

	// 4. Write Data bytes
	if _, err := buf.Write(p.Data); err != nil {
		return nil, err
	}

	// 5. Write length of ResolutionName
	nameLen = uint64(len(p.ResolutionName))
	if err := binary.Write(&buf, binary.BigEndian, nameLen); err != nil {
		return nil, err
	}

	// 6. Write ResolutionName bytes
	if _, err := buf.Write([]byte(p.ResolutionName)); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (p *polledEvent) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)

	// 1. Read length of UniqueName
	var nameLen uint64
	if err := binary.Read(reader, binary.BigEndian, &nameLen); err != nil {
		return err
	}

	// 2. Read UniqueName bytes
	nameBytes := make([]byte, nameLen)
	if _, err := io.ReadFull(reader, nameBytes); err != nil {
		return err
	}
	p.UniqueName = string(nameBytes)

	// 3. Read length of Data
	var dataLen uint64
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return err
	}

	// 4. Read Data bytes
	dataBytes := make([]byte, dataLen)
	if _, err := io.ReadFull(reader, dataBytes); err != nil {
		return err
	}
	p.Data = dataBytes

	// 5. Read length of ResolutionName
	if err := binary.Read(reader, binary.BigEndian, &nameLen); err != nil {
		return err
	}

	// 6. Read ResolutionName bytes
	nameBytes = make([]byte, nameLen)
	if _, err := io.ReadFull(reader, nameBytes); err != nil {
		return err
	}
	p.ResolutionName = string(nameBytes)

	return nil
}

func makeNamespaceKV(namespace string, kv listeners.EventKV) listeners.EventKV {
	return &namespacedKV{
		namespace: []byte(namespace),
		kv:        kv,
	}
}

type namespacedKV struct {
	namespace []byte
	kv        listeners.EventKV
}

func (n *namespacedKV) Set(ctx context.Context, key []byte, value []byte) error {
	return n.kv.Set(ctx, append(n.namespace, key...), value)
}

func (n *namespacedKV) Get(ctx context.Context, key []byte) ([]byte, error) {
	return n.kv.Get(ctx, append(n.namespace, key...))
}

func (n *namespacedKV) Delete(ctx context.Context, key []byte) error {
	return n.kv.Delete(ctx, append(n.namespace, key...))
}
