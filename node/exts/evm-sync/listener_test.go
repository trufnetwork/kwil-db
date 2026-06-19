package evmsync

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
)

func TestGetChainConf(t *testing.T) {
	baseCfg := func() config.ERC20BridgeConfig {
		return config.ERC20BridgeConfig{
			RPC: map[string]string{
				"ethereum":         "ws://localhost:8546",
				"arbitrum_sepolia": "ws://localhost:8547",
			},
		}
	}

	t.Run("defaults", func(t *testing.T) {
		cfg := baseCfg()
		conf, err := getChainConf(cfg, chains.Ethereum)
		require.NoError(t, err)
		require.Equal(t, int64(1000000), conf.BlockSyncChunkSize)
		require.Equal(t, int64(0), conf.StartBlock)
		require.Equal(t, "ws://localhost:8546", conf.Provider)
	})

	t.Run("per-chain BlockSyncChunkSize", func(t *testing.T) {
		cfg := baseCfg()
		cfg.BlockSyncChuckSize = map[string]string{
			"ethereum":         "500",
			"arbitrum_sepolia": "2000",
		}
		ethConf, err := getChainConf(cfg, chains.Ethereum)
		require.NoError(t, err)
		require.Equal(t, int64(500), ethConf.BlockSyncChunkSize)

		arbConf, err := getChainConf(cfg, chains.ArbitrumSepolia)
		require.NoError(t, err)
		require.Equal(t, int64(2000), arbConf.BlockSyncChunkSize)
	})

	t.Run("BlockSyncChunkSize falls back to default per chain", func(t *testing.T) {
		cfg := baseCfg()
		cfg.BlockSyncChuckSize = map[string]string{
			"ethereum": "500",
		}
		// arbitrum_sepolia not in map, should get default 1000000
		arbConf, err := getChainConf(cfg, chains.ArbitrumSepolia)
		require.NoError(t, err)
		require.Equal(t, int64(1000000), arbConf.BlockSyncChunkSize)
	})

	t.Run("valid StartBlock", func(t *testing.T) {
		cfg := baseCfg()
		cfg.StartBlock = map[string]string{
			"ethereum": "50000",
		}
		conf, err := getChainConf(cfg, chains.Ethereum)
		require.NoError(t, err)
		require.Equal(t, int64(50000), conf.StartBlock)
	})

	t.Run("StartBlock missing defaults to 0", func(t *testing.T) {
		cfg := baseCfg()
		conf, err := getChainConf(cfg, chains.Ethereum)
		require.NoError(t, err)
		require.Equal(t, int64(0), conf.StartBlock)
	})

	t.Run("invalid StartBlock value", func(t *testing.T) {
		cfg := baseCfg()
		cfg.StartBlock = map[string]string{
			"ethereum": "not_a_number",
		}
		_, err := getChainConf(cfg, chains.Ethereum)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("negative StartBlock", func(t *testing.T) {
		cfg := baseCfg()
		cfg.StartBlock = map[string]string{
			"ethereum": "-1",
		}
		_, err := getChainConf(cfg, chains.Ethereum)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be non-negative")
	})

	t.Run("invalid chain", func(t *testing.T) {
		cfg := baseCfg()
		_, err := getChainConf(cfg, chains.Chain("fake_chain"))
		require.Error(t, err)
	})

	t.Run("missing RPC for chain", func(t *testing.T) {
		cfg := baseCfg()
		_, err := getChainConf(cfg, chains.Hoodi)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not have an")
	})

	t.Run("invalid BlockSyncChunkSize", func(t *testing.T) {
		cfg := baseCfg()
		cfg.BlockSyncChuckSize = map[string]string{
			"ethereum": "0",
		}
		_, err := getChainConf(cfg, chains.Ethereum)
		require.Error(t, err)
		require.Contains(t, err.Error(), "block_sync_chunk_size must be greater than 0")
	})
}

// fakeEventStore is an in-memory listeners.EventStore for testing the catch-up loop.
type fakeEventStore struct {
	kv map[string][]byte
}

func newFakeEventStore() *fakeEventStore { return &fakeEventStore{kv: map[string][]byte{}} }

func (f *fakeEventStore) Set(_ context.Context, key, value []byte) error {
	f.kv[string(key)] = value
	return nil
}
func (f *fakeEventStore) Get(_ context.Context, key []byte) ([]byte, error) {
	return f.kv[string(key)], nil
}
func (f *fakeEventStore) Delete(_ context.Context, key []byte) error {
	delete(f.kv, string(key))
	return nil
}
func (f *fakeEventStore) Broadcast(_ context.Context, _ string, _ []byte) error { return nil }

func newTestChunkListener(chunkSize int64, getLogs GetBlockLogsFunc) *individualListener {
	return &individualListener{
		chain:               chains.ChainInfo{Name: chains.Chain("test")},
		chainConf:           &chainConfig{BlockSyncChunkSize: chunkSize},
		client:              &ethClient{}, // getLogsFunc ignores the (nil) inner client
		orderedSyncTopic:    "test_topic",
		getLogsFunc:         getLogs,
		blockSyncChunkDelay: 0, // no inter-chunk sleep in tests
	}
}

// TestSyncBlockChunks_AdaptiveChunking pins the behavior that prevents the testnet incident
// where the hoodi deposit listener wedged: a single oversized eth_getLogs request must not
// permanently stall catch-up. Instead the chunk size halves and retries until the request
// fits the provider's range/result limit.
func TestSyncBlockChunks_AdaptiveChunking(t *testing.T) {
	ctx := context.Background()
	logger := log.DiscardLogger

	t.Run("halves chunk size when the RPC rejects an oversized range", func(t *testing.T) {
		const providerLimit = 4 // max blocks the fake RPC allows per (inclusive) getLogs request
		var calls int
		var processed [][2]uint64 // (from,to) of every range actually fetched & processed
		getLogs := func(_ context.Context, _ *ethclient.Client, from, to uint64, _ log.Logger) ([]*EthLog, error) {
			calls++
			// eth_getLogs is inclusive on both ends, so a [from,to] request fetches to-from+1 blocks.
			if to-from+1 > providerLimit {
				return nil, errors.New("exceed maximum block range: 4")
			}
			processed = append(processed, [2]uint64{from, to})
			return nil, nil // empty logs -> processEvents just advances the last-seen height
		}
		// Default-style oversized chunk (64) over a 16-block gap with a 4-block provider limit.
		l := newTestChunkListener(64, getLogs)
		es := newFakeEventStore()

		err := l.syncBlockChunks(ctx, es, 0, 16, logger)
		require.NoError(t, err, "catch-up must recover by shrinking the request")

		got, err := getLastSeenHeight(ctx, es, l.orderedSyncTopic)
		require.NoError(t, err)
		require.Equal(t, int64(16), got, "should sync all the way to the target despite the oversized default chunk")
		require.Greater(t, calls, 1, "should have retried after the first oversized request")

		// The fetched ranges must each fit the provider limit and together cover every block
		// in [0,16] with no gaps. (Boundary blocks may be re-fetched -- overlap is expected and
		// harmless -- but a GAP would mean skipped blocks / lost events.)
		covered := make([]bool, 17)
		for _, r := range processed {
			require.LessOrEqual(t, r[1]-r[0]+1, uint64(providerLimit), "each fetched range must fit the provider limit")
			for b := r[0]; b <= r[1]; b++ {
				covered[b] = true
			}
		}
		for b := range 17 {
			require.Truef(t, covered[b], "block %d must be covered by some chunk (no gaps)", b)
		}
	})

	t.Run("errors (does not loop forever) when even a small request keeps failing", func(t *testing.T) {
		getLogs := func(_ context.Context, _ *ethclient.Client, _, _ uint64, _ log.Logger) ([]*EthLog, error) {
			return nil, errors.New("Request contains invalid block params")
		}
		l := newTestChunkListener(8, getLogs)
		es := newFakeEventStore()

		err := l.syncBlockChunks(ctx, es, 0, 16, logger)
		require.Error(t, err, "a persistently failing RPC must surface an error, not spin")
		require.Contains(t, err.Error(), "sync up blocks failed")
	})

	t.Run("no provider limit: syncs in full configured chunks", func(t *testing.T) {
		var maxSpan uint64
		getLogs := func(_ context.Context, _ *ethclient.Client, from, to uint64, _ log.Logger) ([]*EthLog, error) {
			if to-from > maxSpan {
				maxSpan = to - from
			}
			return nil, nil
		}
		l := newTestChunkListener(8, getLogs)
		es := newFakeEventStore()

		err := l.syncBlockChunks(ctx, es, 0, 20, logger)
		require.NoError(t, err)

		got, err := getLastSeenHeight(ctx, es, l.orderedSyncTopic)
		require.NoError(t, err)
		require.Equal(t, int64(20), got)
		require.LessOrEqual(t, maxSpan, uint64(8), "should never request more than the configured chunk size")
	})
}
