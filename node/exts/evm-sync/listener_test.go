package evmsync

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
)

func TestGetChainConf(t *testing.T) {
	baseCfg := func() config.ERC20BridgeConfig {
		return config.ERC20BridgeConfig{
			RPC: map[string]string{
				"ethereum":        "ws://localhost:8546",
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
			"ethereum":        "500",
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
