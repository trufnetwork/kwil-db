package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestERC20BridgeConfig_Validate_StartBlock(t *testing.T) {
	base := func() ERC20BridgeConfig {
		return ERC20BridgeConfig{
			RPC: map[string]string{
				"ethereum": "ws://localhost:8546",
			},
		}
	}

	t.Run("valid start_block", func(t *testing.T) {
		cfg := base()
		cfg.StartBlock = map[string]string{"ethereum": "50000"}
		require.NoError(t, cfg.Validate())
	})

	t.Run("no start_block is fine", func(t *testing.T) {
		cfg := base()
		require.NoError(t, cfg.Validate())
	})

	t.Run("invalid chain in start_block", func(t *testing.T) {
		cfg := base()
		cfg.StartBlock = map[string]string{"fake_chain": "100"}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "erc20_bridge.start_block")
		require.Contains(t, err.Error(), "invalid chain")
	})

	t.Run("non-numeric start_block value", func(t *testing.T) {
		cfg := base()
		cfg.StartBlock = map[string]string{"ethereum": "abc"}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "erc20_bridge.start_block")
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("negative start_block value", func(t *testing.T) {
		cfg := base()
		cfg.StartBlock = map[string]string{"ethereum": "-5"}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "non-negative")
	})

	t.Run("non-canonical chain key in start_block", func(t *testing.T) {
		cfg := base()
		cfg.StartBlock = map[string]string{"Ethereum": "100"}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "canonical chain name")
	})
}

func TestERC20BridgeConfig_Validate_RPC(t *testing.T) {
	t.Run("non-canonical chain key in rpc", func(t *testing.T) {
		cfg := ERC20BridgeConfig{
			RPC: map[string]string{
				"Ethereum": "ws://localhost:8546",
			},
		}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "erc20_bridge.rpc")
		require.Contains(t, err.Error(), "canonical chain name")
	})

	t.Run("invalid chain in rpc", func(t *testing.T) {
		cfg := ERC20BridgeConfig{
			RPC: map[string]string{
				"fake_chain": "ws://localhost:8546",
			},
		}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "erc20_bridge.rpc")
		require.Contains(t, err.Error(), "invalid chain")
	})
}
