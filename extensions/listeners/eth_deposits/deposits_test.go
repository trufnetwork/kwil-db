package ethdeposits

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// we could use better tests for this package.
// this would require more abstractions, which would then
// take away from this being an example of a simple event listener.
func Test_Config(t *testing.T) {
	cfg := &EthDepositConfig{
		StartingHeight:        45,
		ContractAddress:       "0x1234",
		RequiredConfirmations: 10,
		RPCProvider:           "ws://localhost:8545",
		ReconnectionInterval:  10,
		MaxRetries:            5,
		BlockSyncChunkSize:    100,
	}
	m := cfg.Map()

	cfg2 := &EthDepositConfig{}
	err := cfg2.setConfig(m)
	require.NoError(t, err)
	require.Equal(t, cfg, cfg2)
}
