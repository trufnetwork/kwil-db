package chains

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChainValid(t *testing.T) {
	valid := []Chain{
		Ethereum, Sepolia, BaseSepolia, Hoodi,
		Hardhat, ArbitrumSepolia, ArbitrumOne,
	}
	for _, c := range valid {
		t.Run(string(c), func(t *testing.T) {
			require.NoError(t, c.Valid())
		})
	}

	t.Run("invalid chain", func(t *testing.T) {
		require.Error(t, Chain("fake_chain").Valid())
	})
}

func TestGetChainInfo(t *testing.T) {
	tests := []struct {
		chain  Chain
		id     string
		confs  int64
	}{
		{Ethereum, "1", 12},
		{Sepolia, "11155111", 12},
		{BaseSepolia, "84532", 12},
		{Hoodi, "560048", 12},
		{Hardhat, "31337", 1},
		{ArbitrumSepolia, "421614", 2},
		{ArbitrumOne, "42161", 4},
	}

	for _, tc := range tests {
		t.Run(string(tc.chain), func(t *testing.T) {
			info, ok := GetChainInfo(tc.chain)
			require.True(t, ok)
			require.Equal(t, tc.id, info.ID)
			require.Equal(t, tc.confs, info.RequiredConfirmations)
		})
	}

	t.Run("unknown chain", func(t *testing.T) {
		_, ok := GetChainInfo("nonexistent")
		require.False(t, ok)
	})
}

func TestGetChainInfoByID(t *testing.T) {
	info, ok := GetChainInfoByID("42161")
	require.True(t, ok)
	require.Equal(t, ArbitrumOne, info.Name)

	_, ok = GetChainInfoByID("99999")
	require.False(t, ok)
}
