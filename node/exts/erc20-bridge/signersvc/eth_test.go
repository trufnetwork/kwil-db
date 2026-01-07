package signersvc

import (
	"context"
	"flag"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ethRpc = flag.String("eth-rpc", os.Getenv("ETH_RPC"), "eth provider rpc")

func TestSafe_metadata(t *testing.T) {
	if *ethRpc == "" {
		t.Skip("no eth rpc configured")
	}

	blockNumber := new(big.Int).SetUint64(7660784)

	s, err := NewSafe(*ethRpc, "0x56D510E4782cDed87F8B93D260282776adEd3f4B")
	require.NoError(t, err)

	ctx := context.Background()

	got, err := s.getSafeMetadata3(ctx, blockNumber)
	require.NoError(t, err)

	got2, err := s.getSafeMetadataSeq(ctx, blockNumber)
	require.NoError(t, err)

	require.EqualValues(t, got, got2)
}

// TestNewSafeFromEscrow_CustodialBridge tests Safe detection for custodial bridges (RewardDistributor)
func TestNewSafeFromEscrow_CustodialBridge(t *testing.T) {
	// This test requires an actual RewardDistributor contract deployed
	// Sepolia RewardDistributor address (from your testnet)
	sepoliaEscrow := "0x502430ed0bbe0f230215870c9c2853e126ee5ae3"
	sepoliaRPC := os.Getenv("SEPOLIA_RPC")

	if sepoliaRPC == "" {
		t.Skip("SEPOLIA_RPC not configured")
	}

	safe, err := NewSafeFromEscrow(sepoliaRPC, sepoliaEscrow)
	require.NoError(t, err, "should successfully detect custodial bridge")
	require.NotNil(t, safe, "Safe should not be nil for custodial bridges")
	assert.NotEmpty(t, safe.addr.String(), "Safe address should be populated")
	assert.NotNil(t, safe.chainID, "Chain ID should be populated")
	assert.Equal(t, "11155111", safe.chainID.String(), "Should be Sepolia chain ID")
}

// TestNewSafeFromEscrow_NonCustodialBridge tests Safe detection for non-custodial bridges (TrufNetworkBridge)
func TestNewSafeFromEscrow_NonCustodialBridge(t *testing.T) {
	// This test requires an actual TrufNetworkBridge contract deployed
	// Hoodi TrufNetworkBridge address (from your testnet)
	hoodiEscrow := "0x878D6aaeB6e746033f50B8dC268d54B4631554E7"
	hoodiRPC := os.Getenv("HOODI_RPC")

	if hoodiRPC == "" {
		t.Skip("HOODI_RPC not configured")
	}

	safe, err := NewSafeFromEscrow(hoodiRPC, hoodiEscrow)
	require.NoError(t, err, "should successfully detect non-custodial bridge")
	assert.Nil(t, safe, "Safe should be nil for non-custodial bridges (direct signing)")
}

// TestNewSafeFromEscrow_InvalidRPC tests error handling for invalid RPC
func TestNewSafeFromEscrow_InvalidRPC(t *testing.T) {
	safe, err := NewSafeFromEscrow("http://invalid-rpc-endpoint:8545", "0x0000000000000000000000000000000000000000")
	assert.Error(t, err, "should return error for invalid RPC")
	assert.Nil(t, safe, "Safe should be nil on error")
}
