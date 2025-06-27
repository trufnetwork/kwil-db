package erc20

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
)

func TestSyncedRewardData_MarshalBinary(t *testing.T) {
	tests := []struct {
		name             string
		input            syncedRewardData
		expectedAddr     common.Address
		expectedDecimals int64
	}{
		{
			name: "Valid data positive decimals",
			input: syncedRewardData{
				Erc20Address:  common.HexToAddress("0x1234567890123456789012345678901234567890"),
				Erc20Decimals: 18,
			},
			expectedAddr:     common.HexToAddress("0x1234567890123456789012345678901234567890"),
			expectedDecimals: 18,
		},
		{
			name: "Valid data negative decimals",
			input: syncedRewardData{
				Erc20Address:  common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
				Erc20Decimals: -10,
			},
			expectedAddr:     common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
			expectedDecimals: -10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.input.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary returned an error: %v", err)
			}
			if len(data) != 28 {
				t.Fatalf("expected data length 28, got %d", len(data))
			}
			// Verify that the first 20 bytes match the expected address.
			if !bytes.Equal(data[:20], tt.expectedAddr.Bytes()) {
				t.Errorf("address bytes mismatch: got %x, want %x", data[:20], tt.expectedAddr.Bytes())
			}
			// Verify that the last 8 bytes correctly encode the int64 decimals.
			decimals := int64(binary.BigEndian.Uint64(data[20:]))
			if decimals != tt.expectedDecimals {
				t.Errorf("decimals mismatch: got %d, want %d", decimals, tt.expectedDecimals)
			}
		})
	}
}

func TestSyncedRewardData_UnmarshalBinary(t *testing.T) {
	// Prepare a valid 28-byte slice for one test case.
	validAddress := common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
	validDecimals := int64(8)
	validData := make([]byte, 28)
	copy(validData[:20], validAddress.Bytes())
	binary.BigEndian.PutUint64(validData[20:], uint64(validDecimals))

	tests := []struct {
		name      string
		input     []byte
		expected  *syncedRewardData
		expectErr bool
	}{
		{
			name:  "Valid input",
			input: validData,
			expected: &syncedRewardData{
				Erc20Address:  validAddress,
				Erc20Decimals: validDecimals,
			},
			expectErr: false,
		},
		{
			name:      "Invalid input length",
			input:     []byte("short data"),
			expected:  nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sr syncedRewardData
			err := sr.UnmarshalBinary(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected an error for invalid input length, but got none")
				}
				// No need to check further if an error was expected.
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			// Compare the unmarshaled address.
			if sr.Erc20Address != tt.expected.Erc20Address {
				t.Errorf("address mismatch: got %s, want %s", sr.Erc20Address.Hex(), tt.expected.Erc20Address.Hex())
			}
			// Compare the unmarshaled decimals.
			if sr.Erc20Decimals != tt.expected.Erc20Decimals {
				t.Errorf("decimals mismatch: got %d, want %d", sr.Erc20Decimals, tt.expected.Erc20Decimals)
			}
		})
	}
}

func Test_scaleUpUint256(t *testing.T) {
	d, err := types.ParseDecimal("11.22")
	require.NoError(t, err)

	t.Run("scale up by 4", func(t *testing.T) {
		nd, err := scaleUpUint256(d, 4)
		require.NoError(t, err)
		require.Equal(t, "112200", nd.String())
		require.Equal(t, 78, int(nd.Precision()))
		require.Equal(t, 0, int(nd.Scale()))
	})

	t.Run("scale up by 0, with decimal", func(t *testing.T) {
		nd, err := scaleUpUint256(d, 0)
		require.NoError(t, err)
		require.Equal(t, "11", nd.String())
		require.Equal(t, 78, int(nd.Precision()))
		require.Equal(t, 0, int(nd.Scale()))
	})

	t.Run("scale up by 0, without decimal", func(t *testing.T) {
		d, err := types.ParseDecimal("1122")
		require.NoError(t, err)
		nd, err := scaleUpUint256(d, 0)
		require.NoError(t, err)
		require.Equal(t, "1122", nd.String())
		require.Equal(t, 78, int(nd.Precision()))
		require.Equal(t, 0, int(nd.Scale()))
	})
}

func Test_scaleDownUint256(t *testing.T) {
	d, err := types.ParseDecimal("112200")
	require.NoError(t, err)

	t.Run("scale down by 4", func(t *testing.T) {
		nd, err := scaleDownUint256(d, 4)
		require.NoError(t, err)
		require.Equal(t, "11.2200", nd.String())
		require.Equal(t, 74, int(nd.Precision()))
		require.Equal(t, 4, int(nd.Scale()))
	})

	t.Run("scale down by 0", func(t *testing.T) {
		nd, err := scaleDownUint256(d, 0)
		require.NoError(t, err)
		require.Equal(t, "112200", nd.String())
		require.Equal(t, 78, int(nd.Precision()))
		require.Equal(t, 0, int(nd.Scale()))
	})
}
