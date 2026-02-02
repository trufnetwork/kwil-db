package evmsync

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

// TestSerializeDeserializeEthLogs tests that we can round-trip logs
// via serializeEthLogs -> deserializeEthLogs.
func TestSerializeDeserializeEthLogs(t *testing.T) {
	tests := []struct {
		name    string
		input   []*EthLog
		wantErr bool
	}{
		{
			name:    "EmptyLogs",
			input:   []*EthLog{},
			wantErr: false,
		},
		{
			name: "SingleLog",
			input: []*EthLog{
				{
					Metadata: []byte("metadata"),
					Log: &types.Log{
						Address:     common.HexToAddress("0x1111111111111111111111111111111111111111"),
						Topics:      []common.Hash{common.HexToHash("0xaaaabbbbccccddddeeee11112222333344445555666677778888999900001111")},
						Data:        []byte("test data"),
						BlockNumber: 12345,
						TxHash:      common.HexToHash("0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"),
						BlockHash:   common.HexToHash("0xabcdef1234567890000000000000000000000000000000000000000000000000"),
						Index:       7,
						Removed:     false,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "MultipleLogs",
			input: []*EthLog{
				{
					Metadata: []byte("metadata1"),
					Log: &types.Log{
						Address:     common.HexToAddress("0x2222222222222222222222222222222222222222"),
						Topics:      []common.Hash{common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")},
						Data:        []byte("data1"),
						BlockNumber: 8888,
						TxHash:      common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
						BlockHash:   common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
						Index:       1,
						Removed:     false,
					},
				},
				{
					Metadata: []byte("metadata2"),
					Log: &types.Log{
						Address:     common.HexToAddress("0x3333333333333333333333333333333333333333"),
						Topics:      []common.Hash{common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444")},
						Data:        []byte("data2"),
						BlockNumber: 9999,
						TxHash:      common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555"),
						BlockHash:   common.HexToHash("0x6666666666666666666666666666666666666666666666666666666666666666"),
						Index:       2,
						Removed:     true,
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serialized, err := serializeEthLogs(tc.input)
			require.NoError(t, err, "serializeEthLogs should not fail")

			deserialized, err := deserializeEthLogs(serialized)
			if tc.wantErr {
				require.Error(t, err, "deserializeEthLogs should fail")
				return
			}
			require.NoError(t, err, "deserializeEthLogs should not fail")

			// Compare the original slice with the deserialized slice
			require.Equal(t, len(tc.input), len(deserialized))
			for i := range tc.input {
				require.Equal(t, tc.input[i].Metadata, deserialized[i].Metadata)
				require.Equal(t, tc.input[i].Log.Address, deserialized[i].Log.Address)
				require.Equal(t, tc.input[i].Log.Data, deserialized[i].Log.Data)
				require.Equal(t, tc.input[i].Log.Topics, deserialized[i].Log.Topics)
				require.Equal(t, tc.input[i].Log.BlockNumber, deserialized[i].Log.BlockNumber)
				require.Equal(t, tc.input[i].Log.TxHash, deserialized[i].Log.TxHash)
				require.Equal(t, tc.input[i].Log.BlockHash, deserialized[i].Log.BlockHash)
				require.Equal(t, tc.input[i].Log.Index, deserialized[i].Log.Index)
				require.Equal(t, tc.input[i].Log.Removed, deserialized[i].Log.Removed)
			}
		})
	}
}

// TestSerializeDeserializeLog verifies that types.Log structures
// can be round-tripped through SerializeLog and DeserializeLog without
// losing any data.
func TestSerializeDeserializeLog(t *testing.T) {
	tests := []struct {
		name string
		log  types.Log
	}{
		{
			name: "empty",
			log: types.Log{
				Topics: []common.Hash{},
				Data:   []byte{},
			},
		},
		{
			name: "simple",
			log: types.Log{
				Address:     common.HexToAddress("0x0000000000000000000000000000000000000001"),
				Topics:      []common.Hash{},
				Data:        []byte{},
				BlockNumber: 1,
				TxHash:      common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
				TxIndex:     0,
				BlockHash:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"),
				Index:       0,
				Removed:     false,
			},
		},
		{
			name: "withdata",
			log: types.Log{
				Address: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				Topics: []common.Hash{
					common.HexToHash("0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000000000000000000000000000001"),
					common.HexToHash("0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000000000000000000000000000002"),
				},
				Data:        []byte("Some arbitrary data for testing"),
				BlockNumber: 9999999999,
				TxHash:      common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
				TxIndex:     42,
				BlockHash:   common.HexToHash("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
				Index:       1234,
				Removed:     true,
			},
		},
		{
			name: "multitopics",
			log: types.Log{
				Address: common.HexToAddress("0xbad0bad0bad0bad0bad0bad0bad0bad0bad0bad0"),
				Topics: []common.Hash{
					common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
					common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
					common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
				},
				Data:        []byte("Testing data with multiple topics"),
				BlockNumber: 12345,
				TxHash:      common.HexToHash("0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff11111111111111111111111111111111"),
				TxIndex:     99,
				BlockHash:   common.HexToHash("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabc"),
				Index:       99999,
				Removed:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			serialized, err := serializeLog(&tt.log)
			if err != nil {
				t.Fatalf("SerializeLog() error = %v", err)
			}

			// Deserialize
			deserialized, err := deserializeLog(serialized)
			if err != nil {
				t.Fatalf("DeserializeLog() error = %v", err)
			}

			// Compare
			require.EqualValues(t, tt.log, *deserialized)
		})
	}
}

// TestListenerRecoveryConstants tests that the listener recovery constants are sensible.
func TestListenerRecoveryConstants(t *testing.T) {
	// Verify that the constants are set to reasonable values
	require.Equal(t, 5*time.Second, initialRecoveryDelay, "initial delay should be 5 seconds")
	require.Equal(t, 5*time.Minute, maxRecoveryDelay, "max delay should be 5 minutes")
	require.Equal(t, 2, recoveryBackoffMultiplier, "backoff multiplier should be 2")

	// Verify that the backoff progression is sensible
	// 5s -> 10s -> 20s -> 40s -> 80s -> 160s -> 300s (capped at 5 min)
	delay := initialRecoveryDelay
	expectedDelays := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		maxRecoveryDelay, // 320s would exceed max, so capped at 300s
	}

	for i, expected := range expectedDelays {
		require.Equal(t, expected, delay, "delay at iteration %d should be %v", i, expected)
		delay = delay * time.Duration(recoveryBackoffMultiplier)
		if delay > maxRecoveryDelay {
			delay = maxRecoveryDelay
		}
	}
}

// TestDeserializeEthLogsMalformedData tests that deserialization fails with malformed data.
func TestDeserializeEthLogsMalformedData(t *testing.T) {
	// We build a buffer that's intentionally incomplete
	// (for example, we only write a single log length,
	// but then don't write the full log data).
	buf := bytes.Buffer{}

	// Suppose we declare there's a log length of 100 bytes
	// but then write only 10 bytes
	var length uint64 = 100

	err := binary.Write(&buf, binary.BigEndian, length)
	require.NoError(t, err)

	// Write only 10 bytes of data
	partialData := make([]byte, 10)
	_, err = buf.Write(partialData)
	require.NoError(t, err)

	// Try to deserialize
	_, err = deserializeEthLogs(buf.Bytes())
	require.Error(t, err, "deserialization should fail on malformed data")
}
