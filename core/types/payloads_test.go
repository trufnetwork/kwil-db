package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
)

type StringTestPayload struct {
	val string
}

func (tp StringTestPayload) MarshalBinary() ([]byte, error) {
	return []byte(tp.val), nil
}

func (tp *StringTestPayload) UnmarshalBinary(data []byte) error {
	tp.val = string(data)
	return nil
}

func (tp *StringTestPayload) Type() PayloadType {
	return "testPayload"
}

func init() {
	RegisterPayload("testPayload")
}

func TestValidPayload(t *testing.T) {
	testcases := []struct {
		name  string
		pt    PayloadType
		valid bool
	}{
		{"kv pair payload", PayloadTypeExecute, true},
		{"registered payload", "testPayload", true},
		{"invalid payload", PayloadType("unknown"), false},
	}

	for _, tc := range testcases {
		if got := tc.pt.Valid(); got != tc.valid {
			t.Errorf("Expected %v to be %v, got %v", tc.pt, tc.valid, got)
		}
	}
}

func TestMarshalUnmarshalPayload(t *testing.T) {
	tp := &StringTestPayload{"test"}
	data, err := tp.MarshalBinary()
	require.NoError(t, err)

	var tp2 StringTestPayload
	err = tp2.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, tp.val, tp2.val)
}

func TestValidatorVoteBodyMarshalUnmarshal(t *testing.T) {
	voteBody := &ValidatorVoteBodies{
		Events: []*VotableEvent{
			{
				Type: "emptydata",
				Body: []byte(""),
			},
			{
				Type: "test",
				Body: []byte("test"),
			},
			{
				Type: "test2",
				Body: []byte("random large data, random large data,random large data,random large data,random large data,random large data,random large data,random large data,random large data,random large data,random large data,random large data,random large data,"),
			},
		},
	}

	data, err := voteBody.MarshalBinary()
	require.NoError(t, err)

	voteBody2 := &ValidatorVoteBodies{}
	err = voteBody2.UnmarshalBinary(data)
	require.NoError(t, err)

	require.NotNil(t, voteBody2)
	require.NotNil(t, voteBody2.Events)
	require.Len(t, voteBody2.Events, 3)

	require.Equal(t, voteBody.Events, voteBody2.Events)
}

func TestValidatorRemove_MarshalUnmarshal(t *testing.T) {
	t.Run("valid validator remove", func(t *testing.T) {
		original := ValidatorRemove{
			Validator: []byte("validator-pubkey"),
			KeyType:   crypto.KeyTypeSecp256k1,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorRemove
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original, unmarshaled)
	})

	t.Run("empty validator", func(t *testing.T) {
		original := ValidatorRemove{
			Validator: []byte{},
			KeyType:   crypto.KeyTypeSecp256k1,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorRemove
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original, unmarshaled)
	})

	t.Run("invalid version", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(1))
		WriteBytes(buf, []byte("validator"))
		WriteString(buf, string(crypto.KeyTypeSecp256k1)) // binary.Write(buf, SerializationByteOrder, int32(crypto.KeyTypeSecp256k1))

		var unmarshaled ValidatorRemove
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid validator remove payload version")
	})

	t.Run("invalid key type", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(vrVersion))
		WriteBytes(buf, []byte("validator"))
		// ktStr := "invalid-key-type"
		// binary.Write(buf, SerializationByteOrder, uint16(len(ktStr)))
		// buf.WriteString(ktStr)
		binary.Write(buf, SerializationByteOrder, uint32(999))

		var unmarshaled ValidatorRemove
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key type encoding")
	})

	t.Run("truncated data", func(t *testing.T) {
		original := ValidatorRemove{
			Validator: []byte("validator-pubkey"),
			KeyType:   crypto.KeyTypeSecp256k1,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorRemove
		err = unmarshaled.UnmarshalBinary(data[:len(data)-1])
		require.Error(t, err)
	})

	t.Run("empty data", func(t *testing.T) {
		var unmarshaled ValidatorRemove
		err := unmarshaled.UnmarshalBinary([]byte{})
		require.Error(t, err)
	})
}

func TestValidatorLeave_MarshalUnmarshal(t *testing.T) {
	t.Run("valid marshal", func(t *testing.T) {
		vl := ValidatorLeave{}
		data, err := vl.MarshalBinary()
		require.NoError(t, err)
		require.Len(t, data, 2)
		require.Equal(t, uint16(vlVersion), binary.LittleEndian.Uint16(data))
	})

	t.Run("valid unmarshal", func(t *testing.T) {
		data := make([]byte, 2)
		binary.LittleEndian.PutUint16(data, vlVersion)

		var vl ValidatorLeave
		err := vl.UnmarshalBinary(data)
		require.NoError(t, err)
	})

	t.Run("invalid length - too short", func(t *testing.T) {
		var vl ValidatorLeave
		err := vl.UnmarshalBinary([]byte{0x01})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid validator leave payload")
	})

	t.Run("invalid length - too long", func(t *testing.T) {
		var vl ValidatorLeave
		err := vl.UnmarshalBinary([]byte{0x01, 0x00, 0x00})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid validator leave payload")
	})

	t.Run("invalid version", func(t *testing.T) {
		data := make([]byte, 2)
		binary.LittleEndian.PutUint16(data, vlVersion+1)

		var vl ValidatorLeave
		err := vl.UnmarshalBinary(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid validator leave payload version")
	})

	t.Run("empty data", func(t *testing.T) {
		var vl ValidatorLeave
		err := vl.UnmarshalBinary([]byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid validator leave payload")
	})
}

func TestValidatorApprove_MarshalUnmarshal(t *testing.T) {
	t.Run("valid validator approve", func(t *testing.T) {
		original := ValidatorApprove{
			Candidate: []byte("candidate-pubkey"),
			KeyType:   crypto.KeyTypeEd25519,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorApprove
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original, unmarshaled)
	})

	t.Run("large candidate key", func(t *testing.T) {
		original := ValidatorApprove{
			Candidate: bytes.Repeat([]byte("x"), 1000),
			KeyType:   crypto.KeyTypeSecp256k1,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorApprove
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original, unmarshaled)
	})

	t.Run("nil candidate", func(t *testing.T) {
		original := ValidatorApprove{
			Candidate: nil,
			KeyType:   crypto.KeyTypeSecp256k1,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorApprove
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original, unmarshaled)
	})

	t.Run("corrupted version bytes", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, []byte{0xFF})
		WriteBytes(buf, []byte("candidate"))
		WriteString(buf, string(crypto.KeyTypeSecp256k1)) // binary.Write(buf, SerializationByteOrder, int32(crypto.KeyTypeSecp256k1))

		var unmarshaled ValidatorApprove
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("corrupted key type bytes", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(vrVersion))
		WriteBytes(buf, []byte("candidate"))
		buf.Write([]byte{0xFF})

		var unmarshaled ValidatorApprove
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("partial read of candidate", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(vrVersion))
		binary.Write(buf, SerializationByteOrder, uint32(10))
		buf.Write([]byte("short"))

		var unmarshaled ValidatorApprove
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})
}

func TestValidatorJoin_MarshalUnmarshal(t *testing.T) {
	t.Run("valid validator join", func(t *testing.T) {
		original := ValidatorJoin{
			Power: 1000,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorJoin
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original, unmarshaled)
	})

	t.Run("zero power", func(t *testing.T) {
		original := ValidatorJoin{
			Power: 0,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorJoin
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original, unmarshaled)
	})

	t.Run("max power", func(t *testing.T) {
		original := ValidatorJoin{
			Power: ^uint64(0),
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorJoin
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original, unmarshaled)
	})

	t.Run("truncated data", func(t *testing.T) {
		var vj ValidatorJoin
		err := vj.UnmarshalBinary(make([]byte, 9))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid length")
	})

	t.Run("invalid version", func(t *testing.T) {
		data := make([]byte, 10)
		binary.LittleEndian.PutUint16(data, vjVersion+1)
		binary.LittleEndian.PutUint64(data[2:], 1000)

		var vj ValidatorJoin
		err := vj.UnmarshalBinary(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid version")
	})

	t.Run("empty data", func(t *testing.T) {
		var vj ValidatorJoin
		err := vj.UnmarshalBinary([]byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid length")
	})
}

func TestValidatorVoteIDs_MarshalUnmarshal(t *testing.T) {
	t.Run("empty resolution IDs", func(t *testing.T) {
		original := &ValidatorVoteIDs{
			ResolutionIDs: []*UUID{},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorVoteIDs
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Empty(t, unmarshaled.ResolutionIDs)
		require.Equal(t, original, &unmarshaled)
	})

	t.Run("multiple resolution IDs", func(t *testing.T) {
		original := &ValidatorVoteIDs{
			ResolutionIDs: []*UUID{
				{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ValidatorVoteIDs
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Len(t, unmarshaled.ResolutionIDs, 2)
		require.Equal(t, original, &unmarshaled)
	})

	t.Run("invalid version", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint16(999))
		binary.Write(buf, binary.LittleEndian, uint32(1))

		var unmarshaled ValidatorVoteIDs
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown version")
	})

	t.Run("truncated data after version", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint16(vvidVersion))

		var unmarshaled ValidatorVoteIDs
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("truncated data after length", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint16(vvidVersion))
		binary.Write(buf, binary.LittleEndian, uint32(1))

		var unmarshaled ValidatorVoteIDs
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("invalid UUID data", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint16(vvidVersion))
		binary.Write(buf, binary.LittleEndian, uint32(1))
		WriteBytes(buf, []byte{1, 2, 3}) // Invalid UUID bytes

		var unmarshaled ValidatorVoteIDs
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("empty input", func(t *testing.T) {
		var unmarshaled ValidatorVoteIDs
		err := unmarshaled.UnmarshalBinary([]byte{})
		require.Error(t, err)
	})
}

func TestCreateResolution_MarshalUnmarshal(t *testing.T) {
	t.Run("valid create resolution", func(t *testing.T) {
		original := CreateResolution{
			Resolution: &VotableEvent{
				Type: "test_event",
				Body: []byte("test event data"),
			},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled CreateResolution
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Resolution.Type, unmarshaled.Resolution.Type)
		require.Equal(t, original.Resolution.Body, unmarshaled.Resolution.Body)
	})

	t.Run("nil resolution", func(t *testing.T) {
		original := CreateResolution{
			Resolution: &VotableEvent{
				Type: "empty",
				Body: nil,
			},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled CreateResolution
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Resolution.Type, unmarshaled.Resolution.Type)
		require.Nil(t, unmarshaled.Resolution.Body)
	})

	t.Run("empty data unmarshal", func(t *testing.T) {
		var cr CreateResolution
		err := cr.UnmarshalBinary([]byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload")
	})

	t.Run("invalid version", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint16(999))
		binary.Write(buf, binary.LittleEndian, []byte("test"))

		var cr CreateResolution
		err := cr.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown version")
	})

	t.Run("corrupted resolution data", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint16(crVersion))
		binary.Write(buf, binary.LittleEndian, []byte{0xFF, 0xFF})

		var cr CreateResolution
		err := cr.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("large resolution body", func(t *testing.T) {
		original := CreateResolution{
			Resolution: &VotableEvent{
				Type: "large_event",
				Body: bytes.Repeat([]byte("x"), 1000),
			},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled CreateResolution
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Resolution.Type, unmarshaled.Resolution.Type)
		require.Equal(t, original.Resolution.Body, unmarshaled.Resolution.Body)
	})
}

func TestApproveResolution_MarshalUnmarshal(t *testing.T) {
	t.Run("valid approve resolution", func(t *testing.T) {
		original := ApproveResolution{
			ResolutionID: &UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled ApproveResolution
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.ResolutionID, unmarshaled.ResolutionID)
	})

	t.Run("nil resolution ID", func(t *testing.T) {
		original := ApproveResolution{
			ResolutionID: nil,
		}

		_, err := original.MarshalBinary()
		require.Error(t, err)
	})

	t.Run("truncated data", func(t *testing.T) {
		data := make([]byte, 3)
		binary.LittleEndian.PutUint16(data, arVersion)
		data[2] = 1

		var unmarshaled ApproveResolution
		err := unmarshaled.UnmarshalBinary(data)
		require.Error(t, err)
	})

	t.Run("invalid version", func(t *testing.T) {
		data := make([]byte, 18)
		binary.LittleEndian.PutUint16(data, arVersion+1)

		var unmarshaled ApproveResolution
		err := unmarshaled.UnmarshalBinary(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown version")
	})

	t.Run("empty data", func(t *testing.T) {
		var unmarshaled ApproveResolution
		err := unmarshaled.UnmarshalBinary([]byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload")
	})

	t.Run("exactly 2 bytes", func(t *testing.T) {
		data := make([]byte, 2)
		binary.LittleEndian.PutUint16(data, arVersion)

		var unmarshaled ApproveResolution
		err := unmarshaled.UnmarshalBinary(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload")
	})

	t.Run("invalid UUID length", func(t *testing.T) {
		data := make([]byte, 10)
		binary.LittleEndian.PutUint16(data, arVersion)

		var unmarshaled ApproveResolution
		err := unmarshaled.UnmarshalBinary(data)
		require.Error(t, err)
	})
}

func TestDeleteResolution_MarshalUnmarshal(t *testing.T) {
	t.Run("valid delete resolution", func(t *testing.T) {
		original := DeleteResolution{
			ResolutionID: &UUID{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled DeleteResolution
		err = unmarshaled.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.ResolutionID, unmarshaled.ResolutionID)
	})

	t.Run("nil resolution ID marshal", func(t *testing.T) {
		original := DeleteResolution{
			ResolutionID: nil,
		}

		_, err := original.MarshalBinary()
		require.Error(t, err)
	})

	t.Run("payload type check", func(t *testing.T) {
		dr := &DeleteResolution{}
		require.Equal(t, PayloadTypeDeleteResolution, dr.Type())
	})

	t.Run("unmarshal with exactly 2 bytes", func(t *testing.T) {
		data := make([]byte, 2)
		binary.LittleEndian.PutUint16(data, drVersion)

		var unmarshaled DeleteResolution
		err := unmarshaled.UnmarshalBinary(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload")
	})

	t.Run("unmarshal with invalid UUID size", func(t *testing.T) {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, uint16(drVersion))
		buf.Write([]byte{1, 2, 3, 4}) // Invalid UUID size

		var unmarshaled DeleteResolution
		err := unmarshaled.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("marshal binary write error simulation", func(t *testing.T) {
		original := DeleteResolution{
			ResolutionID: &UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)
		require.Greater(t, len(data), 2)
		require.Equal(t, uint16(drVersion), binary.LittleEndian.Uint16(data[:2]))
	})
}

func TestRawStatement_MarshalUnmarshal(t *testing.T) {
	t.Run("complex statement with multiple parameters", func(t *testing.T) {
		original := RawStatement{
			Statement: "SELECT * FROM table WHERE col1 = @param1 AND col2 = @param2 AND col3 = @param3",
			Parameters: []*NamedValue{
				{Name: "param1", Value: &EncodedValue{
					Type: DataType{Name: TextType.Name},
					Data: [][]byte{[]byte("hello")},
				}},
				{Name: "param2", Value: &EncodedValue{
					Type: DataType{Name: IntType.Name},
					Data: [][]byte{binary.BigEndian.AppendUint64(nil, 123)},
				}},
				{Name: "param3", Value: &EncodedValue{
					Type: DataType{Name: BoolType.Name},
					Data: [][]byte{{1}},
				}},
			},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var decoded RawStatement
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Statement, decoded.Statement)
		require.Len(t, decoded.Parameters, len(original.Parameters))
		for i, p := range original.Parameters {
			require.Equal(t, p.Name, decoded.Parameters[i].Name)
			require.Equal(t, p.Value, decoded.Parameters[i].Value)
		}
	})

	t.Run("empty statement with no parameters", func(t *testing.T) {
		original := RawStatement{
			Statement:  "",
			Parameters: []*NamedValue{},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var decoded RawStatement
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Statement, decoded.Statement)
		require.Empty(t, decoded.Parameters)
	})

	t.Run("max parameters limit", func(t *testing.T) {
		params := make([]*NamedValue, 65535)
		for i := range params {
			params[i] = &NamedValue{
				Name: fmt.Sprintf("param%d", i),
				Value: &EncodedValue{
					Type: DataType{Name: TextType.Name},
					Data: [][]byte{[]byte("value")},
				},
			}
		}

		original := RawStatement{
			Statement:  "SELECT * FROM table",
			Parameters: params,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var decoded RawStatement
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Statement, decoded.Statement)
		require.Len(t, decoded.Parameters, len(original.Parameters))
	})

	t.Run("invalid version", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(999))
		WriteString(buf, "SELECT 1")
		binary.Write(buf, SerializationByteOrder, uint16(0))

		var decoded RawStatement
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported version")
	})

	t.Run("truncated data after version", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(rsVersion))

		var decoded RawStatement
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("truncated data after statement", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(rsVersion))
		WriteString(buf, "SELECT 1")

		var decoded RawStatement
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("truncated data during parameter reading", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(rsVersion))
		WriteString(buf, "SELECT 1")
		binary.Write(buf, SerializationByteOrder, uint16(1))
		WriteString(buf, "param1")

		var decoded RawStatement
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})
}

func TestActionExecution_MarshalUnmarshal(t *testing.T) {
	t.Run("valid action execution with multiple calls", func(t *testing.T) {
		original := ActionExecution{
			Namespace: "testdb",
			Action:    "test_action",
			Arguments: [][]*EncodedValue{
				{
					{Type: DataType{Name: TextType.Name}, Data: [][]byte{[]byte("arg1")}},
					{Type: DataType{Name: IntType.Name}, Data: [][]byte{binary.BigEndian.AppendUint64(nil, 42)}},
				},
				{
					{Type: DataType{Name: BoolType.Name}, Data: [][]byte{{1}}},
					{Type: DataType{Name: TextType.Name}, Data: [][]byte{[]byte("arg2")}},
				},
			},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var decoded ActionExecution
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Namespace, decoded.Namespace)
		require.Equal(t, original.Action, decoded.Action)
		require.Equal(t, len(original.Arguments), len(decoded.Arguments))
		require.Equal(t, original.Arguments, decoded.Arguments)
	})

	t.Run("empty arguments array", func(t *testing.T) {
		original := ActionExecution{
			Namespace: "testdb",
			Action:    "empty_action",
			Arguments: [][]*EncodedValue{},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var decoded ActionExecution
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Namespace, decoded.Namespace)
		require.Equal(t, original.Action, decoded.Action)
		require.Empty(t, decoded.Arguments)
	})

	t.Run("empty strings for Namespace and Action", func(t *testing.T) {
		original := ActionExecution{
			Namespace: "",
			Action:    "",
			Arguments: [][]*EncodedValue{
				{
					{Type: DataType{Name: TextType.Name}, Data: [][]byte{[]byte("test")}},
				},
			},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var decoded ActionExecution
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Empty(t, decoded.Namespace)
		require.Empty(t, decoded.Action)
		require.Len(t, decoded.Arguments, 1)
	})

	t.Run("invalid version", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(999))
		WriteString(buf, "testdb")
		WriteString(buf, "action")
		binary.Write(buf, SerializationByteOrder, uint16(0))

		var decoded ActionExecution
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported version")
	})

	t.Run("truncated data after version", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(aeVersion))

		var decoded ActionExecution
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("truncated data during arguments reading", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(aeVersion))
		WriteString(buf, "testdb")
		WriteString(buf, "action")
		binary.Write(buf, SerializationByteOrder, uint16(1))
		binary.Write(buf, SerializationByteOrder, uint16(1))

		var decoded ActionExecution
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("corrupted encoded value in arguments", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(aeVersion))
		WriteString(buf, "testdb")
		WriteString(buf, "action")
		binary.Write(buf, SerializationByteOrder, uint16(1))
		binary.Write(buf, SerializationByteOrder, uint16(1))
		WriteBytes(buf, []byte{0xFF, 0xFF})

		var decoded ActionExecution
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})
}

func TestActionCall_MarshalUnmarshal(t *testing.T) {
	t.Run("valid action call with multiple arguments", func(t *testing.T) {
		original := ActionCall{
			Namespace: "testdb",
			Action:    "test_action",
			Arguments: []*EncodedValue{
				{
					Type: DataType{Name: TextType.Name},
					Data: [][]byte{[]byte("arg1")},
				},
				{
					Type: DataType{Name: IntType.Name},
					Data: [][]byte{binary.BigEndian.AppendUint64(nil, 42)},
				},
			},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var decoded ActionCall
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Namespace, decoded.Namespace)
		require.Equal(t, original.Action, decoded.Action)
		require.Len(t, decoded.Arguments, len(original.Arguments))
		for i, arg := range original.Arguments {
			require.Equal(t, arg.Type, decoded.Arguments[i].Type)
			require.Equal(t, arg.Data, decoded.Arguments[i].Data)
		}
	})

	t.Run("empty namespace and action with no arguments", func(t *testing.T) {
		original := ActionCall{
			Namespace: "",
			Action:    "",
			Arguments: []*EncodedValue{},
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var decoded ActionCall
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Namespace, decoded.Namespace)
		require.Equal(t, original.Action, decoded.Action)
		require.Empty(t, decoded.Arguments)
	})

	t.Run("max number of arguments", func(t *testing.T) {
		args := make([]*EncodedValue, 65535)
		for i := range args {
			args[i] = &EncodedValue{
				Type: DataType{Name: TextType.Name},
				Data: [][]byte{[]byte(fmt.Sprintf("arg%d", i))},
			}
		}

		original := ActionCall{
			Namespace: "testdb",
			Action:    "bulk_action",
			Arguments: args,
		}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		var decoded ActionCall
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		require.Equal(t, original.Namespace, decoded.Namespace)
		require.Equal(t, original.Action, decoded.Action)
		require.Len(t, decoded.Arguments, len(original.Arguments))
	})

	t.Run("invalid version", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(999))
		WriteString(buf, "testdb")
		WriteString(buf, "action")
		binary.Write(buf, SerializationByteOrder, uint16(0))

		var decoded ActionCall
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported version")
	})

	t.Run("truncated data after version", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(acVersion))

		var decoded ActionCall
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("truncated data after namespace", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(acVersion))
		WriteString(buf, "testdb")

		var decoded ActionCall
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("truncated data during argument reading", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(acVersion))
		WriteString(buf, "testdb")
		WriteString(buf, "action")
		binary.Write(buf, SerializationByteOrder, uint16(1))

		var decoded ActionCall
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})

	t.Run("invalid encoded value in arguments", func(t *testing.T) {
		buf := &bytes.Buffer{}
		binary.Write(buf, SerializationByteOrder, uint16(acVersion))
		WriteString(buf, "testdb")
		WriteString(buf, "action")
		binary.Write(buf, SerializationByteOrder, uint16(1))
		WriteBytes(buf, []byte{0xFF, 0xFF}) // Invalid encoded value

		var decoded ActionCall
		err := decoded.UnmarshalBinary(buf.Bytes())
		require.Error(t, err)
	})
}
