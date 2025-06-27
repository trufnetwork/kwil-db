package pg

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
)

func TestChangesetEntry_Serialize(t *testing.T) {
	tests := []struct {
		name string
		ce   *ChangesetEntry
	}{
		{
			name: "valid changeset entry",
			ce: &ChangesetEntry{
				RelationIdx: 1,
				OldTuple: []*TupleColumn{
					{
						ValueType: SerializedValue,
						Data:      []byte{2, 3, 4, 5},
					},
				},
				NewTuple: []*TupleColumn{
					{
						ValueType: SerializedValue,
						Data:      []byte{4, 5, 6, 7},
					},
				},
			},
		},
		{
			name: "changeset entry with empty old",
			ce: &ChangesetEntry{
				RelationIdx: 1,
				OldTuple:    []*TupleColumn{}, // nil does not round trip in RLP!
				NewTuple: []*TupleColumn{
					{
						ValueType: SerializedValue,
						Data:      []byte{4, 5, 6, 7},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First test round trip with MarshalBinary and UnmarshalBinary
			bts, err := tt.ce.MarshalBinary()
			require.NoError(t, err)

			// Deserialize and compare
			newCE := &ChangesetEntry{}
			err = newCE.UnmarshalBinary(bts)
			require.NoError(t, err)
			assert.Equal(t, tt.ce, newCE)

			// Now as a prefixed element in a stream
			var buf bytes.Buffer
			err = StreamElement(&buf, tt.ce)
			require.NoError(t, err)

			csStream := buf.Bytes()
			csType, csSize := DecodeStreamPrefix([5]byte(csStream[:5]))
			assert.Equal(t, ChangesetEntryType, csType)
			assert.Equal(t, int(csSize), len(bts))
		})
	}
}

func TestRelation_Serialize(t *testing.T) {
	tests := []struct {
		name string
		r    *Relation
	}{
		{
			name: "valid relation",
			r: &Relation{
				Schema: "ns",
				Table:  "table",
				Columns: []*Column{
					{Name: "a", Type: types.IntType},
					{Name: "b", Type: types.TextType},
				},
			},
		},
		{
			name: "changeset entry with no schema",
			r: &Relation{
				Table: "tablex",
				Columns: []*Column{
					{Name: "a", Type: types.ByteaType},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First test round trip with MarshalBinary and UnmarshalBinary
			bts, err := tt.r.MarshalBinary()
			require.NoError(t, err)

			// Deserialize and compare
			rel := &Relation{}
			err = rel.UnmarshalBinary(bts)
			require.NoError(t, err)
			assert.Equal(t, tt.r, rel)

			// Now as a prefixed element in a stream
			var buf bytes.Buffer
			err = StreamElement(&buf, tt.r)
			require.NoError(t, err)

			csStream := buf.Bytes()
			csType, csSize := DecodeStreamPrefix([5]byte(csStream[:5]))
			assert.Equal(t, RelationType, csType)
			assert.Equal(t, int(csSize), len(bts))
		})
	}
}

func TestTupleColumn_Serialize(t *testing.T) {
	tests := []struct {
		name    string
		tc      *TupleColumn
		wantErr bool
	}{
		{
			name: "empty data",
			tc: &TupleColumn{
				ValueType: SerializedValue,
				Data:      []byte{},
			},
		},
		{
			name: "large data payload",
			tc: &TupleColumn{
				ValueType: SerializedValue,
				Data:      bytes.Repeat([]byte{0xFF}, 1024*1024),
			},
		},
		{
			name: "null value type",
			tc: &TupleColumn{
				ValueType: NullValue,
				Data:      nil,
			},
		},
		{
			name: "max value type",
			tc: &TupleColumn{
				ValueType: ValueType(255),
				Data:      []byte{1, 2, 3},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bts, err := tt.tc.MarshalBinary()
			require.NoError(t, err)

			newTC := &TupleColumn{}
			err = newTC.UnmarshalBinary(bts)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.tc.ValueType, newTC.ValueType)
			assert.Equal(t, tt.tc.Data, newTC.Data)
		})
	}
}

func TestTupleColumn_UnmarshalBinary_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: "invalid tuple column data",
		},
		{
			name:    "insufficient data length",
			data:    []byte{0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
			wantErr: "invalid tuple column data",
		},
		{
			name:    "invalid version",
			data:    []byte{0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1},
			wantErr: "invalid tuple column version: 1",
		},
		{
			name:    "data length mismatch",
			data:    []byte{0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 1},
			wantErr: "invalid tuple column data length: 5",
		},
		{
			name:    "oversized length field",
			data:    append([]byte{0, 0, 1, 255, 255, 255, 255, 255, 255, 255, 255}, bytes.Repeat([]byte{1}, 10)...),
			wantErr: "data length too long:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &TupleColumn{}
			err := tc.UnmarshalBinary(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestTuple_Serialize(t *testing.T) {
	tests := []struct {
		name    string
		tup     *Tuple
		wantErr bool
	}{
		{
			name: "valid tuple with multiple columns",
			tup: &Tuple{
				RelationIdx: 42,
				Columns: []*TupleColumn{
					{
						ValueType: SerializedValue,
						Data:      []byte{1, 2, 3},
					},
					{
						ValueType: NullValue,
						Data:      nil,
					},
					{
						ValueType: SerializedValue,
						Data:      []byte{4, 5, 6},
					},
				},
			},
		},
		{
			name: "empty columns slice",
			tup: &Tuple{
				RelationIdx: 1,
				Columns:     []*TupleColumn{},
			},
		},
		{
			name: "max relation index",
			tup: &Tuple{
				RelationIdx: ^uint32(0),
				Columns: []*TupleColumn{
					{
						ValueType: SerializedValue,
						Data:      []byte{1},
					},
				},
			},
		},
		{
			name: "large number of columns",
			tup: &Tuple{
				RelationIdx: 1,
				Columns: func() []*TupleColumn {
					cols := make([]*TupleColumn, 1000)
					for i := range cols {
						cols[i] = &TupleColumn{
							ValueType: SerializedValue,
							Data:      []byte{byte(i)},
						}
					}
					return cols
				}(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bts, err := tt.tup.MarshalBinary()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			newTup := &Tuple{}
			err = newTup.UnmarshalBinary(bts)
			require.NoError(t, err)

			assert.Equal(t, tt.tup.RelationIdx, newTup.RelationIdx)
			assert.Equal(t, len(tt.tup.Columns), len(newTup.Columns))
			for i := range tt.tup.Columns {
				assert.Equal(t, tt.tup.Columns[i].ValueType, newTup.Columns[i].ValueType)
				assert.Equal(t, tt.tup.Columns[i].Data, newTup.Columns[i].Data)
			}
		})
	}
}

func TestTuple_UnmarshalBinary_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: "invalid tuple data, too short",
		},
		{
			name:    "insufficient header length",
			data:    []byte{0, 0, 0, 0, 0},
			wantErr: "invalid tuple data, too short",
		},
		{
			name:    "invalid version",
			data:    []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 1},
			wantErr: "invalid tuple data, unknown version 1",
		},
		// {
		// 	name: "corrupted column data",
		// 	data: func() []byte {
		// 		tup := &Tuple{
		// 			RelationIdx: 1,
		// 			Columns: []*TupleColumn{
		// 				{ValueType: SerializedValue, Data: []byte{1, 2, 3}},
		// 			},
		// 		}
		// 		b, _ := tup.MarshalBinary()
		// 		return append(b, 0xFF)
		// 	}(),
		// 	wantErr: "invalid tuple data, unexpected extra data",
		// },
		{
			name: "truncated column data",
			data: func() []byte {
				tup := &Tuple{
					RelationIdx: 1,
					Columns: []*TupleColumn{
						{ValueType: SerializedValue, Data: []byte{1, 2, 3}},
					},
				}
				b, _ := tup.MarshalBinary()
				return b[:len(b)-1]
			}(),
			wantErr: "invalid tuple column data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tup := &Tuple{}
			err := tup.UnmarshalBinary(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestColumn_Serialize(t *testing.T) {
	tests := []struct {
		name    string
		col     *Column
		wantErr bool
	}{
		{
			name: "column with nil type",
			col: &Column{
				Name: "test_column",
				Type: nil,
			},
		},
		{
			name: "column with empty name",
			col: &Column{
				Name: "",
				Type: types.IntType,
			},
		},
		{
			name: "column with unicode name",
			col: &Column{
				Name: "测试列名",
				Type: types.TextType,
			},
		},
		{
			name: "column with very long name",
			col: &Column{
				Name: strings.Repeat("a", 65535),
				Type: types.BoolType,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bts, err := tt.col.MarshalBinary()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			newCol := &Column{}
			err = newCol.UnmarshalBinary(bts)
			require.NoError(t, err)
			assert.Equal(t, tt.col.Name, newCol.Name)
			if tt.col.Type == nil {
				assert.Nil(t, newCol.Type)
			} else {
				assert.Equal(t, tt.col.Type, newCol.Type)
			}
		})
	}
}

func TestColumn_UnmarshalBinary_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: "invalid data",
		},
		{
			name:    "data too short",
			data:    []byte{0, 0, 0, 0},
			wantErr: "invalid data",
		},
		{
			name:    "invalid version",
			data:    []byte{0, 1, 0, 0, 0, 0},
			wantErr: "invalid column data, unknown version 1",
		},
		{
			name:    "name length exceeds data",
			data:    []byte{0, 0, 255, 255, 255, 255},
			wantErr: "invalid data, name length too long",
		},
		{
			name: "invalid datatype data",
			data: func() []byte {
				col := &Column{
					Name: "test",
					Type: types.IntType,
				}
				b, _ := col.MarshalBinary()
				return b[:len(b)-1]
			}(),
			wantErr: "invalid data length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			col := &Column{}
			err := col.UnmarshalBinary(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestRelation_SerializeSize(t *testing.T) {
	tests := []struct {
		name string
		r    *Relation
		want int
	}{
		{
			name: "empty relation",
			r: &Relation{
				Schema:  "",
				Table:   "",
				Columns: nil,
			},
			want: 14, // 2 + 4 + 0 + 4 + 0 + 4 + 0
		},
		{
			name: "relation with special chars",
			r: &Relation{
				Schema:  "schema€", // 9 bytes
				Table:   "table☺",  // 8 bytes
				Columns: []*Column{},
			},
			want: 2 + 4 + 9 + 4 + 8 + 4 + 0,
		},
		{
			name: "relation with multiple columns",
			r: &Relation{
				Schema: "test",
				Table:  "table",
				Columns: []*Column{
					{Name: "col1", Type: types.IntType},
					{Name: "col2", Type: types.TextType},
					{Name: "col3", Type: types.BoolType},
				},
			},
			want: 2 + 4 + 4 + 4 + 5 + 4 + (2 + 4 + 5 + (2 + 4 + 3 + 1 + 4)) + 2*(2+4+4+(2+4+4+1+4)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.SerializeSize()
			assert.Equal(t, tt.want, got)

			// Verify size matches actual marshaled data
			data, err := tt.r.MarshalBinary()
			require.NoError(t, err)
			assert.Equal(t, tt.want, len(data))
		})
	}
}

func TestRelation_UnmarshalBinary_Additional(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name: "invalid schema length",
			data: func() []byte {
				b := make([]byte, 10)
				binary.BigEndian.PutUint16(b[0:2], 0)
				binary.BigEndian.PutUint32(b[2:6], uint32(1<<31))
				return b
			}(),
			wantErr: "insufficient data",
		},
		{
			name: "invalid table length",
			data: func() []byte {
				b := make([]byte, 14)
				binary.BigEndian.PutUint16(b[0:2], 0)
				binary.BigEndian.PutUint32(b[2:6], 4)
				copy(b[6:10], "test")
				binary.BigEndian.PutUint32(b[10:14], uint32(1<<31))
				return b
			}(),
			wantErr: "insufficient data",
		},
		{
			name: "truncated column count",
			data: func() []byte {
				b := make([]byte, 15)
				binary.BigEndian.PutUint16(b[0:2], 0)
				binary.BigEndian.PutUint32(b[2:6], 4)
				copy(b[6:10], "test")
				binary.BigEndian.PutUint32(b[10:14], 4)
				copy(b[14:15], "t")
				return b
			}(),
			wantErr: "insufficient data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Relation{}
			err := r.UnmarshalBinary(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestRelation_BinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		rel  *Relation
	}{
		{
			name: "full relation with multiple columns",
			rel: &Relation{
				Schema: "public",
				Table:  "users",
				Columns: []*Column{
					{Name: "id", Type: types.IntType},
					{Name: "name", Type: types.TextType},
					{Name: "active", Type: types.BoolType},
				},
			},
		},
		{
			name: "relation with unicode chars",
			rel: &Relation{
				Schema: "测试",
				Table:  "テーブル",
				Columns: []*Column{
					{Name: "名前", Type: types.TextType},
				},
			},
		},
		{
			name: "minimal relation with empty non-nil cols slice",
			rel: &Relation{
				Schema:  "",
				Table:   "minimal",
				Columns: []*Column{},
			},
		},
		{
			name: "minimal relation with nil cols slice",
			rel: &Relation{
				Schema:  "",
				Table:   "minimal",
				Columns: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.rel.MarshalBinary()
			require.NoError(t, err)

			// Unmarshal into new struct
			newRel := &Relation{}
			err = newRel.UnmarshalBinary(data)
			require.NoError(t, err)

			// Verify fields match
			assert.Equal(t, tt.rel.Schema, newRel.Schema)
			assert.Equal(t, tt.rel.Table, newRel.Table)
			assert.Equal(t, len(tt.rel.Columns), len(newRel.Columns))

			// Verify columns match
			for i, col := range tt.rel.Columns {
				assert.Equal(t, col.Name, newRel.Columns[i].Name)
				assert.Equal(t, col.Type, newRel.Columns[i].Type)
			}

			// Verify full structs are equal
			assert.Equal(t, tt.rel, newRel)
		})
	}
}
