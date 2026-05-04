package pg

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/jackc/pglogrepl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
)

// newTestChangesetWriter builds a changesetIoWriter wired to a buffered channel
// so tests can drive decodeInsert/decodeUpdate/decodeDelete without a live
// Postgres connection. The OID-to-type map covers the OID used by the test
// relations below.
func newTestChangesetWriter(buffer int) (*changesetIoWriter, chan any) {
	csChan := make(chan any, buffer)
	cs := &changesetIoWriter{
		csChan: csChan,
		oidToType: map[uint32]*datatype{
			23: {KwilType: types.IntType}, // pg int4; SerializeChangeset never invoked for Null tuple cols
		},
		metadata: &changesetMetadata{relationIdx: map[[2]string]int{}},
	}
	return cs, csChan
}

func testRelation() *pglogrepl.RelationMessageV2 {
	return &pglogrepl.RelationMessageV2{
		RelationMessage: pglogrepl.RelationMessage{
			RelationID:   1,
			Namespace:    "main",
			RelationName: "primitive_events",
			Columns: []*pglogrepl.RelationMessageColumn{
				{Name: "id", DataType: 23},
			},
		},
	}
}

// TestDecodeUpdate_NilOldTuple is the regression test for the mainnet leader
// SIGSEGV in convertPgxTuple at repl_changeset.go:581. Postgres' logical decoder
// emits UPDATE messages with OldTuple==nil whenever the source table has
// REPLICA IDENTITY DEFAULT/INDEX/NOTHING and the key columns are unchanged.
// Pre-fix, decodeUpdate dereferenced that nil and crashed the process; this
// test asserts the consumer is now nil-tolerant.
func TestDecodeUpdate_NilOldTuple(t *testing.T) {
	cs, csChan := newTestChangesetWriter(4)
	relation := testRelation()

	update := &pglogrepl.UpdateMessageV2{
		UpdateMessage: pglogrepl.UpdateMessage{
			RelationID: 1,
			OldTuple:   nil, // the WAL shape that previously crashed the leader
			NewTuple: &pglogrepl.TupleData{
				ColumnNum: 1,
				Columns: []*pglogrepl.TupleDataColumn{
					{DataType: pglogrepl.TupleDataTypeNull},
				},
			},
		},
	}

	require.NotPanics(t, func() {
		require.NoError(t, cs.decodeUpdate(update, relation))
	})

	// First message off the channel is the registered relation, second is the
	// changeset entry. The entry must have no OldTuple but a populated NewTuple.
	msg := <-csChan
	_, isRel := msg.(*Relation)
	require.True(t, isRel, "first csChan element should be *Relation, got %T", msg)

	ce, ok := (<-csChan).(*ChangesetEntry)
	require.True(t, ok)
	assert.Nil(t, ce.OldTuple, "OldTuple must remain unset when WAL omits it")
	require.Len(t, ce.NewTuple, 1)
	assert.Equal(t, NullValue, ce.NewTuple[0].ValueType)
	// Document the downstream consequence: with no OldTuple, Kind() classifies
	// this entry as Insert and ApplyChangesetEntry will route it to applyInserts
	// (ON CONFLICT DO NOTHING) on the receiving network. decodeUpdate logs a
	// warning for operator visibility — see the else-branch in decodeUpdate.
	assert.Equal(t, CSEntryKindInsert, ce.Kind())
}

// TestDecodeUpdate_FullReplicaIdentity confirms that the dedup loop still
// runs (and marks identical columns as UnchangedUpdate) when the WAL carries
// both an old and a new tuple — i.e., REPLICA IDENTITY FULL behaves as before.
func TestDecodeUpdate_FullReplicaIdentity(t *testing.T) {
	cs, csChan := newTestChangesetWriter(4)
	relation := testRelation()

	tupleNull := func() *pglogrepl.TupleData {
		return &pglogrepl.TupleData{
			ColumnNum: 1,
			Columns: []*pglogrepl.TupleDataColumn{
				{DataType: pglogrepl.TupleDataTypeNull},
			},
		}
	}

	update := &pglogrepl.UpdateMessageV2{
		UpdateMessage: pglogrepl.UpdateMessage{
			RelationID:   1,
			OldTupleType: pglogrepl.UpdateMessageTupleTypeOld,
			OldTuple:     tupleNull(),
			NewTuple:     tupleNull(),
		},
	}

	require.NoError(t, cs.decodeUpdate(update, relation))

	<-csChan // discard relation
	ce := (<-csChan).(*ChangesetEntry)
	require.Len(t, ce.OldTuple, 1)
	require.Len(t, ce.NewTuple, 1)
	assert.Equal(t, NullValue, ce.OldTuple[0].ValueType)
	// Identical tuples → NewTuple column is collapsed to UnchangedUpdate.
	assert.Equal(t, UnchangedUpdate, ce.NewTuple[0].ValueType)
	assert.Nil(t, ce.NewTuple[0].Data)
}

// TestDecodeDelete_NilOldTuple covers the defense-in-depth nil-check on
// decodeDelete. Postgres normally always emits an old tuple for DELETE, but
// since the same convertPgxTuple deref pattern existed there too, we lock in
// that the consumer no longer panics if a future PG/replication change ever
// produces an OldTuple-less DELETE.
func TestDecodeDelete_NilOldTuple(t *testing.T) {
	cs, csChan := newTestChangesetWriter(4)
	relation := testRelation()

	del := &pglogrepl.DeleteMessageV2{
		DeleteMessage: pglogrepl.DeleteMessage{
			RelationID: 1,
			OldTuple:   nil,
		},
	}

	require.NotPanics(t, func() {
		require.NoError(t, cs.decodeDelete(del, relation))
	})

	<-csChan // relation
	ce, ok := (<-csChan).(*ChangesetEntry)
	require.True(t, ok)
	assert.Nil(t, ce.OldTuple)
	assert.Nil(t, ce.NewTuple)
}

// TestDecodeDelete_WithOldTuple confirms the normal DELETE path still records
// the old tuple unchanged.
func TestDecodeDelete_WithOldTuple(t *testing.T) {
	cs, csChan := newTestChangesetWriter(4)
	relation := testRelation()

	del := &pglogrepl.DeleteMessageV2{
		DeleteMessage: pglogrepl.DeleteMessage{
			RelationID:   1,
			OldTupleType: pglogrepl.DeleteMessageTupleTypeOld,
			OldTuple: &pglogrepl.TupleData{
				ColumnNum: 1,
				Columns: []*pglogrepl.TupleDataColumn{
					{DataType: pglogrepl.TupleDataTypeNull},
				},
			},
		},
	}

	require.NoError(t, cs.decodeDelete(del, relation))

	<-csChan // relation
	ce := (<-csChan).(*ChangesetEntry)
	require.Len(t, ce.OldTuple, 1)
	assert.Equal(t, NullValue, ce.OldTuple[0].ValueType)
	assert.Nil(t, ce.NewTuple)
}

// TestApplyDeletes_RefusesEmptyOldTuple locks in the guard against building a
// bare "DELETE FROM x.y WHERE " SQL string. The guard returns before tx is
// touched, so a nil sql.DB is safe to pass here.
func TestApplyDeletes_RefusesEmptyOldTuple(t *testing.T) {
	rel := &Relation{
		Schema:  "main",
		Table:   "primitive_events",
		Columns: []*Column{{Name: "id", Type: types.IntType}},
	}
	ce := &ChangesetEntry{RelationIdx: 0} // OldTuple unset

	err := ce.applyDeletes(context.Background(), nil, rel)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no old tuple")
}

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
