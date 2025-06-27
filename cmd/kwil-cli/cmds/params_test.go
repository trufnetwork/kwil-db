package cmds

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
)

func Test_ParseInputs(t *testing.T) {
	type testcase struct {
		input   string
		name    string
		want    any
		wantErr bool
	}

	tests := []testcase{
		// scalars
		{"username:text=satoshi", "username", "satoshi", false},
		{`username:text="satoshi"`, "username", "satoshi", false},
		{"username:text='satoshi'", "username", "satoshi", false},
		{"username:text='null'", "username", "null", false},
		{"age:int=25", "age", int64(25), false},
		{"age:int8='25'", "age", nil, true}, // shouldnt have quotes around the value
		{"balance:numeric(10,5)=100.5", "balance", *types.MustParseDecimalExplicit("100.5", 10, 5), false},
		{"balance:numeric(2,1)=100.5", "balance", nil, true}, // not enough precision
		{"id:uuid=123e4567-e89b-12d3-a456-426614174000", "id", *types.MustParseUUID("123e4567-e89b-12d3-a456-426614174000"), false},
		{"bts:bytea=010203;hex", "bts", []byte{1, 2, 3}, false},
		{"bts:bytea=AQID;b64", "bts", []byte{1, 2, 3}, false},
		{"bts:bytea=AQID;base64", "bts", []byte{1, 2, 3}, false},
		{"bts:bytea=AQID", "bts", []byte{1, 2, 3}, false}, // no encoding specified, should default to base64
		{"bool:boolean=", "bool", nil, true},              // nulls for scalar must be explicit
		{"bool:boolean=null", "bool", nil, false},
		{"bool:boolean=true", "bool", true, false},
		{"bool:invalidtype=true", "bool", nil, true},

		// arrays
		{"names:text[]='satoshi'", "names", ptrArr[string]("satoshi"), false},
		{"names:text[]='satoshi', 'nakamoto'", "names", ptrArr[string]("satoshi", "nakamoto"), false},
		{"ages:int8[]=25,26", "ages", ptrArr[int64](int64(25), int64(26)), false},
		{"ages:int8[]=25,", "ages", ptrArr[int64](int64(25), nil), false},
		{"ages:int8[]=null", "ages", nil, false},
		{"ages:int8[]=[null]", "ages", ptrArr[int64](nil), false},
		{"nums:numeric(10,5)[]=100.5,200.5", "nums", ptrArr[types.Decimal](*types.MustParseDecimalExplicit("100.5", 10, 5), *types.MustParseDecimalExplicit("200.5", 10, 5)), false},
		{"ids:uuid[]=123e4567-e89b-12d3-a456-426614174000,123e4567-e89b-12d3-a456-426614174001", "ids", ptrArr[types.UUID](*types.MustParseUUID("123e4567-e89b-12d3-a456-426614174000"), *types.MustParseUUID("123e4567-e89b-12d3-a456-426614174001")), false},
		{"bts:bytea[]=010203,040506;hex", "bts", ptrArr[[]byte]([]byte{1, 2, 3}, []byte{4, 5, 6}), false},
		{"bts:bytea[]=AQID,BAUG;b64", "bts", ptrArr[[]byte]([]byte{1, 2, 3}, []byte{4, 5, 6}), false},
		{"bts:bytea[]=AQID,BAUG;base64", "bts", ptrArr[[]byte]([]byte{1, 2, 3}, []byte{4, 5, 6}), false},
		{"bts:bytea[]=AQID,BAUG", "bts", ptrArr[[]byte]([]byte{1, 2, 3}, []byte{4, 5, 6}), false}, // no encoding specified, should default to base64
		{"bts:bytea[]=AQID,null", "bts", ptrArr[[]byte]([]byte{1, 2, 3}, nil), false},
		{"bools:boolean[]=", "bools", ptrArr[bool](), false}, // no value for an array is a zero value (zero length array), not null
		{"bools:boolean[]=[]", "bools", ptrArr[bool](), false},
		{"bools:boolean[]=true,false", "bools", ptrArr[bool](true, false), false},
		{"nums:numeric(10,5)[]=100.5,200.5", "nums", ptrArr[types.Decimal](*types.MustParseDecimalExplicit("100.5", 10, 5), *types.MustParseDecimalExplicit("200.5", 10, 5)), false},
		{"nums:numeric(10,5)[]=[100.5,200.5000]", "nums", ptrArr[types.Decimal](*types.MustParseDecimalExplicit("100.5", 10, 5), *types.MustParseDecimalExplicit("200.5", 10, 5)), false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseParams([]string{tt.input})
			if err != nil {
				if !tt.wantErr {
					t.Fatal(err)
				}

				return
			}
			if tt.wantErr {
				t.Fatalf("expected error, got %v", got)
			}

			require.Len(t, got, 1)

			out, ok := got[tt.name]
			require.True(t, ok)

			if tt.want == nil && out == nil {
				return
			}

			var rec any = out
			// if out is a pointer, dereference it
			typeof := reflect.TypeOf(rec)
			if typeof.Kind() == reflect.Ptr {
				rec = reflect.ValueOf(rec).Elem().Interface()
			}

			assert.EqualValues(t, tt.want, rec)
		})
	}
}

func Test_StringToVal(t *testing.T) {
	type testcase struct {
		str  string
		dt   *types.DataType
		want any
	}

	tests := []testcase{
		{"satoshi", types.TextType, ptr("satoshi")},
		{"satoshi,nakamoto", types.TextArrayType, ptr(ptrArr[string]("satoshi", "nakamoto"))},
		{"a0195549-8982-4f94-956d-9d77c5f5c6aa,a0195549-8982-4f94-956d-9d77c5f5c6aa", types.UUIDArrayType, ptr(ptrArr[types.UUID](*types.MustParseUUID("a0195549-8982-4f94-956d-9d77c5f5c6aa"), *types.MustParseUUID("a0195549-8982-4f94-956d-9d77c5f5c6aa")))},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			got, err := stringAndTypeToVal(tt.str, tt.dt)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_Split(t *testing.T) {
	type testcase struct {
		input   string
		want    []string
		wantErr bool
	}

	tests := []testcase{
		{"a", []string{"a"}, false},
		{"a,b", []string{"a", "b"}, false},
		{"a, b", []string{"a", "b"}, false},
		{"'a', 'b'", []string{"a", "b"}, false},
		{"a,,b", []string{"a", NullLiteral, "b"}, false},
		{"a,'',b", []string{"a", "", "b"}, false},
		{"'a','b'", []string{"a", "b"}, false},
		{"'a',b,", []string{"a", "b", NullLiteral}, false},
		{",a,'b'", []string{NullLiteral, "a", "b"}, false},
		{"'a,b,,c'", []string{"a,b,,c"}, false},
		{`"'a','b'",'c'`, []string{"'a','b'", "c"}, false},
		{`"a`, nil, true},
		{`,,,`, []string{NullLiteral, NullLiteral, NullLiteral, NullLiteral}, false},
		{`a,'b'c`, nil, true},
		{`a,'b'`, []string{"a", "b"}, false},
		{`"a"c`, nil, true},
		{`"a""b"`, nil, true},
		{`"a"c"`, nil, true},
		{`"a\"",'b'`, []string{`a"`, "b"}, false},
		{`'a\'','b'`, []string{`a'`, "b"}, false},
		{`'a"\'\'','""\'b'`, []string{`a"''`, `""'b`}, false},
		{`a\,b`, []string{"a,b"}, false},
		{"null", []string{NullLiteral}, false},
		{"null,null", []string{NullLiteral, NullLiteral}, false},
		{"null,' null'", []string{NullLiteral, " null"}, false},
		{"null, null", []string{NullLiteral, NullLiteral}, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := splitByCommas(tt.input)
			if err != nil {
				if !tt.wantErr {
					t.Fatal(err)
				}

				return
			}
			if tt.wantErr {
				t.Fatalf("expected error, got %v", got)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}

			wantPtr := make([]*string, len(tt.want))
			for i, w := range tt.want {
				if w == NullLiteral {
					wantPtr[i] = nil
				} else {
					wantPtr[i] = &w
				}
			}

			for i, g := range got {
				if g == nil {
					if wantPtr[i] != nil {
						t.Fatalf("got %v, want %v", g, wantPtr[i])
					}
					continue
				}
				if wantPtr[i] == nil {
					t.Fatalf("got %v, want %v", *g, wantPtr[i])
				}

				assert.Equal(t, *wantPtr[i], *g)
			}
		})
	}
}

// a helper function to convert a slice of any type to a slice of pointers to that type
func ptrArr[T any](v ...any) []*T {
	out := make([]*T, len(v))
	for i, b := range v {
		if b == nil {
			out[i] = nil
			continue
		}

		convV, ok := b.(T)
		if !ok {
			panic("invalid type")
		}

		out[i] = &convV
	}
	return out
}
