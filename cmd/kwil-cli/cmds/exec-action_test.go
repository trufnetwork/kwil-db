package cmds

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/csv"
	"github.com/trufnetwork/kwil-db/core/types"
)

func Test_CSVParams(t *testing.T) {
	type testcase struct {
		name         string
		actionParams []string // name and type delimited by :
		csv          *csv.CSV
		mapping      []string
		namedParams  []string
		want         [][]any
		wantErr      bool
	}

	testcases := []testcase{
		{
			name:         "simple, mapping named action param",
			actionParams: []string{"id:int"},
			csv: &csv.CSV{
				Header:  []string{"id"},
				Records: [][]string{{"1"}, {"2"}},
			},
			mapping: []string{"id:id"},
			want:    [][]any{{ptr(int64(1))}, {ptr(int64(2))}},
		},
		{
			name:         "simple, positional parameter from csv",
			actionParams: []string{"id:int"},
			csv: &csv.CSV{
				Header:  []string{"id"},
				Records: [][]string{{"1"}, {"2"}},
			},
			mapping: []string{"id:1"},
			want:    [][]any{{ptr(int64(1))}, {ptr(int64(2))}},
		},
		{
			name:         "csv with 1 val, named param with 1 val",
			actionParams: []string{"id:int", "name:text"},
			csv: &csv.CSV{
				Header:  []string{"id"},
				Records: [][]string{{"1"}, {"2"}},
			},
			mapping:     []string{"id:id"},
			namedParams: []string{"name:text=foo"},
			want:        [][]any{{ptr(int64(1)), ptr("foo")}, {ptr(int64(2)), ptr("foo")}},
		},
		{
			name:         "csv with 1 val, named param (positional) with 1 val",
			actionParams: []string{"id:int", "name:text"},
			csv: &csv.CSV{
				Header:  []string{"id"},
				Records: [][]string{{"1"}, {"2"}},
			},
			mapping:     []string{"id:1"},
			namedParams: []string{"name:text=foo"},
			want:        [][]any{{ptr(int64(1)), ptr("foo")}, {ptr(int64(2)), ptr("foo")}},
		},
		{
			name:         "map to non-existent param",
			actionParams: []string{"id:int"},
			csv: &csv.CSV{
				Header:  []string{"id"},
				Records: [][]string{{"1"}},
			},
			mapping: []string{"id:id2"},
			wantErr: true,
		},
		{
			name:         "map to non-existent csv column",
			actionParams: []string{"id:int"},
			csv: &csv.CSV{
				Header:  []string{"id"},
				Records: [][]string{{"1"}},
			},
			mapping: []string{"id2:id"},
			wantErr: true,
		},
		{
			name:         "non-existent named param",
			actionParams: []string{"id:int"},
			csv: &csv.CSV{
				Header:  []string{"id"},
				Records: [][]string{{"1"}},
			},
			mapping:     []string{"id:id"},
			namedParams: []string{"name:text=foo"},
			wantErr:     true,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			var actionParams []NamedParameter
			for _, param := range tt.actionParams {
				parts := strings.Split(param, ":")

				dt, err := types.ParseDataType(parts[1])
				require.NoError(t, err)

				actionParams = append(actionParams, NamedParameter{
					Name: parts[0],
					Type: dt,
				})
			}

			res, err := csvToParams(actionParams, tt.csv, tt.mapping, tt.namedParams)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.EqualValues(t, tt.want, res)
		})
	}
}

func Test_ParseTypedParam(t *testing.T) {
	type testcase struct {
		in      string
		out     any
		outType *types.DataType
		err     bool
	}

	tests := []testcase{
		{

			in:      "numeric(10,5)[]:[100.6, null]",
			out:     ptr(ptrArr[types.Decimal](*types.MustParseDecimalExplicit("100.6", 10, 5), nil)),
			outType: mustNewNumericArr(10, 5),
			err:     false,
		},
		{

			in:      "numeric(10,5)[]:[null, 100.6]",
			out:     ptr(ptrArr[types.Decimal](nil, *types.MustParseDecimalExplicit("100.6", 10, 5))),
			outType: mustNewNumericArr(10, 5),
			err:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			outType, outVal, err := parseTypedParam(tt.in)
			if tt.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.EqualValues(t, tt.outType, outType)
			assert.EqualValues(t, tt.out, outVal)
		})
	}
}

func Test_NamedParameter(t *testing.T) {
	type testcase struct {
		params []NamedParameter
		in     []string
		out    []any
		err    bool
	}

	tests := []testcase{
		{
			params: []NamedParameter{
				np("$id", "int"),
			},
			in:  []string{"id:int=1"},
			out: []any{ptr(int64(1))},
		},
		{
			params: []NamedParameter{
				np("id", "int"),
			},
			in:  []string{"id:int=1"},
			out: []any{ptr(int64(1))},
		},
		{
			params: []NamedParameter{
				np("arr", "text[]"),
			},
			in:  []string{"arr:text[]=['hello', 'world']"},
			out: []any{ptr(ptrArr[string]("hello", "world"))},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d_%v", i, tt.in), func(t *testing.T) {
			_, out, _, err := getNamedParams(tt.params, tt.in)
			if tt.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.EqualValues(t, tt.out, out)
		})
	}
}

func np(name, dt string) NamedParameter {
	dt2, err := types.ParseDataType(dt)
	if err != nil {
		panic(err)
	}

	return NamedParameter{
		Name: name,
		Type: dt2,
	}
}

func mustNewNumericArr(prec, scale uint16) *types.DataType {
	dt, err := types.NewNumericType(prec, scale)
	if err != nil {
		panic(err)
	}
	dt.IsArray = true

	return dt
}

func ptr[T any](a T) *T {
	return &a
}
