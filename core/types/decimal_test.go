package types_test

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
)

func Test_NewParsedDecimal(t *testing.T) {
	type testcase struct {
		name    string
		decimal string
		prec    uint16
		scale   uint16
		want    string
		err     bool
	}

	tests := []testcase{
		{
			name:    "basic",
			decimal: "123.456",
			prec:    6,
			scale:   3,
			want:    "123.456",
		},
		{
			name:    "no scale",
			decimal: "1.456",
			prec:    1,
			scale:   0,
			want:    "1",
		},
		{
			name:    "overflow",
			decimal: "123.456",
			prec:    5,
			scale:   3,
			err:     true,
		},
		{
			name:    "rounding",
			decimal: "123.456",
			prec:    5,
			scale:   2,
			want:    "123.46",
		},
		{
			name:    "negative",
			decimal: "-123.456",
			prec:    6,
			scale:   3,
			want:    "-123.456",
		},
		{
			name:    "round down",
			decimal: "123.44",
			prec:    4,
			scale:   1,
			want:    "123.4",
		},
		{
			name:    "round up",
			decimal: "123.45",
			prec:    4,
			scale:   1,
			want:    "123.5",
		},
		{
			// while this is sort've unideal, it is expected, so keeping
			// it as a test case.
			name:    "second-digit round with enough precision",
			decimal: "123.449",
			prec:    5,
			scale:   1,
			want:    "123.5",
		},
		{
			name:    "second-digit round with not enough precision",
			decimal: "123.449",
			prec:    4,
			scale:   1,
			want:    "123.4",
		},
		{
			name:    "<1",
			decimal: "0.000123",
			prec:    6,
			scale:   6,
			want:    "0.000123",
		},
		{
			name:    "scale exceeds precision",
			decimal: "123.456",
			prec:    6,
			scale:   7,
			err:     true,
		},
		{
			name:    "precision too large",
			decimal: "123.456",
			prec:    1001,
			scale:   3,
			err:     true,
		},
		{
			name:    "invalid syntax",
			decimal: ".-1",
			prec:    153,
			scale:   103,
			err:     true,
		},
	}

	// test cases for decimal creation
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := types.ParseDecimalExplicit(tt.decimal, tt.prec, tt.scale)
			if tt.err {
				require.Errorf(t, err, "result: %v", d)
				return
			}
			if tt.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Equal(t, tt.want, d.String())
		})
	}
}

func Test_DecimalParsing(t *testing.T) {
	type testcase struct {
		name  string
		in    string
		prec  uint16
		scale uint16
		err   bool
	}

	tests := []testcase{
		{
			name:  "basic",
			in:    "123.456",
			prec:  6,
			scale: 3,
		},
		{
			name:  "no decimal",
			in:    "1",
			prec:  1,
			scale: 0,
		},
		{
			name:  "no int",
			in:    "0.456",
			prec:  3,
			scale: 3,
		},
		{
			name: "no decimal or int",
			in:   "",
			err:  true,
		},
		{
			name:  "negative",
			in:    "-123.456",
			prec:  6,
			scale: 3,
		},
		{
			name:  "positive",
			in:    "+123.456",
			prec:  6,
			scale: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := types.ParseDecimal(tt.in)
			if tt.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Equal(t, tt.prec, d.Precision())
			require.Equal(t, tt.scale, d.Scale())
		})

	}
}

func TestParseDecimal_invalid(t *testing.T) {
	s := ".-1e100"
	_, err := types.ParseDecimal(s)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func TestParseDecimalExplicit_invalid(t *testing.T) {
	s := ".-1"
	precision := uint16(153)
	scale := uint16(103)

	_, err := types.ParseDecimalExplicit(s, precision, scale)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func Test_MulDecimal(t *testing.T) {
	// happy path
	a := "123.456"
	b := "2.000"

	decA, err := types.ParseDecimal(a)
	require.NoError(t, err)

	decB, err := types.ParseDecimal(b)
	require.NoError(t, err)

	decMul, err := decA.Mul(decA, decB)
	require.NoError(t, err)

	assert.Equal(t, "246.912", decMul.String())

	// overflow
	decA, err = types.ParseDecimal("123.456")
	require.NoError(t, err)

	decB, err = types.ParseDecimal("10.000")
	require.NoError(t, err)

	_, err = decA.Mul(decA, decB)
	require.Error(t, err)

	// handle the overflow error
	decA, err = types.ParseDecimal("123.456")
	require.NoError(t, err)

	decB, err = types.ParseDecimal("10.000")
	require.NoError(t, err)

	res := types.Decimal{}
	err = res.SetPrecisionAndScale(6, 2)
	require.NoError(t, err)

	_, err = res.Mul(decA, decB)
	require.NoError(t, err)

	require.Equal(t, "1234.56", res.String())
}

func Test_DecimalMath(t *testing.T) {
	type testcase struct {
		name string
		a    string
		b    string
		add  string
		sub  string
		div  string
		mod  string
		pow  any // if string, will be converted to decimal. if error, it should be an error.
	}

	tests := []testcase{
		{
			name: "basic",
			a:    "111.111",
			b:    "222.222",
			add:  "333.333",
			sub:  "-111.111",
			div:  "0.500",
			mod:  "111.111",
			pow:  "40947232792674801703617506513614403879857793764501216315280893639716470307169733631790876461965572518860559362274629485292911547430937978598849436143453399196315550597742244783214288813683207756767414184276471346880686854054933686634595348167818622321108157880891582799953764376652277357220951025024520432205504241275515862333604924257110592561916318338267242907156585216880466294760992172997373034474199040967379214091758725977575036083358700976528684903.650",
		},
		{
			name: "negative",
			a:    "-111.111",
			b:    "222.222",
			add:  "111.111",
			sub:  "-333.333",
			div:  "-0.500",
			mod:  "-111.111",
			pow:  errors.New("invalid operation"),
		},
		{
			name: "different scale",
			a:    "111.111",
			b:    "222.222222",
			add:  "333.333222",
			sub:  "-111.111222",
			div:  "0.500000",
			mod:  "111.111000",
			pow:  "40990075250446852588522441143222156659052130339298453956352655687203237203657240466439592211667686715504210644601279978038974530686828593146537313522798590884099844906484623923249881463686394933736223098662509502986649384011150498473632321057132912354564907462215306517581999096985844562283606145376921572863158587371832747763312385879522316860281871698496720764895161781787801656268494310238885794127539157485892424922658030456199187314559101140337375799.890792",
		},
		{
			name: "different precision",
			a:    "1.111",
			b:    "222.222",
			add:  "223.333",
			sub:  "-221.111",
			div:  "0.005",
			mod:  "1.111",
			pow:  "14410186644.883",
		},
		{
			name: "different precision and scale",
			a:    "11.11",
			b:    "2.2222",
			add:  "13.3322",
			sub:  "8.8878",
			div:  "4.9995",
			mod:  "2.2212",
			pow:  "210.7588",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a *types.Decimal
			var b *types.Decimal
			// greatestScale is the greatest scale of the two decimals
			var greatestScale uint16

			// reset resets the a and b variables,
			// since their pointers get shared between tests.
			reset := func() {
				var err error
				a, err = types.ParseDecimal(tt.a)
				require.NoError(t, err)

				b, err = types.ParseDecimal(tt.b)
				require.NoError(t, err)

				if a.Scale() > b.Scale() {
					greatestScale = a.Scale()
				} else {
					greatestScale = b.Scale()
				}
			}
			reset()

			// add, err := decimal.Add(a, b)
			// require.NoError(t, err)
			// eq(t, add, tt.add, greatestScale)

			// reset()

			// sub, err := decimal.Sub(a, b)
			// require.NoError(t, err)
			// eq(t, sub, tt.sub, greatestScale)

			// reset()

			// // we dont test mul here since it would likely overflow

			// div, err := decimal.Div(a, b)
			// require.NoError(t, err)
			// d := div.String()
			// _ = d
			// eq(t, div, tt.div, greatestScale)

			// reset()

			// mod, err := decimal.Mod(a, b)
			// require.NoError(t, err)
			// eq(t, mod, tt.mod, greatestScale)

			// reset()

			pow, err := types.DecimalPow(a, b)

			switch v := tt.pow.(type) {
			case string:
				require.NoError(t, err)
				eq(t, pow, v, greatestScale)
			case error:
				require.Contains(t, err.Error(), v.Error())
			default:
				t.Fatalf("unexpected type: %T", v)
			}
		})
	}
}

// eq checks that a decimal is equal to a string.
// It will round the decimal to the given scale.
func eq(t *testing.T, dec *types.Decimal, want string, round uint16) {
	dec2, err := types.ParseDecimal(want)
	require.NoError(t, err)

	old := dec.String()

	err = dec.Round(round)
	require.NoError(t, err)

	err = dec2.Round(round)
	if err != nil {
		fmt.Println("dec2", dec2)
	}
	require.NoError(t, err)

	// since dec will get overwritten by Cmp
	got := dec.String()

	cmp, err := dec.Cmp(dec2)
	require.NoError(t, err)

	require.Equalf(t, 0, cmp, "want: %s, got: %s, rounded from: %s", dec2.String(), got, old)
}

func Test_AdjustPrecAndScale(t *testing.T) {
	a, err := types.ParseDecimal("111.111")
	require.NoError(t, err)

	err = a.SetPrecisionAndScale(9, 6)
	require.NoError(t, err)

	require.Equal(t, "111.111000", a.String())

	// set prec/scale back
	err = a.SetPrecisionAndScale(6, 3)
	require.NoError(t, err)

	require.Equal(t, "111.111", a.String())

	// set prec/scale too low
	err = a.SetPrecisionAndScale(3, 2)
	require.Error(t, err)
}

func Test_AdjustScaleMath(t *testing.T) {
	a, err := types.ParseDecimal("111.111")
	require.NoError(t, err)

	err = a.SetPrecisionAndScale(6, 3)
	require.NoError(t, err)

	b, err := types.ParseDecimal("222.22")
	require.NoError(t, err)

	_, err = a.Add(a, b)
	require.NoError(t, err)

	require.Equal(t, "333.331", a.String())

	// set prec/scale back
	err = a.SetPrecisionAndScale(6, 2)
	require.NoError(t, err)

	require.Equal(t, "333.33", a.String())

	c, err := types.ParseDecimal("30.22")
	require.NoError(t, err)

	_, err = a.Sub(a, c)
	require.NoError(t, err)

	require.Equal(t, "303.11", a.String())
}

func Test_RemoveScale(t *testing.T) {
	a, err := types.ParseDecimal("111.111")
	require.NoError(t, err)

	err = a.SetPrecisionAndScale(6, 2)
	require.NoError(t, err)

	require.Equal(t, "111.11", a.String())

	err = a.SetPrecisionAndScale(6, 3)
	require.NoError(t, err)

	require.Equal(t, "111.110", a.String())
}

func Test_DecimalCmp(t *testing.T) {
	type testcase struct {
		name string
		a    string
		b    string
		want int
	}

	tests := []testcase{
		{
			name: "equal",
			a:    "123.456",
			b:    "123.456",
			want: 0,
		},
		{
			name: "equal values, different scale",
			a:    "0123.456",
			b:    "123.456000",
			want: 0,
		},
		{
			name: "different values, different scale",
			a:    "123.456001",
			b:    "123.456",
			want: 1,
		},
		{
			name: "different values, different precision",
			a:    "123.456",
			b:    "1123.456",
			want: -1,
		},
		{
			name: "negative",
			a:    "-123.456",
			b:    "123.456",
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := types.ParseDecimal(tt.a)
			require.NoError(t, err)

			b, err := types.ParseDecimal(tt.b)
			require.NoError(t, err)

			cmp, err := a.Cmp(b)
			require.NoError(t, err)

			require.Equal(t, tt.want, cmp)
		})
	}
}

// Testing setting a decimal from a big int and an exponent
func Test_BigAndExp(t *testing.T) {
	type testcase struct {
		name     string
		big      string // will be converted to a big.Int
		exp      int32
		out      string
		outPrec  uint16
		outScale uint16
		wantErr  bool
	}

	tests := []testcase{
		{
			name:     "basic",
			big:      "123456",
			exp:      -3,
			out:      "123.456",
			outPrec:  6,
			outScale: 3,
		},
		{
			name:     "negative",
			big:      "-123456",
			exp:      -2,
			out:      "-1234.56",
			outPrec:  6,
			outScale: 2,
		},
		{
			name:     "0 exponent",
			big:      "123456",
			exp:      0,
			out:      "123456",
			outPrec:  6,
			outScale: 0,
		},
		{
			name:    "positive exp",
			big:     "123",
			exp:     4,
			out:     "1230000",
			outPrec: 7,
		},
		{
			name:     "exp less than precision properly adjusts precision",
			big:      "123",
			exp:      -4,
			out:      "0.0123",
			outPrec:  4,
			outScale: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bigInt, ok := new(big.Int).SetString(tt.big, 10)
			require.True(t, ok)

			d, err := types.NewDecimalFromBigInt(bigInt, tt.exp)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Equal(t, tt.out, d.String())
			require.Equal(t, tt.outPrec, d.Precision())
			require.Equal(t, tt.outScale, d.Scale())
		})
	}
}
func TestDecimalBinaryMarshaling(t *testing.T) {
	tests := []struct {
		name     string
		decimal  string
		prec     uint16
		scale    uint16
		expected []byte
	}{
		{
			name:     "positive decimal",
			decimal:  "123.456",
			prec:     6,
			scale:    3,
			expected: append([]byte{0, 6, 0, 3}, []byte("123.456")...),
		},
		{
			name:     "negative decimal",
			decimal:  "-987.654",
			prec:     6,
			scale:    3,
			expected: append([]byte{0, 6, 0, 3}, []byte("-987.654")...),
		},
		{
			name:     "zero",
			decimal:  "0",
			prec:     1,
			scale:    0,
			expected: append([]byte{0, 1, 0, 0}, []byte("0")...),
		},
		{
			name:     "large precision and scale",
			decimal:  "1234567890.0987654321",
			prec:     20,
			scale:    10,
			expected: append([]byte{0, 20, 0, 10}, []byte("1234567890.0987654321")...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := types.ParseDecimalExplicit(tt.decimal, tt.prec, tt.scale)
			require.NoError(t, err)

			marshaled, err := d.MarshalBinary()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, marshaled)

			var unmarshaled types.Decimal
			err = unmarshaled.UnmarshalBinary(marshaled)
			require.NoError(t, err)

			assert.Equal(t, d.String(), unmarshaled.String())
			assert.Equal(t, d.Precision(), unmarshaled.Precision())
			assert.Equal(t, d.Scale(), unmarshaled.Scale())
		})
	}
}

func TestDecimalBinaryUnmarshalingErrors(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectedErr string
	}{
		{
			name:        "empty input",
			input:       []byte{},
			expectedErr: "invalid binary data",
		},
		{
			name:        "insufficient data",
			input:       []byte{0, 1, 0},
			expectedErr: "invalid binary data",
		},
		{
			name:        "invalid decimal data",
			input:       []byte{0, 1, 0, 0, 255},
			expectedErr: "parse mantissa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d types.Decimal
			err := d.UnmarshalBinary(tt.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestDecimalBinaryRoundTrip(t *testing.T) {
	original, err := types.ParseDecimal("12345.6789")
	require.NoError(t, err)

	marshaled, err := original.MarshalBinary()
	require.NoError(t, err)

	var unmarshaled types.Decimal
	err = unmarshaled.UnmarshalBinary(marshaled)
	require.NoError(t, err)

	assert.Equal(t, original.String(), unmarshaled.String())
	assert.Equal(t, original.Precision(), unmarshaled.Precision())
	assert.Equal(t, original.Scale(), unmarshaled.Scale())
}

func TestDecimalJSONRoundTrip(t *testing.T) {
	str := "12345.6789"
	original, err := types.ParseDecimal(str)
	require.NoError(t, err)

	marshaled, err := original.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, `"`+str+`"`, string(marshaled))

	var unmarshaled types.Decimal
	err = unmarshaled.UnmarshalJSON(marshaled)
	require.NoError(t, err)

	assert.Equal(t, original.String(), unmarshaled.String())
	assert.Equal(t, original.Precision(), unmarshaled.Precision())
	assert.Equal(t, original.Scale(), unmarshaled.Scale())
}

func TestFullString(t *testing.T) {
	t.Run("very big number", func(t *testing.T) {
		dec := types.MustParseDecimal("1234567890123456789012345678901234567890.0987654321")
		str := dec.FullString()
		assert.Equal(t, "1234567890123456789012345678901234567890.0987654321", str)
	})

	t.Run("very small number", func(t *testing.T) {
		dec := types.MustParseDecimal("0.0000000000000000000000000000000000000000001")
		str := dec.FullString()
		assert.Equal(t, "0.0000000000000000000000000000000000000000001", str)
	})

	t.Run("large integer", func(t *testing.T) {
		dec := types.MustParseDecimal("1234567890123456789012345678901234567890")
		str := dec.FullString()
		assert.Equal(t, "1234567890123456789012345678901234567890", str)
	})

	t.Run("negative number", func(t *testing.T) {
		dec := types.MustParseDecimal("-1234567890123456789012345678901234567890.0987654321")
		str := dec.FullString()
		assert.Equal(t, "-1234567890123456789012345678901234567890.0987654321", str)
	})

	t.Run("negative large integer", func(t *testing.T) {
		dec := types.MustParseDecimal("-1234567890123456789012345678901234567890")
		str := dec.FullString()
		assert.Equal(t, "-1234567890123456789012345678901234567890", str)
	})

	t.Run("negative very small number", func(t *testing.T) {
		dec := types.MustParseDecimal("-0.0000000000000000000000000000000000000000001")
		str := dec.FullString()
		assert.Equal(t, "-0.0000000000000000000000000000000000000000001", str)
	})

	t.Run("zero", func(t *testing.T) {
		dec := types.MustParseDecimal("0")
		str := dec.FullString()
		assert.Equal(t, "0", str)
	})

	t.Run("explicit precision and scale", func(t *testing.T) {
		dec := types.MustParseDecimalExplicit("123.456", 100, 4)
		str := dec.FullString()
		assert.Equal(t, "123.4560", str)
	})
}
