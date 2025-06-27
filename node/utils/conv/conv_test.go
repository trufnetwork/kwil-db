package conv_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/utils/conv"
)

func TestInt(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    int64
		wantErr bool
	}{
		{
			name: "int",
			arg:  1,
			want: 1,
		},
		{
			name: "int8",
			arg:  int8(1),
			want: 1,
		},
		{
			name: "int16",
			arg:  int16(1),
			want: 1,
		},
		{
			name: "string",
			arg:  "1",
			want: 1,
		},
		{
			name:    "string (invalid)",
			arg:     "hello",
			wantErr: true,
		},
		{
			name: "bool (true)",
			arg:  true,
			want: 1,
		},
		{
			name: "bool (false)",
			arg:  false,
			want: 0,
		},
		{
			name:    "struct",
			arg:     struct{}{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.Int(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Int() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Int() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    string
		wantErr bool
	}{
		{
			name: "string",
			arg:  "hello",
			want: "hello",
		},
		{
			name: "int",
			arg:  1,
			want: "1",
		},
		{
			name: "int8",
			arg:  int8(1),
			want: "1",
		},
		{
			name:    "struct",
			arg:     struct{}{},
			wantErr: true,
		},
		{
			name: "bool",
			arg:  true,
			want: "true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.String(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("String() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Blob(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    []byte
		wantErr bool
	}{
		{
			name: "string",
			arg:  "hello",
			want: []byte("hello"),
		},
		{
			name: "[]byte",
			arg:  []byte("hello"),
			want: []byte("hello"),
		},
		{
			name:    "struct",
			arg:     struct{}{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.Blob(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Blob() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != string(tt.want) {
				t.Errorf("Blob() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Bool(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    bool
		wantErr bool
	}{
		{
			name: "bool (true)",
			arg:  true,
			want: true,
		},
		{
			name: "bool (false)",
			arg:  false,
			want: false,
		},
		{
			name: "int (1)",
			arg:  1,
			want: true,
		},
		{
			name: "int (0)",
			arg:  0,
			want: false,
		},
		{
			name:    "string",
			arg:     "hello",
			wantErr: true,
		},
		{
			name:    "struct",
			arg:     struct{}{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.Bool(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Bool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Bool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_UUID(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    *types.UUID
		wantErr bool
	}{
		{
			name: "string",
			arg:  "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			want: mustParseUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
		},
		{
			name: "[]byte",
			arg:  []byte("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
			want: mustParseUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
		},
		{
			name: "uuid",
			arg:  mustParseUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
			want: mustParseUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
		},
		{
			name: "bytes",
			arg:  []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8},
			want: mustParseUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
		},
		{
			name:    "bool",
			arg:     true,
			wantErr: true,
		},
		{
			name:    "struct",
			arg:     struct{}{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.UUID(tt.arg)
			hasErr := err != nil
			if hasErr != tt.wantErr {
				t.Errorf("UUID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hasErr {
				return
			}

			if got.String() != tt.want.String() {
				t.Errorf("UUID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Decimal(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    *types.Decimal
		wantErr bool
	}{
		{
			name: "string",
			arg:  "1.234",
			want: mustDecimal("1.234"),
		},
		{
			name: "int",
			arg:  1234,
			want: mustDecimal("1234"),
		},
		{
			name: "int8",
			arg:  int8(123),
			want: mustDecimal("123"),
		},
		{
			name:    "struct",
			arg:     struct{}{},
			wantErr: true,
		},
		{
			name:    "bool",
			arg:     true,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.Decimal(tt.arg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if got.String() != tt.want.String() {
				t.Errorf("Decimal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mustDecimal(s string) *types.Decimal {
	d, err := types.ParseDecimal(s)
	if err != nil {
		panic(err)
	}
	return d

}

func mustParseUUID(s string) *types.UUID {
	u, err := types.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestStringAdditionalCases(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    string
		wantErr bool
	}{
		{
			name: "uint16",
			arg:  uint16(65535),
			want: "65535",
		},
		{
			name: "uint32",
			arg:  uint32(4294967295),
			want: "4294967295",
		},
		{
			name: "uint64",
			arg:  uint64(18446744073709551615),
			want: "18446744073709551615",
		},
		{
			name: "float32",
			arg:  float32(3.14159),
			want: "3.14159",
		},
		{
			name: "float64",
			arg:  float64(3.14159265359),
			want: "3.14159265359",
		},
		{
			name: "uintptr",
			arg:  uintptr(12345),
			want: "12345",
		},
		{
			name: "int32",
			arg:  int32(-2147483648),
			want: "-2147483648",
		},
		{
			name: "int64",
			arg:  int64(-9223372036854775808),
			want: "-9223372036854775808",
		},
		{
			name:    "nil",
			arg:     nil,
			wantErr: true,
		},
		{
			name: "valid utf8 bytes",
			arg:  []byte("Hello, 世界"),
			want: "Hello, 世界",
		},
		{
			name:    "invalid utf8 bytes",
			arg:     []byte{0xFF, 0xFE, 0xFD},
			wantErr: true,
		},
		{
			name:    "channel",
			arg:     make(chan int),
			wantErr: true,
		},
		{
			name:    "function",
			arg:     func() {},
			wantErr: true,
		},
		{
			name:    "map",
			arg:     map[string]int{},
			wantErr: true,
		},
		{
			name:    "slice",
			arg:     []int{1, 2, 3},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.String(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("String() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIntAdditionalCases(t *testing.T) {
	runSubTests := func(t *testing.T, tests []struct {
		name    string
		arg     any
		want    int64
		wantErr bool
	}) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := conv.Int(tt.arg)
				if (err != nil) != tt.wantErr {
					t.Errorf("Int() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !tt.wantErr && got != tt.want {
					t.Errorf("Int() = %v, want %v", got, tt.want)
				}
			})
		}
	}
	t.Run("integer types", func(t *testing.T) {
		tests := []struct {
			name    string
			arg     any
			want    int64
			wantErr bool
		}{
			{
				name: "int32",
				arg:  int32(2147483647),
				want: 2147483647,
			},
			{
				name: "int64 max",
				arg:  int64(9223372036854775807),
				want: 9223372036854775807,
			},
			{
				name: "int64 min",
				arg:  int64(-9223372036854775808),
				want: -9223372036854775808,
			},
			{
				name: "uint32",
				arg:  uint32(4294967295),
				want: 4294967295,
			},
			{
				name: "uint64",
				arg:  uint64(9223372036854775807),
				want: 9223372036854775807,
			},
		}
		runSubTests(t, tests)
	})

	t.Run("floating point types", func(t *testing.T) {
		tests := []struct {
			name    string
			arg     any
			want    int64
			wantErr bool
		}{
			{
				name: "float32",
				arg:  float32(123.45),
				want: 123,
			},
			{
				name: "float64",
				arg:  float64(123.45),
				want: 123,
			},
		}
		runSubTests(t, tests)
	})

	t.Run("byte and string handling", func(t *testing.T) {
		tests := []struct {
			name    string
			arg     any
			want    int64
			wantErr bool
		}{
			{
				name: "bytes valid",
				arg:  []byte("12345"),
				want: 12345,
			},
			{
				name:    "bytes invalid",
				arg:     []byte("abc"),
				wantErr: true,
			},
			{
				name:    "bytes empty",
				arg:     []byte{},
				wantErr: true,
			},
		}
		runSubTests(t, tests)
	})

	t.Run("edge cases", func(t *testing.T) {
		tests := []struct {
			name    string
			arg     any
			want    int64
			wantErr bool
		}{
			{
				name:    "nil",
				arg:     nil,
				wantErr: true,
			},
			{
				name:    "string empty",
				arg:     "",
				wantErr: true,
			},
			{
				name:    "string float",
				arg:     "123.45",
				wantErr: true,
			},
			{
				name:    "string overflow",
				arg:     "9223372036854775808",
				wantErr: true,
			},
			{
				name:    "string underflow",
				arg:     "-9223372036854775809",
				wantErr: true,
			},
		}
		runSubTests(t, tests)
	})
}

func TestIntAdditionalCasesDeeper(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    int64
		wantErr bool
	}{
		{
			name: "int32",
			arg:  int32(2147483647),
			want: 2147483647,
		},
		{
			name: "int64 max",
			arg:  int64(9223372036854775807),
			want: 9223372036854775807,
		},
		{
			name: "int64 min",
			arg:  int64(-9223372036854775808),
			want: -9223372036854775808,
		},
		{
			name: "uint32",
			arg:  uint32(4294967295),
			want: 4294967295,
		},
		{
			name: "uint64",
			arg:  uint64(9223372036854775807),
			want: 9223372036854775807,
		},
		{
			name: "float32",
			arg:  float32(123.45),
			want: 123,
		},
		{
			name: "float64",
			arg:  float64(123.45),
			want: 123,
		},
		{
			name: "bytes valid",
			arg:  []byte("12345"),
			want: 12345,
		},
		{
			name:    "bytes invalid",
			arg:     []byte("abc"),
			wantErr: true,
		},
		{
			name:    "bytes empty",
			arg:     []byte{},
			wantErr: true,
		},
		{
			name:    "nil",
			arg:     nil,
			wantErr: true,
		},
		{
			name:    "string empty",
			arg:     "",
			wantErr: true,
		},
		{
			name:    "string float",
			arg:     "123.45",
			wantErr: true,
		},
		{
			name:    "string overflow",
			arg:     "9223372036854775808",
			wantErr: true,
		},
		{
			name:    "string underflow",
			arg:     "-9223372036854775809",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.Int(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Int() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Int() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBlobAdditionalCases(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    []byte
		wantErr bool
	}{
		{
			name: "uint8",
			arg:  uint8(255),
			want: []byte("255"),
		},
		{
			name: "uint16",
			arg:  uint16(65535),
			want: []byte("65535"),
		},
		{
			name: "uint32",
			arg:  uint32(4294967295),
			want: []byte("4294967295"),
		},
		{
			name: "uint64",
			arg:  uint64(18446744073709551615),
			want: []byte("18446744073709551615"),
		},
		{
			name: "int16",
			arg:  int16(-32768),
			want: []byte("-32768"),
		},
		{
			name: "int32",
			arg:  int32(-2147483648),
			want: []byte("-2147483648"),
		},
		{
			name: "int64",
			arg:  int64(-9223372036854775808),
			want: []byte("-9223372036854775808"),
		},
		{
			name: "uint",
			arg:  uint(4294967295),
			want: []byte("4294967295"),
		},
		{
			name:    "nil",
			arg:     nil,
			wantErr: true,
		},
		{
			name:    "float32",
			arg:     float32(3.14),
			wantErr: true,
		},
		{
			name:    "float64",
			arg:     float64(3.14),
			wantErr: true,
		},
		{
			name:    "complex",
			arg:     complex(1, 2),
			wantErr: true,
		},
		{
			name:    "channel",
			arg:     make(chan int),
			wantErr: true,
		},
		{
			name:    "function",
			arg:     func() {},
			wantErr: true,
		},
		{
			name:    "map",
			arg:     map[string]int{},
			wantErr: true,
		},
		{
			name: "empty string",
			arg:  "",
			want: []byte{},
		},
		{
			name: "unicode string",
			arg:  "Hello, 世界",
			want: []byte("Hello, 世界"),
		},
		{
			name: "special characters",
			arg:  "!@#$%^&*()",
			want: []byte("!@#$%^&*()"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.Blob(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Blob() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("Blob() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecimalAdditionalCases(t *testing.T) {
	tests := []struct {
		name    string
		arg     any
		want    *types.Decimal
		wantErr bool
	}{
		{
			name: "nil value",
			arg:  nil,
			want: mustDecimal("0"),
		},
		{
			name: "uint8",
			arg:  uint8(255),
			want: mustDecimal("255"),
		},
		{
			name: "uint16",
			arg:  uint16(65535),
			want: mustDecimal("65535"),
		},
		{
			name: "uint32",
			arg:  uint32(4294967295),
			want: mustDecimal("4294967295"),
		},
		{
			name: "uint64",
			arg:  uint64(18446744073709551615),
			want: mustDecimal("18446744073709551615"),
		},
		{
			name: "float32",
			arg:  float32(3.14159),
			want: mustDecimal("3.14159"),
		},
		{
			name: "float64",
			arg:  float64(3.14159265359),
			want: mustDecimal("3.14159265359"),
		},
		{
			name: "negative decimal string",
			arg:  "-123.456",
			want: mustDecimal("-123.456"),
		},
		// {
		// 	name: "scientific notation string",
		// 	arg:  "1.23e5",
		// 	want: mustDecimal("123000"),
		// },
		{
			name: "very large decimal string",
			arg:  "9999999999999999999999999999.999999999999",
			want: mustDecimal("9999999999999999999999999999.999999999999"),
		},
		{
			name: "very small decimal string",
			arg:  "0.000000000000000000000001",
			want: mustDecimal("0.000000000000000000000001"),
		},
		{
			name:    "invalid decimal string",
			arg:     "abc.def",
			wantErr: true,
		},
		{
			name:    "empty string",
			arg:     "",
			wantErr: true,
		},
		{
			name:    "invalid characters",
			arg:     "12.34.56",
			wantErr: true,
		},
		{
			name:    "slice",
			arg:     []int{1, 2, 3},
			wantErr: true,
		},
		{
			name:    "map",
			arg:     map[string]int{"a": 1},
			wantErr: true,
		},
		{
			name:    "channel",
			arg:     make(chan int),
			wantErr: true,
		},
		{
			name:    "function",
			arg:     func() {},
			wantErr: true,
		},
		{
			name:    "complex number",
			arg:     complex(1, 2),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := conv.Decimal(tt.arg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want.String(), got.String())
		})
	}
}
