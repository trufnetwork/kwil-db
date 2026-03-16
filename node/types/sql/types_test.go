package sql

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestInt64(t *testing.T) {
	tests := []struct {
		name   string
		val    any
		want   int64
		wantOK bool
	}{
		{
			name:   "pg numeric",
			val:    pgtype.Numeric{Int: big10, Valid: true},
			want:   10,
			wantOK: true,
		},
		{
			name:   "our numeric (value)",
			val:    numeric{pgtype.Numeric{Int: big10, Valid: true}},
			want:   10,
			wantOK: true,
		},
		{
			name:   "our numeric (pointer)",
			val:    &numeric{pgtype.Numeric{Int: big10, Valid: true}},
			want:   10,
			wantOK: true,
		},
		{
			name:   "int64",
			val:    int64(10),
			want:   10,
			wantOK: true,
		},
		{
			name:   "int32",
			val:    int32(10),
			want:   10,
			wantOK: true,
		},
		{
			name:   "int16",
			val:    int64(10),
			want:   10,
			wantOK: true,
		},
		{
			name:   "int8",
			val:    int8(10),
			want:   10,
			wantOK: true,
		},
		{
			name:   "uint64",
			val:    uint64(10),
			want:   10,
			wantOK: true,
		},
		{
			name:   "uint32",
			val:    uint32(10),
			want:   10,
			wantOK: true,
		},
		{
			name:   "uint16",
			val:    uint64(10),
			want:   10,
			wantOK: true,
		},
		{
			name:   "uint8",
			val:    uint8(10),
			want:   10,
			wantOK: true,
		},
		{
			name:   "byte",
			val:    byte(10),
			want:   10,
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Int64(tt.val)
			if got != tt.want {
				t.Errorf("Int64() got = %v, want %v", got, tt.want)
			}
			if ok != tt.wantOK {
				t.Errorf("Int64() ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}
