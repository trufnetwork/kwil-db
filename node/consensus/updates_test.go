package consensus

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
)

func TestParamUpdatesDeclaration_MarshalBinary(t *testing.T) {
	_, pubkey, _ := crypto.GenerateSecp256k1Key(nil)

	tests := []struct {
		name        string
		declaration ParamUpdatesDeclaration
		wantErr     bool
	}{
		{
			name: "valid declaration",
			declaration: ParamUpdatesDeclaration{
				Description:  "test update",
				ParamUpdates: types.ParamUpdates{},
			},
			wantErr: false,
		},
		{
			name: "empty description",
			declaration: ParamUpdatesDeclaration{
				Description:  "",
				ParamUpdates: types.ParamUpdates{},
			},
			wantErr: false,
		},
		{
			name: "lots of param updates",
			declaration: ParamUpdatesDeclaration{
				Description: "test update",
				ParamUpdates: types.ParamUpdates{
					types.ParamNameLeader:           types.PublicKey{PublicKey: pubkey},
					types.ParamNameDisabledGasCosts: false,
					types.ParamNameJoinExpiry:       types.Duration(10 * time.Second),
					types.ParamNameMigrationStatus:  types.MigrationCompleted,
				},
			},
		},
		{
			name: "invalid expiry param updates",
			declaration: ParamUpdatesDeclaration{
				Description: "test update",
				ParamUpdates: types.ParamUpdates{
					types.ParamNameLeader:           types.PublicKey{PublicKey: pubkey},
					types.ParamNameDisabledGasCosts: false,
					types.ParamNameJoinExpiry:       int64(10),
					types.ParamNameMigrationStatus:  types.MigrationCompleted,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bz, err := tt.declaration.MarshalBinary()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bz)

			var decoded ParamUpdatesDeclaration
			err = decoded.UnmarshalBinary(bz)
			require.NoError(t, err)

			assert.Equal(t, tt.declaration.Description, decoded.Description)

			if !reflect.DeepEqual(tt.declaration.ParamUpdates, decoded.ParamUpdates) {
				t.Errorf("ParamUpdatesDeclaration.MarshalBinary() = %v, want %v", decoded.ParamUpdates, tt.declaration.ParamUpdates)
			}
		})
	}
}

func TestParamUpdatesDeclaration_UnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		input   func() []byte
		wantErr bool
	}{
		{
			name: "invalid version",
			input: func() []byte {
				buf := &bytes.Buffer{}
				binary.Write(buf, types.SerializationByteOrder, uint16(0))
				return buf.Bytes()
			},
			wantErr: true,
		},
		{
			name: "truncated input",
			input: func() []byte {
				return []byte{0x0, 0x1}
			},
			wantErr: true,
		},
		{
			name: "invalid param updates bytes",
			input: func() []byte {
				buf := &bytes.Buffer{}
				binary.Write(buf, types.SerializationByteOrder, uint16(pudVersion))
				types.WriteString(buf, "test")
				types.WriteBytes(buf, []byte{0x1, 0x2, 0x3})
				return buf.Bytes()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pud ParamUpdatesDeclaration
			err := pud.UnmarshalBinary(tt.input())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
