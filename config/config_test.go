package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	gotoml "github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
)

// TestMarshalDuration ensures that a time.Duration can be marshaled and
// unmarshaled with the pelletier/go-toml/v2 library. This wasn't always the
// case for some reason **cough specs cough**.
func TestMarshalDuration(t *testing.T) {
	type td struct {
		Duration types.Duration `koanf:"duration" toml:"duration"`
	}
	tt := td{
		Duration: types.Duration(10 * time.Second),
	}
	bts, err := gotoml.Marshal(tt)
	if err != nil {
		t.Fatal(err)
	}

	var tt2 td
	err = gotoml.Unmarshal(bts, &tt2)
	if err != nil {
		t.Fatal(err)
	}
	if tt2.Duration != tt.Duration {
		t.Fatalf("got %v, want %v", tt2.Duration, tt.Duration)
	}
}

func TestConfigSaveAndLoad(t *testing.T) {
	tempFile := t.TempDir() + "/config.toml"

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Log: Logging{
					Level:  log.LevelDebug,
					Format: log.FormatJSON,
				},
				P2P: PeerConfig{
					ListenAddress: "0.0.0.0:6600",
					Pex:           false,
					BootNodes:     []string{"/ip4/192.168.1.1/tcp/8080/p2p/test"},
				},
				DB: DBConfig{
					Host:          "127.0.0.1",
					Port:          "5432",
					User:          "kwild",
					Pass:          "kwild",
					DBName:        "kwild",
					ReadTxTimeout: types.Duration(45 * time.Second),
					MaxConns:      10,
				},
			},
			wantErr: false,
		},
		{
			name: "empty config",
			config: Config{
				Log: Logging{
					Level:  log.LevelInfo,
					Format: log.FormatUnstructured,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.SaveAs(tempFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveAs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			loaded, err := LoadConfig(tempFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if loaded.Log.Level != tt.config.Log.Level {
					t.Errorf("LogLevel mismatch: got %v, want %v", loaded.Log.Level, tt.config.Log.Level)
				}
				if loaded.Log.Format != tt.config.Log.Format {
					t.Errorf("LogFormat mismatch: got %v, want %v", loaded.Log.Format, tt.config.Log.Format)
				}
				if loaded.P2P.ListenAddress != tt.config.P2P.ListenAddress {
					t.Errorf("P2P.ListenAddress mismatch: got %v, want %v", loaded.P2P.ListenAddress, tt.config.P2P.ListenAddress)
				}
				if loaded.P2P.Pex != tt.config.P2P.Pex {
					t.Errorf("P2P.Pex mismatch: got %v, want %v", loaded.P2P.Pex, tt.config.P2P.Pex)
				}
				if !slices.Equal(loaded.P2P.BootNodes, tt.config.P2P.BootNodes) {
					t.Errorf("P2P.BootNode mismatch: got %v, want %v", loaded.P2P.BootNodes, tt.config.P2P.BootNodes)
				}
				fmt.Println(loaded.DB)
				if loaded.DB.Host != tt.config.DB.Host {
					t.Errorf("DB.Host mismatch: got %v, want %v", loaded.DB.Host, tt.config.DB.Host)
				}
				if loaded.DB.Port != tt.config.DB.Port {
					t.Errorf("DB.Port mismatch: got %v, want %v", loaded.DB.Port, tt.config.DB.Port)
				}
				if loaded.DB.User != tt.config.DB.User {
					t.Errorf("DB.User mismatch: got %v, want %v", loaded.DB.User, tt.config.DB.User)
				}
			}
		})
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "non-existent file",
			filename: "nonexistent.toml",
			wantErr:  true,
		},
		{
			name:     "empty filename",
			filename: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadConfig(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeDecodePubKeyType(t *testing.T) {
	testCases := []struct {
		name          string
		encodedPubKey string
		decodedPubKey string
		keyType       crypto.KeyType
		wantErr       bool
		typeErr       bool
	}{
		{
			name:          "valid encoded public key",
			encodedPubKey: "021072159608e8bfa10102cc74d3e1b533dfdf1904538a61de42811cc3066de014#secp256k1",
			decodedPubKey: "021072159608e8bfa10102cc74d3e1b533dfdf1904538a61de42811cc3066de014",
			keyType:       crypto.KeyTypeSecp256k1,
			wantErr:       false,
		},
		{
			name:          "invalid encoded public key format, missing key type and delimiter",
			encodedPubKey: "021072159608e8bfa10102cc74d3e1b533dfdf1904538a61de42811cc3066de014",
			decodedPubKey: "",
			keyType:       crypto.KeyTypeSecp256k1,
			wantErr:       true,
		},
		{
			name:          "invalid encoded public key format, missing key type",
			encodedPubKey: "021072159608e8bfa10102cc74d3e1b533dfdf1904538a61de42811cc3066de014#",
			decodedPubKey: "",
			keyType:       crypto.KeyTypeSecp256k1,
			wantErr:       true,
		},
		{
			name:          "invalid encoded public key",
			encodedPubKey: "0abcd#secp256k1",
			decodedPubKey: "",
			keyType:       crypto.KeyTypeSecp256k1,
			wantErr:       true,
		},
		{
			name:          "custom key type",
			encodedPubKey: "021072159608e8bfa10102cc74d3e1b533dfdf1904538a61de42811cc3066de014#custom",
			decodedPubKey: "021072159608e8bfa10102cc74d3e1b533dfdf1904538a61de42811cc3066de014",
			keyType:       "custom", // some custom key type
			wantErr:       false,
		},
		{
			name:          "invalid key type with space",
			encodedPubKey: "021072159608e8bfa10102cc74d3e1b533dfdf1904538a61de42811cc3066de014#custom invalid",
			decodedPubKey: "",
			keyType:       "",
			wantErr:       true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			pubKeyBts, keyType, err := DecodePubKeyAndType(tt.encodedPubKey)
			if tt.wantErr {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tt.decodedPubKey, hex.EncodeToString(pubKeyBts))

			require.Equal(t, tt.keyType, keyType)
		})
	}

}

func Test_KeyHexBytes(t *testing.T) {
	k := &KeyHexBytes{
		HexBytes: []byte("test"),
	}
	bts, err := k.MarshalJSON()
	require.NoError(t, err)

	var k2 KeyHexBytes
	err = k2.UnmarshalJSON(bts)
	require.NoError(t, err)

	require.Equal(t, k.HexBytes, k2.HexBytes)

	k = &KeyHexBytes{}

	// ethereum 0x address
	err = k.UnmarshalJSON([]byte(`"0xAfFDC06cF34aFD7D5801A13d48C92AD39609901D"`))
	require.NoError(t, err)

	bts, err = k.MarshalJSON()
	require.NoError(t, err)

	var k3 KeyHexBytes
	err = k3.UnmarshalJSON(bts)
	require.NoError(t, err)

	require.Equal(t, k.HexBytes, k3.HexBytes)
	require.Equal(t, `"0xAfFDC06cF34aFD7D5801A13d48C92AD39609901D"`, string(bts))
}

func TestDisallowUnknownFields(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "unknown field present",
			input: `
                [log]
				level = "debug"
				unknown_field = "value"
				format = "json"
			`,
			wantErr: true,
		},
		{
			name: "nested unknown field",
			input: `
				[p2p]
				listen_address = "0.0.0.0:6600"
				unknown_nested = true
			`,
			wantErr: true,
		},
		{
			name: "array with unknown field",
			input: `
				[p2p.boot_nodes]
				address = "test"
				unknown_array_field = 123
			`,
			wantErr: true,
		},
		{
			name: "valid config no unknown fields",
			input: `
                [log]
				level = "debug"
				format = "json"
				[p2p]
				listen = "0.0.0.0:6600"
			`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile := t.TempDir() + "/config.toml"
			err := os.WriteFile(tempFile, []byte(tt.input), 0644)
			require.NoError(t, err)

			_, err = LoadConfig(tempFile)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrorExtraFields)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfigFromTOML(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Config
		wantErr bool
	}{
		{
			name: "minimal valid config",
			input: `
                [log]
				level = "info"
				format = "plain"
			`,
			want: Config{
				Log: Logging{
					Level:  log.LevelInfo,
					Format: log.FormatUnstructured,
				},
			},
			wantErr: false,
		},
		{
			name:    "empty config bytes",
			input:   "",
			want:    Config{},
			wantErr: false,
		},
		{
			name: "invalid TOML syntax",
			input: `
                [log]
				level = "debug"
				format = ["invalid"
			`,
			wantErr: true,
		},
		{
			name: "invalid log level value",
			input: `
                [log]
				level = "invalid"
				format = "json"
			`,
			wantErr: true,
		},
		{
			name: "config with missing struct fields",
			input: `
                [log]
				format = "json"
				[p2p]
				listen_address = "0.0.0.0:6600"
				pex = true
				boot_nodes = ["/ip4/192.168.1.1/tcp/8080/p2p/test"]
				[db]
				host = "localhost"
				port = "5432"
				user = "testuser"
				pass = "testpass"
				dbname = "testdb"
				read_tx_timeout = "30s"
				max_conns = 20
			`,
			wantErr: true,
		},
		{
			name: "full config with all fields and correct names",
			input: `
                [log]
				level = "debug"
				format = "json"
				[p2p]
				listen = "0.0.0.0:6600"
				pex = true
				bootnodes = ["/ip4/192.168.1.1/tcp/8080/p2p/test"]
				[db]
				host = "localhost"
				port = "5432"
				user = "testuser"
				pass = "testpass"
				dbname = "testdb"
				read_timeout = "30s"
				max_connections = 20
			`,
			want: Config{
				Log: Logging{
					Level:  log.LevelDebug,
					Format: log.FormatJSON,
				},
				P2P: PeerConfig{
					ListenAddress: "0.0.0.0:6600",
					Pex:           true,
					BootNodes:     []string{"/ip4/192.168.1.1/tcp/8080/p2p/test"},
				},
				DB: DBConfig{
					Host:          "localhost",
					Port:          "5432",
					User:          "testuser",
					Pass:          "testpass",
					DBName:        "testdb",
					ReadTxTimeout: types.Duration(30 * time.Second),
					MaxConns:      20,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid duration format",
			input: `
				[db]
				read_tx_timeout = "invalid"
			`,
			wantErr: true,
		},
		{
			name: "negative max_conns",
			input: `
				[db]
				max_conns = -1
			`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := cfg.FromTOML([]byte(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if !tt.wantErr {
				require.Equal(t, tt.want.Log.Level, cfg.Log.Level)
				require.Equal(t, tt.want.Log.Format, cfg.Log.Format)
				require.Equal(t, tt.want.P2P.ListenAddress, cfg.P2P.ListenAddress)
				require.Equal(t, tt.want.P2P.Pex, cfg.P2P.Pex)
				require.Equal(t, tt.want.P2P.BootNodes, cfg.P2P.BootNodes)
				require.Equal(t, tt.want.DB.Host, cfg.DB.Host)
				require.Equal(t, tt.want.DB.Port, cfg.DB.Port)
				require.Equal(t, tt.want.DB.User, cfg.DB.User)
				require.Equal(t, tt.want.DB.Pass, cfg.DB.Pass)
				require.Equal(t, tt.want.DB.DBName, cfg.DB.DBName)
				require.Equal(t, tt.want.DB.ReadTxTimeout, cfg.DB.ReadTxTimeout)
				require.Equal(t, tt.want.DB.MaxConns, cfg.DB.MaxConns)
			}
		})
	}
}

func TestStateSyncStreamTimeout(t *testing.T) {
	// Test default configuration
	cfg := DefaultConfig()

	expectedDefault := 300 * time.Second
	actualDefault := time.Duration(cfg.StateSync.StreamTimeout)

	if actualDefault != expectedDefault {
		t.Errorf("Expected default StreamTimeout to be %v, got %v", expectedDefault, actualDefault)
	}

	// Test custom configuration
	cfg.StateSync.StreamTimeout = types.Duration(600 * time.Second)
	actualCustom := time.Duration(cfg.StateSync.StreamTimeout)
	expectedCustom := 600 * time.Second

	if actualCustom != expectedCustom {
		t.Errorf("Expected custom StreamTimeout to be %v, got %v", expectedCustom, actualCustom)
	}
}
