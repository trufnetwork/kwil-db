package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/kwilteam/kwil-db/core/crypto"
	"github.com/kwilteam/kwil-db/core/crypto/auth"
	"github.com/kwilteam/kwil-db/core/log"
	"github.com/kwilteam/kwil-db/core/types"
	"github.com/kwilteam/kwil-db/node/exts/evm-sync/chains"
)

var (
	ErrorExtraFields = errors.New("unrecognized fields")
)

const (
	ConfigFileName  = "config.toml"
	GenesisFileName = "genesis.json"

	DefaultAdminRPCAddr = "/tmp/kwild.socket"
	AdminServerKeyName  = "admin.key"
	AdminServerCertName = "admin.cert"

	MinProposeTimeout = types.Duration(500 * time.Millisecond)
)

// These are the recognized RPC services, which may be used in the
// RPC.DisableServices config field.
const (
	RPCNamespaceUser     = "user"
	RPCNamespaceChain    = "chain"
	RPCNamespaceFunction = "function"
	RPCNamespaceAdmin    = "admin"
)

func isValidRPCNamespace(ns string) bool {
	switch ns {
	case RPCNamespaceUser, RPCNamespaceFunction, RPCNamespaceChain,
		RPCNamespaceAdmin:
		return true
	default:
		return false
	}
}

type GenesisAlloc struct {
	ID      KeyHexBytes `json:"id"`
	KeyType string      `json:"key_type"`
	Amount  *big.Int    `json:"amount"`
}

// KeyHexBytes wraps hex bytes, and allows it to receive Ethereum 0x addresses
type KeyHexBytes struct{ types.HexBytes }

func (l *KeyHexBytes) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		if bytes.Equal(b, []byte("null")) {
			l.HexBytes = nil
			return nil
		}
		return fmt.Errorf("invalid hex string: %s", b)
	}
	sub := b[1 : len(b)-1] // strip the quotes

	// if it's an ethereum address, strip the 0x prefix
	if len(sub) == hex.EncodedLen(ethAddressLength)+2 && sub[0] == '0' && sub[1] == 'x' {
		sub = sub[2:]
	}

	dec := make([]byte, hex.DecodedLen(len(sub)))
	_, err := hex.Decode(dec, sub)
	if err != nil {
		return err
	}
	l.HexBytes = types.HexBytes(dec)
	return nil
}

const ethAddressLength = 20 // 20 bytes = 40 hex chars

func (l *KeyHexBytes) MarshalJSON() ([]byte, error) {
	if l.HexBytes == nil {
		return []byte("null"), nil
	}

	if len(l.HexBytes) == ethAddressLength {
		checksummed, err := auth.EthSecp256k1Authenticator{}.Identifier(l.HexBytes)
		if err != nil {
			return nil, err
		}

		return []byte(`"` + checksummed + `"`), nil
	}

	return []byte(`"` + hex.EncodeToString(l.HexBytes) + `"`), nil
}

type GenesisConfig struct {
	ChainID       string `json:"chain_id"`
	InitialHeight int64  `json:"initial_height"`

	// DBOwner is the owner of the database.
	// This should be either a public key or address.
	DBOwner string `json:"db_owner"`

	// Validators is the list of genesis validators (including the leader).
	Validators []*types.Validator `json:"validators"`

	// StateHash is the hash of the initial state of the chain, used when bootstrapping
	// the chain with a network snapshot during migration.
	StateHash types.HexBytes `json:"state_hash,omitempty"` // TODO: make it a *types.Hash
	// StateHash *types.Hash `json:"state_hash,omitempty"`

	// Alloc is the initial allocation of balances.
	Allocs []GenesisAlloc `json:"alloc,omitempty"`

	// Migration specifies the migration configuration required for zero downtime migration.
	Migration MigrationParams `json:"migration"`

	// NetworkParameters are network level configurations that can be
	// evolved over the lifetime of a network.
	types.NetworkParameters
}

func (gc *GenesisConfig) SanityChecks() error {
	switch len(gc.StateHash) {
	case 0, types.HashLen:
	default:
		return errors.New("invalid state hash, must be empty or 32 bytes")
	}

	if len(gc.Validators) == 0 {
		return errors.New("no validators provided")
	}

	// Validators power should not be zero
	for _, val := range gc.Validators {
		if val.Power <= 0 {
			return fmt.Errorf("Genesis validators should have non-zero power")
		}

		// ensure that the key type is valid
		_, ok := crypto.KeyTypeDefinition(val.KeyType)
		if !ok {
			return fmt.Errorf("invalid key type: %s", val.KeyType)
		}

		// ensure that the pubkey is valid
		_, err := crypto.UnmarshalPublicKey(val.Identifier, val.KeyType)
		if err != nil {
			return fmt.Errorf("invalid public key: %s error: %s", val.Identifier, err)
		}
	}

	if gc.InitialHeight < 0 {
		return errors.New("initial height must be greater than or equal to 0")
	}

	if err := gc.NetworkParameters.SanityChecks(); err != nil {
		return err
	}

	// Migration params should be both set or both unset
	if (gc.Migration.StartHeight == 0 && gc.Migration.EndHeight != 0) ||
		(gc.Migration.StartHeight != 0 && gc.Migration.EndHeight == 0) {
		return errors.New("both start and end height should be set or unset")
	}

	// ensure that the leader is part of the validator set
	isValidator := slices.ContainsFunc(gc.Validators, func(v *types.Validator) bool {
		if v.KeyType != gc.Leader.Type() {
			return false
		}
		return bytes.Equal(v.Identifier, gc.Leader.Bytes())
	})
	if !isValidator {
		return errors.New("leader is not part of the validator set")
	}

	return nil
}

func DecodePubKeyAndType(encodedPubKey string) ([]byte, crypto.KeyType, error) {
	parts := strings.Split(encodedPubKey, "#")
	if len(parts) != 2 {
		return nil, "", errors.New("invalid pubkey format, expected <pubkey#pubkeytype>")
	}

	pubKey, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("error decoding public key: %s error: %s", parts[0], err)
	}

	pubKeyType := parts[1]
	if pubKeyType == "" || strings.ContainsRune(pubKeyType, ' ') {
		return nil, "", errors.New("invalid pubkey type, expected <pubkey#pubkeytype>")
	}

	return pubKey, crypto.KeyType(pubKeyType), nil
}

func EncodePubKeyAndType(pubKey []byte, pubKeyType crypto.KeyType) string {
	return fmt.Sprintf("%s#%s", hex.EncodeToString(pubKey), pubKeyType)
}

func FormatAccountID(acctID *types.AccountID) string {
	if acctID == nil {
		return ""
	}
	return fmt.Sprintf("%s#%s", acctID.Identifier.String(), acctID.KeyType)
}

// MigrationParams is the migration configuration required for zero downtime
// migration. The height values refer to the height of the old/from chain.
type MigrationParams struct {
	// StartHeight is the height from which the state from the old chain is to be migrated.
	StartHeight int64 `json:"start_height"`
	// EndHeight is the height till which the state from the old chain is to be migrated.
	EndHeight int64 `json:"end_height"`
}

func (m *MigrationParams) IsMigration() bool {
	return m.StartHeight != 0 || m.EndHeight != 0
}

func (nc *GenesisConfig) SaveAs(filename string) error {
	bts, err := json.MarshalIndent(nc, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, bts, 0644)
}

func LoadGenesisConfig(filename string) (*GenesisConfig, error) {
	fid, err := os.Open(filename)
	if err != nil {
		return nil, err // can be os.ErrNotExist
	}
	defer fid.Close()

	var nc GenesisConfig
	dec := json.NewDecoder(fid)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&nc); err != nil {
		return nil, err
	}

	return &nc, nil
}

func DefaultGenesisConfig() *GenesisConfig {
	return &GenesisConfig{
		ChainID:       "kwil-testnet",
		InitialHeight: 0,
		DBOwner:       "",
		Validators:    nil,
		StateHash:     nil,
		Migration:     MigrationParams{},
		NetworkParameters: types.NetworkParameters{
			Leader:           types.PublicKey{ /* nil crypto.PublicKey */ },
			MaxBlockSize:     6 * 1024 * 1024,
			JoinExpiry:       types.Duration(7 * 24 * time.Hour), // 1 week
			DisabledGasCosts: true,
			MaxVotesPerTx:    200,
			MigrationStatus:  types.NoActiveMigration,
		},
	}
}

// DefaultConfig generates an instance of the default config.
func DefaultConfig() *Config {
	return &Config{
		Log: Logging{
			Level:          log.LevelInfo,
			Format:         log.FormatUnstructured,
			Output:         []string{"stdout", "kwild.log"},
			FileRollSize:   10_000, // KB
			RetainMaxRolls: 0,      // retain all archived logs
		},
		Telemetry: Telemetry{
			Enable:       false,
			OTLPEndpoint: "127.0.0.1:4318",
		},
		P2P: PeerConfig{
			ListenAddress:     "0.0.0.0:6600",
			Pex:               true,
			BootNodes:         []string{},
			TargetConnections: 20,
		},
		Consensus: ConsensusConfig{
			ProposeTimeout:        types.Duration(1000 * time.Millisecond),
			EmptyBlockTimeout:     types.Duration(1 * time.Minute),
			BlockProposalInterval: types.Duration(1 * time.Second),
			BlockAnnInterval:      types.Duration(3 * time.Second),
		},
		Mempool: MempoolConfig{
			MaxSize:    200 * 1024 * 1024, // 200 MiB
			MaxTxBytes: 4 * 1024 * 1024,   // 4 MiB
		},
		Store: StoreConfig{
			Compression: true,
		},
		DB: DBConfig{
			Host:          "127.0.0.1",
			Port:          "5432",
			User:          "kwild",
			Pass:          "",
			DBName:        "kwild",
			ReadTxTimeout: types.Duration(45 * time.Second),
			MaxConns:      60,
		},
		RPC: RPCConfig{
			ListenAddress:      "0.0.0.0:8484",
			BroadcastTxTimeout: types.Duration(15 * time.Second),
			Timeout:            types.Duration(20 * time.Second),
			MaxReqSize:         6_000_000,
			Private:            false,
			ChallengeExpiry:    types.Duration(30 * time.Second),
			ChallengeRateLimit: 10,
			DisableServices:    []string{}, // e.g. "chain", see ServiceDisabled
		},
		Admin: AdminConfig{
			Enable:        true,
			ListenAddress: DefaultAdminRPCAddr,
			Pass:          "",
			NoTLS:         false,
		},
		Snapshots: SnapshotConfig{
			Enable:           false,
			RecurringHeight:  14400,
			MaxSnapshots:     3,
			ChunkSendTimeout: types.Duration(300 * time.Second),
		},
		StateSync: StateSyncConfig{
			Enable:                  false,
			DiscoveryTimeout:        types.Duration(15 * time.Second),
			MaxRetries:              3,
			PsqlPath:                "psql",
			CatalogTimeout:          types.Duration(30 * time.Second),
			ChunkTimeout:            types.Duration(120 * time.Second), // Generous timeout for large chunks over slow networks
			MetadataTimeout:         types.Duration(60 * time.Second),
			StreamTimeout:           types.Duration(300 * time.Second), // Matches chunk send timeout for protocol symmetry
			ConcurrentChunkFetchers: 5,                                 // Balanced concurrency: reduces network congestion while improving throughput
		},
		BlockSync: BlockSyncConfig{
			BlockGetTimeout:      types.Duration(90 * time.Second), // Accommodates large blocks in slow network conditions
			BlockSendTimeout:     types.Duration(45 * time.Second), // Half of get timeout to prevent sender timeout before receiver
			RequestTimeout:       types.Duration(2 * time.Second),  // Short timeout for lightweight request messages
			ResponseTimeout:      types.Duration(20 * time.Second),
			IdleTimeout:          types.Duration(500 * time.Millisecond), // Quick detection of stalled transfers
			AnnounceWriteTimeout: types.Duration(5 * time.Second),
			AnnounceRespTimeout:  types.Duration(5 * time.Second),
			TxGetTimeout:         types.Duration(20 * time.Second),
			TxAnnTimeout:         types.Duration(5 * time.Second),
		},
		Extensions: make(map[string]map[string]string),
		Checkpoint: Checkpoint{
			Height: 0,
			Hash:   "",
		},
		Erc20Bridge: ERC20BridgeConfig{
			RPC:                make(map[string]string),
			BlockSyncChuckSize: make(map[string]string),
			Signer:             make(map[string]string),
		},
		SkipDependencyVerification: false,
		PGDumpPath:                 "pg_dump",
	}
}

// Config is the node's config.
type Config struct {
	Log Logging `toml:"log" comment:"logging configuration"`

	ProfileMode string `toml:"profile_mode,commented" comment:"profile mode (http, cpu, mem, mutex, or block)"`
	ProfileFile string `toml:"profile_file,commented" comment:"profile output file path (e.g. cpu.pprof)"`

	Telemetry Telemetry `toml:"telemetry" comment:"telemetry (metrics and traces) configuration"`

	P2P          PeerConfig                   `toml:"p2p" comment:"P2P related configuration"`
	Consensus    ConsensusConfig              `toml:"consensus" comment:"Consensus related configuration"`
	Mempool      MempoolConfig                `toml:"mempool" comment:"Mempool related configuration"`
	DB           DBConfig                     `toml:"db" comment:"DB (PostgreSQL) related configuration"`
	Store        StoreConfig                  `toml:"store" comment:"Block store configuration"`
	RPC          RPCConfig                    `toml:"rpc" comment:"User RPC service configuration"`
	Admin        AdminConfig                  `toml:"admin" comment:"Admin RPC service configuration"`
	Snapshots    SnapshotConfig               `toml:"snapshots" comment:"Snapshot creation and provider configuration"`
	StateSync    StateSyncConfig              `toml:"state_sync" comment:"Statesync configuration (vs block sync)"`
	Extensions   map[string]map[string]string `toml:"extensions" comment:"extension configuration"`
	GenesisState string                       `toml:"genesis_state" comment:"path to the genesis state file, relative to the root directory"`
	Migrations   MigrationConfig              `toml:"migrations" comment:"zero downtime migration configuration"`
	Checkpoint   Checkpoint                   `toml:"checkpoint" comment:"checkpoint info for the leader to sync to before proposing a new block"`
	Erc20Bridge  ERC20BridgeConfig            `toml:"erc20_bridge" comment:"ERC20 bridge configuration"`
	BlockSync    BlockSyncConfig              `toml:"block_sync" comment:"Block synchronization configuration"`

	SkipDependencyVerification bool `toml:"skip_dependency_verification" comment:"skip runtime dependency verification (the pg_dump and psql binaries)"`
	// PGDump: used by the snapshot and the migration module for producing snapshots.
	PGDumpPath string `toml:"pg_dump_path" comment:"path to the pg_dump binary for taking snapshots"`
}

type Logging struct {
	Level          log.Level  `toml:"level" comment:"log level\npossible values: 'debug', 'info', 'warn', and 'error'"`
	Format         log.Format `toml:"format" comment:"log format\npossible values: 'json', 'text' (kv), and 'plain' (fmt-style)"`
	Output         []string   `toml:"output" comment:"output paths for the log"`
	FileRollSize   int64      `toml:"file_roll_size" comment:"threshold in KB at which the log file rolls over and archives the current one"`
	RetainMaxRolls int        `toml:"retain_max_rolls" comment:"retention limit on the number of archived log files to keep (0 meaning retain all)"`
}

type Telemetry struct {
	Enable       bool   `toml:"enable" comment:"enable telemetry"`
	OTLPEndpoint string `toml:"otlp_endpoint" comment:"open telemetry protocol collector endpoint"` // "127.0.0.1:4318"
}

type MempoolConfig struct {
	// MaxSize is the maximum size of the mempool in bytes.
	MaxSize int64 `toml:"max_size" comment:"maximum size of the mempool in bytes"`

	// MaxTxBytes limits the size of any one transaction in mempool.
	MaxTxBytes int64 `mapstructure:"max_tx_bytes"`
}

// PeerConfig corresponds to the [p2p] section of the config.
type PeerConfig struct {
	ListenAddress     string   `toml:"listen" comment:"address in host:port format to listen on for P2P connections"`
	Pex               bool     `toml:"pex" comment:"enable peer exchange"`
	BootNodes         []string `toml:"bootnodes" comment:"bootnodes to connect to on startup"`
	PrivateMode       bool     `toml:"private" comment:"operate in private mode using a node ID whitelist"`
	Whitelist         []string `toml:"whitelist" comment:"allowed node IDs when in private mode"`
	TargetConnections int      `toml:"target_connections" comment:"target number of connections to maintain"`
	ExternalAddress   string   `toml:"external_address" comment:"external address in host:port format to advertise to the network"`
}

// StoreConfig contains options related to the block store. This is the embedded
// database used to store the raw block data, unlike the DBConfig which is
// effectively the state store.
type StoreConfig struct {
	Compression bool `toml:"compression" comment:"compress data when writing new data"`

	// Internal block size and block cache size may be of use soon.
	//   https://github.com/kwilteam/kwil-db/issues/1347
	// CacheSize int `toml:"cache_size" comment:"size of the block store cache in bytes"`
	// ChunkSize int `toml:"chunk_size" comment:"size of the block store's internal blocks"`
}

type DBConfig struct {
	// PostgreSQL DB settings. DBName is the name if the PostgreSQL database to
	// connect to. The different data stores (e.g. engine, acct store, event
	// store, etc.) are all in the same database. Assuming "kwild" is the
	// DBName, this would be created with psql with the commands:
	//  CREATE USER kwild WITH SUPERUSER REPLICATION;
	//  CREATE DATABASE kwild OWNER kwild;
	//
	// All of these settings are strings and separate, but it is possible to
	// have a single DB "connection string" to pass to the PostgreSQL backend.
	// However, this is less error prone, and prevents passing settings that
	// would alter the functionality of the connection. An advanced option could
	// be added to supplement the conn string if that seems useful.
	Host          string         `toml:"host" comment:"postgres host name (IP or UNIX socket path)"`
	Port          string         `toml:"port" comment:"postgres TCP port (leave empty for UNIX socket)"`
	User          string         `toml:"user" comment:"postgres role/user name"`
	Pass          string         `toml:"pass" comment:"postgres password if required for the user and host"`
	DBName        string         `toml:"dbname" comment:"postgres database name"`
	ReadTxTimeout types.Duration `toml:"read_timeout" comment:"timeout on read transactions from user RPC calls and queries"`
	MaxConns      uint32         `toml:"max_connections" comment:"maximum number of DB connections to permit"`
}

type ConsensusConfig struct {
	ProposeTimeout types.Duration `toml:"propose_timeout" comment:"minimum duration to wait before proposing a block with transactions (applies to leader). This value should be greater than 500ms."`

	EmptyBlockTimeout types.Duration `toml:"empty_block_timeout" comment:"timeout for proposing an empty block. If set to 0, disables empty blocks, leader will wait indefinitely until transactions are available to produce a block."`

	// BlockProposalInterval is the interval between block proposal reannouncements by the leader.
	// This affects the time it takes for an out-of-sync validator to receive the current block proposal,
	// thereby impacting the block times. Default is 1 second.
	BlockProposalInterval types.Duration `toml:"block_proposal_interval" comment:"interval between block proposal reannouncements by the leader"`

	// BlockAnnInterval is the frequency with which the block commit messages are reannounced by the leader,
	// and votes reannounced by validators. Default is 3 seconds. This affects the time it takes for
	// out-of-sync nodes to catch up with the latest block.
	BlockAnnInterval types.Duration `toml:"block_ann_interval" comment:"interval between block commit reannouncements by the leader, and votes reannouncements by validators"`
}

type RPCConfig struct {
	ListenAddress      string         `toml:"listen" comment:"address in host:port format on which the RPC server will listen"`
	BroadcastTxTimeout types.Duration `toml:"broadcast_tx_timeout" comment:"duration to wait for a tx to be committed when transactions are authored with --sync flag"`
	Timeout            types.Duration `toml:"timeout" comment:"user request duration limit after which it is cancelled"`
	MaxReqSize         int            `toml:"max_req_size" comment:"largest permissible user request size"`
	Private            bool           `toml:"private" comment:"enable private mode that requires challenge authentication for each call"`
	Compression        bool           `toml:"compression" comment:"use compression in RPC responses"`
	ChallengeExpiry    types.Duration `toml:"challenge_expiry" comment:"lifetime of a server-generated challenge"`
	ChallengeRateLimit float64        `toml:"challenge_rate_limit" comment:"maximum number of challenges per second that a user can request"`
	DisableServices    []string       `toml:"disabled_services" comment:"services to disable on the RPC server e.g. 'chain'"`
}

func (c *RPCConfig) ServiceDisabled(svc string) bool {
	return slices.ContainsFunc(c.DisableServices, func(s string) bool {
		return strings.EqualFold(s, svc)
	})
}

type AdminConfig struct {
	Enable        bool   `toml:"enable" comment:"enable the admin RPC service"`
	ListenAddress string `toml:"listen" comment:"address in host:port format or UNIX socket path on which the admin RPC server will listen"`
	Pass          string `toml:"pass" comment:"optional password for the admin service"`
	NoTLS         bool   `toml:"notls" comment:"disable TLS when the listen address is not a loopback IP or UNIX socket"`
}

type SnapshotConfig struct {
	Enable           bool           `toml:"enable" comment:"enable creating and providing snapshots for peers using statesync"`
	RecurringHeight  uint64         `toml:"recurring_height" comment:"snapshot creation period in blocks"`
	MaxSnapshots     uint64         `toml:"max_snapshots" comment:"number of snapshots to keep, after the oldest is removed when creating a new one"`
	ChunkSendTimeout types.Duration `toml:"chunk_send_timeout" comment:"timeout for sending snapshot chunks to peers"`
}

type StateSyncConfig struct {
	Enable           bool     `toml:"enable" comment:"enable using statesync rather than blocksync"`
	TrustedProviders []string `toml:"trusted_providers" comment:"trusted snapshot providers in node ID format (see bootnodes)"`

	DiscoveryTimeout types.Duration `toml:"discovery_time" comment:"how long to discover snapshots before selecting one to use"`
	MaxRetries       uint64         `toml:"max_retries" comment:"how many times to try after failing to apply a snapshot before switching to blocksync"`
	PsqlPath         string         `toml:"psql_path" comment:"path to the PSQL binary for applying snapshots"`

	// Network timeouts for remote regions
	CatalogTimeout  types.Duration `toml:"catalog_timeout" comment:"timeout for requesting snapshot catalogs from peers"`
	ChunkTimeout    types.Duration `toml:"chunk_timeout" comment:"timeout for downloading individual snapshot chunks"`
	MetadataTimeout types.Duration `toml:"metadata_timeout" comment:"timeout for requesting snapshot metadata"`
	StreamTimeout   types.Duration `toml:"stream_timeout" comment:"timeout for libp2p stream creation and operations"`

	// Concurrency control
	ConcurrentChunkFetchers uint32 `toml:"concurrent_chunk_fetchers" comment:"number of concurrent chunk downloads during state sync (1-20)"`
}

// Validate validates the StateSyncConfig and sets defaults for unspecified values
func (cfg *StateSyncConfig) Validate() error {
	// Set default for ConcurrentChunkFetchers if not specified
	if cfg.ConcurrentChunkFetchers == 0 {
		cfg.ConcurrentChunkFetchers = 5 // Default value
	}

	// Range 1-20: Below 1 eliminates concurrency benefits, above 20 can overwhelm network/disk I/O
	if cfg.ConcurrentChunkFetchers < 1 || cfg.ConcurrentChunkFetchers > 20 {
		return fmt.Errorf("state_sync.concurrent_chunk_fetchers: must be between 1 and 20, got %d", cfg.ConcurrentChunkFetchers)
	}

	return nil
}

// BlockSyncConfig contains configuration for block synchronization timeouts
type BlockSyncConfig struct {
	// Block fetching timeouts
	BlockGetTimeout  types.Duration `toml:"block_get_timeout" comment:"overall timeout for fetching a block"`
	BlockSendTimeout types.Duration `toml:"block_send_timeout" comment:"timeout for sending a block to a peer"`

	// Request/response timeouts
	RequestTimeout  types.Duration `toml:"request_timeout" comment:"timeout for writing block requests"`
	ResponseTimeout types.Duration `toml:"response_timeout" comment:"timeout for reading block responses"`
	IdleTimeout     types.Duration `toml:"idle_timeout" comment:"timeout between reading chunks of a block"`

	// Protocol timeouts
	AnnounceWriteTimeout types.Duration `toml:"announce_write_timeout" comment:"timeout for writing block announcements"`
	AnnounceRespTimeout  types.Duration `toml:"announce_resp_timeout" comment:"timeout for announcement responses"`

	// Transaction timeouts
	TxGetTimeout types.Duration `toml:"tx_get_timeout" comment:"timeout for fetching transactions"`
	TxAnnTimeout types.Duration `toml:"tx_ann_timeout" comment:"timeout for transaction announcements"`
}

type MigrationConfig struct {
	Enable      bool   `toml:"enable" comment:"enable zero downtime migrations"`
	MigrateFrom string `toml:"migrate_from" comment:"JSON-RPC listening address of the node to replicate the state from"`
}

type Checkpoint struct {
	// Height 0 indicates no checkpoint is set. The leader will attempt regular block sync.
	Height int64  `toml:"height" comment:"checkpoint height for the leader. If the leader is behind this height, it will sync to this height before attempting to propose a new block"`
	Hash   string `toml:"hash" comment:"checkpoint block hash"`
}

type ERC20BridgeConfig struct {
	RPC                map[string]string `toml:"rpc" comment:"evm websocket RPC; format: chain_name='rpc_url'"`
	BlockSyncChuckSize map[string]string `toml:"block_sync_chuck_size" comment:"rpc option block sync chunk size; format: chain_name='chunk_size'"`
	Signer             map[string]string `toml:"signer" comment:"signer service configuration; format: ext_alias='file_path_to_private_key'"`
}

// Validate validates the bridge general config, other validations will be performed
// when correspond components derive config from it.
// BlockSyncChuckSize config will be validated by evm-sync listener.
// Signer config will be validated by erc20 signerSvc.
func (cfg ERC20BridgeConfig) Validate() error {
	for chain, rpc := range cfg.RPC {
		if err := chains.Chain(strings.ToLower(chain)).Valid(); err != nil {
			return fmt.Errorf("erc20_bridge.rpc: %s", chain)
		}

		// enforce websocket
		if !strings.HasPrefix(rpc, "wss://") && !strings.HasPrefix(rpc, "ws://") {
			return fmt.Errorf("erc20_bridge.rpc: must start with wss:// or ws://")
		}
	}

	for _, pkPath := range cfg.Signer {
		if !ethCommon.FileExist(pkPath) {
			return fmt.Errorf("erc20_bridge.signer: private key file %s not found", pkPath)
		}
	}

	return nil
}

// ToTOML marshals the config to TOML. The `toml` struct field tag
// specifies the field names. For example:
//
//	Enable  bool  `toml:"enable,commented" comment:"enable the thing"`
//
// The above field will be written like:
//
//	# enable the thing
//	#enable=false
func (nc Config) ToTOML() ([]byte, error) {
	return toml.Marshal(nc)
}

func (nc *Config) FromTOML(b []byte) error {
	return nc.fromTOML(bytes.NewReader(b))
}

func (nc *Config) fromTOML(rd io.Reader) error {
	dec := toml.NewDecoder(rd)
	dec.DisallowUnknownFields()
	err := dec.Decode(&nc)
	var tomlErr *toml.StrictMissingError
	if errors.As(err, &tomlErr) {
		err = fmt.Errorf("%w:\n%s", ErrorExtraFields, tomlErr.String())
	}
	return err
}

// SaveAs writes the Config to the specified TOML file.
func (nc *Config) SaveAs(filename string) error {
	bts, err := nc.ToTOML()
	if err != nil {
		return err
	}

	// TODO: write a toml header/comment or do some prettification. The template
	// was a maintenance burden, and we get setting and section comment with
	// field tags, so I do not prefer ea template. If it does not look pretty
	// enough, we may consider some basic post-processing of bts before writing
	// it. For example, insert newlines before each "#", write a header at the
	// top, etc.

	return os.WriteFile(filename, bts, 0644)
}

func LoadConfig(filename string) (*Config, error) {
	fid, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fid.Close()

	var nc Config
	if err := nc.fromTOML(fid); err != nil {
		return nil, err
	}

	// Validate DisableServices
	for _, ns := range nc.RPC.DisableServices {
		if !isValidRPCNamespace(ns) {
			return nil, fmt.Errorf("rpc.disable_services: invalid namespace %s", ns)
		}
	}

	// Validate StateSyncConfig
	if err := nc.StateSync.Validate(); err != nil {
		return nil, err
	}

	return &nc, nil
}
