package node

import (
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/types"
)

// Config is the configuration for a [Node] instance.
type Config struct {
	RootDir string
	ChainID string
	PrivKey crypto.PrivateKey
	DB      DB

	P2P       *config.PeerConfig
	DBConfig  *config.DBConfig
	Statesync *config.StateSyncConfig
	BlockSync *config.BlockSyncConfig

	Mempool     types.MemPool
	BlockStore  types.BlockStore
	Consensus   ConsensusEngine
	Snapshotter SnapshotStore
	BlockProc   BlockProcessor
	Logger      log.Logger

	P2PService *P2PService
}
