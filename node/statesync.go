package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/kwilteam/kwil-db/config"
	"github.com/kwilteam/kwil-db/core/log"
	ktypes "github.com/kwilteam/kwil-db/core/types"
	"github.com/kwilteam/kwil-db/node/peers"
	"github.com/kwilteam/kwil-db/node/snapshotter"
	"github.com/kwilteam/kwil-db/node/types"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	snapshotCatalogNS    = "snapshot-catalog" // namespace on which snapshot catalogs are advertised
	discoverSnapshotsMsg = "discover_snapshots"
)

type snapshotKey = snapshotter.SnapshotKey
type snapshotMetadata = snapshotter.SnapshotMetadata
type snapshotReq = snapshotter.SnapshotReq
type snapshotChunkReq = snapshotter.SnapshotChunkReq

type blockStore interface {
	GetByHeight(height int64) (types.Hash, *ktypes.Block, *ktypes.CommitInfo, error)
	Best() (height int64, blkHash, appHash types.Hash, stamp time.Time)
	Store(*ktypes.Block, *ktypes.CommitInfo) error
}

type StatesyncConfig struct {
	StateSyncCfg *config.StateSyncConfig
	DBConfig     config.DBConfig
	BlockSyncCfg *config.BlockSyncConfig
	RcvdSnapsDir string
	P2PService   *P2PService

	DB            DB
	SnapshotStore SnapshotStore
	BlockStore    blockStore
	Logger        log.Logger
}

type StateSyncService struct {
	// Config
	cfg              *config.StateSyncConfig
	dbConfig         config.DBConfig
	blockSyncCfg     *config.BlockSyncConfig
	snapshotDir      string
	trustedProviders []*peer.AddrInfo // trusted providers

	// DHT
	host       host.Host
	discoverer discovery.Discovery

	// Interfaces
	db            DB
	snapshotStore SnapshotStore
	blockStore    blockStore

	// statesync operation specific fields
	snapshotPool *snapshotPool // resets with every discovery

	// Logger
	log log.Logger
}

func NewStateSyncService(ctx context.Context, cfg *StatesyncConfig) (*StateSyncService, error) {
	if cfg.StateSyncCfg.Enable && cfg.StateSyncCfg.TrustedProviders == nil {
		return nil, fmt.Errorf("at least one trusted provider is required for state sync")
	}

	ss := &StateSyncService{
		cfg:           cfg.StateSyncCfg,
		dbConfig:      cfg.DBConfig,
		blockSyncCfg:  cfg.BlockSyncCfg,
		snapshotDir:   cfg.RcvdSnapsDir,
		db:            cfg.DB,
		host:          cfg.P2PService.host,
		discoverer:    cfg.P2PService.discovery,
		snapshotStore: cfg.SnapshotStore,
		log:           cfg.Logger,
		blockStore:    cfg.BlockStore,
		snapshotPool: &snapshotPool{
			snapshots: make(map[snapshotKey]*snapshotMetadata),
			providers: make(map[snapshotKey][]peer.AddrInfo),
			blacklist: make(map[snapshotKey]struct{}),
		},
	}

	// remove the existing snapshot directory
	if err := os.RemoveAll(ss.snapshotDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(ss.snapshotDir, 0755); err != nil {
		return nil, err
	}

	// provide stream handler for snapshot catalogs requests and chunk requests.
	// This is replaced by the Node's handler when it comes up.
	ss.host.SetStreamHandler(ProtocolIDBlockHeight, ss.blkGetHeightRequestHandler)
	if err := ss.Bootstrap(ctx); err != nil {
		return nil, err
	}

	return ss, nil
}

func (s *StateSyncService) Bootstrap(ctx context.Context) error {
	providers, err := peers.ConvertPeersToMultiAddr(s.cfg.TrustedProviders)
	if err != nil {
		return err
	}

	for _, provider := range providers {
		// connect to the provider
		i, err := connectPeer(ctx, provider, s.host)
		if err != nil {
			s.log.Warn("failed to connect to trusted provider", "provider", provider, "error", err)
		}

		s.trustedProviders = append(s.trustedProviders, i)
	}
	return nil
}

// DoStatesync attempts to perform statesync if the db is uninitialized.
// It also initializes the blockstore with the initial block data at the
// height of the discovered snapshot.
func (ss *StateSyncService) DoStatesync(ctx context.Context) (bool, error) {
	// If statesync is enabled and the db is uninitialized, discover snapshots
	if !ss.cfg.Enable {
		return false, nil
	}

	// Check if the Block store and DB are initialized
	h, _, _, _ := ss.blockStore.Best()
	if h != 0 {
		return false, nil
	}

	// check if the db is uninitialized
	height, err := ss.DiscoverSnapshots(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to attempt statesync: %w", err)
	}

	if height <= 0 { // no snapshots found, or statesync failed
		return false, nil
	}

	// request and commit the block to the blockstore
	_, rawBlk, ci, _, err := getBlkHeight(ctx, height, ss.host, ss.log, ss.blockSyncCfg)
	if err != nil {
		return false, fmt.Errorf("failed to get statesync block %d: %w", height, err)
	}
	blk, err := ktypes.DecodeBlock(rawBlk)
	if err != nil {
		return false, fmt.Errorf("failed to decode statesync block %d: %w", height, err)
	}
	// store block
	if err := ss.blockStore.Store(blk, ci); err != nil {
		return false, fmt.Errorf("failed to store statesync block to the blockstore %d: %w", height, err)
	}
	return true, nil
}

// blkGetHeightRequestHandler handles the incoming block requests for a given height.
func (ss *StateSyncService) blkGetHeightRequestHandler(stream network.Stream) {
	defer stream.Close()

	stream.SetReadDeadline(time.Now().Add(reqRWTimeout))

	var req blockHeightReq
	if _, err := req.ReadFrom(stream); err != nil {
		ss.log.Warn("Bad get block (height) request", "error", err) // Debug when we ship
		return
	}
	ss.log.Debug("Peer requested block", "height", req.Height)

	hash, blk, ci, err := ss.blockStore.GetByHeight(req.Height)
	if err != nil || ci == nil {
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData) // don't have it
	} else {
		rawBlk := ktypes.EncodeBlock(blk) // blkHash := blk.Hash()
		ciBytes, _ := ci.MarshalBinary()
		// maybe we remove hash from the protocol, was thinking receiver could
		// hang up earlier depending...
		stream.SetWriteDeadline(time.Now().Add(defaultBlkSendTimeout))
		stream.Write(hash[:])
		ktypes.WriteCompactBytes(stream, ciBytes)
		ktypes.WriteCompactBytes(stream, rawBlk)
	}
}

// verifySnapshot verifies the snapshot with the trusted provider and returns the app hash if the snapshot is valid.
func (ss *StateSyncService) VerifySnapshot(ctx context.Context, snap *snapshotMetadata) (bool, []byte) {
	// verify the snapshot
	for _, provider := range ss.trustedProviders {
		// request the snapshot from the provider and verify the contents of the snapshot
		stream, err := ss.host.NewStream(ctx, provider.ID, snapshotter.ProtocolIDSnapshotMeta)
		if err != nil {
			ss.log.Warn("failed to request snapshot meta", "provider", provider.ID.String(),
				"error", peers.CompressDialError(err))
			continue
		}

		// request for the snapshot metadata
		req := snapshotReq{
			Height: snap.Height,
			Format: snap.Format,
		}
		reqBts, _ := req.MarshalBinary()
		stream.SetWriteDeadline(time.Now().Add(time.Duration(ss.cfg.CatalogTimeout)))

		if _, err := stream.Write(reqBts); err != nil {
			ss.log.Warn("failed to send snapshot request", "provider", provider.ID.String(), "error", err)
			stream.Close()
			continue
		}

		stream.SetReadDeadline(time.Now().Add(time.Duration(ss.cfg.MetadataTimeout)))
		var meta snapshotMetadata
		if err := json.NewDecoder(stream).Decode(&meta); err != nil {
			ss.log.Warn("failed to decode snapshot metadata", "provider", provider.ID.String(), "error", err)
			stream.Close()
			continue
		}
		stream.Close()

		// verify the snapshot metadata
		if snap.Height != meta.Height || snap.Format != meta.Format || snap.Chunks != meta.Chunks {
			ss.log.Warnf("snapshot metadata mismatch: expected %v, got %v", snap, meta)
			continue
		}

		// snapshot hashes should match
		if !bytes.Equal(snap.Hash, meta.Hash) {
			ss.log.Warnf("snapshot metadata mismatch: expected %v, got %v", snap, meta)
			continue
		}

		// chunk hashes should match
		for i, chunkHash := range snap.ChunkHashes {
			if !bytes.Equal(chunkHash[:], meta.ChunkHashes[i][:]) {
				ss.log.Warnf("snapshot metadata mismatch: expected %v, got %v", snap, meta)
				continue
			}
		}

		ss.log.Info("verified snapshot with trusted provider", "provider", provider.ID.String(), "snapshot", snap,
			"appHash", hex.EncodeToString(meta.AppHash))
		return true, meta.AppHash
	}
	return false, nil
}

// snapshotPool keeps track of snapshots that have been discovered from the snapshot providers.
// It also keeps track of the providers that have advertised the snapshots and the blacklisted snapshots.
// Each snapshot is identified by a snapshot key which is generated from the snapshot metadata.
type snapshotPool struct {
	mtx       sync.Mutex // RWMutex?? no
	snapshots map[snapshotKey]*snapshotMetadata
	providers map[snapshotKey][]peer.AddrInfo // TODO: do we need this? should we request from all the providers instead?

	// Snapshot keys that have been blacklisted due to failed attempts to retrieve them or invalid data.
	blacklist map[snapshotKey]struct{}

	peers []peer.AddrInfo // do we need this?
}

func (sp *snapshotPool) blacklistSnapshot(snap *snapshotMetadata) {
	sp.mtx.Lock()
	defer sp.mtx.Unlock()

	key := snap.Key()
	sp.blacklist[key] = struct{}{}
	// delete the snapshot from the pool
	delete(sp.snapshots, key)
	delete(sp.providers, key)
}

func (sp *snapshotPool) updatePeers(peers []peer.AddrInfo) {
	sp.mtx.Lock()
	defer sp.mtx.Unlock()

	sp.peers = peers
}

func (sp *snapshotPool) keyProviders(key snapshotKey) []peer.AddrInfo {
	sp.mtx.Lock()
	defer sp.mtx.Unlock()

	return sp.providers[key]
}

func (sp *snapshotPool) getPeers() []peer.AddrInfo {
	sp.mtx.Lock()
	defer sp.mtx.Unlock()

	return sp.peers
}

func (sp *snapshotPool) listSnapshots() []*snapshotMetadata {
	sp.mtx.Lock()
	defer sp.mtx.Unlock()

	snapshots := make([]*snapshotMetadata, 0, len(sp.snapshots))
	for _, snap := range sp.snapshots {
		snapshots = append(snapshots, snap)
	}
	return snapshots
}
