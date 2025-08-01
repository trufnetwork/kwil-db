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

	"bufio"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/peers"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
	"github.com/trufnetwork/kwil-db/node/types"
)

const (
	snapshotCatalogNS    = "snapshot-catalog" // namespace on which snapshot catalogs are advertised
	discoverSnapshotsMsg = "discover_snapshots"
)

type snapshotKey = snapshotter.SnapshotKey
type snapshotMetadata = snapshotter.SnapshotMetadata
type snapshotReq = snapshotter.SnapshotReq

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
	snapshotPool    *snapshotPool     // resets with every discovery
	currentSnapshot *snapshotMetadata // track current snapshot to avoid unnecessary cleanup

	// Logger
	log log.Logger
}

// VerificationResult represents the result of snapshot verification
type VerificationResult int

const (
	VerificationValid   VerificationResult = iota // Snapshot is verified as valid
	VerificationInvalid                           // Snapshot is confirmed invalid (should blacklist)
	VerificationFailed                            // Verification failed due to network issues (should retry, not blacklist)
)

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
	const maxBlockRetries = 20
	const retryBackoff = 2 * time.Second
	var rawBlk []byte
	var ci *ktypes.CommitInfo
	for attempt := 1; attempt <= maxBlockRetries; attempt++ {
		ss.log.Info("Attempting to fetch statesync block", "height", height, "attempt", attempt)
		_, rawBlk, ci, _, err = getBlkHeight(ctx, height, ss.host, ss.log, ss.blockSyncCfg)
		if err == nil {
			break
		}
		ss.log.Warn("Block fetch failed, retrying after backoff", "error", err, "backoff", retryBackoff)
		time.Sleep(retryBackoff)
	}
	if err != nil {
		return false, fmt.Errorf("failed to get statesync block %d after %d attempts: %w", height, maxBlockRetries, err)
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

// VerifySnapshot verifies the snapshot with the trusted provider and returns the verification result and app hash.
// Returns VerificationValid with app hash if valid, VerificationInvalid if rejected by provider,
// or VerificationFailed if unable to verify due to network issues.
func (ss *StateSyncService) VerifySnapshot(ctx context.Context, snap *snapshotMetadata) (VerificationResult, []byte) {
	networkErrorCount := 0
	sentinelCount := 0 // providers responded with noData sentinel (snapshot absent)
	totalProviders := len(ss.trustedProviders)

	// verify the snapshot
	for _, provider := range ss.trustedProviders {
		// Create a context with stream timeout for libp2p operations
		streamCtx, cancel := context.WithTimeout(ctx, time.Duration(ss.cfg.StreamTimeout))
		defer cancel()

		// request the snapshot from the provider and verify the contents of the snapshot
		stream, err := ss.host.NewStream(streamCtx, provider.ID, snapshotter.ProtocolIDSnapshotMeta)
		if err != nil {
			ss.log.Warn("failed to request snapshot meta", "provider", provider.ID.String(),
				"error", peers.CompressDialError(err))
			networkErrorCount++
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
			networkErrorCount++
			continue
		}

		stream.SetReadDeadline(time.Now().Add(time.Duration(ss.cfg.MetadataTimeout)))

		br := bufio.NewReader(stream)

		// Peek a single byte
		first, err := br.Peek(1)
		if err != nil {
			ss.log.Warn("failed to peek snapshot metadata", "provider", provider.ID.String(), "error", err)
			stream.Close()
			networkErrorCount++
			continue
		}

		// If that byte is the sentinel → invalid snapshot
		if first[0] == 0 {
			ss.log.Info("trusted provider lacks snapshot", "provider", provider.ID.String(), "height", snap.Height)
			sentinelCount++
			continue
		}

		// Otherwise decode JSON without loading the whole thing
		var meta snapshotMetadata
		dec := json.NewDecoder(br)
		if err := dec.Decode(&meta); err != nil {
			ss.log.Warn("failed to decode snapshot metadata", "provider", provider.ID.String(), "error", err)
			networkErrorCount++
			continue
		}

		// verify the snapshot metadata
		if snap.Height != meta.Height || snap.Format != meta.Format || snap.Chunks != meta.Chunks {
			ss.log.Warnf("snapshot metadata mismatch: expected %v, got %v", snap, meta)
			// This is a definitive rejection - snapshot is invalid
			return VerificationInvalid, nil
		}

		// snapshot hashes should match
		if !bytes.Equal(snap.Hash, meta.Hash) {
			ss.log.Warnf("snapshot metadata mismatch: expected %v, got %v", snap, meta)
			// This is a definitive rejection - snapshot is invalid
			return VerificationInvalid, nil
		}

		// chunk hashes should match
		for i, chunkHash := range snap.ChunkHashes {
			if !bytes.Equal(chunkHash[:], meta.ChunkHashes[i][:]) {
				ss.log.Warnf("snapshot metadata mismatch: expected %v, got %v", snap, meta)
				// This is a definitive rejection - snapshot is invalid
				return VerificationInvalid, nil
			}
		}

		ss.log.Info("verified snapshot with trusted provider", "provider", provider.ID.String(), "snapshot", snap,
			"appHash", hex.EncodeToString(meta.AppHash))
		return VerificationValid, meta.AppHash
	}

	// If we got here, none of the providers produced valid metadata

	if sentinelCount == totalProviders { // everyone said they don't have it
		return VerificationInvalid, nil
	}

	if networkErrorCount == totalProviders { // all had network errors
		ss.log.Warn("Failed to verify snapshot due to network connectivity issues with all trusted providers",
			"snapshot_height", snap.Height, "providers_tried", totalProviders)
		return VerificationFailed, nil
	}

	// Mixed responses: some sentinels, some network errors, but no valid metadata
	if sentinelCount+networkErrorCount == totalProviders {
		// At least one sentinel (no snapshot) but others network issues – treat as invalid to avoid endless retries
		return VerificationInvalid, nil
	}

	// Fallback
	return VerificationFailed, nil
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
