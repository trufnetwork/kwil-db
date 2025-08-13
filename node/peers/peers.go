package peers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/utils/random"
	"github.com/trufnetwork/kwil-db/node/metrics"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"github.com/multiformats/go-multiaddr"
)

// ErrNoRecordedAddress is returned when a peer is known or even connected, but
// there are no addresses available for it. This can be case when an incoming
// connection is established from a peer that does not have a routable IP
// address on which they can accept incoming connections.
var ErrNoRecordedAddress = errors.New("no address for peer in peerstore")

var mets metrics.NodeMetrics = metrics.Node

const (
	maxRetries      = 500
	disconnectLimit = 7 * 24 * time.Hour // 1 week
)

// config for about 48 hrs startup reconnect in backoff, to match peer store TTL
const (
	reconnectRetries   = 58
	baseReconnectDelay = 2 * time.Second
	maxReconnectDelay  = 1 * time.Hour
)

// PeerIDStringer provides lazy lazy conversion of a libp2p peer ID into a Kwil
// node ID, which is a public key with a type suffix.
type PeerIDStringer string

func (p PeerIDStringer) String() string {
	pid, err := peer.Decode(string(p))
	if err != nil {
		pid = peer.ID(p) // assume it was the multihash bytes, not peer.ID.String() output
	}
	nodeID, err := nodeIDFromPeerID(pid)
	if err == nil {
		return nodeID
	}
	return string(p)
}

type Connector interface {
	Connect(ctx context.Context, pi peer.AddrInfo) error
	// ClosePeer(peer.ID) error
	// Connectedness(peer.ID) network.Connectedness
	// LocalPeer() peer.ID
}

// peer/connection manager:
//	1. manage peerstore (and it's address book)
//  2. store and load from our address book file
//	3. provide the Notifee (connect/disconnect hooks)
//	4. maintain connections (min/max limits)

type RemotePeersFn func(ctx context.Context, peerID peer.ID) ([]peer.AddrInfo, error)

type PeerMan struct {
	log log.Logger
	h   host.Host // TODO: remove with just interfaces needed
	c   Connector
	ps  peerstore.Peerstore

	idService identify.IDService

	// the connection gater enforces an effective ephemeral whitelist.
	cg                  *WhitelistGater
	wlMtx               sync.RWMutex
	persistentWhitelist map[peer.ID]bool // whitelist to persist

	// blacklist management
	blacklistMtx     sync.RWMutex
	blacklistedPeers map[peer.ID]BlacklistEntry
	blacklistConfig  config.BlacklistConfig

	requiredProtocols []protocol.ID

	chainID           string
	pex               bool
	addrBook          string
	targetConnections int
	seedMode          bool
	crawlPeerInfos    map[peer.ID]crawlPeerInfo

	done  chan struct{}
	close func()
	wg    sync.WaitGroup

	// TODO: revise address book file format as needed if these should persist
	mtx         sync.Mutex
	lastAttempt map[peer.ID]time.Time
	disconnects map[peer.ID]time.Time // Track disconnection timestamps
	noReconnect map[peer.ID]bool
}

// In seed mode:
//	1. hang up after a short period (TTL set differently after discover?)
//	2. hang up on completion of incoming discovery stream
//	3. maybe have a crawl goroutine instead of maintainMinPeers

type Config struct {
	PEX      bool
	AddrBook string
	Host     host.Host

	SeedMode          bool
	TargetConnections int
	ChainID           string

	// Optionals
	Logger            log.Logger
	ConnGater         *WhitelistGater
	RequiredProtocols []protocol.ID
	BlacklistConfig   config.BlacklistConfig
}

type idService interface {
	IDService() identify.IDService
}

func NewPeerMan(cfg *Config) (*PeerMan, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = log.DiscardLogger
	}
	done := make(chan struct{})
	host := cfg.Host

	hi, ok := host.(idService)
	if !ok {
		return nil, errors.New("no IDService available.")
	}

	pm := &PeerMan{
		h:                   host, // tmp: tooo much, should become minimal interface, maybe set after construction
		c:                   host,
		ps:                  host.Peerstore(),
		cg:                  cfg.ConnGater,
		idService:           hi.IDService(),
		persistentWhitelist: make(map[peer.ID]bool),
		blacklistedPeers:    make(map[peer.ID]BlacklistEntry),
		blacklistConfig:     cfg.BlacklistConfig,
		log:                 logger,
		done:                done,
		close: sync.OnceFunc(func() {
			close(done)
		}),
		requiredProtocols: cfg.RequiredProtocols,
		chainID:           cfg.ChainID,
		pex:               cfg.PEX,
		seedMode:          cfg.SeedMode,
		addrBook:          cfg.AddrBook,
		crawlPeerInfos:    make(map[peer.ID]crawlPeerInfo),
		targetConnections: cfg.TargetConnections,
		lastAttempt:       make(map[peer.ID]time.Time),
		disconnects:       make(map[peer.ID]time.Time),
		noReconnect:       make(map[peer.ID]bool),
	}

	numPeers, err := pm.loadAddrBook()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load address book %s", pm.addrBook)
	}
	logger.Infof("Loaded address book with %d peers", numPeers)

	if cfg.PEX || cfg.SeedMode {
		host.SetStreamHandler(ProtocolIDDiscover, pm.DiscoveryStreamHandler)
	} else {
		host.SetStreamHandler(ProtocolIDDiscover, func(s network.Stream) {
			s.Close()
		})
	}

	host.SetStreamHandler(ProtocolIDPrefixChainID+protocol.ID(cfg.ChainID), func(s network.Stream) {
		s.Close() // protocol handshake is all we need
		// TODO (maybe): get and serve our height is a peer actually tries to use this protocol
	})

	if cfg.SeedMode {
		host.SetStreamHandler(ProtocolIDCrawler, func(s network.Stream) {
			s.Close() // this protocol is just to signal capabilities
		})
	}

	// If we have a WhitelistGater, set the PeerMan reference for blacklist checking
	if cfg.ConnGater != nil {
		// Update the WhitelistGater with PeerMan reference
		pm.cg = NewWhitelistGater(cfg.ConnGater.Allowed(), WithLogger(cfg.ConnGater.logger), WithPeerMan(pm))
	}

	return pm, nil
}

func (pm *PeerMan) Start(ctx context.Context) error {
	// listen for messages when peer identification (protocol listing) is completed
	evtSub, err := pm.h.EventBus().Subscribe(&event.EvtPeerIdentificationCompleted{})
	if err != nil {
		return fmt.Errorf("event subscribe failed: %w", err)
	}
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case evt := <-evtSub.Out():
				idComplete, ok := evt.(event.EvtPeerIdentificationCompleted)
				if !ok {
					pm.log.Infof("event %T", evt)
					continue
				}
				if !slices.Contains(idComplete.Protocols, ProtocolIDPrefixChainID+protocol.ID(pm.chainID)) {
					pm.log.Warn("Removing peer not on "+pm.chainID, "agent", idComplete.AgentVersion, "pver", idComplete.ProtocolVersion)
					pm.removePeer(idComplete.Peer)
				} else {
					pm.log.Debug("Peer is on "+pm.chainID, "agent", idComplete.AgentVersion, "pver", idComplete.ProtocolVersion)
				}
			}
		}
	}()

	if pm.seedMode {
		pm.wg.Add(1)
		go func() {
			defer pm.wg.Done()
			pm.crawl(ctx)
		}()
	} else {
		pm.wg.Add(1)
		go func() {
			defer pm.wg.Done()
			pm.maintainMinPeers(ctx)
		}()

		if pm.pex {
			pm.wg.Add(1)
			go func() {
				defer pm.wg.Done()
				pm.startPex(ctx)
			}()
		}
	}

	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		pm.removeOldPeers()
	}()

	<-ctx.Done()

	pm.close()

	pm.wg.Wait()

	return pm.savePeers()
}

// Close stops any background goroutines and releases resources.
// This should be called when the PeerMan is no longer needed to prevent goroutine leaks.
func (pm *PeerMan) Close() error {
	// Close the WhitelistGater if it exists to stop its background logger
	if pm.cg != nil {
		pm.cg.Close()
	}

	// Signal all goroutines to stop
	pm.close()

	// Wait for all goroutines to finish
	pm.wg.Wait()

	// Save peers before shutting down
	return pm.savePeers()
}

const (
	urgentConnInterval = time.Second
	normalConnInterval = 20 * urgentConnInterval
)

func (pm *PeerMan) maintainMinPeers(ctx context.Context) {
	// Start with a fast iteration until we determine that we either have some
	// connected peers, or we don't even have candidate addresses yet.
	ticker := time.NewTicker(urgentConnInterval)
	defer ticker.Stop()

	lastAttempts := make(map[peer.ID]*backoffer)

	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}

		_, activeConns, unconnectedPeers := pm.KnownPeers()
		if numActive := len(activeConns); numActive < pm.targetConnections {
			if numActive == 0 && len(unconnectedPeers) == 0 {
				pm.log.Warnln("No connected peers and no known addresses to dial!")
				continue
			}

			pm.log.Debugf("Active connections: %d, below target: %d. Initiating new connections.",
				numActive, pm.targetConnections)

			var added int
			for _, peerInfo := range unconnectedPeers {
				pid := peerInfo.ID
				if pm.h.ID() == pid {
					continue
				}
				if !pm.IsAllowed(pid) {
					continue // Connect would error anyway, just be silent
				}
				bk := lastAttempts[pid]
				if bk == nil {
					bk = newBackoffer(reconnectRetries, baseReconnectDelay, maxReconnectDelay, true)
					lastAttempts[pid] = bk
				}
				if !bk.try() {
					if bk.maxedOut() {
						pm.log.Warnf("Failed to connect to peer %s (%v) after %d attempts", peerIDStringer(pid), pid, bk.attempts)

						// Auto-blacklist peer that exhausted connection retries if enabled
						if pm.blacklistConfig.Enable && pm.blacklistConfig.AutoBlacklistOnMaxRetries {
							duration := pm.blacklistConfig.AutoBlacklistDuration

							// Enhanced structured logging for auto-blacklist
							pm.log.Warn("Auto-blacklisted peer due to connection exhaustion",
								"peer_id", peerIDStringer(pid),
								"reason", "connection_exhaustion",
								"attempts", bk.attempts,
								"duration", duration.String(),
								"operation", "auto_blacklist",
							)

							// Add metrics for auto-blacklist event
							metrics.Node.AutoBlacklistEvent(context.Background(), "connection_exhaustion", int64(bk.attempts))

							pm.BlacklistPeer(pid, "connection_exhaustion", duration) // configurable duration blacklist (also removes peer)
						} else {
							pm.removePeer(pid)
						}
					}
					continue
				}
				pm.log.Infof("Connecting to peer %s", peerIDStringer(pid))
				err := pm.h.Connect(ctx, peer.AddrInfo{ID: pid})
				if err != nil {
					// NOTE: if this fails because of security protocol
					// handshake failure (e.g. chain ID mismatch), we can't tell the precise reason.
					pm.log.Warnf("Failed to connect to peer %s (%v): %v", peerIDStringer(pid), pid, CompressDialError(err))
				} else {
					pm.log.Infof("Connected to peer %s", peerIDStringer(pid))
					added++
				}
			}

			if added == 0 && numActive == 0 {
				// Keep trying known peer addresses more frequently until we
				// have at least on connection.
				ticker.Reset(urgentConnInterval)
			} else {
				ticker.Reset(normalConnInterval)
			}
		} else {
			pm.log.Debugf("Have %d connections and %d candidates of %d target", numActive, len(unconnectedPeers), pm.targetConnections)
			ticker.Reset(normalConnInterval)
		}
	}
}

func (pm *PeerMan) startPex(ctx context.Context) {
	for {
		// discover for this node
		peerChan, err := pm.FindPeers(ctx, "kwil_namespace")
		if err != nil {
			pm.log.Errorf("FindPeers: %v", err)
		} else {
			go func() {
				var count int
				for peer := range peerChan {
					if pm.addPeerAddrs(peer) {
						pm.log.Infof("Found new peer %v, connecting", peerIDStringer(peer.ID))
						// TODO: connection manager, with limits
						if err = pm.c.Connect(ctx, peer); err != nil {
							pm.log.Warnf("Failed to connect to %s: %v", peerIDStringer(peer.ID), CompressDialError(err))
						}
					}
					count++
				}
				if count > 0 {
					if err := pm.savePeers(); err != nil {
						pm.log.Warnf("Failed to write address book: %v", err)
					}
				}
			}()
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}

		if err := pm.savePeers(); err != nil {
			pm.log.Warnf("Failed to write address book: %v", err)
		}
	}
}

func filterPeer(peers []peer.ID, peerID peer.ID) []peer.ID {
	return slices.DeleteFunc(peers, func(p peer.ID) bool {
		return p == peerID
	})
}

type crawlPeerInfo struct {
	ID peer.ID `json:"id"`
	// Addr *Addr `json:"addr"`
	LastCrawl time.Time `json:"last_crawl"`
}

const recrawlThreshold = time.Minute

// randomPeerToCrawl gets a random peer to crawl i.e. request peers from and
// begin crawling through them.
func (pm *PeerMan) randomPeerToCrawl() (peer.ID, bool) {
	// Connected peers first.
	peers := filterPeer(pm.h.Network().Peers(), pm.h.ID())
	// Filter out peers that were crawled too recently.
	peers = slices.DeleteFunc(peers, func(p peer.ID) bool {
		return time.Since(pm.crawlPeerInfos[p].LastCrawl) < recrawlThreshold
	})
	if n := len(peers); n > 0 {
		i := mrand.IntN(n)
		return peers[i], true
	}

	// Address book peers if no eligible connected peers.
	peers = filterPeer(pm.ps.PeersWithAddrs(), pm.h.ID())
	peers = slices.DeleteFunc(peers, func(p peer.ID) bool {
		return time.Since(pm.crawlPeerInfos[p].LastCrawl) < recrawlThreshold
	})
	if n := len(peers); n > 0 {
		i := mrand.IntN(n)
		return peers[i], true
	}
	return "", false
}

func (pm *PeerMan) crawl(ctx context.Context) {
	for {
		peer, found := pm.randomPeerToCrawl()
		if !found {
			pm.log.Warn("no known peers available to crawl")
		} else {
			pm.crawlPeer(ctx, peer)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
			continue
		}
	}
}

const maxCrawlSpread = 20

var rng = random.New()

func (pm *PeerMan) crawlPeer(ctx context.Context, peerID peer.ID) {
	if peerID == pm.h.ID() {
		return
	}

	pm.log.Infoln("Crawling network through peer", peerIDStringer(peerID))

	// TODO: make this smarter by trying to connect first so we can only add the
	// peer to the store if the connect succeeds. Presently it's just a low TTL.

	ctxPR, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	peersInfo, err := pm.RequestPeers(ctxPR, peerID)
	if err != nil {
		pm.log.Warnf("Failed to get peers from %v: %v", peerIDStringer(peerID), err)
		return
	}
	defer pm.h.Network().ClosePeer(peerID) // we're done here

	// Remember successful crawl so we don't bother them again too soon.
	pm.crawlPeerInfos[peerID] = crawlPeerInfo{
		ID:        peerID,
		LastCrawl: time.Now(),
	}

	var newPeers []peer.AddrInfo

	for _, peerInfo := range peersInfo {
		if peerInfo.ID == pm.h.ID() {
			continue
		}
		pai := peer.AddrInfo(peerInfo.AddrInfo)
		if pm.addPeerAddrs(pai) {
			// new peer address, added to address book with temp TTL
			newPeers = append(newPeers, pai)
		}
	}

	if len(newPeers) == 0 {
		pm.log.Infof("No new peers found from %v", peerIDStringer(peerID))
		return
	}

	if err := pm.savePeers(); err != nil {
		pm.log.Warnf("Failed to write address book: %v", err)
	}

	rng.Shuffle(len(newPeers), func(i, j int) {
		newPeers[i], newPeers[j] = newPeers[j], newPeers[i]
	})

	for i, newPeer := range newPeers[:min(len(newPeers), maxCrawlSpread)] {
		// go request their peers
		pm.wg.Add(1)
		go func() {
			defer pm.wg.Done()
			time.Sleep(time.Duration(i) * 200 * time.Millisecond) // slight staggering
			pm.crawlPeer(ctx, newPeer.ID)                         // outer context
		}()
	}
}

var _ discovery.Discoverer = (*PeerMan)(nil) // FindPeers method, namespace ignored

func (pm *PeerMan) FindPeers(ctx context.Context, ns string, opts ...discovery.Option) (<-chan peer.AddrInfo, error) {
	peerChan := make(chan peer.AddrInfo)

	peers := pm.h.Network().Peers()
	if len(peers) == 0 {
		close(peerChan)
		pm.log.Warn("no existing peers for peer discovery")
		return peerChan, nil
	}

	var wg sync.WaitGroup
	wg.Add(len(peers))
	for _, peerID := range peers {
		peerIDCopy := peerID // capture the loop variable
		go func() {
			defer wg.Done()
			if peerIDCopy == pm.h.ID() {
				return
			}
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			peers, err := pm.RequestPeers(ctx, peerIDCopy)
			if err != nil {
				pm.log.Warnf("Failed to get peers from %v: %v", peerIDStringer(peerIDCopy), err)
				return
			}

			for _, p := range peers {
				peerChan <- peer.AddrInfo(p.AddrInfo)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(peerChan)
	}()

	return peerChan, nil
}

// ConnectedPeers returns a list of peer info for all connected peers.
func (pm *PeerMan) ConnectedPeers() []PeerInfo {
	var peers []PeerInfo
	for _, peerID := range pm.h.Network().Peers() { // connected peers first
		if peerID == pm.h.ID() { // me
			continue
		}
		peerInfo, err := pm.peerInfo(peerID)
		if err != nil {
			if !errors.Is(err, ErrNoRecordedAddress) {
				pm.log.Warnf("(ConnectedPeers) peerInfo for %v: %v", peerIDStringer(peerID), err)
			}
			continue
		}

		peers = append(peers, *peerInfo)
	}

	return peers
}

// KnownPeers returns a list of peer info for all known peers (connected or just
// in peer store).
func (pm *PeerMan) KnownPeers() (all, connected, disconnected []PeerInfo) {
	// connected peers first
	peers := pm.ConnectedPeers()
	connectedPeers := make(map[peer.ID]bool)
	for _, peerInfo := range peers {
		connectedPeers[peerInfo.ID] = true
		connected = append(connected, peerInfo)
	}

	// all others in peer store
	for _, peerID := range pm.ps.Peers() {
		if peerID == pm.h.ID() { // me
			continue
		}
		if connectedPeers[peerID] {
			continue // it is connected
		}
		peerInfo, err := pm.peerInfo(peerID)
		if err != nil {
			if !errors.Is(err, ErrNoRecordedAddress) {
				pm.log.Warnf("(other peers) peerInfo for %v: %v", peerIDStringer(peerID), err)
			}
			continue
		}

		disconnected = append(disconnected, *peerInfo)
		peers = append(peers, *peerInfo)
	}

	return peers, connected, disconnected
}

func CheckProtocolSupport(_ context.Context, ps peerstore.Peerstore, peerID peer.ID, protoIDs ...protocol.ID) (bool, error) {
	// supported, err := ps.SupportsProtocols(peerID, protoIDs...)
	// if err != nil { return false, err }
	// return len(protoIDs) == len(supported), nil

	supportedProtos, err := ps.GetProtocols(peerID)
	if err != nil {
		return false, err
	}

	for _, protoID := range protoIDs {
		if !slices.Contains(supportedProtos, protoID) {
			return false, nil
		}
	}

	return true, nil
}

func RequirePeerProtos(ctx context.Context, ps peerstore.Peerstore, peer peer.ID, protoIDs ...protocol.ID) error {
	for _, pid := range protoIDs {
		ok, err := CheckProtocolSupport(ctx, ps, peer, pid)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("protocol not supported: %v", pid)
		}
	}
	return nil
}

func (pm *PeerMan) peerInfo(peerID peer.ID) (*PeerInfo, error) {
	addrs := pm.ps.Addrs(peerID)
	if len(addrs) == 0 {
		// They are not in our *peerstore*, but they may be connected, such as
		// if they lack a routable IP address to which others may connect.
		if conns := pm.h.Network().ConnsToPeer(peerID); len(conns) > 0 {
			ma := conns[0].RemoteMultiaddr()
			return nil, fmt.Errorf("%w but connected from %v", ErrNoRecordedAddress, ma)
		}
		return nil, ErrNoRecordedAddress
	}

	supportedProtos, err := pm.ps.GetProtocols(peerID)
	if err != nil {
		return nil, fmt.Errorf("GetProtocols failed: %w", err)
	}

	return &PeerInfo{
		AddrInfo: AddrInfo{
			ID:    peerID,
			Addrs: addrs,
		},
		Protos: supportedProtos,
	}, nil
}

func (pm *PeerMan) PrintKnownPeers() {
	_, connected, disconnected := pm.KnownPeers()
	for _, p := range connected {
		pm.log.Info("Known peer", "id", p.ID.String(), "node", peerIDStringer(p.ID), "connected", true)
	}
	for _, p := range disconnected {
		pm.log.Info("Known peer", "id", p.ID.String(), "node", peerIDStringer(p.ID), "connected", false)
	}
}

// savePeers writes the address book file.
func (pm *PeerMan) savePeers() error {
	peerList, _, _ := pm.KnownPeers()
	pm.log.Debugf("Saving %d peers to address book", len(peerList))

	// set whitelisted and blacklisted flags for persistence
	pm.wlMtx.RLock()
	pm.blacklistMtx.RLock()
	persistentPeerList := make([]PersistentPeerInfo, len(peerList))
	for i, peerInfo := range peerList {
		pk, _ := pubKeyFromPeerID(peerInfo.ID)
		if pk == nil {
			pm.log.Errorf("Invalid peer ID %v", peerInfo.ID)
			pm.removePeer(peerInfo.ID)
			continue
		}
		nodeID := NodeIDFromPubKey(pk)

		// Get blacklist entry if it exists (and is not expired)
		var blacklistEntry *BlacklistEntry
		if entry, exists := pm.blacklistedPeers[peerInfo.ID]; exists {
			if entry.Permanent || !entry.IsExpired() {
				// Create a copy to avoid issues with pointer sharing
				blacklistEntry = &BlacklistEntry{
					PeerID:    entry.PeerID,
					Reason:    entry.Reason,
					Timestamp: entry.Timestamp,
					Permanent: entry.Permanent,
					ExpiresAt: entry.ExpiresAt,
				}
			}
		}

		persistentPeerList[i] = PersistentPeerInfo{
			NodeID:      nodeID,
			Addrs:       peerInfo.Addrs,
			Protos:      peerInfo.Protos,
			Whitelisted: pm.persistentWhitelist[peerInfo.ID],
			Blacklisted: blacklistEntry,
		}
	}
	pm.blacklistMtx.RUnlock()
	pm.wlMtx.RUnlock()

	return persistPeers(persistentPeerList, pm.addrBook)
}

func (pm *PeerMan) removePeer(pid peer.ID) {
	pm.ps.RemovePeer(pid)
	pm.ps.ClearAddrs(pid)
	for _, conn := range pm.h.Network().ConnsToPeer(pid) {
		if conn.Stat().Extra != nil {
			conn.Stat().Extra[kicked] = struct{}{}
		}
		conn.Close()
	}
	pm.mtx.Lock()
	pm.noReconnect[pid] = true
	pm.mtx.Unlock()
}

// persistPeers saves known peers to a JSON file
func persistPeers(peers []PersistentPeerInfo, filePath string) error {
	data, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling peers to JSON: %v", err)
	}

	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("writing peers to file: %w", err)
	}
	return nil
}

func loadPeers(filePath string) ([]PersistentPeerInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read peerstore file: %w", err)
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	var peerList []PersistentPeerInfo
	if err := json.Unmarshal(data, &peerList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal peerstore data: %w", err)
	}
	return peerList, nil
}

func (pm *PeerMan) loadAddrBook() (int, error) {
	peerList, err := loadPeers(pm.addrBook)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("failed to load address book %s", pm.addrBook)
	}

	var count int
	for _, pInfo := range peerList {
		peerID, err := nodeIDToPeerID(pInfo.NodeID)
		if err != nil {
			pm.log.Errorf("invalid node ID in address book (%v): %w", pInfo.NodeID, err)
			continue
		}

		if pm.cg != nil { // private mode
			if pInfo.Whitelisted {
				pm.cg.Allow(peerID)
				pm.wlMtx.Lock()
				pm.persistentWhitelist[peerID] = true
				pm.wlMtx.Unlock()
			}
		}

		// Load blacklist data if it exists and is still valid
		if pInfo.Blacklisted != nil {
			entry := pInfo.Blacklisted
			// Only restore if entry hasn't expired
			if entry.Permanent || !entry.IsExpired() {
				pm.blacklistMtx.Lock()
				pm.blacklistedPeers[peerID] = *entry
				pm.blacklistMtx.Unlock()

				// Also set noReconnect for immediate effect
				pm.mtx.Lock()
				pm.noReconnect[peerID] = true
				pm.mtx.Unlock()

				pm.log.Infof("Restored blacklist entry for peer %s (reason: %s, permanent: %v)",
					peerIDStringer(peerID), entry.Reason, entry.Permanent)
			} else {
				pm.log.Infof("Expired blacklist entry for peer %s not restored", peerIDStringer(peerID))
			}
		}

		peerInfo := PeerInfo{
			AddrInfo: AddrInfo{
				ID:    peerID,
				Addrs: pInfo.Addrs,
			},
			Protos: pInfo.Protos,
		}

		ttl := calculateBackoffTTL(baseReconnectDelay, maxReconnectDelay, reconnectRetries, true)
		if pm.addPeer(peerInfo, ttl) {
			count++
		}
	}

	return count, nil
}

// addPeer adds a peer to the peerstore and returns if a new address was added
// for the peer. This does not check peer whitelist in private mode.
func (pm *PeerMan) addPeer(pInfo PeerInfo, ttl time.Duration) bool {
	nodeID, err := nodeIDFromPeerID(pInfo.ID)
	if err != nil {
		pm.log.Errorln("Unsupported peer ID %v", pInfo.ID)
		return false
	}

	var addrCount int

	knownAddrs := pm.ps.Addrs(pInfo.ID)
	for _, addr := range pInfo.Addrs {
		if multiaddr.Contains(knownAddrs, addr) {
			continue // address already known
		}
		pm.ps.AddAddr(pInfo.ID, addr, ttl)
		pm.log.Infof("Added new peer address to store: %v (%v) @ %v", nodeID, pInfo.ID, addr)
		addrCount++
	}
	for _, proto := range pInfo.Protos {
		if err := pm.ps.AddProtocols(pInfo.ID, proto); err != nil {
			pm.log.Warnf("Error adding protocol %s for peer %s: %v", proto, pInfo.ID, err)
		}
	}

	return addrCount > 0
}

func (pm *PeerMan) Connect(ctx context.Context, info AddrInfo) error {
	if !pm.cg.IsAllowed(info.ID) {
		return errors.New("peer not whitelisted while in private mode")
	} // else it still wouldn't pass the connection gater, but we don't want to try or touch the peerstore
	return CompressDialError(pm.c.Connect(ctx, peer.AddrInfo(info)))
}

func (pm *PeerMan) Allow(p peer.ID) {
	pm.cg.Allow(p)
}

func (pm *PeerMan) AllowPersistent(p peer.ID) {
	pm.wlMtx.Lock()
	pm.persistentWhitelist[p] = true
	pm.wlMtx.Unlock()
	if err := pm.savePeers(); err != nil {
		pm.log.Errorf("failed to save address book: %v", err)
	}
	pm.cg.Allow(p)
}

func (pm *PeerMan) Disallow(p peer.ID) {
	pm.wlMtx.Lock()
	delete(pm.persistentWhitelist, p)
	pm.wlMtx.Unlock()
	if pm.cg.Disallow(p) {
		// Disconnect the peer if it is connected
		pm.log.Infof("Removing disallowed peer %s (%v)", peerIDStringer(p), p)
		pm.removePeer(p)
	}
}

func (pm *PeerMan) IsAllowed(p peer.ID) bool {
	return pm.cg.IsAllowed(p)
}

func (pm *PeerMan) Allowed() []peer.ID {
	return pm.cg.Allowed()
}

func (pm *PeerMan) AllowedPersistent() []peer.ID {
	var peerList []peer.ID
	pm.wlMtx.Lock()
	defer pm.wlMtx.Unlock()
	for peerID := range pm.persistentWhitelist {
		peerList = append(peerList, peerID)
	}
	return peerList
}

// addPeerAddrs adds a discovered peer to the local peer store.
func (pm *PeerMan) addPeerAddrs(p peer.AddrInfo) (added bool) {
	// We may have discovered the address of a whitelisted peer ID.
	// 	if !pm.cg.IsAllowed(p.ID) {
	// 		return
	//  }

	return pm.addPeer(
		PeerInfo{
			AddrInfo: AddrInfo(p),
			// No known protocols, yet
		},
		peerstore.TempAddrTTL,
	)
}

type peerIDStringer peer.ID

func (p peerIDStringer) String() string {
	pid := peer.ID(p)
	nodeID, err := nodeIDFromPeerID(pid)
	if err == nil {
		return nodeID
	}
	return pid.String()
}

func (pm *PeerMan) numConnectedPeers() int {
	return len(pm.h.Network().Peers())
}

// Connected is triggered when a peer is connected (inbound or outbound).
func (pm *PeerMan) Connected(net network.Network, conn network.Conn) {
	defer mets.PeerCount(context.Background(), pm.numConnectedPeers())

	peerID := conn.RemotePeer()
	addr := conn.RemoteMultiaddr()
	pm.log.Infof("Connected to peer (%s) %s @ %v", conn.Stat().Direction, peerIDStringer(peerID), addr)

	if _, err := pubKeyFromPeerID(peerID); err != nil {
		pm.log.Warnf("Peer with unsupported peer ID connected (%v): %v", peerIDStringer(peerID), err)
		pm.removePeer(peerID)
		return
	}

	// Reset disconnect timestamp on successful connection
	pm.mtx.Lock()
	delete(pm.disconnects, peerID)
	pm.mtx.Unlock()

	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()

		// Particularly for inbound, there seems to be a race condition with
		// protocol negotiation after connect. We have to delay this check.
		// https://github.com/libp2p/go-libp2p/issues/2643
		t0 := time.Now()
		select {
		case <-time.After(5 * time.Second):
			pm.log.Warnf("Peer identify not complete after %v (%v)", time.Since(t0), peerIDStringer(peerID))
		case <-pm.idService.IdentifyWait(conn):
			pm.log.Infof("Identified peer %s in %v", peerIDStringer(peerID), time.Since(t0))
		case <-pm.done:
			return
		}

		if conn.IsClosed() {
			return
		}

		supportedProtos, err := pm.ps.GetProtocols(peerID)
		if err != nil {
			conn.Close()
			return
		}

		if !slices.ContainsFunc(supportedProtos, func(pid protocol.ID) bool {
			return pid == ProtocolIDPrefixChainID+protocol.ID(pm.chainID)
		}) {
			pm.log.Warnf("Peer %v is not on chain %v", peerIDStringer(peerID), pm.chainID)
			pm.removePeer(peerID)
			return
		}

		if slices.Contains(supportedProtos, ProtocolIDCrawler) {
			pm.log.Infof("Connected to crawler at %v", peerIDStringer(peerID))
			pm.h.ConnManager().TagPeer(peerID, "crawler", -1) // can't do this with pm.ps.RemovePeer(peerID)
			pm.ps.ClearAddrs(peerID)                          // don't advertise them to others, and don't reconnect on disconnect
			// pm.ps.RemovePeer(peerID) // forget peer ID, and also remove metadata and keys

			// allow time for PEX then close
			// pm.breakableWait(5 * time.Second)
			// pm.log.Info("hanging up on crawler")
			// pm.removePeer(peerID)
		} else { // normal host
			for _, protoID := range pm.requiredProtocols {
				if !slices.Contains(supportedProtos, protoID) {
					pm.log.Warnf("Peer %v does not support required protocol: %v", peerIDStringer(peerID), protoID)
					pm.h.ConnManager().TagPeer(peerID, "lame", -1) // prune first
					pm.ps.ClearAddrs(peerID)                       // don't advertise them to others
					break
				}
			}
		}
	}()

}

// breakableWait is for use in methods that do not have a context, such as those
// of the Notifiee interface.
func (pm *PeerMan) breakableWait(after time.Duration) (quit bool) { //nolint
	select {
	case <-pm.done:
		return true
	case <-time.After(after):
		return false
	}
}

const kicked = "kicked"

// Disconnected is triggered when a peer disconnects
func (pm *PeerMan) Disconnected(net network.Network, conn network.Conn) {
	defer mets.PeerCount(context.Background(), pm.numConnectedPeers())

	if _, wasKicked := conn.Stat().Extra[kicked]; wasKicked {
		pm.log.Info("KICKED PEER")
		return // do not initiate reconnect loop
	}

	peerID := conn.RemotePeer()

	// might handle it this way instead...
	if meta := pm.h.ConnManager().GetTagInfo(peerID); meta != nil {
		if _, isCrawler := meta.Tags["crawler"]; isCrawler {
			pm.log.Infof("Disconnected from crawler %v", peerIDStringer(peerID))
			pm.ps.ClearAddrs(peerID)
			pm.ps.RemovePeer(peerID) // forget peer ID, and also remove metadata and keys
			return
		}
	}

	if len(pm.ps.Addrs(peerID)) == 0 { // we explicitly removed it
		pm.log.Warnf("Disconnected from peer %v with no addresses.", peerIDStringer(peerID))
		pm.ps.RemovePeer(peerID) // forget peer ID, and also remove metadata and keys
		return
	}

	pm.log.Infof("Disconnected from peer %v", peerIDStringer(peerID))

	// Store disconnection timestamp
	pm.mtx.Lock()
	defer pm.mtx.Unlock()

	pm.disconnects[peerID] = time.Now()

	if pm.noReconnect[peerID] {
		// pm.log.Info("KICKED PEER")
		return
	}

	select {
	case <-pm.done:
		return
	default:
	}

	// Create a context that is canceled if pm.done is closed (Notifiee
	// interface doesn't pass one).
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		select {
		case <-ctx.Done():
			return
		case <-pm.done:
			return
		}
	}()

	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		defer cancel()
		var delay = time.Second
		if time.Since(conn.Stat().Opened) < time.Second {
			delay *= 3 // ugh, but what was the reason
		}
		select {
		case <-ctx.Done(): // pm.done closed (shutdown)
			return
		case <-time.After(delay):
		}
		pm.reconnectWithRetry(ctx, peerID)
	}()
}

func (pm *PeerMan) Listen(network.Network, multiaddr.Multiaddr)      {}
func (pm *PeerMan) ListenClose(network.Network, multiaddr.Multiaddr) {}

// Reconnect logic with exponential backoff and capped retries
func (pm *PeerMan) reconnectWithRetry(ctx context.Context, peerID peer.ID) {
	bo := newBackoffer(maxRetries, baseReconnectDelay, time.Minute, true)
	delay := bo.next() // NOTE: first attempt is always 0 delay
	for {
		select {
		case <-pm.done:
			return
		case <-time.After(delay):
		}

		addrInfo := peer.AddrInfo{
			ID:    peerID,
			Addrs: pm.ps.Addrs(peerID),
		}
		if len(addrInfo.Addrs) == 0 { // removed from peer store
			pm.log.Infof("Peer %s no longer has known addresses", peerIDStringer(peerID))
			return
		}

		attempt := bo.tries()

		if pm.h.Network().Connectedness(peerID) == network.Connected {
			return // reestablished since last try
		}

		pm.log.Infof("Attempting reconnection to peer %s (attempt %d/%d)", peerIDStringer(peerID), attempt, maxRetries)
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := pm.c.Connect(ctx, addrInfo)
		if err == nil {
			cancel()
			pm.log.Infof("Successfully reconnected to peer %s", peerIDStringer(peerID))
			return
		}
		cancel()

		if attempt >= maxRetries { // or bo.maxedOut
			break
		}

		delay = bo.next()
		pm.log.Infof("Failed to reconnect to peer %s (trying again in %v): %v",
			peerIDStringer(peerID), delay, CompressDialError(err))
	}

	pm.log.Infof("Exceeded max retries for peer %s. Giving up.", peerIDStringer(peerID))
}

// Periodically remove peers disconnected for over a week
func (pm *PeerMan) removeOldPeers() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pm.done:
			return
		case <-ticker.C:
		}

		// Clean up expired blacklist entries
		pm.cleanupExpiredBlacklist()

		now := time.Now()
		func() {
			pm.mtx.Lock()
			defer pm.mtx.Unlock()
			for peerID, disconnectTime := range pm.disconnects {
				pm.wlMtx.RLock()
				if pm.persistentWhitelist[peerID] {
					pm.wlMtx.RUnlock()
					continue
				}
				pm.wlMtx.RUnlock()
				if now.Sub(disconnectTime) > disconnectLimit {
					// a seeder needs to periodically recheck though...

					pm.ps.RemovePeer(peerID)
					delete(pm.disconnects, peerID) // Remove from tracking map
					pm.log.Infof("Removed peer %s last connected %v ago", peerIDStringer(peerID), time.Since(disconnectTime))
				}
			}
		}()
	}
}

// BlacklistPeer adds a peer to the blacklist with the given reason and duration.
// If duration is 0, the peer is permanently blacklisted.
func (pm *PeerMan) BlacklistPeer(pid peer.ID, reason string, duration time.Duration) {
	if !pm.blacklistConfig.Enable {
		pm.log.Debugf("Blacklisting disabled, ignoring blacklist request for peer %s", peerIDStringer(pid))
		return
	}

	// Prevent self-blacklisting
	if pid == pm.h.ID() {
		pm.log.Warnf("Attempted to blacklist self (peer ID: %s), ignoring", peerIDStringer(pid))
		return
	}

	pm.blacklistMtx.Lock()
	entry := BlacklistEntry{
		PeerID:    pid,
		Reason:    reason,
		Timestamp: time.Now(),
		Permanent: duration == 0,
	}

	if !entry.Permanent {
		entry.ExpiresAt = time.Now().Add(duration)
	}

	pm.blacklistedPeers[pid] = entry
	// Capture values needed for logging/metrics while holding the lock
	blacklistCount := len(pm.blacklistedPeers)
	expiresAt := "never"
	if !entry.Permanent {
		expiresAt = entry.ExpiresAt.Format(time.RFC3339)
	}
	isPermanent := entry.Permanent
	pm.blacklistMtx.Unlock()

	// Enhanced structured logging and metrics after releasing lock
	pm.log.Info("Peer blacklisted",
		"peer_id", peerIDStringer(pid),
		"reason", reason,
		"permanent", isPermanent,
		"expires_at", expiresAt,
		"operation", "blacklist_add",
	)

	// Add metrics
	metrics.Node.BlacklistOperation(context.Background(), "add", reason, isPermanent)
	metrics.Node.BlacklistedPeerCount(context.Background(), blacklistCount)

	// Remove the peer immediately if it's connected (called after releasing lock)
	pm.removePeer(pid)
}

// RemoveFromBlacklist removes a peer from the blacklist.
func (pm *PeerMan) RemoveFromBlacklist(pid peer.ID) bool {
	pm.blacklistMtx.Lock()

	if _, exists := pm.blacklistedPeers[pid]; !exists {
		pm.blacklistMtx.Unlock()
		return false
	}

	delete(pm.blacklistedPeers, pid)
	// Capture blacklistCount while holding the lock
	blacklistCount := len(pm.blacklistedPeers)
	pm.blacklistMtx.Unlock()

	// Enhanced structured logging and metrics after releasing lock
	pm.log.Info("Peer removed from blacklist",
		"peer_id", peerIDStringer(pid),
		"operation", "blacklist_remove",
	)

	// Add metrics
	metrics.Node.BlacklistOperation(context.Background(), "remove", "manual", false)
	metrics.Node.BlacklistedPeerCount(context.Background(), blacklistCount)

	return true
}

// IsBlacklisted checks if a peer is currently blacklisted, cleaning up expired entries.
func (pm *PeerMan) IsBlacklisted(pid peer.ID) (bool, string) {
	if !pm.blacklistConfig.Enable {
		return false, ""
	}

	pm.blacklistMtx.Lock()
	defer pm.blacklistMtx.Unlock()

	entry, exists := pm.blacklistedPeers[pid]
	if !exists {
		return false, ""
	}

	// Clean up expired temporary blacklists
	if !entry.Permanent && entry.IsExpired() {
		delete(pm.blacklistedPeers, pid)
		pm.log.Infof("Expired blacklist entry removed for peer %s", peerIDStringer(pid))
		return false, ""
	}

	return true, entry.Reason
}

// ListBlacklisted returns a copy of all currently active blacklist entries.
func (pm *PeerMan) ListBlacklisted() []BlacklistEntry {
	pm.blacklistMtx.RLock()
	defer pm.blacklistMtx.RUnlock()

	var entries []BlacklistEntry
	now := time.Now()

	for _, entry := range pm.blacklistedPeers {
		// Skip expired temporary entries (but don't remove them here to avoid race conditions)
		if !entry.Permanent && now.After(entry.ExpiresAt) {
			continue
		}
		entries = append(entries, entry)
	}

	return entries
}

// cleanupExpiredBlacklist removes expired temporary blacklist entries.
// This should be called periodically (e.g., from removeOldPeers).
func (pm *PeerMan) cleanupExpiredBlacklist() {
	if !pm.blacklistConfig.Enable {
		return
	}

	pm.blacklistMtx.Lock()
	defer pm.blacklistMtx.Unlock()

	var expiredPeers []peer.ID
	for pid, entry := range pm.blacklistedPeers {
		if !entry.Permanent && entry.IsExpired() {
			expiredPeers = append(expiredPeers, pid)
		}
	}

	for _, pid := range expiredPeers {
		delete(pm.blacklistedPeers, pid)
		pm.log.Infof("Expired blacklist entry cleaned up for peer %s", peerIDStringer(pid))
	}
}
