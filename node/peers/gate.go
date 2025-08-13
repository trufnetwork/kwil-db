package peers

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	msmux "github.com/multiformats/go-multistream"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/metrics"
)

// blockedConnectionStats tracks blocked connection attempts for aggregate logging
type blockedConnectionStats struct {
	peerID string
	reason string
	count  int
}

// WhitelistGater is a libp2p connmgr.ConnectionGater implementation to enforce
// a peer whitelist and blacklist.
type WhitelistGater struct {
	logger log.Logger

	mtx       sync.RWMutex // very infrequent whitelist updates
	permitted map[peer.ID]bool

	// Reference to PeerMan for blacklist checking
	peerManMtx sync.RWMutex // protects peerMan field
	peerMan    interface {
		IsBlacklisted(peer.ID) (bool, string)
	}

	// Controls whether whitelist restrictions are enforced
	// When false, only blacklist checking is performed (blacklist-only mode)
	// When true, both whitelist and blacklist are enforced (private mode)
	enforceWhitelist bool

	// Aggregate logging for blocked connections
	statsMtx      sync.Mutex
	blockedStats  map[string]*blockedConnectionStats // key: "peerID:reason"
	stopLogger    chan struct{}
	loggerStarted bool
}

type gateOpts struct {
	logger  log.Logger
	peerMan interface {
		IsBlacklisted(peer.ID) (bool, string)
	}
	enforceWhitelist bool
}

type GateOpt func(*gateOpts)

func WithLogger(logger log.Logger) GateOpt {
	return func(opts *gateOpts) {
		opts.logger = logger
	}
}

func WithPeerMan(peerMan interface{ IsBlacklisted(peer.ID) (bool, string) }) GateOpt {
	return func(opts *gateOpts) {
		opts.peerMan = peerMan
	}
}

func WithWhitelistEnforcement(enforce bool) GateOpt {
	return func(opts *gateOpts) {
		opts.enforceWhitelist = enforce
	}
}

var _ connmgr.ConnectionGater = (*OutboundWhitelistGater)(nil)

// OutboundWhitelistGater is to prevent dialing out to peers that are not
// explicitly allowed by an application provided filter function. This exists in
// part to prevent other modules such as the DHT and gossipsub from dialing out
// to peers that are not explicitly allowed (e.g. already connected or added by
// the application).
type OutboundWhitelistGater struct {
	AllowedOutbound func(peer.ID) bool
}

// OUTBOUND

func (g *OutboundWhitelistGater) InterceptPeerDial(p peer.ID) bool {
	if g == nil || g.AllowedOutbound == nil {
		return true
	}
	return g.AllowedOutbound(p)
}

func (g *OutboundWhitelistGater) InterceptAddrDial(p peer.ID, addr multiaddr.Multiaddr) bool {
	return true
}

// INBOUND

func (g *OutboundWhitelistGater) InterceptAccept(connAddrs network.ConnMultiaddrs) bool { return true }

func (g *OutboundWhitelistGater) InterceptSecured(dir network.Direction, p peer.ID, conn network.ConnMultiaddrs) bool {
	return true
}

func (g *OutboundWhitelistGater) InterceptUpgraded(conn network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

// NewWhitelistGater creates a new WhitelistGater that enforces peer whitelist and blacklist rules.
// The returned gater starts a background goroutine for aggregate logging that must be stopped
// by calling Close() when the gater is no longer needed to prevent goroutine leaks.
func NewWhitelistGater(allowed []peer.ID, opts ...GateOpt) *WhitelistGater {
	options := &gateOpts{
		logger:           log.DiscardLogger,
		enforceWhitelist: true, // Default to true for backward compatibility
	}
	for _, opt := range opts {
		opt(options)
	}

	permitted := make(map[peer.ID]bool)
	for _, pid := range allowed {
		permitted[pid] = true
	}

	g := &WhitelistGater{
		logger:           options.logger,
		permitted:        permitted,
		peerMan:          options.peerMan,
		enforceWhitelist: options.enforceWhitelist,
		blockedStats:     make(map[string]*blockedConnectionStats),
		stopLogger:       make(chan struct{}),
	}

	// Start aggregate logging goroutine
	g.startAggregateLogger()

	return g
}

// SetPeerMan sets the peer manager reference for blacklist checking.
// This allows the WhitelistGater to be created before the PeerMan during initialization.
func (g *WhitelistGater) SetPeerMan(peerMan interface{ IsBlacklisted(peer.ID) (bool, string) }) {
	if g == nil {
		return
	}
	g.peerManMtx.Lock()
	g.peerMan = peerMan
	g.peerManMtx.Unlock()
}

// Close stops the aggregate logger and cleans up resources
func (g *WhitelistGater) Close() {
	if g == nil {
		return
	}
	g.stopAggregateLogger()
}

// Allow and Disallow work with a nil *WhitelistGater, but not the
// connmgr.ConnectionGater methods. So, do not give a nil *WhitelistGater to
// libp2p.New via libp2p.ConnectionGater.

// Allow adds a peer to the whitelist.
func (g *WhitelistGater) Allow(p peer.ID) {
	if g == nil {
		return
	}
	g.mtx.Lock()
	defer g.mtx.Unlock()
	g.permitted[p] = true
}

// Disallow removes a peer from the whitelist and returns true
// if the whitelistGater is enabled and the peer was removed.
func (g *WhitelistGater) Disallow(p peer.ID) bool {
	if g == nil {
		return false
	}
	g.mtx.Lock()
	defer g.mtx.Unlock()
	delete(g.permitted, p)

	return true
}

// Allowed returns the list of peers in the whitelist.
func (g *WhitelistGater) Allowed() []peer.ID {
	if g == nil {
		return nil
	}
	g.mtx.RLock()
	defer g.mtx.RUnlock()
	allowed := make([]peer.ID, 0, len(g.permitted))
	for pid := range g.permitted {
		allowed = append(allowed, pid)
	}
	return allowed
}

// IsAllowed indicates if a peer is in the whitelist and not blacklisted.
// This is mainly for the connmgr.ConnectionGater methods.
func (g *WhitelistGater) IsAllowed(p peer.ID) bool {
	if g == nil {
		return true
	}

	// Check blacklist first - blacklisted peers are never allowed
	g.peerManMtx.RLock()
	peerMan := g.peerMan
	g.peerManMtx.RUnlock()
	if peerMan != nil {
		if blacklisted, _ := peerMan.IsBlacklisted(p); blacklisted {
			return false
		}
	}

	// Check whitelist only if enforcement is enabled
	if g.enforceWhitelist {
		g.mtx.RLock()
		defer g.mtx.RUnlock()
		return g.permitted[p]
	}

	// Allow by default if whitelist enforcement is disabled
	return true
}

// startAggregateLogger starts the background goroutine for aggregate logging
func (g *WhitelistGater) startAggregateLogger() {
	g.statsMtx.Lock()
	defer g.statsMtx.Unlock()

	if g.loggerStarted {
		return
	}
	g.loggerStarted = true

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-g.stopLogger:
				return
			case <-ticker.C:
				g.logAggregateStats()
			}
		}
	}()
}

// stopAggregateLogger stops the background logging goroutine
func (g *WhitelistGater) stopAggregateLogger() {
	g.statsMtx.Lock()
	if !g.loggerStarted {
		g.statsMtx.Unlock()
		return
	}
	// Stop logger
	close(g.stopLogger)
	g.loggerStarted = false
	g.statsMtx.Unlock()

	// Best-effort: flush any accumulated stats once at shutdown
	g.logAggregateStats()
}

// recordBlockedConnection tracks a blocked connection attempt for aggregate logging
func (g *WhitelistGater) recordBlockedConnection(peerID peer.ID, reason, direction string) {
	g.statsMtx.Lock()
	if !g.loggerStarted {
		g.statsMtx.Unlock()
		return
	}
	defer g.statsMtx.Unlock()

	key := peerID.String() + ":" + reason + ":" + direction
	if stats, exists := g.blockedStats[key]; exists {
		stats.count++
	} else {
		g.blockedStats[key] = &blockedConnectionStats{
			peerID: peerID.String(),
			reason: reason,
			count:  1,
		}
	}
}

// logAggregateStats logs a summary of blocked connections since last report
func (g *WhitelistGater) logAggregateStats() {
	g.statsMtx.Lock()
	defer g.statsMtx.Unlock()

	if len(g.blockedStats) == 0 {
		return // No blocked connections to report
	}

	// Calculate totals
	totalBlocked := 0
	inboundBlocked := 0
	outboundBlocked := 0
	peerCounts := make(map[string]int)
	reasonCounts := make(map[string]int)

	for key, stats := range g.blockedStats {
		totalBlocked += stats.count
		peerCounts[stats.peerID] += stats.count
		reasonCounts[stats.reason] += stats.count

		// Determine direction from key safely
		if strings.HasSuffix(key, "inbound") {
			inboundBlocked += stats.count
		} else if strings.HasSuffix(key, "outbound") {
			outboundBlocked += stats.count
		}
	}

	// Log structured summary
	g.logger.Info("Blacklist connection blocking summary",
		"total_blocked", totalBlocked,
		"inbound_blocked", inboundBlocked,
		"outbound_blocked", outboundBlocked,
		"unique_peers", len(peerCounts),
		"operation", "blacklist_summary",
	)

	// Log detailed breakdown if there are many blocked attempts
	if totalBlocked > 10 {
		g.logger.Info("Top blocked peers and reasons",
			"peer_counts", peerCounts,
			"reason_counts", reasonCounts,
			"operation", "blacklist_detail",
		)
	}

	// Clear stats for next period
	g.blockedStats = make(map[string]*blockedConnectionStats)
}

var _ connmgr.ConnectionGater = (*WhitelistGater)(nil)

// OUTBOUND

func (g *WhitelistGater) InterceptPeerDial(p peer.ID) bool {
	// PHASE 1: Always check blacklist first (highest priority)
	g.peerManMtx.RLock()
	peerMan := g.peerMan
	g.peerManMtx.RUnlock()
	if peerMan != nil {
		if blacklisted, reason := peerMan.IsBlacklisted(p); blacklisted {
			// Add metrics
			metrics.Node.BlockedConnection(context.Background(), "outbound", reason)

			// Record for aggregate logging instead of immediate log
			g.recordBlockedConnection(p, reason, "outbound")
			return false
		}
	}

	// PHASE 2: Check whitelist only if enforcement is enabled
	if g.enforceWhitelist {
		g.mtx.RLock()
		whitelisted := g.permitted[p]
		g.mtx.RUnlock()

		if !whitelisted {
			g.logger.Infof("Blocking OUTBOUND dial to peer not on whitelist: %v", p)
			return false
		}
	}

	// PHASE 3: Allow connection (either whitelisted or whitelist not enforced)
	return true
}

func (g *WhitelistGater) InterceptAddrDial(p peer.ID, addr multiaddr.Multiaddr) bool {
	// InterceptPeerDial came first, don't bother doing it again here. Only
	// filter here if we want to filter by network address.
	return true
}

// INBOUND

func (g *WhitelistGater) InterceptAccept(connAddrs network.ConnMultiaddrs) bool {
	// Filter here if we want to filter by network address; we get the peer ID
	// after a secure connection is established (InterceptSecured).
	return true
}

func (g *WhitelistGater) InterceptSecured(dir network.Direction, p peer.ID, conn network.ConnMultiaddrs) bool {
	// PHASE 1: Always check blacklist first (highest priority)
	g.peerManMtx.RLock()
	peerMan := g.peerMan
	g.peerManMtx.RUnlock()
	if peerMan != nil {
		if blacklisted, reason := peerMan.IsBlacklisted(p); blacklisted {
			// Add metrics
			directionStr := "inbound"
			if dir == network.DirOutbound {
				directionStr = "outbound"
			}
			metrics.Node.BlockedConnection(context.Background(), directionStr, reason)

			// Record for aggregate logging instead of immediate log
			g.recordBlockedConnection(p, reason, directionStr)
			return false
		}
	}

	// PHASE 2: Check whitelist only if enforcement is enabled
	if g.enforceWhitelist {
		g.mtx.RLock()
		whitelisted := g.permitted[p]
		g.mtx.RUnlock()

		if !whitelisted {
			g.logger.Infof("Blocking INBOUND connection from peer not on whitelist: %v", p)
			return false
		}
	}

	// PHASE 3: Allow connection (either whitelisted or whitelist not enforced)
	return true
}

func (g *WhitelistGater) InterceptUpgraded(conn network.Conn) (bool, control.DisconnectReason) {
	// maybe signal back to creator that protocol checks can be done now
	return true, 0
}

type ChainIDGater struct {
	logger  log.Logger
	chainID string
}

func NewChainIDGater(chainID string, opts ...GateOpt) *ChainIDGater {
	options := &gateOpts{
		logger: log.DiscardLogger,
	}
	for _, opt := range opts {
		opt(options)
	}
	return &ChainIDGater{
		logger:  options.logger,
		chainID: chainID,
	}
}

var _ connmgr.ConnectionGater = (*ChainIDGater)(nil)

// OUTBOUND

func (g *ChainIDGater) InterceptPeerDial(p peer.ID) bool { return true }

func (g *ChainIDGater) InterceptAddrDial(p peer.ID, addr multiaddr.Multiaddr) bool { return true }

// INBOUND

func (g *ChainIDGater) InterceptAccept(connAddrs network.ConnMultiaddrs) bool { return true }

func (g *ChainIDGater) InterceptSecured(dir network.Direction, p peer.ID, conn network.ConnMultiaddrs) bool {
	return true
}

func (g *ChainIDGater) InterceptUpgraded(conn network.Conn) (bool, control.DisconnectReason) {
	// I can't get this to work. What can you do with network.Conn here?
	s, err := conn.NewStream(context.Background())
	if err != nil {
		g.logger.Warnf("cannot create stream: %v", err)
		return false, 1
	}
	defer s.Close()
	proto := ProtocolIDPrefixChainID + protocol.ID(g.chainID)
	err = msmux.SelectProtoOrFail(proto, s)
	if err != nil {
		g.logger.Warnf("cannot handshake for protocol %v: %v", proto, err)
		return false, 1
	}

	return true, 0
}

type chainedConnectionGater struct {
	gaters []connmgr.ConnectionGater
}

func ChainConnectionGaters(gaters ...connmgr.ConnectionGater) connmgr.ConnectionGater {
	return &chainedConnectionGater{
		gaters: slices.DeleteFunc(gaters, func(g connmgr.ConnectionGater) bool {
			return g == nil
		}),
	}
}

var _ connmgr.ConnectionGater = (*chainedConnectionGater)(nil)

func (g *chainedConnectionGater) InterceptAccept(connAddrs network.ConnMultiaddrs) (allow bool) {
	for _, gater := range g.gaters {
		if !gater.InterceptAccept(connAddrs) {
			return false
		}
	}
	return true
}

func (g *chainedConnectionGater) InterceptSecured(dir network.Direction, p peer.ID, conn network.ConnMultiaddrs) (allow bool) {
	for _, gater := range g.gaters {
		if !gater.InterceptSecured(dir, p, conn) {
			return false
		}
	}
	return true
}

func (g *chainedConnectionGater) InterceptUpgraded(conn network.Conn) (bool, control.DisconnectReason) {
	for _, gater := range g.gaters {
		if ok, reason := gater.InterceptUpgraded(conn); !ok {
			return false, reason
		}
	}
	return true, 0
}

func (g *chainedConnectionGater) InterceptPeerDial(p peer.ID) bool {
	for _, gater := range g.gaters {
		if !gater.InterceptPeerDial(p) {
			return false
		}
	}
	return true
}

func (g *chainedConnectionGater) InterceptAddrDial(p peer.ID, addr multiaddr.Multiaddr) bool {
	for _, gater := range g.gaters {
		if !gater.InterceptAddrDial(p, addr) {
			return false
		}
	}
	return true
}
