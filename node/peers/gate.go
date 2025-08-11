package peers

import (
	"context"
	"slices"
	"sync"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	msmux "github.com/multiformats/go-multistream"
	"github.com/trufnetwork/kwil-db/core/log"
)

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

	return &WhitelistGater{
		logger:           options.logger,
		permitted:        permitted,
		peerMan:          options.peerMan,
		enforceWhitelist: options.enforceWhitelist,
	}
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

var _ connmgr.ConnectionGater = (*WhitelistGater)(nil)

// OUTBOUND

func (g *WhitelistGater) InterceptPeerDial(p peer.ID) bool {
	// PHASE 1: Always check blacklist first (highest priority)
	g.peerManMtx.RLock()
	peerMan := g.peerMan
	g.peerManMtx.RUnlock()
	if peerMan != nil {
		if blacklisted, reason := peerMan.IsBlacklisted(p); blacklisted {
			g.logger.Infof("Blocking OUTBOUND dial to blacklisted peer %v (reason: %s)", p, reason)
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
			g.logger.Infof("Blocking INBOUND connection from blacklisted peer %v (reason: %s)", p, reason)
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
