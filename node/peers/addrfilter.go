package peers

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// usableAddrs returns the subset of addrs worth keeping given that we learned
// them over, or about a peer reached over, via. The classification mirrors the
// policy go-libp2p's identify service already applies to every address it
// learns on a connection (filterAddrs in p2p/protocol/identify/id.go), which
// the peer exchange protocol otherwise bypasses. A via we cannot classify (nil,
// or the discard prefix used by mocknet) filters nothing.
func usableAddrs(addrs []multiaddr.Multiaddr, via multiaddr.Multiaddr) []multiaddr.Multiaddr {
	// An unspecified address is not dialable no matter where we heard it.
	addrs = multiaddr.FilterAddrs(addrs, func(a multiaddr.Multiaddr) bool {
		return !manet.IsIPUnspecified(a)
	})

	switch {
	case manet.IsIPLoopback(via):
		return addrs
	case manet.IsPrivateAddr(via):
		return multiaddr.FilterAddrs(addrs, func(a multiaddr.Multiaddr) bool {
			return !manet.IsIPLoopback(a)
		})
	case manet.IsPublicAddr(via):
		return multiaddr.FilterAddrs(addrs, manet.IsPublicAddr)
	default:
		return addrs
	}
}

// routablePeers filters each peer's addresses for a counterparty reached over
// via, dropping any peer left with no address since it cannot be dialed. It
// also reports how many addresses were discarded, for logging.
func routablePeers(peers []PeerInfo, via multiaddr.Multiaddr) ([]PeerInfo, int) {
	var dropped int
	out := make([]PeerInfo, 0, len(peers))
	for _, p := range peers {
		if len(p.Addrs) == 0 {
			out = append(out, p) // nothing to filter, leave as-is
			continue
		}
		addrs := usableAddrs(p.Addrs, via)
		dropped += len(p.Addrs) - len(addrs)
		if len(addrs) == 0 {
			continue
		}
		p.Addrs = addrs
		out = append(out, p)
	}
	return out, dropped
}

// persistAddrs returns the addresses to write to the address book for a peer
// reached over via. A nil via means we have no evidence of where we reached the
// peer, so nothing is filtered. Otherwise the filtered set is written even when
// it is empty: the entry itself survives, and loadAddrBook restores a peer's
// whitelist and blacklist flags before it looks at the addresses at all.
func persistAddrs(addrs []multiaddr.Multiaddr, via multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if via == nil || len(addrs) == 0 {
		return addrs
	}
	return usableAddrs(addrs, via)
}

// rememberConnAddr records the remote address of a connection to peerID.
func (pm *PeerMan) rememberConnAddr(peerID peer.ID, addr multiaddr.Multiaddr) {
	pm.connAddrsMtx.Lock()
	defer pm.connAddrsMtx.Unlock()
	pm.connAddrs[peerID] = addr
}

// forgetConnAddr discards the remembered address for a peer we no longer track.
func (pm *PeerMan) forgetConnAddr(peerID peer.ID) {
	pm.connAddrsMtx.Lock()
	defer pm.connAddrsMtx.Unlock()
	delete(pm.connAddrs, peerID)
}

// connAddr returns the remote multiaddr of a live connection to peerID, falling
// back to the address of the last connection this process had with it, or nil
// if we have never talked to it. This is the evidence usableAddrs classifies
// against, and it has to outlive the connection: a peer is routinely offline
// when a save tick lands, and without the fallback its full unfiltered address
// set would be written straight back into the address book.
func (pm *PeerMan) connAddr(peerID peer.ID) multiaddr.Multiaddr {
	if conns := pm.h.Network().ConnsToPeer(peerID); len(conns) > 0 {
		return conns[0].RemoteMultiaddr()
	}
	pm.connAddrsMtx.Lock()
	defer pm.connAddrsMtx.Unlock()
	return pm.connAddrs[peerID]
}
