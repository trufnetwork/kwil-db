package peers

import (
	"sync"

	"github.com/multiformats/go-multiaddr"

	"github.com/trufnetwork/kwil-db/core/log"
)

// advertisedAddrs splits addrs into the ones a host should announce as its own
// and the ones it should withhold, given the TCP ports it can actually be
// reached on. go-libp2p merges into this set every address a peer claims to
// have observed us at (OwnObservedAddrs, appended by AllAddrs in
// p2p/host/basic/basic_host.go), and those observations include the source
// ports of our own outbound connections: TCP reuseport sources them from the
// listen port, so they satisfy identify's own check that the connection came
// from an address we listen on, and whatever port a NAT rewrote them to is then
// advertised as though it were a listen port. Nobody can connect back to a
// rewritten source port.
//
// Withholding by port never removes a listen address. AllAddrs builds those by
// resolving the listen address against this host's interfaces, which substitutes
// the IP and leaves the port alone, so every one of them carries the listen
// port. An address with no TCP component cannot be classified and is kept, as in
// usableAddrs.
func advertisedAddrs(addrs []multiaddr.Multiaddr, ports map[string]bool) (advertise, withheld []multiaddr.Multiaddr) {
	for _, addr := range addrs {
		port, err := addr.ValueForProtocol(multiaddr.P_TCP)
		if err != nil || ports[port] {
			advertise = append(advertise, addr)
			continue
		}
		withheld = append(withheld, addr)
	}
	return advertise, withheld
}

// listenPorts returns the single TCP port a host binds, or nil when that cannot
// be determined: no listen address, or an ephemeral port, where the port the
// host actually bound is not the one in its configuration and none of the
// resolved listen addresses would match it.
//
// Only one address is ever passed to libp2p.ListenAddrs, so the listen port is
// the only port these hosts bind. A second listener would need its port added.
func listenPorts(listen multiaddr.Multiaddr) map[string]bool {
	if listen == nil {
		return nil
	}
	port, err := listen.ValueForProtocol(multiaddr.P_TCP)
	if err != nil || port == "0" {
		return nil
	}
	return map[string]bool{port: true}
}

// reachablePorts returns the TCP ports a host listening on listen and declaring
// external can be connected back to, or nil when no external address was
// declared, in which case the addresses peers observe are the only thing
// telling the network where this host is and none may be withheld.
func reachablePorts(listen, external multiaddr.Multiaddr) map[string]bool {
	if external == nil {
		return nil
	}
	ports := listenPorts(listen)
	if ports == nil {
		return nil
	}
	if externalPort, err := external.ValueForProtocol(multiaddr.P_TCP); err == nil {
		ports[externalPort] = true
	}
	return ports
}

// AddrsFactory returns the libp2p address factory for a host that listens on
// listen and has been told by its operator that it is reachable at external.
// The external address is always advertised, as it has been since this factory
// was first written. When we know the ports the host can be reached on, every
// other address is withheld; when we do not, nothing is withheld and the factory
// behaves exactly as it did before. A host with no declared address of its own
// is therefore never filtered: peer observations are all it has.
func AddrsFactory(listen, external multiaddr.Multiaddr, logger log.Logger) func([]multiaddr.Multiaddr) []multiaddr.Multiaddr {
	return addrsFactory(reachablePorts(listen, external), external, logger)
}

// ListenAddrsFactory returns an address factory that withholds every address
// off the listen port, with no gate on a declared address. It is for a host
// nothing ever dials back, where an address a peer observed us at can only ever
// become junk in that peer's address book: the seed host, whose addresses a
// kwild node clears as soon as identify reports the crawler protocol
// (PeerMan.Connected), and which it then hangs up on.
//
// A regular node must not use this. A node that declared no external address
// has nothing but peer observations telling the network where it is, which is
// what the gate in AddrsFactory protects.
func ListenAddrsFactory(listen multiaddr.Multiaddr, logger log.Logger) func([]multiaddr.Multiaddr) []multiaddr.Multiaddr {
	return addrsFactory(listenPorts(listen), nil, logger)
}

func addrsFactory(ports map[string]bool, external multiaddr.Multiaddr, logger log.Logger) func([]multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if logger == nil {
		logger = log.DiscardLogger
	}

	// The withheld set grows as peers report new observations, so report each
	// address once rather than only the first batch: this log line is the only
	// signal an operator has if they ever suspect the filter of hiding an
	// address their node really is reachable at.
	var mtx sync.Mutex
	reported := make(map[string]bool)

	return func(m []multiaddr.Multiaddr) []multiaddr.Multiaddr {
		if ports == nil {
			if external != nil {
				m = append(m, external)
			}
			return m
		}
		advertise, withheld := advertisedAddrs(m, ports)
		if fresh := firstReport(&mtx, reported, withheld); len(fresh) > 0 {
			logger.Infof("Not advertising %v: no peer can connect back to a port this node does not listen on", fresh)
		}
		if external != nil {
			advertise = append(advertise, external)
		}
		return advertise
	}
}

// firstReport returns the addresses of withheld that have not been reported
// before, recording them as reported.
func firstReport(mtx *sync.Mutex, reported map[string]bool, withheld []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if len(withheld) == 0 {
		return nil
	}
	mtx.Lock()
	defer mtx.Unlock()
	var fresh []multiaddr.Multiaddr
	for _, addr := range withheld {
		if key := addr.String(); !reported[key] {
			reported[key] = true
			fresh = append(fresh, addr)
		}
	}
	return fresh
}
