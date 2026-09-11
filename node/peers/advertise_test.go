package peers

import (
	"testing"

	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/log"
)

// countingLogger records how many times the address factory reported withheld
// addresses. The factory is called every few seconds for the life of the
// process, so it must report at most once.
type countingLogger struct {
	log.Logger
	infof int
}

func (l *countingLogger) Infof(msg string, args ...any) { l.infof++ }

func TestAdvertisedAddrs(t *testing.T) {
	tests := []struct {
		name          string
		addrs         []string
		ports         []string
		wantAdvertise []string
		wantWithheld  []string
	}{{
		// The measured mainnet case: node-1 listens on 26656 and every other
		// port in its entry is a source port of its own outbound connections.
		name: "withholds observed source ports",
		addrs: []string{
			"/ip4/172.31.4.10/tcp/26656",
			"/ip4/127.0.0.1/tcp/26656",
			"/ip4/3.134.167.133/tcp/26656",
			"/ip4/3.134.167.133/tcp/13335",
			"/ip4/3.134.167.133/tcp/15519",
			"/ip4/3.134.167.133/tcp/24414",
			"/ip4/3.134.167.133/tcp/33221",
			"/ip4/3.134.167.133/tcp/34191",
			"/ip4/3.134.167.133/tcp/42534",
			"/ip4/3.134.167.133/tcp/46247",
			"/ip4/3.134.167.133/tcp/47356",
			"/ip4/3.134.167.133/tcp/62215",
		},
		ports: []string{"26656"},
		wantAdvertise: []string{
			"/ip4/172.31.4.10/tcp/26656",
			"/ip4/127.0.0.1/tcp/26656",
			"/ip4/3.134.167.133/tcp/26656",
		},
		wantWithheld: []string{
			"/ip4/3.134.167.133/tcp/13335",
			"/ip4/3.134.167.133/tcp/15519",
			"/ip4/3.134.167.133/tcp/24414",
			"/ip4/3.134.167.133/tcp/33221",
			"/ip4/3.134.167.133/tcp/34191",
			"/ip4/3.134.167.133/tcp/42534",
			"/ip4/3.134.167.133/tcp/46247",
			"/ip4/3.134.167.133/tcp/47356",
			"/ip4/3.134.167.133/tcp/62215",
		},
	}, {
		// An operator who declares a port translation keeps both ports.
		name: "keeps a port the operator declared",
		addrs: []string{
			"/ip4/172.31.4.10/tcp/6600",
			"/ip4/5.6.7.8/tcp/30000",
			"/ip4/5.6.7.8/tcp/41000",
		},
		ports: []string{"6600", "30000"},
		wantAdvertise: []string{
			"/ip4/172.31.4.10/tcp/6600",
			"/ip4/5.6.7.8/tcp/30000",
		},
		wantWithheld: []string{"/ip4/5.6.7.8/tcp/41000"},
	}, {
		name: "keeps an address it cannot classify",
		addrs: []string{
			"/ip4/1.2.3.4/udp/6600/quic-v1",
			"/dns4/example.com/tcp/26656",
			"/dns4/example.com/tcp/41000",
		},
		ports: []string{"26656"},
		wantAdvertise: []string{
			"/ip4/1.2.3.4/udp/6600/quic-v1",
			"/dns4/example.com/tcp/26656",
		},
		wantWithheld: []string{"/dns4/example.com/tcp/41000"},
	}, {
		name:  "empty input",
		ports: []string{"26656"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := make(map[string]bool, len(tt.ports))
			for _, p := range tt.ports {
				ports[p] = true
			}
			advertise, withheld := advertisedAddrs(mustAddrs(t, tt.addrs), ports)
			require.Equal(t, tt.wantAdvertise, addrStringsOrNil(advertise))
			require.Equal(t, tt.wantWithheld, addrStringsOrNil(withheld))
		})
	}

	t.Run("all nine measured ports withheld", func(t *testing.T) {
		_, withheld := advertisedAddrs(mustAddrs(t, node1Ephemeral), map[string]bool{"26656": true})
		require.Len(t, withheld, 9)
	})
}

func TestReachablePorts(t *testing.T) {
	tests := []struct {
		name      string
		listen    string // empty means nil
		external  string // empty means nil
		wantPorts []string
	}{{
		name:      "listen and external agree",
		listen:    "/ip4/0.0.0.0/tcp/26656",
		external:  "/ip4/3.134.167.133/tcp/26656",
		wantPorts: []string{"26656"},
	}, {
		name:      "declared port translation",
		listen:    "/ip4/0.0.0.0/tcp/6600",
		external:  "/ip4/1.2.3.4/tcp/30000",
		wantPorts: []string{"6600", "30000"},
	}, {
		// A pinned listen IP is filtered, not exempted: the resolved address
		// still carries the listen port.
		name:      "pinned listen address",
		listen:    "/ip4/10.0.0.5/tcp/6600",
		external:  "/ip4/1.2.3.4/tcp/6600",
		wantPorts: []string{"6600"},
	}, {
		// The whole population of nodes that never declared an address: peer
		// observations are all they have, so nothing is ever withheld.
		name:   "no external address",
		listen: "/ip4/0.0.0.0/tcp/6600",
	}, {
		// With an ephemeral port the resolved addresses carry the port the
		// kernel picked, not the configured 0, so filtering by it would
		// withhold everything.
		name:     "ephemeral listen port",
		listen:   "/ip4/0.0.0.0/tcp/0",
		external: "/ip4/1.2.3.4/tcp/6600",
	}, {
		name:     "no listen address",
		external: "/ip4/1.2.3.4/tcp/6600",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var listen, external multiaddr.Multiaddr
			if tt.listen != "" {
				listen = mustAddr(t, tt.listen)
			}
			if tt.external != "" {
				external = mustAddr(t, tt.external)
			}
			ports := reachablePorts(listen, external)
			if tt.wantPorts == nil {
				require.Nil(t, ports)
				return
			}
			want := make(map[string]bool, len(tt.wantPorts))
			for _, p := range tt.wantPorts {
				want[p] = true
			}
			require.Equal(t, want, ports)
		})
	}
}

func TestAddrsFactory(t *testing.T) {
	node1Input := []string{
		"/ip4/172.31.4.10/tcp/26656",
		"/ip4/127.0.0.1/tcp/26656",
		"/ip4/3.134.167.133/tcp/26656",
		"/ip4/3.134.167.133/tcp/13335",
		"/ip4/3.134.167.133/tcp/15519",
		"/ip4/3.134.167.133/tcp/24414",
		"/ip4/3.134.167.133/tcp/33221",
		"/ip4/3.134.167.133/tcp/34191",
		"/ip4/3.134.167.133/tcp/42534",
		"/ip4/3.134.167.133/tcp/46247",
		"/ip4/3.134.167.133/tcp/47356",
		"/ip4/3.134.167.133/tcp/62215",
	}

	t.Run("gated on a declared address", func(t *testing.T) {
		listen := mustAddr(t, "/ip4/0.0.0.0/tcp/26656")
		external := mustAddr(t, "/ip4/3.134.167.133/tcp/26656")
		factory := AddrsFactory(listen, external, log.DiscardLogger)
		// An observation on the listen port survives, since it is the one class
		// of observation a peer could dial back. The duplicate external address
		// is expected; BasicHost.Addrs dedupes after the factory runs.
		require.Equal(t, []string{
			"/ip4/172.31.4.10/tcp/26656",
			"/ip4/127.0.0.1/tcp/26656",
			"/ip4/3.134.167.133/tcp/26656",
			"/ip4/3.134.167.133/tcp/26656",
		}, addrStrings(factory(mustAddrs(t, node1Input))))
	})

	t.Run("no declared address changes nothing", func(t *testing.T) {
		listen := mustAddr(t, "/ip4/0.0.0.0/tcp/26656")
		factory := AddrsFactory(listen, nil, log.DiscardLogger)
		require.Equal(t, node1Input, addrStrings(factory(mustAddrs(t, node1Input))))
	})

	t.Run("ephemeral listen port changes nothing", func(t *testing.T) {
		listen := mustAddr(t, "/ip4/0.0.0.0/tcp/0")
		external := mustAddr(t, "/ip4/1.2.3.4/tcp/6600")
		factory := AddrsFactory(listen, external, log.DiscardLogger)
		require.Equal(t, append(append([]string{}, node1Input...), "/ip4/1.2.3.4/tcp/6600"),
			addrStrings(factory(mustAddrs(t, node1Input))))
	})

	t.Run("no listen addresses", func(t *testing.T) {
		listen := mustAddr(t, "/ip4/0.0.0.0/tcp/26656")
		external := mustAddr(t, "/ip4/3.134.167.133/tcp/26656")
		factory := AddrsFactory(listen, external, log.DiscardLogger)
		require.Equal(t, []string{"/ip4/3.134.167.133/tcp/26656"}, addrStrings(factory(nil)))
	})

	t.Run("reports each withheld address once", func(t *testing.T) {
		logger := &countingLogger{Logger: log.DiscardLogger}
		listen := mustAddr(t, "/ip4/0.0.0.0/tcp/26656")
		external := mustAddr(t, "/ip4/3.134.167.133/tcp/26656")
		factory := AddrsFactory(listen, external, logger)

		for range 3 {
			factory(mustAddrs(t, node1Input))
		}
		require.Equal(t, 1, logger.infof, "the same withheld set was reported more than once")

		// A peer observes the node at a port it has never seen before, which is
		// how the measured set grew by two in a single day. That has to be
		// visible, or an operator debugging reachability later sees nothing.
		grown := append(append([]string{}, node1Input...), "/ip4/3.134.167.133/tcp/51234")
		factory(mustAddrs(t, grown))
		require.Equal(t, 2, logger.infof, "a newly withheld address was not reported")

		factory(mustAddrs(t, grown))
		require.Equal(t, 2, logger.infof, "an already reported address was reported again")
	})
}

func TestListenAddrsFactory(t *testing.T) {
	// The seed host's shape: it binds a port and declares nothing, because
	// nothing dials it back.
	input := []string{
		"/ip4/172.31.4.10/tcp/26656",
		"/ip4/127.0.0.1/tcp/26656",
		"/ip4/3.134.167.133/tcp/26656",
		"/ip4/3.134.167.133/tcp/13335",
		"/ip4/3.134.167.133/tcp/62215",
	}

	t.Run("withholds every address off the listen port", func(t *testing.T) {
		factory := ListenAddrsFactory(mustAddr(t, "/ip4/0.0.0.0/tcp/26656"), log.DiscardLogger)
		require.Equal(t, []string{
			"/ip4/172.31.4.10/tcp/26656",
			"/ip4/127.0.0.1/tcp/26656",
			"/ip4/3.134.167.133/tcp/26656",
		}, addrStrings(factory(mustAddrs(t, input))))
	})

	// Unlike a node, it has no declared address to append.
	t.Run("appends nothing", func(t *testing.T) {
		factory := ListenAddrsFactory(mustAddr(t, "/ip4/0.0.0.0/tcp/26656"), log.DiscardLogger)
		require.Empty(t, factory(nil))
	})

	t.Run("ephemeral listen port changes nothing", func(t *testing.T) {
		factory := ListenAddrsFactory(mustAddr(t, "/ip4/0.0.0.0/tcp/0"), log.DiscardLogger)
		require.Equal(t, input, addrStrings(factory(mustAddrs(t, input))))
	})

	t.Run("no listen address changes nothing", func(t *testing.T) {
		factory := ListenAddrsFactory(nil, log.DiscardLogger)
		require.Equal(t, input, addrStrings(factory(mustAddrs(t, input))))
	})
}

// addrStringsOrNil is addrStrings with a nil result for an empty set, so a
// table can distinguish "nothing withheld" from "an empty slice".
func addrStringsOrNil(addrs []multiaddr.Multiaddr) []string {
	if len(addrs) == 0 {
		return nil
	}
	return addrStrings(addrs)
}
