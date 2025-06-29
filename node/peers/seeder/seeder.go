package seeder

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/libp2p/go-libp2p"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node"
	"github.com/trufnetwork/kwil-db/node/peers"
)

type Seeder struct {
	logger log.Logger
	host   host.Host
	pm     *peers.PeerMan
}

type Config struct {
	Dir        string
	ChainID    string
	Logger     log.Logger
	ListenAddr string
	PeerKey    crypto.PrivateKey
	// RequiredProtocols []string
}

func NewSeeder(cfg *Config) (*Seeder, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = log.DiscardLogger
	}
	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, err
	}
	addr, portStr, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 64)
	if err != nil {
		return nil, err
	}
	host, err := newHost(addr, port, cfg.ChainID, cfg.PeerKey, logger)
	if err != nil {
		return nil, err
	}
	addrBook := filepath.Join(cfg.Dir, "addrbook.json")

	pmCfg := &peers.Config{
		ChainID:           cfg.ChainID,
		SeedMode:          true,
		AddrBook:          addrBook,
		Logger:            logger.New("PEERS"),
		Host:              host,
		ConnGater:         nil,
		RequiredProtocols: node.RequiredStreamProtocols,
	}

	pm, err := peers.NewPeerMan(pmCfg)
	if err != nil {
		return nil, err
	}

	return &Seeder{
		host:   host,
		pm:     pm,
		logger: logger,
	}, nil
}

func (s *Seeder) Start(ctx context.Context, bootpeers ...string) error {
	defer s.host.Close()

	peersMA, err := peers.ConvertPeersToMultiAddr(bootpeers)
	if err != nil {
		return err
	}

	for _, peerMA := range peersMA {
		addrInfo, err := makePeerAddrInfo(peerMA)
		if err != nil {
			return err
		}
		s.logger.Infoln("Connecting to bootpeer", addrInfo)
		err = s.pm.Connect(ctx, peers.AddrInfo(*addrInfo))
		if err != nil {
			s.logger.Warnf("Failed to connect to bootpeer %v", addrInfo)
		}
	}

	return s.pm.Start(ctx)
}

func (s *Seeder) NumKnownPeers() int {
	all, _, _ := s.pm.KnownPeers()
	return len(all)
}

func makePeerAddrInfo(addr string) (*peer.AddrInfo, error) {
	// Turn the destination into a multiaddr.
	maddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return nil, err
	}

	// Extract the peer ID from the multiaddr.
	return peer.AddrInfoFromP2pAddr(maddr)
}

func newHost(ip string, port uint64, _ string, privKey crypto.PrivateKey, _ log.Logger) (host.Host, error) {
	// convert to the libp2p crypto key type
	var privKeyP2P p2pcrypto.PrivKey
	var err error
	switch kt := privKey.(type) {
	case *crypto.Secp256k1PrivateKey:
		privKeyP2P, err = p2pcrypto.UnmarshalSecp256k1PrivateKey(privKey.Bytes())
	case *crypto.Ed25519PrivateKey: // TODO
		privKeyP2P, err = p2pcrypto.UnmarshalEd25519PrivateKey(privKey.Bytes())
	default:
		err = fmt.Errorf("unknown private key type %T", kt)
	}
	if err != nil {
		return nil, err
	}

	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", ip, port))

	// cm, err := connmgr.NewConnManager(60, 100, connmgr.WithGracePeriod(20*time.Minute)) // TODO: absorb this into peerman
	// if err != nil {
	// 	return nil, nil, err
	// }

	// sec, secID := sec.NewScopedNoiseTransport(chainID, logger.New("SEC")) // noise.New plus chain ID check in handshake

	h, err := libp2p.New(
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(noise.ID, noise.New), // modified TLS based on node-ID
		// libp2p.Security(secID, sec),
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(privKeyP2P),
		// libp2p.ConnectionManager(cm),
	)
	if err != nil {
		return nil, err
	}

	return h, nil
}
