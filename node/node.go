package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand2 "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	adminTypes "github.com/trufnetwork/kwil-db/core/types/admin"
	chainTypes "github.com/trufnetwork/kwil-db/core/types/chain"
	"github.com/trufnetwork/kwil-db/node/consensus"
	"github.com/trufnetwork/kwil-db/node/metrics"
	"github.com/trufnetwork/kwil-db/node/peers"
	"github.com/trufnetwork/kwil-db/node/peers/sec"
	"github.com/trufnetwork/kwil-db/node/types"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/connmgr"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
)

// by default the mets interface points to the metrics.Node struct
// implementation in the metrics packages. The use of an interface allows this
// to be overridden.
var mets metrics.NodeMetrics = metrics.Node

// AppVersion encompasses all aspects of the Kwil DB application. A new version
// indicates incompatible changes to the application, and nodes with different
// versions should not communicate (TODO).
const AppVersion = 1

const (
	blockTxCount    = 50 // for "mining"
	txReAnnInterval = 30 * time.Second
)

type peerManager interface {
	network.Notifiee
	Start(context.Context) error
	ConnectedPeers() []peers.PeerInfo
	KnownPeers() ([]peers.PeerInfo, []peers.PeerInfo, []peers.PeerInfo)
	Connect(ctx context.Context, info peers.AddrInfo) error

	// Whitelist methods
	Allow(p peer.ID)
	AllowPersistent(p peer.ID)
	Disallow(p peer.ID)
	// Allowed() []peer.ID
	AllowedPersistent() []peer.ID
	// IsAllowed(p peer.ID) bool
}

type WhitelistMgr struct {
	pm     peerManager
	logger log.Logger
}

type BlacklistMgr struct {
	pm     *peers.PeerMan // Need direct access to PeerMan for blacklist methods
	logger log.Logger
}

// Whitelister is a shim between the a Kwil consumer like RPC service and the
// p2p layer (PeerMan) which manages the persistent and effective white list in
// terms of libp2p types.
func (n *Node) Whitelister() *WhitelistMgr {
	return &WhitelistMgr{pm: n.pm, logger: n.log.New("WHITELIST")}
}

// Blacklister is a shim between the a Kwil consumer like RPC service and the
// p2p layer (PeerMan) which manages the persistent and effective blacklist in
// terms of libp2p types.
func (n *Node) Blacklister() *BlacklistMgr {
	// Cast the peerManager interface to *peers.PeerMan
	pm, ok := n.pm.(*peers.PeerMan)
	if !ok {
		// This should never happen in normal operation
		n.log.Error("peerManager is not a *peers.PeerMan, blacklist functionality unavailable")
		return &BlacklistMgr{pm: nil, logger: n.log.New("BLACKLIST")}
	}
	return &BlacklistMgr{pm: pm, logger: n.log.New("BLACKLIST")}
}

func (wl *WhitelistMgr) AddPeer(nodeID string) error {
	wl.logger.Info(nodeID)
	peerID, err := nodeIDToPeerID(nodeID)
	if err != nil {
		return err
	}
	wl.logger.Info(peerID.String())
	wl.pm.AllowPersistent(peerID)
	return nil
}

func (wl *WhitelistMgr) RemovePeer(nodeID string) error {
	peerID, err := nodeIDToPeerID(nodeID)
	if err != nil {
		return err
	}
	wl.pm.Disallow(peerID)
	return nil
}

func (wl *WhitelistMgr) List() []string {
	var list []string
	for _, peerID := range wl.pm.AllowedPersistent() {
		nodeID, err := peers.NodeIDFromPeerID(peerID.String())
		if err != nil { // this shouldn't happen
			wl.logger.Errorf("invalid peer ID in whitelist: %v", err)
			continue // return nil, err
		}
		list = append(list, nodeID)
	}
	return list
}

func (bl *BlacklistMgr) BlacklistPeer(nodeID string, reason string, duration time.Duration) error {
	if bl.pm == nil {
		return fmt.Errorf("blacklist functionality unavailable")
	}
	bl.logger.Infof("blacklisting peer %s (reason: %s, duration: %s)", nodeID, reason, duration)
	peerID, err := nodeIDToPeerID(nodeID)
	if err != nil {
		return err
	}
	bl.pm.BlacklistPeer(peerID, reason, duration)
	return nil
}

func (bl *BlacklistMgr) RemoveFromBlacklist(nodeID string) error {
	if bl.pm == nil {
		return fmt.Errorf("blacklist functionality unavailable")
	}
	peerID, err := nodeIDToPeerID(nodeID)
	if err != nil {
		return err
	}
	removed := bl.pm.RemoveFromBlacklist(peerID)
	if !removed {
		return fmt.Errorf("peer not found in blacklist")
	}
	bl.logger.Infof("removed peer %s from blacklist", nodeID)
	return nil
}

func (bl *BlacklistMgr) ListBlacklisted() ([]peers.BlacklistEntry, error) {
	if bl.pm == nil {
		return nil, fmt.Errorf("blacklist functionality unavailable")
	}
	return bl.pm.ListBlacklisted(), nil
}

type Node struct {
	// Base services
	P2PService

	// cfg
	pubkey crypto.PublicKey
	dir    string
	// pf *prefetch
	chainID      string
	blockSyncCfg *config.BlockSyncConfig

	// interfaces
	bki types.BlockStore
	mp  types.MemPool
	ce  ConsensusEngine
	ss  SnapshotStore
	bp  BlockProcessor

	// broadcast channels
	ackChan  chan AckRes         // from consensus engine, to gossip to leader
	resetMsg chan ConsensusReset // gossiped in from peers, to consensus engine
	// from consensus engine, to gossip to leader for calculating best height of the validators during blocksync.
	// discReq  chan types.DiscoveryRequest
	// from gossip, to consensus engine for calculating best height of the validators during blocksync.
	// discResp chan types.DiscoveryResponse

	blkPropHandling chan struct{}

	txQueue chan orderedTxn // enforces ordering in the tx broadcasts to the network.

	sendQueue txSendQueue

	wg  sync.WaitGroup
	log log.Logger
}

type orderedTxn struct {
	txID  types.Hash
	rawtx []byte
	from  peer.ID
}

const txQueueSize = 1000 // rare to have a really long queue of unbroadcasted txns

// NewNode creates a new node. The config struct is for required configuration,
// and the functional options for optional settings, like dependency overrides.
func NewNode(cfg *Config, opts ...Option) (*Node, error) {
	options := &options{}
	for _, opt := range opts {
		opt(options)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.DiscardLogger
	}

	pubkey := cfg.PrivKey.Public()

	node := &Node{
		log:          logger,
		pubkey:       pubkey,
		mp:           cfg.Mempool,
		bki:          cfg.BlockStore,
		ce:           cfg.Consensus,
		dir:          cfg.RootDir,
		chainID:      cfg.ChainID,
		blockSyncCfg: cfg.BlockSync,
		ss:           cfg.Snapshotter,
		bp:           cfg.BlockProc,

		ackChan:         make(chan AckRes, 1),
		resetMsg:        make(chan ConsensusReset, 1),
		txQueue:         make(chan orderedTxn, txQueueSize),
		blkPropHandling: make(chan struct{}, 1),

		P2PService: *cfg.P2PService,
	}

	node.host.SetStreamHandler(ProtocolIDTxAnn, node.txAnnStreamHandler)
	node.host.SetStreamHandler(ProtocolIDBlkAnn, node.blkAnnStreamHandler)
	node.host.SetStreamHandler(ProtocolIDBlock, node.blkGetStreamHandler)
	node.host.SetStreamHandler(ProtocolIDBlockHeight, node.blkGetHeightStreamHandler)
	node.host.SetStreamHandler(ProtocolIDTx, node.txGetStreamHandler)

	node.host.SetStreamHandler(ProtocolIDBlockPropose, node.blkPropStreamHandler)

	return node, nil
}

func FormatPeerString(rawPubKey []byte, keyType crypto.KeyType, ip string, port int) string {
	return fmt.Sprintf("%s#%s@%s", hex.EncodeToString(rawPubKey), keyType,
		net.JoinHostPort(ip, strconv.Itoa(port)))
}

func (n *Node) Addrs() []string {
	return addrs(n.host)
}

func addrs(h host.Host) []string {
	hosts, ports, _ := hostPort(h)
	if len(hosts) == 0 {
		return nil
	}

	addrs := make([]string, len(hosts))
	for i, h := range hosts {
		addrs[i] = fmt.Sprintf("%s:%d", h, ports[i])
	}
	return addrs
}

func maddrs(h host.Host) []string {
	hosts, ports, protocols := hostPort(h)
	id := h.ID()
	if len(hosts) == 0 {
		return nil
	}
	addrs := make([]string, len(hosts))
	for i, host := range hosts {
		addrs[i] = fmt.Sprintf("/%s/%s/tcp/%d/p2p/%s", protocols[i], host, ports[i], id)
	}
	return addrs
}

func (n *Node) MultiAddrs() []string {
	return maddrs(n.host)
}

func (n *Node) Dir() string {
	return n.dir
}

func (n *Node) ID() string {
	return peers.PeerIDStringer(n.host.ID()).String()
}

// Start begins tx and block gossip, connects to any bootstrap peers, and begins
// peer discovery.
func (n *Node) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ps, err := pubsub.NewGossipSub(ctx, n.host, pubsub.WithPeerExchange(n.P2PService.PEX()))
	if err != nil {
		return err
	}

	// Check protocol support for connected peers, which were established
	// earlier during P2PService startup.
	for _, peer := range n.peers() {
		if err = n.checkPeerProtos(ctx, peer); err != nil {
			n.log.Warnf("WARNING: peer does not support required protocols %v: %v", peer, err)
			if err = n.host.Network().ClosePeer(peer); err != nil {
				n.log.Errorf("failed to disconnect from %v: %v", peer, err)
			}
			// n.host.Peerstore().RemovePeer()
			continue
		}
	} // else would use persistent peer store (address book)

	for _, val := range n.bp.GetValidators() {
		n.log.Infof("Adding validator %v to peer whitelist", val.Identifier)
		peerID, err := peerIDForValidator(val)
		if err != nil {
			n.log.Errorf("cannot get peerID for validator (%v): %v", val.Identifier, err)
			continue
		}
		n.pm.Allow(peerID)
	}

	valSub := n.bp.SubscribeValidators()
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for {
			select {
			case valUpdates, open := <-valSub:
				if !open {
					return
				}
				// update peer filter
				for _, up := range valUpdates {
					peerID, err := peerIDForValidator(up)
					if err != nil {
						n.log.Errorf("cannot get peerID for validator (%v): %v", up.Identifier, err)
						continue
					}
					if up.Power > 0 {
						n.pm.Allow(peerID)
					} else {
						n.pm.Disallow(peerID)
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := n.startAckGossip(ctx, ps); err != nil {
		cancel()
		return err
	}

	if err := n.startConsensusResetGossip(ctx, ps); err != nil {
		cancel()
		return err
	}

	n.startOrderedTxQueueAnns(ctx)

	/*
		if err := n.startDiscoveryRequestGossip(ctx, ps); err != nil {
			cancel()
			return err
		}

		if err := n.startDiscoveryResponseGossip(ctx, ps); err != nil {
			cancel()
			return err
		} */

	// custom stream-based gossip uses txAnnStreamHandler and announceTx.
	// This dummy method will make create+announce new pretend transactions.
	// It also periodically rebroadcasts txns.
	n.startTxAnns(ctx, txReAnnInterval)

	// mine is our block anns goroutine, which must be only for leader
	n.wg.Add(1)
	var ceErr error

	go func() {
		defer n.wg.Done()
		defer cancel()

		broadcastFns := consensus.BroadcastFns{
			ProposalBroadcaster: func(ctx context.Context, blk *ktypes.Block, senderPubkey []byte) {
				n.announceBlkProp(ctx, blk, senderPubkey, n.host.ID())
			},
			TxAnnouncer: func(ctx context.Context, txID types.Hash) {
				n.announceTx(ctx, txID, n.host.ID())
			},
			BlkAnnouncer:        n.announceBlk,
			AckBroadcaster:      n.sendACK,
			BlkRequester:        n.getBlkHeight,
			RstStateBroadcaster: n.sendReset,
			TxBroadcaster:       n.BroadcastTx,
		}

		whitelistFns := consensus.WhitelistFns{
			AddPeer:    n.Whitelister().AddPeer,
			RemovePeer: n.Whitelister().RemovePeer,
		}

		ceErr = n.ce.Start(ctx, broadcastFns, whitelistFns)
	}()

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.pm.Start(ctx)
	}()

	// Launch peer-height cache GC ticker
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				gcPeerCache()
			}
		}
	}()

	n.log.Info("Node started.")

	<-ctx.Done()
	n.wg.Wait()

	n.log.Info("Node stopped.")
	return ceErr
}

func peerIDForValidator(pubkey *ktypes.Validator) (peer.ID, error) {
	// We only support secp256k1 keys for validators presently.
	switch pubkey.KeyType {
	case crypto.KeyTypeSecp256k1:
		p2pPub, err := p2pcrypto.UnmarshalSecp256k1PublicKey(pubkey.Identifier)
		if err != nil {
			return "", fmt.Errorf("Invalid validator pubkey: %vw", err)
		}
		return peer.IDFromPublicKey(p2pPub)
	case crypto.KeyTypeEd25519:
		p2pPub, err := p2pcrypto.UnmarshalEd25519PublicKey(pubkey.Identifier)
		if err != nil {
			return "", fmt.Errorf("Invalid validator pubkey: %vw", err)
		}
		return peer.IDFromPublicKey(p2pPub)
	default:
		return "", fmt.Errorf("unsupported validator key type: %s", pubkey.KeyType)
	}
}

func nodeIDToPeerID(nodeID string) (peer.ID, error) {
	pubKey, err := peers.NodeIDToPubKey(nodeID)
	if err != nil {
		return "", err
	}
	return pubkeyToPeerID(pubKey)
}

func pubkeyToPeerID(pubkey crypto.PublicKey) (peer.ID, error) {
	var p2pPub p2pcrypto.PubKey
	var err error
	switch pt := pubkey.(type) {
	case *crypto.Secp256k1PublicKey:
		p2pPub = (*p2pcrypto.Secp256k1PublicKey)(pt)
	case *crypto.Ed25519PublicKey:
		// no shortcuts for ed25519
		rawPub := pubkey.Bytes()
		p2pPub, err = p2pcrypto.UnmarshalEd25519PublicKey(rawPub)
	default:
		return "", fmt.Errorf("unsupported pubkey type: %T", pubkey)
	}
	if err != nil {
		return "", err
	}
	p2pAddr, err := peer.IDFromPublicKey(p2pPub)
	if err != nil {
		return "", err
	}
	return p2pAddr, nil
}

func multiAddrToHostPort(addr multiaddr.Multiaddr) string {
	host, port, _ := maHostPort(addr)
	return net.JoinHostPort(host, port)
}

func (n *Node) Peers(context.Context) ([]*adminTypes.PeerInfo, error) {
	peers := n.pm.ConnectedPeers()
	peersInfo := []*adminTypes.PeerInfo{}
	for _, peer := range peers {
		conns := n.host.Network().ConnsToPeer(peer.ID)
		if len(conns) == 0 { // should be at least one
			continue
		}
		conn := conns[0]

		peersInfo = append(peersInfo, &adminTypes.PeerInfo{
			Inbound:    conn.Stat().Direction == network.DirInbound,
			RemoteAddr: multiAddrToHostPort(conn.RemoteMultiaddr()),
			LocalAddr:  multiAddrToHostPort(conn.LocalMultiaddr()),
		})
	}
	return peersInfo, nil
}

// Status returns the current status of the node.
func (n *Node) Status(ctx context.Context) (*adminTypes.Status, error) {
	ceStatus := n.ce.Status()
	var height int64
	var blkHash, appHash ktypes.Hash
	var stamp time.Time
	if ceStatus.CommittedHeader != nil {
		height = ceStatus.CommittedHeader.Height
		blkHash = ceStatus.CommittedHeader.Hash()
		stamp = ceStatus.CommittedHeader.Timestamp
	}
	if ceStatus.CommitInfo != nil {
		appHash = ceStatus.CommitInfo.AppHash
	}

	// If CE is initialized, we should not have to use the block store. In
	// addition, the blockstore may be ahead of the CE, such as during replay
	// from blockstore if the app (postgres DBs) has been reset.
	//	 if stamp.IsZero() || blkHash.IsZero() || height == 0 {
	//	 	height, blkHash, appHash, stamp = n.bki.Best()
	//	 }

	var addr string
	if addrs := n.Addrs(); len(addrs) > 0 {
		addr = addrs[0]
	}
	pkBytes := n.pubkey.Bytes()
	return &adminTypes.Status{
		Node: &adminTypes.NodeInfo{
			ChainID:    n.chainID,
			NodeID:     peers.NodeIDFromPubKey(n.pubkey),
			ListenAddr: addr,
			AppVersion: AppVersion,
			Role:       ceStatus.Role,
		},
		Sync: &adminTypes.SyncInfo{
			AppHash:         appHash,
			BestBlockHash:   blkHash,
			BestBlockHeight: height,
			BestBlockTime:   stamp,
			Syncing:         ceStatus.CatchingUp, // n.ce.InCatchup(), //
		},
		Validator: &adminTypes.ValidatorInfo{
			AccountID: ktypes.AccountID{
				Identifier: pkBytes,
				KeyType:    n.pubkey.Type(),
			},
			Power: 1, // Let's default to 1 for now
		},
	}, nil
}

func (n *Node) TxQuery(ctx context.Context, hash types.Hash, prove bool) (*ktypes.TxQueryResponse, error) {
	if tx := n.mp.Get(hash); tx != nil {
		return &ktypes.TxQueryResponse{
			Tx:     tx.Transaction,
			Hash:   hash,
			Height: -1,
		}, nil
	}

	tx, height, blkHash, blkIdx, err := n.bki.GetTx(hash)
	if err != nil {
		return nil, ErrTxNotFound
	}

	res, err := n.bki.Result(blkHash, blkIdx)
	if err != nil {
		return nil, ErrTxNotFound
	}

	return &ktypes.TxQueryResponse{
		Tx:     tx,
		Hash:   hash,
		Height: height,
		Result: res,
	}, nil
}

func (n *Node) BroadcastTx(ctx context.Context, tx *ktypes.Transaction, sync uint8) (ktypes.Hash, *ktypes.TxResult, error) {
	if n.ce.InCatchup() {
		return ktypes.Hash{}, nil, errors.New("node is catching up, cannot process transactions right now")
	}

	ntx := types.NewTx(tx) // create the immutable transaction with stored hash for CE

	// Do a TxQuery first maybe so as not to spam existing txns.
	_, err := n.TxQuery(ctx, ntx.Hash(), false)
	if err == nil {
		return ktypes.Hash{}, nil, ErrTxAlreadyExists
	}

	return n.ce.BroadcastTx(ctx, ntx, sync)
}

// ChainTx return tx info that is used in Chain rpc.
func (n *Node) ChainTx(hash types.Hash) (*chainTypes.Tx, error) {
	tx, height, blkHash, blkIdx, err := n.bki.GetTx(hash)
	if err != nil {
		return nil, err
	}
	blkResults, err := n.bki.Results(blkHash)
	if err != nil {
		return nil, err
	}
	if int(blkIdx) >= len(blkResults) {
		return nil, errors.New("invalid block index")
	}
	res := blkResults[blkIdx]
	return &chainTypes.Tx{
		Hash:     hash,
		Height:   height,
		Index:    blkIdx,
		Tx:       tx,
		TxResult: &res,
	}, nil
}

// ChainUnconfirmedTx return unconfirmed tx info that is used in Chain rpc.
func (n *Node) ChainUnconfirmedTx(limit int) (int, []*types.Tx) {
	total, _ := n.mp.Size()
	if limit <= 0 {
		return total, nil
	}
	// max 8 MB (TODO consider RPC max request size, possible request field)
	return total, n.mp.PeekN(limit, 8_000_000)
}

func (n *Node) BlockHeight() int64 {
	height, _, _, _ := n.bki.Best()
	return height
}

func (n *Node) ConsensusParams() *ktypes.NetworkParameters {
	return n.ce.ConsensusParams()
}

func (n *Node) AbortBlockExecution(height int64, txIDs []types.Hash) error {
	return n.ce.CancelBlockExecution(height, txIDs)
}

func (n *Node) PromoteLeader(candidate crypto.PublicKey, height int64) error {
	return n.ce.PromoteLeader(candidate, height)
}

func (n *Node) Role() types.Role {
	return n.ce.Role()
}

var RequiredStreamProtocols = []protocol.ID{
	ProtocolIDDiscover,
	ProtocolIDTx,
	ProtocolIDTxAnn,
	ProtocolIDBlockHeight,
	ProtocolIDBlock,
	ProtocolIDBlkAnn,
	ProtocolIDBlockPropose,
	pubsub.GossipSubID_v12,
}

func (n *Node) checkPeerProtos(ctx context.Context, peer peer.ID) error {
	return peers.RequirePeerProtos(ctx, n.host.Peerstore(), peer, RequiredStreamProtocols...)
}

type randSrc struct{}

func (randSrc) Uint64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

var rng = mrand2.New(randSrc{})

func (n *Node) peers() []peer.ID {
	return peerHosts(n.host)
}

func peerHosts(host host.Host) []peer.ID {
	peers := host.Network().Peers()
	rng.Shuffle(len(peers), func(i, j int) {
		peers[i], peers[j] = peers[j], peers[i]
	})
	return peers
}

// NewKey generates a new private key from a reader, which should provide random data.
func NewKey(r io.Reader) *crypto.Secp256k1PrivateKey {
	privKey, _, err := crypto.GenerateSecp256k1Key(r)
	if err != nil {
		panic(err)
	}

	pk, ok := privKey.(*crypto.Secp256k1PrivateKey)
	if !ok {
		panic("invalid private key type")
	}

	return pk
}

type hostConfig struct {
	ip              string
	port            uint64
	privKey         crypto.PrivateKey
	chainID         string
	connGater       connmgr.ConnectionGater
	logger          log.Logger
	externalAddress string // host:port
}

func newHost(cfg *hostConfig) (host.Host, error) {
	privKey := cfg.privKey
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

	ip, ipv, err := peers.ResolveHost(cfg.ip)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve %v: %w", ip, err)
	}

	sourceMultiAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/%s/%s/tcp/%d", ipv, ip, cfg.port))
	if err != nil {
		return nil, fmt.Errorf("invalid listen address: %w", err)
	}

	var externalMultiAddr multiaddr.Multiaddr
	if cfg.externalAddress != "" {
		ePort := cfg.port // fallback if none given
		eHost, ePortStr, err := net.SplitHostPort(cfg.externalAddress)
		if err != nil {
			if !strings.Contains(err.Error(), "missing port") {
				return nil, fmt.Errorf("invalid external address: %w", err)
			}
			// no port given => use port from listen address
			eHost = cfg.externalAddress
		} else { // full host:port given => use port from external address
			ePort, err = strconv.ParseUint(ePortStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid external address: %w", err)
			}
		}
		ip, ipv, err := peers.ResolveHost(eHost)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve %v: %w", ip, err)
		}
		externalMultiAddr, err = multiaddr.NewMultiaddr(fmt.Sprintf("/%s/%s/tcp/%d", ipv, ip, ePort))
		if err != nil {
			return nil, fmt.Errorf("invalid external address: %w", err)
		}
		cfg.logger.Infof("Using external address %v: %v", cfg.externalAddress, externalMultiAddr)
	}

	// listenAddrs := libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0", "/ip4/0.0.0.0/tcp/0/ws")

	// The BasicConnManager can keep connections below an upper limit, dropping
	// down to some lower limit (presumably to keep a dynamic peer list), but it
	// won't try to initiation new connections to reach the min. Maybe this will
	// be helpful later, so leaving as a comment:

	// cm, err := connmgr.NewConnManager(60, 100, connmgr.WithGracePeriod(20*time.Minute)) // TODO: absorb this into peerman
	// if err != nil {
	// 	return nil, nil, err
	// }

	sec, secID := sec.NewScopedNoiseTransport(cfg.chainID, cfg.logger.New("SEC")) // noise.New plus chain ID check in handshake

	h, err := libp2p.New(
		libp2p.AddrsFactory(func(m []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			if externalMultiAddr != nil {
				// Perhaps we should return *only* the external address if it is set?
				// This could break peers on a local network...
				// return []multiaddr.Multiaddr{externalMultiAddr}

				// For now, just add the specified address to the list of
				// advertised addresses, and peers will eventually get to it.
				m = append(m, externalMultiAddr)
			}
			return m
			// If we add a "disallow private addresses" setting then we
			// return multiaddr.FilterAddrs(m, manet.IsPublicAddr)
		}),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(noise.ID, noise.New), // modified TLS based on node-ID
		libp2p.Security(secID, sec),
		libp2p.ListenAddrs(sourceMultiAddr),
		// listenAddrs,
		libp2p.Identity(privKeyP2P),
		libp2p.ConnectionGater(cfg.connGater),
		// libp2p.ConnectionManager(cm),
	) // libp2p.RandomIdentity, in-mem peer store, ...
	if err != nil {
		return nil, err
	}

	// cg.SetPeerStore(h.Peerstore())

	return h, nil
}

func maHostPort(addr multiaddr.Multiaddr) (host, port, protocol string) {
	port, _ = addr.ValueForProtocol(multiaddr.P_TCP)
	protocol = "ip4"
	host, _ = addr.ValueForProtocol(multiaddr.P_IP4)
	if host == "" {
		host, _ = addr.ValueForProtocol(multiaddr.P_IP6)
		protocol = "ip6"
	}
	return
}

func hostPort(host host.Host) ([]string, []int, []string) {
	var addrStr []string
	var ports []int
	var protocols []string              // ip4 or ip6
	for _, addr := range host.Addrs() { // host.Network().ListenAddresses()
		host, portStr, protocol := maHostPort(addr)
		port, _ := strconv.Atoi(portStr)
		ports = append(ports, port)
		addrStr = append(addrStr, host)
		protocols = append(protocols, protocol)
	}

	return addrStr, ports, protocols
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

func connectPeer(ctx context.Context, addr string, host host.Host) (*peer.AddrInfo, error) {
	// Extract the peer ID and address info from the multiaddr.
	info, err := makePeerAddrInfo(addr)
	if err != nil {
		return nil, err
	}

	// Add the destination's peer multiaddress in the peerstore.
	// This will be used during connection and stream creation by libp2p.
	// host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	return info, peers.CompressDialError(host.Connect(ctx, *info))
}

// TODO: this is WRONG considering paths like ~user. We should rewrite this
// correctly, for both ~/ and ~user/ and without assuming a platform separator.
func ExpandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[2:])
	}
	return filepath.Abs(path)
}

func (n *Node) InCatchup() bool {
	return n.ce.InCatchup()
}
