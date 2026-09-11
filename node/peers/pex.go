package peers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const (
	ProtocolIDDiscover protocol.ID = "/kwil/discovery/1.0.0" // the PEX protocol that all peers support, and is the only real protocol that crawlers support other than the dummy ProtocolIDCrawler
	ProtocolIDCrawler  protocol.ID = "/kwil/crawler/1.0.0"   // dummy to identify a crawler that should not stay connected

	ProtocolIDPrefixChainID protocol.ID = "/kwil/chain/1.0.0/"
)

// DiscoveryStreamHandler sends a list of peer addresses on the stream. This
// implements the receiving side of ProtocolIDDiscover.
func (pm *PeerMan) DiscoveryStreamHandler(s network.Stream) {
	defer s.Close()

	pid := s.Conn().RemotePeer()
	if pm.seedMode { // in seed mode hang up after serving the peer list
		defer func() {
			pm.log.Debugf("Hanging up after serving peers to %v", pid)
			pm.h.Network().ClosePeer(pid)
		}()
	}

	peers := pm.ConnectedPeers()
	// peers = slices.DeleteFunc(peers, func(p PeerInfo) bool {
	// 	return p.ID == pid
	// })

	// Only tell the requester about addresses they could plausibly dial from
	// where they are, so this node does not relay e.g. another operator's
	// docker bridge addresses out to the public network.
	peers, dropped := routablePeers(peers, s.Conn().RemoteMultiaddr())
	if dropped > 0 {
		pm.log.Debugf("Withheld %d unroutable addresses from peer list for %v", dropped, peerIDStringer(pid))
	}

	s.SetWriteDeadline(time.Now().Add(4 * time.Second))
	if err := writePeers(s, pm.chainID, peers); err != nil {
		pm.log.Warn("failed to send peer list to peer", "error", err)
		return
	}

	pm.log.Debug("sent peer list to remote peer", "num_peers", len(peers),
		"to_peer", pid)
}

type peersMsg struct {
	ChainID string     `json:"chain_id"`
	Peers   []PeerInfo `json:"peers"`
}

func writePeers(s io.WriteCloser, chainID string, peers []PeerInfo) error {
	resp := peersMsg{
		ChainID: chainID,
		Peers:   peers,
	}
	encoder := json.NewEncoder(s)
	if err := encoder.Encode(resp); err != nil {
		return fmt.Errorf("failed to encode peers: %w", err)
	}
	return nil
}

// RequestPeers initiates the ProtocolIDDiscover stream.
func (pm *PeerMan) RequestPeers(ctx context.Context, peerID peer.ID) ([]PeerInfo, error) {
	if peerID == pm.h.ID() {
		return nil, nil
	}

	pm.log.Debug("Requesting peers", "from", peerID.String())

	stream, err := pm.h.NewStream(ctx, peerID, ProtocolIDDiscover)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", CompressDialError(err))
	}
	defer stream.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}

	stream.SetDeadline(deadline)

	chainID, peers, err := recvPeersProto(stream)
	if err != nil {
		return nil, err
	}

	if chainID != pm.chainID {
		return nil, fmt.Errorf("peer %v is on chain %v, expected %v", peerID, chainID, pm.chainID)
	}

	// Ensure that each received peer ID is an "identity" multihash that encodes
	// a supported public key.
	var okPeers []PeerInfo
	for _, peer := range peers {
		pk, _ := pubKeyFromPeerID(peer.ID)
		if pk == nil {
			pm.log.Warnf("Invalid peer ID received from %v: %v", peerID, peer.ID)
		} else {
			okPeers = append(okPeers, peer)
		}
	}

	// Discard addresses we could not route to from the vantage point of the
	// connection we learned them over. Peer exchange is the one path that
	// bypasses identify's equivalent filter, so without this a peer launders
	// private addresses learned over a private link out to the whole network.
	okPeers, dropped := routablePeers(okPeers, stream.Conn().RemoteMultiaddr())
	if dropped > 0 {
		pm.log.Debugf("Discarded %d unroutable addresses received from %v", dropped, peerIDStringer(peerID))
	}

	return okPeers, nil
}

// recvPeersProto reads a list of peer addresses from the stream.
// This implements the initiating side of ProtocolIDDiscover.
func recvPeersProto(stream io.Reader) (string, []PeerInfo, error) {
	stream = io.LimitReader(stream, 1_000_000)
	var resp peersMsg
	decoder := json.NewDecoder(stream)
	if err := decoder.Decode(&resp); err != nil {
		return "", nil, fmt.Errorf("failed to read and decode peers: %w", err)
	}
	return resp.ChainID, resp.Peers, nil
}
