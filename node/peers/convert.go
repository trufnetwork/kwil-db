package peers

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/trufnetwork/kwil-db/core/crypto"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/multiformats/go-multiaddr"
)

/* PeerList is a silly way to encapsulate libp2p types.
type PeerList struct {
	pids peer.IDSlice
}

func (pl PeerList) String() string {
	return pl.pids.String()
}

func NewPeerList(nodeIDs []string) (*PeerList, error) {
	pl := new(PeerList)
	for _, nodeID := range nodeIDs {
		pk, err := NodeIDToPubKey(nodeID)
		if err != nil {
			return nil, err
		}
		_, pid, err := convertPubKey(pk)
		if err != nil {
			return nil, err
		}
		pl.pids = append(pl.pids, pid)
	}
	return pl, nil
}*/

// PeerIDFromPubKey converts a pubkey to a peer ID string.
func PeerIDFromPubKey(pubkey crypto.PublicKey) (peer.ID, error) {
	_, peerID, err := convertPubKey(pubkey)
	if err != nil {
		return "", err
	}
	return peerID, nil // base58 encoding of identity multihash
}

// PubKeyFromPeerID tries to decode the pubkey from a peer ID string.
// This will only work if the peer ID is an "identity" multihash.
func PubKeyFromPeerID(peerID string) (crypto.PublicKey, error) {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return nil, err
	}
	return pubKeyFromPeerID(pid)
}

func pubKeyFromPeerID(peerID peer.ID) (crypto.PublicKey, error) {
	p2pPubKey, err := peerID.ExtractPublicKey()
	if err != nil {
		return nil, err
	}
	rawPub, err := p2pPubKey.Raw()
	if err != nil {
		return nil, err
	}
	switch p2pPubKey.(type) {
	case *p2pcrypto.Secp256k1PublicKey:
		return crypto.UnmarshalSecp256k1PublicKey(rawPub)
	case *p2pcrypto.Ed25519PublicKey:
		return crypto.UnmarshalEd25519PublicKey(rawPub)
	default:
		return nil, fmt.Errorf("unsupported pubkey type: %T", p2pPubKey)
	}
}

func convertPubKey(pubkey crypto.PublicKey) (p2pcrypto.PubKey, peer.ID, error) {
	rawPub := pubkey.Bytes()
	var p2pPub p2pcrypto.PubKey
	var err error
	switch pubkey.(type) {
	case *crypto.Secp256k1PublicKey:
		p2pPub, err = p2pcrypto.UnmarshalSecp256k1PublicKey(rawPub)
	case *crypto.Ed25519PublicKey:
		p2pPub, err = p2pcrypto.UnmarshalEd25519PublicKey(rawPub)
	default:
		return nil, "", fmt.Errorf("unsupported pubkey type: %T", pubkey)
	}
	if err != nil {
		return nil, "", err
	}
	p2pAddr, err := peer.IDFromPublicKey(p2pPub)
	if err != nil {
		return nil, "", err
	}
	return p2pPub, p2pAddr, nil
}

// Convert from go-libp2p's peer.ID format to Kwil's node ID format.
func NodeIDFromPeerID(peerID string) (string, error) {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return "", err
	}
	return nodeIDFromPeerID(pid)
}

func nodeIDFromPeerID(pid peer.ID) (string, error) {
	pk, err := pubKeyFromPeerID(pid)
	if err != nil { // peers should have IDENTITY peer IDs
		return "", err
	}
	return NodeIDFromPubKey(pk), nil
}

func NodeIDFromPubKey(pubkey crypto.PublicKey) string {
	if pubkey == nil {
		return "<invalid>"
	}
	// kd, ok := authExt.KeyDefinition(pubkey.Type())
	// if !ok {
	// 	return "<invalid key type>"
	// }
	return fmt.Sprintf("%x#%s", pubkey.Bytes(), pubkey.Type().String())
}

func NodeIDToPubKey(nodeID string) (crypto.PublicKey, error) {
	parts := strings.Split(nodeID, "#")
	if len(parts) != 2 {
		return nil, errors.New("invalid peer notation")
	}
	pubkeyStr, keyTypeStr := parts[0], parts[1]
	pubkeyBts, err := hex.DecodeString(pubkeyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid node pubkey: %w", err)
	}
	return crypto.UnmarshalPublicKey(pubkeyBts, crypto.KeyType(keyTypeStr))
}

func nodeIDToPeerID(nodeID string) (peer.ID, error) {
	pk, err := NodeIDToPubKey(nodeID)
	if err != nil {
		return "", fmt.Errorf("pubkey not recoverable from node ID: %w", err)
	}
	_, peerID, err := convertPubKey(pk)
	return peerID, err
}

// ConvertPeersToMultiAddr convert a peer from pubkeyHex#keyTypeInt@ip:port to /ip4/ip/tcp/port/p2p/peerID
func ConvertPeersToMultiAddr(peers []string) ([]string, error) {
	addrs := make([]string, len(peers))
	for i, peerAddr := range peers {
		// split the pieces of pubkey#type@ip:port
		parts := strings.Split(peerAddr, "@")
		if len(parts) != 2 {
			return nil, errors.New("invalid peer notation")
		}
		addr := parts[1]

		pubkey, err := NodeIDToPubKey(parts[0])
		if err != nil {
			return nil, err
		}

		peerID, err := PeerIDFromPubKey(pubkey)
		if err != nil {
			return nil, err
		}

		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, err
		}

		ip, ipv, err := ResolveHost(host)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve %v: %w", ip, err)
		}

		maStr := fmt.Sprintf("/%s/%s/tcp/%d/p2p/%s", ipv, ip, port, peerID)
		// ensure the multiaddress string is parsable
		_, err = multiaddr.NewMultiaddr(maStr)
		if err != nil {
			return nil, err
		}
		addrs[i] = maStr
	}
	return addrs, nil
}

func ResolveHost(addr string) (ip, ipv string, err error) {
	// fast path with no lookup
	// if netIP, err := netip.ParseAddr(addr); err != nil {
	// 	ip = netIP.String()
	// 	if netIP.Is4() {
	// 		return ip, "ip4", nil
	// 	}
	// 	return ip, "ip4", nil
	// }

	ipAddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return
	}
	if len(ipAddr.IP) == 0 {
		err = fmt.Errorf("invalid IP address: %v", addr)
		return
	}
	ip = ipAddr.IP.String()
	ipv = "ip4"
	if ipAddr.IP.To4() == nil {
		ipv = "ip6"
	}
	return
}

func CompressDialError(err error) error {
	var dErr *swarm.DialError
	if errors.Is(err, swarm.ErrAllDialsFailed) && errors.As(err, &dErr) {
		// the actual DialError string is multi-line
		addrs := make([]string, len(dErr.DialErrors))
		for i, te := range dErr.DialErrors {
			addrs[i] = te.Address.String()
		}
		err = fmt.Errorf("%w: [%s]", dErr.Cause, strings.Join(addrs, ", "))
	}
	return err
}
