package peers

import (
	"encoding/json"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

type AddrInfo struct {
	ID    peer.ID               `json:"id"`
	Addrs []multiaddr.Multiaddr `json:"addrs"`
}

type PeerInfo struct {
	AddrInfo
	Protos []protocol.ID `json:"protos"`
}

func (p PeerInfo) MarshalJSON() ([]byte, error) {
	var addrStrs []string
	for _, addr := range p.Addrs {
		addrStrs = append(addrStrs, addr.String())
	}
	var protoStrs []string
	for _, proto := range p.Protos {
		protoStrs = append(protoStrs, string(proto))
	}
	return json.Marshal(struct {
		ID     string   `json:"id"`
		Addrs  []string `json:"addrs"`
		Protos []string `json:"protos"`
	}{
		ID:     p.ID.String(),
		Addrs:  addrStrs,
		Protos: protoStrs,
	})
}

func (p *PeerInfo) UnmarshalJSON(data []byte) error {
	aux := struct {
		ID     string   `json:"id"`
		Addrs  []string `json:"addrs"`
		Protos []string `json:"protos"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	peerID, err := peer.Decode(aux.ID)
	if err != nil {
		return err
	}
	p.ID = peerID

	for _, addrStr := range aux.Addrs {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			return err
		}
		p.Addrs = append(p.Addrs, addr)
	}
	for _, protoStr := range aux.Protos {
		p.Protos = append(p.Protos, protocol.ID(protoStr))
	}
	return nil
}

type PersistentPeerInfo struct {
	NodeID      string                `json:"id"` // "node ID" (pubkeybytes#keytype)
	Addrs       []multiaddr.Multiaddr `json:"addrs"`
	Protos      []protocol.ID         `json:"protos"`
	Whitelisted bool                  `json:"whitelisted"`
	Blacklisted *BlacklistEntry       `json:"blacklisted,omitempty"` // nil if not blacklisted
	// We probably need a last connected time and/or ttl
}

func (p PersistentPeerInfo) MarshalJSON() ([]byte, error) {
	var addrStrs []string
	for _, addr := range p.Addrs {
		addrStrs = append(addrStrs, addr.String())
	}
	var protoStrs []string
	for _, proto := range p.Protos {
		protoStrs = append(protoStrs, string(proto))
	}
	return json.Marshal(struct {
		ID          string          `json:"id"`
		Addrs       []string        `json:"addrs"`
		Protos      []string        `json:"protos"`
		Whitelisted bool            `json:"whitelisted"`
		Blacklisted *BlacklistEntry `json:"blacklisted,omitempty"`
	}{
		ID:          p.NodeID,
		Addrs:       addrStrs,
		Protos:      protoStrs,
		Whitelisted: p.Whitelisted,
		Blacklisted: p.Blacklisted,
	})
}

func (p *PersistentPeerInfo) UnmarshalJSON(data []byte) error {
	aux := struct {
		ID          string          `json:"id"`
		Addrs       []string        `json:"addrs"`
		Protos      []string        `json:"protos"`
		Whitelisted bool            `json:"whitelisted"`
		Blacklisted *BlacklistEntry `json:"blacklisted,omitempty"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	p.NodeID = aux.ID
	p.Whitelisted = aux.Whitelisted
	p.Blacklisted = aux.Blacklisted

	for _, addrStr := range aux.Addrs {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			return err
		}
		p.Addrs = append(p.Addrs, addr)
	}
	for _, protoStr := range aux.Protos {
		p.Protos = append(p.Protos, protocol.ID(protoStr))
	}
	return nil
}

// BlacklistEntry represents a blacklisted peer with metadata about why and when it was blacklisted.
type BlacklistEntry struct {
	PeerID    peer.ID   `json:"peer_id"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
	Permanent bool      `json:"permanent"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // Only set for temporary blacklists
}

// IsExpired returns true if this is a temporary blacklist entry that has expired.
func (be BlacklistEntry) IsExpired() bool {
	if be.Permanent {
		return false
	}
	return time.Now().After(be.ExpiresAt)
}

// MarshalJSON implements custom JSON marshaling for BlacklistEntry.
func (be BlacklistEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PeerID    string `json:"peer_id"`
		Reason    string `json:"reason"`
		Timestamp string `json:"timestamp"`
		Permanent bool   `json:"permanent"`
		ExpiresAt string `json:"expires_at,omitempty"`
	}{
		PeerID:    be.PeerID.String(),
		Reason:    be.Reason,
		Timestamp: be.Timestamp.Format(time.RFC3339),
		Permanent: be.Permanent,
		ExpiresAt: func() string {
			if be.Permanent || be.ExpiresAt.IsZero() {
				return ""
			}
			return be.ExpiresAt.Format(time.RFC3339)
		}(),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for BlacklistEntry.
func (be *BlacklistEntry) UnmarshalJSON(data []byte) error {
	aux := struct {
		PeerID    string `json:"peer_id"`
		Reason    string `json:"reason"`
		Timestamp string `json:"timestamp"`
		Permanent bool   `json:"permanent"`
		ExpiresAt string `json:"expires_at,omitempty"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	peerID, err := peer.Decode(aux.PeerID)
	if err != nil {
		return err
	}
	be.PeerID = peerID
	be.Reason = aux.Reason
	be.Permanent = aux.Permanent

	if be.Timestamp, err = time.Parse(time.RFC3339, aux.Timestamp); err != nil {
		return err
	}

	if aux.ExpiresAt != "" {
		if be.ExpiresAt, err = time.Parse(time.RFC3339, aux.ExpiresAt); err != nil {
			return err
		}
	}

	return nil
}
