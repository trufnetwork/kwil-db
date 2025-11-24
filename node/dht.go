package node

import (
	"context"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
)

// This file has some building blocks for DHT that can be used for both content
// routing and peer discovery.
//
// One tentative approach for snapshots is:
//  1. discover snapshot providers (peer discover)
//  2. retrieve their snapshot catalogs (ProtocolIDSnapshotCatalog), which describe their provided snapshots (height, hash, chunk count)
//  3. aggregate the catalogs and pick the best snapshot
//  4. begin retrieving the chunks (ProtocolIDSnapshotChunk)
//
// Higher level logic will be needed for the aggregation, and fallback to
// next-best snapshots in the event that restore of the current best fails.

func makeDHT(ctx context.Context, h host.Host, peers []peer.AddrInfo, mode dht.ModeOpt, pex bool) (*dht.IpfsDHT, error) {
	// Create a DHT
	opts := []dht.Option{
		dht.BootstrapPeers(peers...),
		dht.Mode(mode),
	}
	if !pex {
		opts = append(opts, dht.DisableAutoRefresh()) // just use connected peers
	}
	kadDHT, err := dht.New(ctx, h, opts...)
	if err != nil {
		return nil, err
	}

	// Bootstrap DHT
	err = kadDHT.Bootstrap(ctx)
	if err != nil {
		kadDHT.Close()
		return nil, err
	}

	return kadDHT, nil
}

func makeDiscovery(kad *dht.IpfsDHT) discovery.Discovery { //nolint
	return drouting.NewRoutingDiscovery(kad)
}

func advertise(ctx context.Context, namespace string, a discovery.Advertiser) {
	util.Advertise(ctx, a, namespace)
}

func discoverProviders(ctx context.Context, namespace string, d discovery.Discoverer) ([]peer.AddrInfo, error) {
	peerChan, err := d.FindPeers(ctx, namespace)
	if err != nil {
		return nil, err
	}
	var peers []peer.AddrInfo
	for p := range peerChan {
		peers = append(peers, p)
	}
	return peers, nil
}
