package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	mock "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/types"
)

// newStateSyncServer stands a state-sync service on its own host, through
// NewStateSyncService so that the stream handler is registered the way it is in
// production. Delete that registration and these tests stop finding a peer to
// ask, which is the point: ProtocolIDBlockHeight is in RequiredStreamProtocols,
// so a node that stops serving it while state syncing gets its addresses
// cleared by everyone it meets.
func newStateSyncServer(ctx context.Context, t *testing.T, mn mock.Mocknet, bs blockStore) host.Host {
	t.Helper()

	priv, h := newTestHost(t, mn, crypto.KeyTypeSecp256k1)
	kadDHT, err := makeDHT(ctx, h, nil, dht.ModeServer, true)
	require.NoError(t, err)
	t.Cleanup(func() { kadDHT.Close() })

	// Enabling state sync requires a trusted provider. This one is never
	// reached, which Bootstrap warns about and carries on from; the service is
	// up either way, which is all these tests need of it.
	rawKey, err := priv.Raw()
	require.NoError(t, err)
	pk, err := crypto.UnmarshalSecp256k1PrivateKey(rawKey)
	require.NoError(t, err)
	provider := fmt.Sprintf("%s#%s@127.0.0.1:6600", hex.EncodeToString(pk.Public().Bytes()), pk.Type())

	_, err = NewStateSyncService(ctx, &StatesyncConfig{
		StateSyncCfg:  testSSConfig(true, []string{provider}),
		RcvdSnapsDir:  t.TempDir(),
		P2PService:    &P2PService{host: h, dht: kadDHT, discovery: makeDiscovery(kadDHT)},
		SnapshotStore: newSnapshotStore(bs),
		BlockStore:    bs,
		BlockSyncCfg:  &config.BlockSyncConfig{},
		Logger:        log.DiscardLogger,
	})
	require.NoError(t, err)

	return h
}

func askForBlock(ctx context.Context, t *testing.T, client host.Host, server host.Host, height int64) ([]byte, error) {
	t.Helper()
	return requestBlockHeight(ctx, client, server.ID(), height, blkReadLimit,
		2*time.Second, 20*time.Second, 500*time.Millisecond)
}

// TestStateSyncAnswersBlockRequestsLikeTheNode covers the window between a node
// starting to state sync and its node service coming up. Both serve
// ProtocolIDBlockHeight, and a peer sends one request and runs one parser over
// whatever comes back, so the two have to answer identically.
func TestStateSyncAnswersBlockRequestsLikeTheNode(t *testing.T) {
	ctx := context.Background()
	nodes, extraHosts, _, mn := makeTestHosts(t, 1, 1, 5*time.Hour, crypto.KeyTypeSecp256k1)

	n1 := nodes[0]
	blk, appHash := createTestBlock(1, 2)
	require.NoError(t, n1.bki.Store(blk, &ktypes.CommitInfo{AppHash: appHash}))

	// The same store behind both, so any difference is the handler's.
	stateSyncing := newStateSyncServer(ctx, t, mn, n1.bki)

	linkAll(t, mn)
	startNodes(t, nodes)
	client := extraHosts[0]

	t.Run("the answers are the same bytes", func(t *testing.T) {
		fromNode, err := askForBlock(ctx, t, client, n1.host, 1)
		require.NoError(t, err)

		fromStateSync, err := askForBlock(ctx, t, client, stateSyncing, 1)
		require.NoError(t, err, "a 1.1.0 client could not read the state-sync answer")

		require.Equal(t, fromNode, fromStateSync,
			"a peer must not be able to tell which service answered")
	})

	t.Run("the answer is the stored block", func(t *testing.T) {
		// requestBlockHeight has already taken the data flag off the front.
		resp, err := askForBlock(ctx, t, client, stateSyncing, 1)
		require.NoError(t, err)
		require.Greater(t, len(resp), types.HashLen)

		var hash types.Hash
		copy(hash[:], resp[:types.HashLen])
		require.Equal(t, blk.Hash(), hash)

		r := bytes.NewReader(resp[types.HashLen:])
		ciBytes, err := ktypes.ReadCompactBytes(r)
		require.NoError(t, err)
		var ci ktypes.CommitInfo
		require.NoError(t, ci.UnmarshalBinary(ciBytes))
		require.Equal(t, appHash, ci.AppHash)

		rawBlk, err := ktypes.ReadCompactBytes(r)
		require.NoError(t, err)
		require.Equal(t, ktypes.EncodeBlock(blk), rawBlk)

		var bestHeight int64
		require.NoError(t, binary.Read(r, binary.LittleEndian, &bestHeight))
		require.EqualValues(t, 1, bestHeight, "the trailing best height arrived")
		require.Zero(t, r.Len(), "nothing follows the best height")
	})

	t.Run("a block it does not have comes back with its best height", func(t *testing.T) {
		_, err := askForBlock(ctx, t, client, stateSyncing, 2)
		require.ErrorIs(t, err, ErrBlkNotFound)

		be := new(ErrNotFoundWithBestHeight)
		require.ErrorAs(t, err, &be, "a bare no-data byte reads as no response at all")
		require.EqualValues(t, 1, be.BestHeight)
	})
}
