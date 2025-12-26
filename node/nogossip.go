package node

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/peers"
	"github.com/trufnetwork/kwil-db/node/types"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func (n *Node) txAnnStreamHandler(s network.Stream) {
	defer s.Close()

	if n.InCatchup() { // we are in catchup, don't accept new txs
		return
	}

	txGetTimeout := defaultTxGetTimeout
	if n.blockSyncCfg != nil {
		txGetTimeout = time.Duration(n.blockSyncCfg.TxGetTimeout)
	}
	s.SetDeadline(time.Now().Add(txGetTimeout))

	var ann txHashAnn
	if _, err := ann.ReadFrom(s); err != nil {
		n.log.Warnf("bad tx ann: %v", err)
		return
	}

	txHash := ann.Hash

	ok, done := n.mp.PreFetch(txHash)
	if !ok { // it's in mempool or being fetched already
		return
	}
	defer done()

	// not in mempool, check tx index
	if n.bki.HaveTx(txHash) {
		return // we have or are currently fetching it, do nothing, assuming we have already re-announced
	}
	// we don't have it. time to fetch

	// t0 := time.Now(); log.Printf("retrieving new tx: %q", txid)

	// First try to get from this stream.
	rawTx, err := requestTx(s, []byte(getMsg))
	if err != nil {
		n.log.Warnf("announcer failed to provide %v due to error %v, trying other peers", txHash, err)
		// Since we are aware, ask other peers. we could also put this in a goroutine
		s.Close() // close the announcers stream first
		rawTx, err = n.getTxWithRetry(context.TODO(), txHash, 500*time.Millisecond, 10)
		if err != nil {
			n.log.Errorf("unable to retrieve tx %v: %v", txHash, err)
			return
		}
	}

	var tx ktypes.Transaction
	if err = tx.UnmarshalBinary(rawTx); err != nil {
		n.log.Errorf("invalid transaction received %v: %v", txHash, err)
		return
	}

	// Ensure the received transaction is the one requested by hash.
	ntx := types.NewTx(&tx) // the immutable tx for CE with Hash stored
	if txHash != ntx.Hash() {
		n.log.Errorf("tx hash mismatch: %v != %v", txHash, ntx.Hash())
		return
	}

	// n.log.Infof("obtained content for tx %q in %v", txid, time.Since(t0))

	// here we could check tx index again in case a block was mined with it
	// while we were fetching it

	ctx := context.Background()
	if err := n.ce.QueueTx(ctx, ntx); err != nil {
		n.log.Warnf("tx %v (sz %d) failed check: %v from peer: %s", txHash, len(rawTx), err, s.Conn().RemotePeer())
		return
	}

	// re-announce
	n.queueTxn(ctx, txHash, rawTx, s.Conn().RemotePeer())
}

func (n *Node) queueTxn(ctx context.Context, txID types.Hash, rawTx []byte, from peer.ID) {
	tx := orderedTxn{txID: txID, rawtx: rawTx, from: from}

	select {
	case n.txQueue <- tx:
	case <-ctx.Done():
	default:
		n.log.Warnf("tx queue full, dropping tx %v", txID)
	}
}

func (n *Node) announceRawTx(ctx context.Context, txHash types.Hash, rawTx []byte, from peer.ID) {
	peers := n.host.Network().Peers()
	if len(peers) == 0 {
		n.log.Warnf("no peers to advertise tx to")
		return
	}

	for _, peerID := range peers {
		if peerID == from {
			continue
		}
		// n.log.Infof("advertising tx %v (len %d) to peer %v", txHash, len(rawTx), peerID)
		n.advertiseTxToPeer(ctx, peerID, txHash, rawTx)
	}
}

func (n *Node) announceTx(ctx context.Context, txID types.Hash, from peer.ID) {
	// Storing nil for the raw transaction as it is already in the mempool and can be retrieved
	// when dequeued. This helps in reducing the memory footprint of the queue.
	n.queueTxn(ctx, txID, nil, from)
}

type txSendQueue struct {
	mtx    sync.Mutex
	queues map[peer.ID]*signallingQueue
	cp     *sync.Pool
}

func (n *Node) peerQueue(peerID peer.ID) (<-chan struct{}, func(), bool) {
	n.sendQueue.mtx.Lock()
	defer n.sendQueue.mtx.Unlock()
	if n.sendQueue.cp == nil {
		n.sendQueue.cp = &sync.Pool{
			New: func() any {
				return make(chan struct{}, 1)
			},
		}
	}
	q, ok := n.sendQueue.queues[peerID]
	if !ok {
		q = newSignallingQueue(nil) // n.sendQueue.cp
		if n.sendQueue.queues == nil {
			n.sendQueue.queues = make(map[peer.ID]*signallingQueue)
		}
		n.sendQueue.queues[peerID] = q
	}
	return q.tryEnqueue()
}

const txQueueCap = 4000

type signallingQueue struct {
	mtx    sync.Mutex
	active bool
	q      []chan struct{}
	// cursor int // TODO: circular buffer indexing of q
	// cap    int // commented to use global txQueueCap for now

	// a pool of channels to avoid allocations, may be shared across many queues
	cp *sync.Pool // must be *buffered* (1) chan struct{}
}

func newSignallingQueue(cp *sync.Pool) *signallingQueue {
	return &signallingQueue{
		cp: cp,
	}
}

func (sg *signallingQueue) tryEnqueue() (<-chan struct{}, func(), bool) {
	sg.mtx.Lock()
	defer sg.mtx.Unlock()

	if sg.active && len(sg.q) >= txQueueCap {
		return nil, nil, false // full, can't get in queue
	}

	if sg.cp == nil { // internal (unshared) pool, not yet initialized
		sg.cp = &sync.Pool{
			New: func() any {
				return make(chan struct{}, 1)
			},
		}
	}

	c := sg.cp.Get().(chan struct{})

	if sg.active {
		sg.q = append(sg.q, c)
	} else {
		sg.active = true
		c <- struct{}{}
	}

	return c, func() {
		// trigger the next and return this channel to the pool
		sg.mtx.Lock()
		defer sg.mtx.Unlock()
		sg.next()
		sg.cp.Put(c)
	}, true
}

func (sg *signallingQueue) next() {
	if len(sg.q) == 0 { // nothing waiting, go back to sleep
		sg.active = false
		return
	}
	// signal to the next
	c := sg.q[0]
	sg.q = sg.q[1:]
	c <- struct{}{}
	sg.active = true // should be true already, but just in case
}

// advertiseTxToPeer sends a lightweight advertisement to a connected peer.
// The stream remains open in case the peer wants to request the content right.
func (n *Node) advertiseTxToPeer(ctx context.Context, peerID peer.ID, txHash types.Hash, rawTx []byte) {
	start, done, ok := n.peerQueue(peerID) // queueing is synchronous; p2p stream is async but sequential
	if !ok {
		n.log.Warnf("peer queue full, dropping tx advertisement for %s", peers.PeerIDStringer(peerID))
		return
	}

	// Probably a better approach would be to only start the goroutines when
	// ready. This would require a master goroutine somewhere to start the
	// goroutines using the stored peer ID and tx info. It's easier for now to
	// capture the info in a closure here.

	go func() {
		select {
		case <-start:
			defer done()
		case <-ctx.Done():
			return
		}

		s, err := n.host.NewStream(ctx, peerID, ProtocolIDTxAnn)
		if err != nil {
			n.log.Warnf("failed to open stream to peer: %w", peers.CompressDialError(err))
			return
		}
		defer s.Close()

		txAnnTimeout := defaultTxAnnTimeout
		if n.blockSyncCfg != nil {
			txAnnTimeout = time.Duration(n.blockSyncCfg.TxAnnTimeout)
		}
		roundTripDeadline := time.Now().Add(txAnnTimeout)
		s.SetWriteDeadline(roundTripDeadline)

		// Send a lightweight advertisement with the object ID
		_, err = newTxHashAnn(txHash).WriteTo(s)
		if err != nil {
			n.log.Warnf("txann failed to peer %s: %w", peerID, err)
			return
		}

		mets.Advertised(ctx, string(ProtocolIDTxAnn))

		// n.log.Infof("advertised tx content %s to peer %s", txid, peerID)

		txAnnRespTimeout := defaultTxAnnRespTimeout
		if n.blockSyncCfg != nil {
			txAnnRespTimeout = time.Duration(n.blockSyncCfg.TxAnnTimeout) // Use same timeout as announcement
		}
		s.SetReadDeadline(time.Now().Add(txAnnRespTimeout))

		// wait to hear for a get request, otherwise peer will simply hang up
		req := make([]byte, len(getMsg))
		nr, err := s.Read(req)
		if err != nil && !(errors.Is(err, io.EOF) || errors.Is(err, network.ErrReset)) {
			n.log.Warn("bad get tx req", "error", err)
			return
		}
		if nr == 0 {
			mets.AdvertiseRejected(ctx, string(ProtocolIDTxAnn))
			return // they hung up, probably didn't want it
		}
		if getMsg != string(req) {
			n.log.Warnf("advertise wait: bad get tx request %q", string(req))
			return
		}

		// we could queue at this level too

		txGetTimeout := defaultTxGetTimeout
		if n.blockSyncCfg != nil {
			txGetTimeout = time.Duration(n.blockSyncCfg.TxGetTimeout)
		}
		s.SetWriteDeadline(time.Now().Add(txGetTimeout))
		s.Write(rawTx)

		mets.AdvertiseServed(ctx, string(ProtocolIDTxAnn), int64(len(rawTx)))
	}()
}

// startTxAnns handles periodic reannouncement. It can also be modified to
// regularly create dummy transactions.
func (n *Node) startTxAnns(ctx context.Context, reannouncePeriod time.Duration) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(reannouncePeriod):
			}

			func() {
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()

				// Check if it's safe to re-announce (not during block execution)
				// This prevents re-announcing transactions with nonces that will be
				// invalidated once the currently executing block commits.
				if !n.ce.CanReannounce() {
					n.log.Debug("skipping re-announcement: block execution in progress")
					return
				}

				const sendN = 200
				const sendBtsLimit = 8_000_000
				txns := n.mp.PeekN(sendN, sendBtsLimit)
				if len(txns) == 0 {
					return // from this anon func, not the goroutine!
				}
				n.log.Infof("re-announcing %d unconfirmed txns", len(txns))

				var numSent, bytesSent int64
				for _, tx := range txns {
					rawTx := tx.Bytes()
					n.queueTxn(ctx, tx.Hash(), rawTx, n.host.ID()) // response handling is async
					if ctx.Err() != nil {
						n.log.Warn("interrupting long re-broadcast")
						break
					}
					numSent++
					bytesSent += int64(len(rawTx))
				}

				mets.TxnsReannounced(ctx, numSent, bytesSent)
			}()
		}
	}()
}

// startOrderedTxQueueAnns ensures that transaction announcements are broadcasted
// in the order they are received, maintaining FIFO order for nonce consistency.
func (n *Node) startOrderedTxQueueAnns(ctx context.Context) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case txn := <-n.txQueue:
				rawTx := txn.rawtx
				if txn.rawtx == nil {
					// fetch the raw tx from the mempool
					tx := n.mp.Get(txn.txID)
					if tx == nil {
						continue // tx was removed from mempool
					}
					rawTx = tx.Bytes()
				}

				n.announceRawTx(ctx, txn.txID, rawTx, txn.from)
			}
		}
	}()
}
