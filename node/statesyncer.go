// StateSyncService is responsible for discovering and syncing snapshots from peers in the network.
// It utilizes libp2p for peer discovery and communication.

package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/kwilteam/kwil-db/config"
	"github.com/kwilteam/kwil-db/core/log"
	"github.com/kwilteam/kwil-db/node/meta"
	"github.com/kwilteam/kwil-db/node/peers"
	"github.com/kwilteam/kwil-db/node/snapshotter"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

var (
	ErrNoSnapshotsDiscovered = errors.New("no snapshots discovered")
)

// DiscoverSnapshots discovers snapshot providers and their catalogs. It waits for responsesp
// from snapshot catalog providers for the duration of the discoveryTimeout. If the timeout is reached,
// the best snapshot is selected and snapshot chunks are requested. If no snapshots are discovered,
// it reenters the discovery phase after a delay, retrying up to maxRetries times. If discovery fails
// after maxRetries, the node will switch to block sync.
// If snapshots and their chunks are successfully fetched, the DB is restored from the snapshot and the
// application state is verified.
func (s *StateSyncService) DiscoverSnapshots(ctx context.Context) (int64, error) {
	retry := uint64(0)
	for {
		if retry > s.cfg.MaxRetries {
			s.log.Warn("Failed to discover snapshots", "retries", retry)
			return -1, nil
		}

		s.log.Info("Discovering snapshots...")
		peers, err := discoverProviders(ctx, snapshotCatalogNS, s.discoverer) // TODO: set appropriate limit
		if err != nil {
			return -1, err
		}
		peers = filterLocalPeer(peers, s.host.ID())
		s.snapshotPool.updatePeers(peers)

		// discover snapshot catalogs from the discovered peers for the duration of the discoveryTimeout
		for _, p := range peers {
			go func(peer peer.AddrInfo) {
				if err := s.requestSnapshotCatalogs(ctx, peer); err != nil {
					s.log.Warn("failed to request snapshot catalogs from peer %s: %v", peer.ID, err)
				}
			}(p)
		}

		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-time.After(time.Duration(s.cfg.DiscoveryTimeout)):
			synced, snap, err := s.downloadSnapshot(ctx)
			if err != nil {
				return -1, err
			}

			if synced {
				// RestoreDB from the snapshot
				if err := s.restoreDB(ctx, snap); err != nil {
					s.log.Warn("failed to restore DB from snapshot", "error", err)
					return -1, err
				}

				// ensure that the apphash matches
				err := s.verifyState(ctx, snap)
				if err != nil {
					s.log.Warn("failed to verify state after DB restore", "error", err)
					return -1, err
				}

				return int64(snap.Height), nil
			}
			retry++
		}
	}
}

// downloadSnapshot selects the best snapshot and verifies the snapshot contents with the trusted providers.
// If the snapshot is valid, it fetches the snapshot chunks from the providers.
// If a snapshot is deemed invalid by any of the trusted providers, it is blacklisted and the next best snapshot is selected.
func (s *StateSyncService) downloadSnapshot(ctx context.Context) (synced bool, snap *snapshotMetadata, err error) {
	for {
		// select the best snapshot and request chunks
		bestSnapshot, err := s.bestSnapshot()
		if err != nil {
			if err == ErrNoSnapshotsDiscovered {
				return false, nil, nil // reenter discovery phase
			}
			return false, nil, err
		}

		s.log.Info("Requesting contents of the snapshot", "height", bestSnapshot.Height, "hash", hex.EncodeToString(bestSnapshot.Hash))

		// Verify the correctness of the snapshot with the trusted providers
		// and request the providers for the appHash at the snapshot height
		valid, appHash := s.VerifySnapshot(ctx, bestSnapshot)
		if !valid {
			// invalid snapshots are blacklisted
			s.snapshotPool.blacklistSnapshot(bestSnapshot)
			continue
		}
		bestSnapshot.AppHash = appHash

		// fetch snapshot chunks
		if err := s.chunkFetcher(ctx, bestSnapshot); err != nil {
			// remove the chunks and retry
			os.RemoveAll(s.snapshotDir)
			os.MkdirAll(s.snapshotDir, 0755)
			continue
		}

		// retrieved all chunks successfully
		return true, bestSnapshot, nil
	}
}

// chunkFetcher fetches snapshot chunks from the snapshot providers
// It returns if any of the chunk fetches fail
func (s *StateSyncService) chunkFetcher(ctx context.Context, snapshot *snapshotMetadata) error {
	// fetch snapshot chunks and write them to the snapshot directory
	var wg sync.WaitGroup
	// errCh := make(chan error, snapshot.Chunks)

	key := snapshot.Key()
	providers := s.snapshotPool.keyProviders(key)
	if len(providers) == 0 {
		providers = append(providers, s.snapshotPool.getPeers()...)
	}

	const chunkFetchers = 10 // limit the number of concurrent chunk fetches

	errChan := make(chan error, snapshot.Chunks)
	tasks := make(chan uint32, snapshot.Chunks) // channel to send tasks to chunk fetchers

	chunkCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// start chunk fetchers
	for range chunkFetchers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for chunkIdx := range tasks {
				success := false
				for _, provider := range providers {
					select {
					case <-chunkCtx.Done():
						// Exit early if the context is cancelled
						return
					default:
					}
					if err := s.requestSnapshotChunk(chunkCtx, snapshot, provider, chunkIdx); err != nil {
						s.log.Warn("failed to request snapshot chunk %d from peer %s: %v", chunkIdx, provider.ID, err)
						continue
					}
					// successfully fetched the chunk
					s.log.Info("Received snapshot chunk", "height", snapshot.Height, "index", chunkIdx, "provider", provider.ID)
					success = true
					break // Move to next chunk after successful fetch
				}

				if success {
					continue // Move to next chunk after successful fetch
				}

				// failed to fetch the chunk from all providers
				select {
				case errChan <- fmt.Errorf("failed to fetch snapshot chunk index %d", chunkIdx):
					cancel()
					// Exit early if the context is cancelled
					return
				default:
				}
			}
		}()
	}

	// send chunk indexes to chunk fetchers
	for chunk := range snapshot.Chunks {
		tasks <- chunk
	}
	close(tasks) // close the tasks channel to signal the end of chunks to fetch

	wg.Wait()

	// check if any of the chunk fetches failed
	select {
	case err := <-errChan:
		return err
	default:
		return nil
	}
}

// requestSnapshotChunk requests a snapshot chunk from a specified provider.
// The chunk is written to <chunk-idx.sql.gz> file in the snapshot directory.
// This also ensures that the hash of the received chunk matches the expected hash
func (s *StateSyncService) requestSnapshotChunk(ctx context.Context, snap *snapshotMetadata, provider peer.AddrInfo, index uint32) error {
	stream, err := s.host.NewStream(ctx, provider.ID, snapshotter.ProtocolIDSnapshotChunk)
	if err != nil {
		s.log.Warn("failed to create stream to provider", "provider", provider.ID.String(),
			"error", peers.CompressDialError(err))
		return err
	}
	defer stream.Close()

	// Create the request for the snapshot chunk
	req := snapshotChunkReq{
		Height: snap.Height,
		Format: snap.Format,
		Index:  index,
		Hash:   snap.ChunkHashes[index],
	}
	reqBts, err := req.MarshalBinary()
	if err != nil {
		s.log.Warn("failed to marshal snapshot chunk request", "error", err)
		return err
	}

	// Send the request
	stream.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.ChunkTimeout)))
	if _, err := stream.Write(reqBts); err != nil {
		s.log.Warn("failed to send snapshot chunk request", "error", err)
		return err
	}

	// Read the response to temporary file first
	chunkFile := filepath.Join(s.snapshotDir, fmt.Sprintf("chunk-%d.sql.gz", index))
	tempFile := chunkFile + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create temp chunk file: %w", err)
	}
	defer func() {
		file.Close()
		// Clean up temp file if we don't rename it
		if _, err := os.Stat(tempFile); err == nil {
			os.Remove(tempFile)
		}
	}()

	stream.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.ChunkTimeout)))
	hasher := sha256.New()
	writer := io.MultiWriter(file, hasher)
	if _, err := io.Copy(writer, stream); err != nil {
		return fmt.Errorf("failed to read snapshot chunk: %w", err)
	}

	// Get file size for validation
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get chunk file info: %w", err)
	}
	actualSize := fileInfo.Size()

	// Size validation - quick check before expensive hash validation
	// Note: We need to add expected size to chunk metadata in the future
	// For now, we can at least check if the file is suspiciously small
	if actualSize < 1024 { // Less than 1KB is definitely wrong for these chunks
		return fmt.Errorf("chunk too small: got %d bytes, minimum expected 1KB", actualSize)
	}

	hash := hasher.Sum(nil)
	if !bytes.Equal(hash, snap.ChunkHashes[index][:]) {
		return fmt.Errorf("chunk hash mismatch: expected %x, got %x (size: %d bytes)", snap.ChunkHashes[index][:], hash, actualSize)
	}

	// All validations passed - atomically move temp file to final location
	file.Close() // Close before rename
	if err := os.Rename(tempFile, chunkFile); err != nil {
		return fmt.Errorf("failed to finalize chunk file: %w", err)
	}

	s.log.Debug("Chunk validation passed", "index", index, "size", actualSize, "hash", fmt.Sprintf("%x", hash[:8]))
	return nil
}

// requestSnapshotCatalogs requests the available snapshots from a peer.
func (s *StateSyncService) requestSnapshotCatalogs(ctx context.Context, peer peer.AddrInfo) error {
	// request snapshot catalogs from the discovered peer
	s.host.Peerstore().AddAddrs(peer.ID, peer.Addrs, peerstore.PermanentAddrTTL)
	stream, err := s.host.NewStream(ctx, peer.ID, snapshotter.ProtocolIDSnapshotCatalog)
	if err != nil {
		return peers.CompressDialError(err)
	}
	defer stream.Close()

	stream.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.CatalogTimeout)))
	if _, err := stream.Write([]byte(discoverSnapshotsMsg)); err != nil {
		return fmt.Errorf("failed to send discover snapshot catalog request: %w", err)
	}

	// read catalogs from the stream
	snapshots := make([]*snapshotMetadata, 0)
	stream.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.CatalogTimeout)))
	if err := json.NewDecoder(stream).Decode(&snapshots); err != nil {
		return fmt.Errorf("failed to read snapshot catalogs: %w", err)
	}

	// add the snapshots to the pool
	s.snapshotPool.mtx.Lock()
	defer s.snapshotPool.mtx.Unlock()
	for _, snap := range snapshots {
		key := snap.Key()
		s.snapshotPool.snapshots[key] = snap
		s.snapshotPool.providers[key] = append(s.snapshotPool.providers[key], peer)
		s.log.Info("Discovered snapshot", "height", snap.Height, "snapshotHash", snap.Hash, "provider", peer.ID)
	}

	return nil
}

// bestSnapshot returns the latest snapshot from the discovered snapshots.
func (s *StateSyncService) bestSnapshot() (*snapshotMetadata, error) {
	s.snapshotPool.mtx.Lock()
	defer s.snapshotPool.mtx.Unlock()

	// select the best snapshot
	var best *snapshotMetadata
	for _, snap := range s.snapshotPool.snapshots {
		if best == nil || snap.Height > best.Height {
			best = snap
		}
	}

	if best == nil {
		return nil, ErrNoSnapshotsDiscovered
	}

	return best, nil
}

// VerifySnapshot verifies the final state of the application after the DB is restored from the snapshot.
func (s *StateSyncService) verifyState(ctx context.Context, snapshot *snapshotMetadata) error {
	tx, err := s.db.BeginReadTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	height, appHash, _, _ := meta.GetChainState(ctx, tx)
	if uint64(height) != snapshot.Height {
		return fmt.Errorf("height mismatch after DB restore: expected %d, actual %d", snapshot.Height, height)
	}
	if !bytes.Equal(appHash[:], snapshot.AppHash[:]) {
		return fmt.Errorf("apphash mismatch after DB restore: expected %x, actual %x", snapshot.AppHash, appHash)
	}

	return nil
}

// RestoreDB restores the database from the logical sql dump using psql command
// It also validates the snapshot hash, before restoring the database
func (s *StateSyncService) restoreDB(ctx context.Context, snapshot *snapshotMetadata) error {
	streamer := NewStreamer(snapshot.Chunks, s.snapshotDir, s.log)
	defer streamer.Close()

	reader, err := gzip.NewReader(streamer)
	if err != nil {
		return err
	}

	return RestoreDB(ctx, reader, s.dbConfig, snapshot.Hash, s.log)
}

func RestoreDB(ctx context.Context, reader io.Reader, db config.DBConfig, snapshotHash []byte, logger log.Logger) error {

	// unzip and stream the sql dump to psql
	cmd := exec.CommandContext(ctx,
		"psql",
		"--username", db.User,
		"--host", db.Host,
		"--port", db.Port,
		"--dbname", db.DBName,
		"--no-password",
	)
	if db.Pass != "" {
		cmd.Env = append(os.Environ(), "PGPASSWORD="+db.Pass)
	}

	// cmd.Stdout = &stderr
	stdinPipe, err := cmd.StdinPipe() // stdin for psql command
	if err != nil {
		return err
	}
	defer stdinPipe.Close()

	logger.Info("Restore DB: ", "command", cmd.String())

	if err := cmd.Start(); err != nil {
		return err
	}

	// decompress the chunk streams and stream the sql dump to psql stdinPipe
	if err := decompressAndValidateSnapshotHash(stdinPipe, reader, snapshotHash); err != nil {
		return err
	}
	stdinPipe.Close() // signifies the end of the input stream to the psql command

	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

// decompressAndValidateChunkStreams decompresses the chunk streams and validates the snapshot hash
func decompressAndValidateSnapshotHash(output io.Writer, reader io.Reader, snapshotHash []byte) error {
	hasher := sha256.New()
	_, err := io.Copy(io.MultiWriter(output, hasher), reader)
	if err != nil {
		return fmt.Errorf("failed to decompress chunk streams: %w", err)
	}
	hash := hasher.Sum(nil)

	// Validate the hash of the decompressed chunks
	if !bytes.Equal(hash, snapshotHash) {
		return fmt.Errorf("invalid snapshot hash %x, expected %x", hash, snapshotHash)
	}
	return nil
}

// Utility to stream chunks of a snapshot
type Streamer struct {
	log               log.Logger
	numChunks         uint32
	files             []string
	currentChunk      *os.File
	currentChunkIndex uint32
}

func NewStreamer(numChunks uint32, chunkDir string, logger log.Logger) *Streamer {
	files := make([]string, numChunks)
	for i := range numChunks {
		file := filepath.Join(chunkDir, fmt.Sprintf("chunk-%d.sql.gz", i))
		files[i] = file
	}

	return &Streamer{
		log:       logger,
		numChunks: numChunks,
		files:     files,
	}
}

// Next opens the next chunk file for streaming
func (s *Streamer) Next() error {
	if s.currentChunk != nil {
		s.currentChunk.Close()
	}

	if s.currentChunkIndex >= s.numChunks {
		return io.EOF // no more chunks to stream
	}

	file, err := os.Open(s.files[s.currentChunkIndex])
	if err != nil {
		return fmt.Errorf("failed to open chunk file %s (chunk %d of %d): %w",
			s.files[s.currentChunkIndex], s.currentChunkIndex, s.numChunks, err)
	}

	s.currentChunk = file
	s.currentChunkIndex++

	return nil
}

func (s *Streamer) Close() error {
	if s.currentChunk != nil {
		s.currentChunk.Close()
	}

	return nil
}

// Read reads from the current chunk file
// If the current chunk is exhausted, it opens the next chunk file
// until all chunks are read
func (s *Streamer) Read(p []byte) (n int, err error) {
	if s.currentChunk == nil {
		if err := s.Next(); err != nil {
			return 0, err
		}
	}

	n, err = s.currentChunk.Read(p)
	if err == io.EOF {
		err = s.currentChunk.Close()
		s.currentChunk = nil
		if s.currentChunkIndex < s.numChunks {
			return s.Read(p)
		}
	}
	return n, err
}

// filterLocalPeer filters the local peer from the list of peers
func filterLocalPeer(peers []peer.AddrInfo, localID peer.ID) []peer.AddrInfo {
	var filteredPeers []peer.AddrInfo
	for _, p := range peers {
		if p.ID != localID {
			filteredPeers = append(filteredPeers, p)
		}
	}
	return filteredPeers
}
