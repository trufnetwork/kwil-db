package snapshotter

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"

	"github.com/trufnetwork/kwil-db/core/log"
)

const (
	DiscoverSnapshotsMsg    = "discover_snapshots"
	reqRWTimeout            = 15 * time.Second
	catalogSendTimeout      = 15 * time.Second
	defaultChunkSendTimeout = 300 * time.Second // good to match client StreamTimeout
	chunkGetTimeout         = 45 * time.Second
	snapshotGetTimeout      = 45 * time.Second

	ProtocolIDSnapshotCatalog protocol.ID = "/kwil/snapcat/1.0.0"
	ProtocolIDSnapshotChunk   protocol.ID = "/kwil/snapchunk/1.1.0"
	ProtocolIDSnapshotRange   protocol.ID = "/kwil/snaprange/1.0.0"
	ProtocolIDSnapshotMeta    protocol.ID = "/kwil/snapmeta/1.0.0"

	SnapshotCatalogNS = "snapshot-catalog" // namespace on which snapshot catalogs are advertised
)

var noData = []byte{0}

// RegisterSnapshotStreamHandlers registers the snapshot stream handlers if snapshotting is enabled.
func (s *SnapshotStore) RegisterSnapshotStreamHandlers(ctx context.Context, host host.Host, discovery discovery.Discovery) {
	if s == nil || s.cfg == nil || !s.cfg.Enable {
		// return if snapshotting is disabled
		return
	}

	// Register snapshot stream handlers
	host.SetStreamHandler(ProtocolIDSnapshotCatalog, s.snapshotCatalogRequestHandler)
	host.SetStreamHandler(ProtocolIDSnapshotChunk, s.snapshotChunkRequestHandler)
	host.SetStreamHandler(ProtocolIDSnapshotRange, s.snapshotChunkRangeRequestHandler)
	host.SetStreamHandler(ProtocolIDSnapshotMeta, s.snapshotMetadataRequestHandler)

	// Advertise the snapshotcatalog service if snapshots are enabled
	// umm, but gotcha, if a node has previous snapshots but snapshots are disabled, these snapshots will be unusable.
	util.Advertise(ctx, discovery, SnapshotCatalogNS)
}

// SnapshotCatalogRequestHandler handles the incoming snapshot catalog requests.
// It sends the list of metadata of all the snapshots that are available with the node.
func (s *SnapshotStore) snapshotCatalogRequestHandler(stream network.Stream) {
	// read request
	// send snapshot catalogs
	defer stream.Close()

	stream.SetReadDeadline(time.Now().Add(time.Second))

	req := make([]byte, len(DiscoverSnapshotsMsg))
	if _, err := io.ReadFull(stream, req); err != nil {
		s.log.Warn("failed to read discover snapshots request", "error", err)
		return
	}

	if string(req) != DiscoverSnapshotsMsg {
		s.log.Warn("invalid discover snapshots request")
		return
	}

	snapshots := s.ListSnapshots()
	if snapshots == nil {
		// nothing to send
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}

	// send the snapshot catalogs
	catalogs := make([]*SnapshotMetadata, len(snapshots))
	for i, snap := range snapshots {
		catalogs[i] = &SnapshotMetadata{
			Height:      snap.Height,
			Format:      snap.Format,
			Chunks:      snap.ChunkCount,
			Hash:        snap.SnapshotHash,
			Size:        snap.SnapshotSize,
			ChunkHashes: make([][32]byte, snap.ChunkCount),
		}

		for j, chunk := range snap.ChunkHashes {
			copy(catalogs[i].ChunkHashes[j][:], chunk[:])
		}
	}

	encoder := json.NewEncoder(stream)
	stream.SetWriteDeadline(time.Now().Add(catalogSendTimeout))
	if err := encoder.Encode(catalogs); err != nil {
		s.log.Warn("failed to send snapshot catalogs", "error", err)
		return
	}

	s.log.Info("sent snapshot catalogs to remote peer", "peer", stream.Conn().RemotePeer(), "num_snapshots", len(catalogs))
}

// SnapshotChunkRequestHandler handles the incoming snapshot chunk requests.
func (s *SnapshotStore) snapshotChunkRequestHandler(stream network.Stream) {
	// read request
	// send snapshot chunk
	defer stream.Close()

	startTime := time.Now()
	peerID := stream.Conn().RemotePeer().String()

	stream.SetReadDeadline(time.Now().Add(chunkGetTimeout))
	var req SnapshotChunkReq
	if _, err := req.ReadFrom(stream); err != nil {
		s.log.Warn("failed to read snapshot chunk request", "error", err, "peer", peerID)
		return
	}

	s.log.Info("starting chunk transmission", "chunk", req.Index, "height", req.Height,
		"peer", peerID, "start_time", startTime.Format(time.RFC3339Nano))

	// get the snapshot chunk file path for streaming
	chunkFile, err := s.GetSnapshotChunkFile(req.Height, req.Format, req.Index)
	if err != nil {
		s.log.Warn("failed to get chunk file", "error", err, "chunk", req.Index, "peer", peerID)
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}

	// open the chunk file for streaming
	file, err := os.Open(chunkFile)
	if err != nil {
		s.log.Warn("failed to open chunk file", "error", err, "chunk", req.Index, "peer", peerID)
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}
	defer file.Close()

	// get file size for logging
	fileInfo, err := file.Stat()
	if err != nil {
		s.log.Warn("failed to stat chunk file", "error", err, "chunk", req.Index, "peer", peerID)
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}
	fileSize := fileInfo.Size()

	// set write deadline for the entire transmission
	stream.SetWriteDeadline(time.Now().Add(s.getChunkSendTimeout()))

	// create buffered writer for better network efficiency
	bufWriter := bufio.NewWriterSize(stream, 64*1024) // 64KB buffer

	// create progress writer for monitoring
	progressWriter := &progressWriter{
		writer:      bufWriter,
		logger:      s.log,
		chunk:       req.Index,
		peer:        peerID,
		startTime:   startTime,
		lastLogTime: startTime,
	}

	// stream the chunk data
	copyStartTime := time.Now()
	bytesWritten, err := io.Copy(progressWriter, file)
	copyDuration := time.Since(copyStartTime)

	if err != nil {
		s.log.Warn("failed to stream chunk data", "error", err, "chunk", req.Index,
			"peer", peerID, "bytes_written", bytesWritten, "file_size", fileSize,
			"copy_duration", copyDuration, "total_duration", time.Since(startTime))
		return
	}

	// flush the buffer
	if err := bufWriter.Flush(); err != nil {
		s.log.Warn("failed to flush chunk data", "error", err, "chunk", req.Index, "peer", peerID)
		return
	}

	totalDuration := time.Since(startTime)
	rate := float64(bytesWritten) / totalDuration.Seconds() / 1024 // KB/s

	s.log.Info("successfully sent snapshot chunk", "chunk", req.Index, "height", req.Height,
		"peer", peerID, "bytes_sent", bytesWritten, "file_size", fileSize,
		"copy_duration", copyDuration, "total_duration", totalDuration, "rate_kbps", rate)
}

// SnapshotChunkRangeRequestHandler handles range-based chunk requests for resumable downloads
func (s *SnapshotStore) snapshotChunkRangeRequestHandler(stream network.Stream) {
	defer stream.Close()

	startTime := time.Now()
	peerID := stream.Conn().RemotePeer().String()

	stream.SetReadDeadline(time.Now().Add(chunkGetTimeout))
	var req SnapshotChunkRangeReq
	if _, err := req.ReadFrom(stream); err != nil {
		s.log.Warn("failed to read snapshot chunk range request", "error", err, "peer", peerID)
		return
	}

	s.log.Info("starting range chunk transmission", "chunk", req.Index, "height", req.Height,
		"offset", req.Offset, "length", req.Length, "peer", peerID, "start_time", startTime.Format(time.RFC3339Nano),
		"is_resume", req.Offset > 0)

	// get the snapshot chunk file path for streaming
	chunkFile, err := s.GetSnapshotChunkFile(req.Height, req.Format, req.Index)
	if err != nil {
		s.log.Warn("failed to get chunk file", "error", err, "chunk", req.Index, "peer", peerID)
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}

	// open the chunk file for streaming
	file, err := os.Open(chunkFile)
	if err != nil {
		s.log.Warn("failed to open chunk file", "error", err, "chunk", req.Index, "peer", peerID)
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}
	defer file.Close()

	// get file size for validation
	fileInfo, err := file.Stat()
	if err != nil {
		s.log.Warn("failed to stat chunk file", "error", err, "chunk", req.Index, "peer", peerID)
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}
	fileSize := fileInfo.Size()

	// Validate range request
	if req.Offset >= uint64(fileSize) {
		s.log.Warn("invalid range request: offset beyond file size", "chunk", req.Index,
			"offset", req.Offset, "file_size", fileSize, "peer", peerID)
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}

	// Seek to the requested offset
	if _, err := file.Seek(int64(req.Offset), io.SeekStart); err != nil {
		s.log.Warn("failed to seek to offset", "error", err, "chunk", req.Index,
			"offset", req.Offset, "peer", peerID)
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}

	// Calculate actual length to read
	remainingBytes := uint64(fileSize) - req.Offset
	lengthToRead := req.Length
	if req.Length == 0 || req.Length > remainingBytes {
		lengthToRead = remainingBytes
	}

	// set write deadline for the entire transmission
	stream.SetWriteDeadline(time.Now().Add(s.getChunkSendTimeout()))

	// create buffered writer for better network efficiency
	bufWriter := bufio.NewWriterSize(stream, 64*1024) // 64KB buffer

	// create progress writer for monitoring
	progressWriter := &progressWriter{
		writer:      bufWriter,
		logger:      s.log,
		chunk:       req.Index,
		peer:        peerID,
		startTime:   startTime,
		lastLogTime: startTime,
	}

	// stream the chunk data with limited reader
	limitedReader := io.LimitReader(file, int64(lengthToRead))
	copyStartTime := time.Now()
	bytesWritten, err := io.Copy(progressWriter, limitedReader)
	copyDuration := time.Since(copyStartTime)

	if err != nil {
		s.log.Warn("failed to stream range chunk data", "error", err, "chunk", req.Index,
			"peer", peerID, "bytes_written", bytesWritten, "requested_length", lengthToRead,
			"copy_duration", copyDuration, "total_duration", time.Since(startTime))
		return
	}

	// flush the buffer
	if err := bufWriter.Flush(); err != nil {
		s.log.Warn("failed to flush range chunk data", "error", err, "chunk", req.Index, "peer", peerID)
		return
	}

	totalDuration := time.Since(startTime)
	rate := float64(bytesWritten) / totalDuration.Seconds() / 1024 // KB/s

	s.log.Info("successfully sent snapshot chunk range", "chunk", req.Index, "height", req.Height,
		"peer", peerID, "offset", req.Offset, "bytes_sent", bytesWritten, "requested_length", lengthToRead,
		"copy_duration", copyDuration, "total_duration", totalDuration, "rate_kbps", rate, "is_resume", req.Offset > 0)
}

// SnapshotMetadataRequestHandler handles the incoming snapshot metadata request and
// sends the snapshot metadata at the requested height.
func (s *SnapshotStore) snapshotMetadataRequestHandler(stream network.Stream) {
	// read request
	// send snapshot chunk
	defer stream.Close()

	stream.SetReadDeadline(time.Now().Add(chunkGetTimeout))
	var req SnapshotReq
	if _, err := req.ReadFrom(stream); err != nil {
		s.log.Warn("failed to read snapshot request", "error", err)
		return
	}

	// read the snapshot chunk from the store
	snap := s.GetSnapshot(req.Height, req.Format)
	if snap == nil {
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}

	meta := &SnapshotMetadata{
		Height:      snap.Height,
		Format:      snap.Format,
		Chunks:      snap.ChunkCount,
		Hash:        snap.SnapshotHash,
		ChunkHashes: make([][32]byte, snap.ChunkCount),
		Size:        snap.SnapshotSize,
	}
	for i, chunk := range snap.ChunkHashes {
		copy(meta.ChunkHashes[i][:], chunk[:])
	}

	// get the app hash from the db
	_, _, ci, err := s.blockStore.GetByHeight(int64(snap.Height))
	if err != nil || ci == nil {
		s.log.Warn("failed to get app hash", "height", snap.Height, "error", err)
		stream.SetWriteDeadline(time.Now().Add(reqRWTimeout))
		stream.Write(noData)
		return
	}
	meta.AppHash = ci.AppHash[:]

	// send the snapshot data
	encoder := json.NewEncoder(stream)

	stream.SetWriteDeadline(time.Now().Add(s.getChunkSendTimeout()))
	if err := encoder.Encode(meta); err != nil {
		s.log.Warn("failed to send snapshot metadata", "error", err)
		return
	}

	s.log.Info("sent snapshot metadata to remote peer", "peer", stream.Conn().RemotePeer(), "height", req.Height, "format", req.Format, "appHash", ci.AppHash.String())
}

// getChunkSendTimeout returns the configured chunk send timeout or default
// Timeout should match client's StreamTimeout to prevent asymmetric disconnections
func (s *SnapshotStore) getChunkSendTimeout() time.Duration {
	if s.cfg.ChunkSendTimeout > 0 {
		return s.cfg.ChunkSendTimeout
	}
	return defaultChunkSendTimeout
}

// progressWriter wraps a writer to log transmission progress
type progressWriter struct {
	writer      io.Writer
	logger      log.Logger
	chunk       uint32
	peer        string
	startTime   time.Time
	lastLogTime time.Time
	totalBytes  int64
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.writer.Write(p)
	pw.totalBytes += int64(n)

	now := time.Now()
	// Log progress every 10 seconds to balance observability with log volume
	// Large chunks can take minutes to transfer, so users need progress feedback
	if now.Sub(pw.lastLogTime) >= 10*time.Second {
		elapsed := now.Sub(pw.startTime)
		rate := float64(pw.totalBytes) / elapsed.Seconds() / 1024 // KB/s
		pw.logger.Info("chunk transmission progress",
			"chunk", pw.chunk,
			"peer", pw.peer,
			"bytes_sent", pw.totalBytes,
			"elapsed", elapsed,
			"rate_kbps", rate)
		pw.lastLogTime = now
	}

	return n, err
}
