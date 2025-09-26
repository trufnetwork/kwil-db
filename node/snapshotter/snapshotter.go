package snapshotter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	"golang.org/x/sync/errgroup"
)

const (
	chunkSize int64 = 16e6 - 4096 // 16 MB

	DefaultSnapshotFormat = 0

	defaultCopySorterBuffer = 256 << 20
	maxOpenRunFiles         = 64

	CreateSchema   = "CREATE SCHEMA"
	CreateTable    = "CREATE TABLE"
	CreateFunction = "CREATE FUNCTION"
)

// This file deals with creating a snapshot instance at a given snapshotID.
// The whole process occurs in multiple stages:
// STAGE1: Streaming pg_dump output to obtain the database state at the snapshot boundary
// STAGE2: Sanitizing the dump stream to make it deterministic
//   - Removing white spaces, comments and SET and SELECT statements
//   - Sorting the COPY blocks of data based on the hash of the row-data
// STAGE3: Compressing the sanitized stream with deterministic gzip headers
// STAGE4: Splitting the compressed stream into chunks of fixed size (16MB)

type NamespaceManager interface {
	ListPostgresSchemasToDump() []string
}

type Snapshotter struct {
	dbConfig     *config.DBConfig
	snapshotDir  string
	namespaceMgr NamespaceManager
	log          log.Logger
}

type contextReader struct {
	ctx    context.Context
	Reader io.Reader
}

// contextReader aborts ongoing reads as soon as the context is cancelled. It
// lets downstream errors propagate upstream immediately instead of waiting for
// explicit cancellation checks between copy operations.
func (cr *contextReader) Read(p []byte) (int, error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := cr.Reader.Read(p)
	if err == nil {
		if errCtx := cr.ctx.Err(); errCtx != nil {
			return 0, errCtx
		}
	}
	return n, err
}

func NewSnapshotter(cfg *config.DBConfig, dir string, namespaceMgr NamespaceManager, logger log.Logger) *Snapshotter {
	return &Snapshotter{
		dbConfig:     cfg,
		snapshotDir:  dir,
		namespaceMgr: namespaceMgr,
		log:          logger,
	}
}

// CreateSnapshot orchestrates pg_dump, sanitisation, compression, and chunking
// through a streaming pipeline. The pipeline exists specifically to avoid the
// huge I/O spikes caused by materialising intermediate stage files in older
// versions. By wiring the stages with pipes we cap disk usage to the final
// chunk artefacts and surface errors as soon as a downstream stage fails.
func (s *Snapshotter) CreateSnapshot(ctx context.Context, height uint64, snapshotID string, schemas, excludeTables []string, excludeTableData []string) (*Snapshot, error) {
	// create snapshot directory
	snapshotDir := snapshotHeightDir(s.snapshotDir, height)
	formatDir := snapshotFormatDir(s.snapshotDir, height, DefaultSnapshotFormat)
	chunkDir := snapshotChunkDir(s.snapshotDir, height, DefaultSnapshotFormat)
	err := os.MkdirAll(chunkDir, 0755)
	if err != nil {
		return nil, err
	}

	// Stage1: Stream the database snapshot via pg_dump
	dumpReader, waitDump, err := s.dbSnapshotStream(ctx, height, DefaultSnapshotFormat, snapshotID, schemas, excludeTables, excludeTableData)
	if err != nil {
		os.RemoveAll(snapshotDir)
		return nil, err
	}

	sanitizedReader, sanitizedWriter := io.Pipe()
	compressedReader, compressedWriter := io.Pipe()
	hashCh := make(chan []byte, 1)

	var snapshot *Snapshot
	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		defer sanitizedWriter.Close()
		defer close(hashCh)

		hash, err := s.sanitizeDumpStream(groupCtx, height, DefaultSnapshotFormat, formatDir, dumpReader, sanitizedWriter)
		dumpReader.Close()
		if err != nil {
			sanitizedWriter.CloseWithError(err)
			_ = waitDump()
			return err
		}

		if err := waitDump(); err != nil {
			sanitizedWriter.CloseWithError(err)
			return err
		}

		hashCh <- hash
		return nil
	})

	group.Go(func() error {
		defer compressedWriter.Close()
		if err := compressStream(groupCtx, sanitizedReader, compressedWriter); err != nil {
			compressedWriter.CloseWithError(err)
			return err
		}
		return nil
	})

	group.Go(func() error {
		var err error
		snapshot, err = s.splitStreamIntoChunks(groupCtx, height, DefaultSnapshotFormat, compressedReader, hashCh)
		return err
	})

	if err := group.Wait(); err != nil {
		sanitizedReader.CloseWithError(err)
		compressedReader.CloseWithError(err)
		os.RemoveAll(snapshotDir)
		return nil, err
	}

	compressedReader.Close()
	sanitizedReader.Close()

	return snapshot, nil
}

// dbSnapshotStream runs pg_dump and returns a reader for its stdout along with a function
// that must be invoked to wait for the command to finish.
// dbSnapshotStream launches pg_dump configured for deterministic output. It
// returns a reader for pg_dump's stdout plus a wait function so callers can
// observe pg_dump failures. The flag set mirrors the legacy implementation
// (notably --no-unlogged-table-data) so streamed snapshots stay byte-compatible
// with older ones.
func (s *Snapshotter) dbSnapshotStream(ctx context.Context, height uint64, format uint32, snapshotID string, internalSchemas, excludeTables []string, excludeTableData []string) (io.ReadCloser, func() error, error) {
	args := []string{
		"--format", "plain",
		"--dbname", s.dbConfig.DBName,
		"-U", s.dbConfig.User,
		"-h", s.dbConfig.Host,
		"-p", s.dbConfig.Port,
		"--no-password",
		"--snapshot", snapshotID,
		"--no-unlogged-table-data",
		"--no-comments",
		"--create",
		"--no-publications",
		"--no-tablespaces",
		"--no-table-access-method",
		"--no-security-labels",
		"--no-subscriptions",
		"--large-objects",
		"--no-owner",
	}

	pgSchemas := s.namespaceMgr.ListPostgresSchemasToDump()

	for _, schema := range pgSchemas {
		args = append(args, "--schema", schema)
	}

	// Schemas to include in the snapshot
	for _, schema := range internalSchemas {
		args = append(args, "--schema", schema)
	}

	// Tables to exclude from the snapshot
	for _, table := range excludeTables {
		args = append(args, "-T", table)
	}

	// Tables for which defintions should be included but not the data
	for _, table := range excludeTableData {
		args = append(args, "--exclude-table-data", table)
	}

	pgDumpCmd := exec.CommandContext(ctx, "pg_dump", args...)
	stderrBuf := &bytes.Buffer{}
	pgDumpCmd.Stderr = stderrBuf

	stdout, err := pgDumpCmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get pg_dump stdout: %w", err)
	}

	if s.dbConfig.Pass != "" {
		pgDumpCmd.Env = append(pgDumpCmd.Env, "PGPASSWORD="+s.dbConfig.Pass)
	}

	s.log.Info("Executing pg_dump", "cmd", pgDumpCmd.String())

	if err := pgDumpCmd.Start(); err != nil {
		stdout.Close()
		return nil, nil, fmt.Errorf("failed to start pg_dump: %w, stderr: %s", err, stderrBuf.String())
	}

	waitFn := func() error {
		if err := pgDumpCmd.Wait(); err != nil {
			return fmt.Errorf("failed to execute pg_dump: %w, stderr: %s", err, stderrBuf.String())
		}
		s.log.Info("pg_dump successful", "height", height)
		return nil
	}

	return stdout, waitFn, nil
}

// sanitizeDumpStream normalises the pg_dump stream and sorts COPY rows in a
// deterministic order. The heavy lifting lives in copyBlockSorter which spills
// large COPY blocks to disk and merges them sequentially so we never re-seek
// the original dump. That choice removes the random-I/O hotspot that previously
// made sanitisation drag on for hours.
func (s *Snapshotter) sanitizeDumpStream(ctx context.Context, height uint64, format uint32, tempDir string, r io.Reader, w io.Writer) ([]byte, error) {
	reader := bufio.NewReader(r)
	rowHasher := sha256.New()
	bufWriter := bufio.NewWriter(io.MultiWriter(w, rowHasher))

	var inCopyBlock, schemaStarted bool
	sorter := newCopyBlockSorter(tempDir, defaultCopySorterBuffer)
	defer sorter.Reset()

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read line {%s} from pg dump stream: %w", line, err)
		}

		trimLine := strings.TrimSpace(line)

		if inCopyBlock {
			if trimLine == `\.` {
				inCopyBlock = false

				if err := sorter.Flush(bufWriter); err != nil {
					return nil, err
				}

				if _, err = bufWriter.WriteString(line); err != nil {
					return nil, fmt.Errorf("failed to write end of COPY block: %w", err)
				}
			} else {
				if err := sorter.AddLine([]byte(line)); err != nil {
					return nil, err
				}
			}
		} else {
			if line == "" || trimLine == "" {
				continue
			} else if strings.HasPrefix(trimLine, "--") {
				continue
			} else if !schemaStarted && (strings.HasPrefix(trimLine, CreateSchema) ||
				strings.HasPrefix(trimLine, CreateTable) || strings.HasPrefix(trimLine, CreateFunction)) {
				schemaStarted = true
				if _, err := bufWriter.WriteString(line); err != nil {
					return nil, fmt.Errorf("failed to write schema statement: %w", err)
				}
			} else if !schemaStarted && (strings.HasPrefix(trimLine, "SET") || strings.HasPrefix(trimLine, "SELECT") ||
				strings.HasPrefix(trimLine, `\connect`) || strings.HasPrefix(trimLine, "CREATE DATABASE")) {
				continue
			} else {
				if strings.HasPrefix(trimLine, "COPY") && strings.Contains(trimLine, "FROM stdin;") {
					inCopyBlock = true
				}
				if _, err := bufWriter.WriteString(line); err != nil {
					return nil, fmt.Errorf("failed to write sanitized line: %w", err)
				}
			}
		}
	}

	if err := bufWriter.Flush(); err != nil {
		return nil, fmt.Errorf("failed to flush sanitized dump stream: %w", err)
	}

	hash := rowHasher.Sum(nil)
	s.log.Info("Sanitized dump stream", "height", height, "snapshot-hash", fmt.Sprintf("%x", hash))

	return hash, nil
}

// compressStream wraps gzip with deterministic headers. Controlling the header
// values prevents accidental hash mismatches when two nodes compress identical
// input at different times.
func compressStream(ctx context.Context, r io.Reader, w io.Writer) error {
	gzipWriter := gzip.NewWriter(w)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	gzipWriter.Header.Name = ""
	gzipWriter.Header.OS = 255

	if _, err := io.Copy(gzipWriter, &contextReader{ctx: ctx, Reader: r}); err != nil {
		gzipWriter.Close()
		return err
	}

	return gzipWriter.Close()
}

// splitStreamIntoChunks writes the compressed stream into on-disk chunk files.
// We hash each chunk while it is written to avoid double-reading the data and
// to keep the snapshot header in sync with the files we just produced.
func (s *Snapshotter) splitStreamIntoChunks(ctx context.Context, height uint64, format uint32, r io.Reader, hashCh <-chan []byte) (*Snapshot, error) {
	var chunkIndex uint32
	var hashes [][HashLen]byte
	var fileSize uint64

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunkFileName := snapshotChunkFile(s.snapshotDir, height, format, chunkIndex)
		chunkFile, err := os.Create(chunkFileName)
		if err != nil {
			return nil, fmt.Errorf("failed to create chunk file: %w", err)
		}

		hasher := sha256.New()
		multiWriter := io.MultiWriter(chunkFile, hasher)
		written, copyErr := io.CopyN(multiWriter, &contextReader{ctx: ctx, Reader: r}, chunkSize)

		if err := chunkFile.Close(); err != nil {
			return nil, fmt.Errorf("failed to close chunk file: %w", err)
		}

		if copyErr != nil {
			if copyErr != io.EOF {
				os.Remove(chunkFileName)
				return nil, fmt.Errorf("failed to write chunk to file: %w", copyErr)
			}
			if written == 0 {
				os.Remove(chunkFileName)
				break
			}
		}

		var chunkHash [HashLen]byte
		copy(chunkHash[:], hasher.Sum(nil))

		hashes = append(hashes, chunkHash)
		fileSize += uint64(written)
		chunkIndex++

		indexLogged := chunkIndex - 1
		s.log.Info("Chunk created", "index", indexLogged, "chunkfile", chunkFileName, "size", written)

		if copyErr == io.EOF || written < chunkSize {
			break
		}
	}

	sqlDumpHash, ok := <-hashCh
	if !ok {
		return nil, fmt.Errorf("sanitized hash unavailable")
	}

	snapshot := &Snapshot{
		Height:       height,
		Format:       format,
		ChunkCount:   chunkIndex,
		ChunkHashes:  hashes,
		SnapshotHash: sqlDumpHash,
		SnapshotSize: fileSize,
	}
	headerFile := snapshotHeaderFile(s.snapshotDir, height, format)
	if err := snapshot.SaveAs(headerFile); err != nil {
		return nil, fmt.Errorf("failed to save snapshot header: %w", err)
	}

	s.log.Info("Chunk files created successfully", "height", height, "chunk-count", chunkIndex, "Total Snapshot Size", fileSize)

	return snapshot, nil
}

type copyRow struct {
	hash [32]byte
	data []byte
}

type copyBlockSorter struct {
	tempDir string
	limit   int
	rows    []copyRow
	rowSize int
	spills  []*os.File
}

func newCopyBlockSorter(tempDir string, limit int) *copyBlockSorter {
	if limit <= 0 {
		limit = defaultCopySorterBuffer
	}
	return &copyBlockSorter{
		tempDir: tempDir,
		limit:   limit,
	}
}

func (s *copyBlockSorter) AddLine(line []byte) error {
	if len(line) == 0 {
		return nil
	}
	rowCopy := append([]byte(nil), line...)
	row := copyRow{
		hash: sha256.Sum256(rowCopy),
		data: rowCopy,
	}
	s.rows = append(s.rows, row)
	s.rowSize += len(rowCopy)
	if s.rowSize >= s.limit {
		return s.spill()
	}
	return nil
}

func (s *copyBlockSorter) Flush(w io.Writer) error {
	defer s.Reset()

	if len(s.spills) == 0 {
		s.sortInMemory()
		for _, row := range s.rows {
			if _, err := w.Write(row.data); err != nil {
				return err
			}
		}
		s.rows = nil
		s.rowSize = 0
		return nil
	}

	if len(s.rows) > 0 {
		if err := s.spill(); err != nil {
			return err
		}
	}

	if err := s.reduceRuns(maxOpenRunFiles); err != nil {
		return err
	}

	readers := make([]*runReader, 0, len(s.spills))
	for _, f := range s.spills {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		readers = append(readers, newRunReader(f))
	}

	h := mergeHeap{}
	heap.Init(&h)
	for _, r := range readers {
		row, err := r.next()
		if err != nil {
			if err == io.EOF {
				continue
			}
			return err
		}
		heap.Push(&h, mergeItem{row: row, reader: r})
	}

	for h.Len() > 0 {
		item := heap.Pop(&h).(mergeItem)
		if _, err := w.Write(item.row.data); err != nil {
			return err
		}
		next, err := item.reader.next()
		if err != nil {
			if err == io.EOF {
				continue
			}
			return err
		}
		heap.Push(&h, mergeItem{row: next, reader: item.reader})
	}

	return nil
}

func (s *copyBlockSorter) Reset() {
	for _, f := range s.spills {
		name := f.Name()
		f.Close()
		os.Remove(name)
	}
	s.spills = nil
	s.rows = nil
	s.rowSize = 0
}

func (s *copyBlockSorter) reduceRuns(maxOpen int) error {
	if maxOpen <= 0 {
		return errors.New("maxOpen must be positive")
	}

	for len(s.spills) > maxOpen {
		batch := append([]*os.File(nil), s.spills[:maxOpen]...)
		merged, err := s.mergeRunBatch(batch)
		if err != nil {
			return err
		}

		for _, f := range batch {
			f.Close()
			os.Remove(f.Name())
		}

		rest := append([]*os.File(nil), s.spills[maxOpen:]...)
		s.spills = append([]*os.File{merged}, rest...)
	}

	return nil
}

func (s *copyBlockSorter) mergeRunBatch(batch []*os.File) (*os.File, error) {
	file, err := os.CreateTemp(s.tempDir, "copy-merge-*.tmp")
	if err != nil {
		return nil, err
	}

	writer := bufio.NewWriter(file)
	readers := make([]*runReader, 0, len(batch))

	for _, f := range batch {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			file.Close()
			os.Remove(file.Name())
			return nil, err
		}
		readers = append(readers, newRunReader(f))
	}

	h := mergeHeap{}
	heap.Init(&h)
	for _, r := range readers {
		row, err := r.next()
		if err != nil {
			if err == io.EOF {
				continue
			}
			file.Close()
			os.Remove(file.Name())
			return nil, err
		}
		heap.Push(&h, mergeItem{row: row, reader: r})
	}

	for h.Len() > 0 {
		item := heap.Pop(&h).(mergeItem)
		if len(item.row.data) > int(^uint32(0)) {
			file.Close()
			os.Remove(file.Name())
			return nil, fmt.Errorf("copy row exceeds maximum size: %d", len(item.row.data))
		}
		if err := binary.Write(writer, binary.LittleEndian, uint32(len(item.row.data))); err != nil {
			file.Close()
			os.Remove(file.Name())
			return nil, err
		}
		if _, err := writer.Write(item.row.hash[:]); err != nil {
			file.Close()
			os.Remove(file.Name())
			return nil, err
		}
		if _, err := writer.Write(item.row.data); err != nil {
			file.Close()
			os.Remove(file.Name())
			return nil, err
		}

		next, err := item.reader.next()
		if err != nil {
			if err == io.EOF {
				continue
			}
			file.Close()
			os.Remove(file.Name())
			return nil, err
		}
		heap.Push(&h, mergeItem{row: next, reader: item.reader})
	}

	if err := writer.Flush(); err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}

	return file, nil
}

func (s *copyBlockSorter) spill() error {
	if len(s.rows) == 0 {
		return nil
	}

	s.sortInMemory()
	file, err := os.CreateTemp(s.tempDir, "copy-run-*.tmp")
	if err != nil {
		return err
	}

	bufWriter := bufio.NewWriter(file)
	for _, row := range s.rows {
		if len(row.data) > int(^uint32(0)) {
			file.Close()
			os.Remove(file.Name())
			return fmt.Errorf("copy row exceeds maximum size: %d", len(row.data))
		}
		if err := binary.Write(bufWriter, binary.LittleEndian, uint32(len(row.data))); err != nil {
			file.Close()
			os.Remove(file.Name())
			return err
		}
		if _, err := bufWriter.Write(row.hash[:]); err != nil {
			file.Close()
			os.Remove(file.Name())
			return err
		}
		if _, err := bufWriter.Write(row.data); err != nil {
			file.Close()
			os.Remove(file.Name())
			return err
		}
	}

	if err := bufWriter.Flush(); err != nil {
		file.Close()
		os.Remove(file.Name())
		return err
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		os.Remove(file.Name())
		return err
	}

	s.spills = append(s.spills, file)
	s.rows = nil
	s.rowSize = 0
	return nil
}

func (s *copyBlockSorter) sortInMemory() {
	if len(s.rows) <= 1 {
		return
	}
	// stable sort to preserve input order when hashes and rows match
	slices.SortStableFunc(s.rows, func(a, b copyRow) int {
		if cmp := bytes.Compare(a.hash[:], b.hash[:]); cmp != 0 {
			return cmp
		}
		return bytes.Compare(a.data, b.data)
	})
}

type runReader struct {
	file   *os.File
	reader *bufio.Reader
}

func newRunReader(f *os.File) *runReader {
	return &runReader{
		file:   f,
		reader: bufio.NewReader(f),
	}
}

func (r *runReader) next() (copyRow, error) {
	var length uint32
	if err := binary.Read(r.reader, binary.LittleEndian, &length); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return copyRow{}, io.EOF
		}
		return copyRow{}, err
	}

	var hash [32]byte
	if _, err := io.ReadFull(r.reader, hash[:]); err != nil {
		return copyRow{}, err
	}

	data := make([]byte, int(length))
	if _, err := io.ReadFull(r.reader, data); err != nil {
		return copyRow{}, err
	}

	return copyRow{hash: hash, data: data}, nil
}

type mergeItem struct {
	row    copyRow
	reader *runReader
}

type mergeHeap []mergeItem

func (h mergeHeap) Len() int { return len(h) }

func (h mergeHeap) Less(i, j int) bool {
	if cmp := bytes.Compare(h[i].row.hash[:], h[j].row.hash[:]); cmp != 0 {
		return cmp < 0
	}
	return bytes.Compare(h[i].row.data, h[j].row.data) < 0
}

func (h mergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *mergeHeap) Push(x any) {
	item := x.(mergeItem)
	*h = append(*h, item)
}

func (h *mergeHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func hashFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
