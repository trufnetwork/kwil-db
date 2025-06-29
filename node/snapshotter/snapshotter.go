package snapshotter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
)

const (
	chunkSize int64 = 16e6 - 4096 // 16 MB

	DefaultSnapshotFormat = 0

	stage1output = "stage1output.sql"
	stage2output = "stage2output.sql"
	stage3output = "stage3output.sql.gz"

	CreateSchema   = "CREATE SCHEMA"
	CreateTable    = "CREATE TABLE"
	CreateFunction = "CREATE FUNCTION"
)

// This file deals with creating a snapshot instance at a given snapshotID
// The whole process occurs in multiple stages:
// STAGE1: Dumping the database state using pg_dump and writing it to a file
// STAGE2: Sanitizing the dump file to make it deterministic
//   - Removing white spaces, comments and SET and SELECT statements
//   - Sorting the COPY blocks of data based on the hash of the row-data
//
// STAGE3: Compressing the sanitized dump file
// STAGE4: Splitting the compressed dump file into chunks of fixed size (16MB)
// TODO: STAGE2 could be optimized by sorting based on the first column,
// but it might not work if the first column is not unique.

type NamespaceManager interface {
	ListPostgresSchemasToDump() []string
}

type Snapshotter struct {
	dbConfig     *config.DBConfig
	snapshotDir  string
	namespaceMgr NamespaceManager
	log          log.Logger
}

func NewSnapshotter(cfg *config.DBConfig, dir string, namespaceMgr NamespaceManager, logger log.Logger) *Snapshotter {
	return &Snapshotter{
		dbConfig:     cfg,
		snapshotDir:  dir,
		namespaceMgr: namespaceMgr,
		log:          logger,
	}
}

// CreateSnapshot creates a snapshot at the given height and snapshotID
func (s *Snapshotter) CreateSnapshot(ctx context.Context, height uint64, snapshotID string, schemas, excludeTables []string, excludeTableData []string) (*Snapshot, error) {
	// create snapshot directory
	snapshotDir := snapshotHeightDir(s.snapshotDir, height)
	chunkDir := snapshotChunkDir(s.snapshotDir, height, DefaultSnapshotFormat)
	err := os.MkdirAll(chunkDir, 0755)
	if err != nil {
		return nil, err
	}

	// Stage1: Dump the database at the given height and snapshot ID
	err = s.dbSnapshot(ctx, height, DefaultSnapshotFormat, snapshotID, schemas, excludeTables, excludeTableData)
	if err != nil {
		os.RemoveAll(snapshotDir)
		return nil, err
	}

	// Stage2: Sanitize the dump
	hash, err := s.sanitizeDump(height, DefaultSnapshotFormat)
	if err != nil {
		os.RemoveAll(snapshotDir)
		return nil, err
	}

	// Stage3: Compress the dump
	err = s.compressDump(height, DefaultSnapshotFormat)
	if err != nil {
		os.RemoveAll(snapshotDir)
		return nil, err
	}

	// Stage4: Split the dump into chunks
	snapshot, err := s.splitDumpIntoChunks(height, DefaultSnapshotFormat, hash)
	if err != nil {
		os.RemoveAll(snapshotDir)
		return nil, err
	}

	return snapshot, nil
}

// dbSnapshot is the STAGE1 of the snapshot creation process
// It uses pg_dump to dump the database state at the given height and snapshotID
// The pg dump is stored as "/stage1output.sql" in the snapshot directory
// This is a temporary file and will be removed after the snapshot is created.
// The function takes the following parameters to specify what to include in the snapshot:
// schemas: List of schemas to include in the snapshot
// excludeTables: List of tables to exclude from the snapshot
// excludeTableData: List of tables for which definitions should be included but not the data
func (s *Snapshotter) dbSnapshot(ctx context.Context, height uint64, format uint32, snapshotID string, internalSchemas, excludeTables []string, excludeTableData []string) error {
	snapshotDir := snapshotFormatDir(s.snapshotDir, height, format)
	dumpFile := filepath.Join(snapshotDir, stage1output)

	args := []string{
		// File format options
		"--file", dumpFile,
		"--format", "plain",
		// Snapshot ID ensures a consistent snapshot taken at the given block boundary across all nodes
		"--dbname", s.dbConfig.DBName,
		// Connection options
		"-U", s.dbConfig.User,
		"-h", s.dbConfig.Host,
		"-p", s.dbConfig.Port,
		"--no-password",
		// Snapshot options
		"--snapshot", snapshotID,
		// other sql dump specific options
		"--no-unlogged-table-data",
		"--no-comments",
		"--create",
		"--no-publications",
		"--no-unlogged-table-data",
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

	if s.dbConfig.Pass != "" {
		pgDumpCmd.Env = append(pgDumpCmd.Env, "PGPASSWORD="+s.dbConfig.Pass)
	}

	s.log.Info("Executing pg_dump", "cmd", pgDumpCmd.String())

	output, err := pgDumpCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute pg_dump: %w, output: %s", err, string(output))
	}

	s.log.Info("pg_dump successful", "height", height)

	return nil
}

type hashedLine struct {
	Hash   [32]byte // sha256 hash of the line
	offset int64
}

// sanitizeDump is the STAGE2 of the snapshot creation process
// This stage sanitizes the dump file to make it deterministic across all the nodes
// It removes white spaces, comments, SET and SELECT statements
// It sorts the COPY blocks of data based on the hash of the row-data
// The sanitized dump is stored as "/stage2output.sql" in the snapshot directory
// This is a temporary file and will be removed after the snapshot is created
func (s *Snapshotter) sanitizeDump(height uint64, format uint32) ([]byte, error) {
	// check if the stage1output file exists
	snapshotDir := snapshotFormatDir(s.snapshotDir, height, format)
	dumpFile := filepath.Join(snapshotDir, stage1output)
	dumpInst1, err := os.Open(dumpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open dump file: %w", err)
	}
	defer dumpInst1.Close()

	dumpInst2, err := os.Open(dumpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open dump file: %w", err)
	}
	defer dumpInst2.Close()

	// sanitized dump file
	sanitizedDumpFile := filepath.Join(snapshotDir, stage2output)
	outputFile, err := os.Create(sanitizedDumpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create sanitized dump file: %w", err)
	}
	defer outputFile.Close()

	reader := bufio.NewReader(dumpInst1)

	var inCopyBlock, schemaStarted bool
	var lineHashes []hashedLine
	var offset int64
	hasher := sha256.New()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read line {%s} from pg dump file: %w", line, err)
		}

		numBytes := int64(len(line)) //  newline character is included in the line
		trimLine := strings.TrimSpace(line)

		if inCopyBlock {
			/*
				COPY schema.table (id, name) FROM stdin;
				2 entry2
				1 entry1
				3 entry3
				\.
			*/
			if trimLine == `\.` { // end of COPY block
				inCopyBlock = false

				// Inline sort the lineHashes array based on the row hash
				slices.SortFunc(lineHashes, func(a, b hashedLine) int {
					return bytes.Compare(a.Hash[:], b.Hash[:])
				})

				/*
					TODO: Consider optimizing the sorting process:
					- #len(lineHashes) number of fseeks per copy block -> not good, saves memory but huge IO overhead
					- Preferably, sort based on the first column or a unique column for data locality
				*/

				// Write the sorted data to the output file based on the offset
				for _, hashedLine := range lineHashes {
					// Seek to the offset of the line in the input file
					_, err := dumpInst2.Seek(hashedLine.offset, io.SeekStart)
					if err != nil {
						return nil, fmt.Errorf("failed to seek to offset: %w", err)
					}

					lineBytes, err := bufio.NewReader(dumpInst2).ReadBytes('\n')
					if err != nil {
						return nil, fmt.Errorf("failed to read line from input file: %w", err)
					}

					_, err = outputFile.Write(lineBytes)
					if err != nil {
						return nil, fmt.Errorf("failed to write to sanitized dump file: %w", err)
					}
				}

				// Write the end of COPY block to the output file
				_, err = outputFile.WriteString(line) // \n character is included in the line
				if err != nil {
					return nil, fmt.Errorf("failed to write to sanitized dump file: %w", err)
				}

				// Clear the lineHashes array
				lineHashes = make([]hashedLine, 0)
				offset += numBytes
			} else {
				// If we are in a COPY block, we need to sort the data based on the row hash
				hasher.Reset()
				hasher.Write([]byte(line))
				var hash [32]byte
				copy(hash[:], hasher.Sum(nil))
				lineHashes = append(lineHashes, hashedLine{Hash: hash, offset: offset})
				offset += numBytes
			}
		} else {
			offset += numBytes // +1 for newline character
			if line == "" || trimLine == "" {
				// skip empty lines
				continue
			} else if strings.HasPrefix(trimLine, "--") {
				// skip comments
				continue
			} else if !schemaStarted && (strings.HasPrefix(trimLine, CreateSchema) ||
				strings.HasPrefix(trimLine, CreateTable) || strings.HasPrefix(trimLine, CreateFunction)) {
				schemaStarted = true

				// write the line to the output file
				_, err := outputFile.WriteString(line) // \n character is included in the line
				if err != nil {
					return nil, fmt.Errorf("failed to write to sanitized dump file: %w", err)
				}
			} else if !schemaStarted && (strings.HasPrefix(trimLine, "SET") || strings.HasPrefix(trimLine, "SELECT") ||
				strings.HasPrefix(trimLine, `\connect`) || strings.HasPrefix(trimLine, "CREATE DATABASE")) {
				// skip any SET, SELECT, CREATE DATABASE and connect statements that appear before the schema definition
				// These are postgres specific commands that should not be included in the snapshot
				continue
			} else {
				// Example: COPY kwild_voting.voters (id, name, power) FROM stdin;
				if strings.HasPrefix(trimLine, "COPY") && strings.Contains(trimLine, "FROM stdin;") {
					inCopyBlock = true // start of COPY block
				}
				// write the line to the output file
				_, err := outputFile.WriteString(line)
				if err != nil {
					return nil, fmt.Errorf("failed to write to sanitized dump file: %w", err)
				}
			}
		}
	}

	outputFile.Sync()

	// remove the dump file
	err = os.Remove(dumpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to remove dump file: %w", err)
	}

	hash, err := hashFile(sanitizedDumpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to hash the sanitized dump file: %w", err)
	}

	s.log.Info("Sanitized dump file", "height", height, "snapshot-hash", fmt.Sprintf("%x", hash))

	return hash, nil
}

// CompressDump is the STAGE3 of the snapshot creation process
// This method compresses the sanitized dump file using gzip compression
// Should we do inline compression? or using exec.Command?
func (s *Snapshotter) compressDump(height uint64, format uint32) error {
	// Check if the dump file exists
	snapshotDir := snapshotFormatDir(s.snapshotDir, height, format)
	dumpFile := filepath.Join(snapshotDir, stage2output)
	inputFile, err := os.Open(dumpFile)
	if err != nil {
		return fmt.Errorf("failed to open dump file: %w", err)
	}
	defer inputFile.Close()

	// dump file stats
	stats, err := os.Stat(dumpFile)
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	compressedFile := filepath.Join(snapshotDir, stage3output)
	outputFile, err := os.Create(compressedFile)
	if err != nil {
		return fmt.Errorf("failed to create compressed dump file: %w", err)
	}
	defer outputFile.Close()

	// gzip writer
	// Do we need faster compression at the expense of larger file size?
	// [gzip.BestSpeed or gzip.HuffmanOnly]
	// or slower compression for smaller file size? [gzip.BestCompression]
	// or a balance between the two? [gzip.DefaultCompression]
	gzipWriter := gzip.NewWriter(outputFile)
	defer gzipWriter.Close()

	_, err = io.Copy(gzipWriter, inputFile)
	if err != nil {
		return fmt.Errorf("failed to copy data to compressed dump file: %w", err)
	}

	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	compressedStats, err := os.Stat(compressedFile)
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}

	// Remove the sanitized dump file
	err = os.Remove(dumpFile)
	if err != nil {
		return fmt.Errorf("failed to remove dump file: %w", err)
	}

	s.log.Info("Dump file compressed", "height", height, "Uncompressed dump size", uint64(stats.Size()), "Compressed dump size", uint64(compressedStats.Size()))

	return nil
}

// SplitDumpIntoChunks is the STAGE4 of the snapshot creation process
// This method splits the compressed dump file into chunks of fixed size (16MB)
// The chunks are stored in the height/format/chunks directory
// The snapshot header is created and stored in the height/format/header.json file
func (s *Snapshotter) splitDumpIntoChunks(height uint64, format uint32, sqlDumpHash []byte) (*Snapshot, error) {
	// check if the dump file exists
	snapshotDir := snapshotFormatDir(s.snapshotDir, height, format)
	dumpFile := filepath.Join(snapshotDir, stage3output)
	inputFile, err := os.Open(dumpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open dump file: %w", err)
	}
	defer inputFile.Close()

	// split the dump file into chunks
	var chunkIndex uint32
	var hashes [][HashLen]byte
	var fileSize uint64

	for {
		chunkFileName := snapshotChunkFile(s.snapshotDir, height, format, chunkIndex)
		chunkFile, err := os.Create(chunkFileName)
		if err != nil {
			return nil, fmt.Errorf("failed to create chunk file: %w", err)
		}
		defer chunkFile.Close()

		// write the chunk to the file
		written, err := io.CopyN(chunkFile, inputFile, chunkSize)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to write chunk to file: %w", err)
		}
		chunkFile.Close() // chunkFile.Sync() probably

		// calculate the hash of the chunk
		var chunkHash [HashLen]byte
		hash, err := hashFile(chunkFileName)
		if err != nil {
			return nil, fmt.Errorf("failed to hash the chunk file: %w", err)
		}

		copy(chunkHash[:], hash)

		hashes = append(hashes, chunkHash)
		fileSize += uint64(written)
		chunkIndex++

		s.log.Info("Chunk created", "index", chunkIndex, "chunkfile", chunkFileName, "size", written)

		if err == io.EOF || written < chunkSize {
			break // EOF, Last chunk
		}

	}

	// get file size
	fileInfo, err := os.Stat(dumpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}
	if fileSize != uint64(fileInfo.Size()) {
		return nil, fmt.Errorf("file size mismatch: %d != %d", fileSize, fileInfo.Size())
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
	err = snapshot.SaveAs(headerFile)
	if err != nil {
		return nil, fmt.Errorf("failed to save snapshot header: %w", err)
	}

	// remove the compressed dump file
	err = os.Remove(dumpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to remove dump file: %w", err)
	}

	s.log.Info("Chunk files created successfully", "height", height, "chunk-count", chunkIndex, "Total Snapzhot Size", fileSize)

	return snapshot, nil
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
