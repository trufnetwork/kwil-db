package migrations

import (
	"bytes"
	"context"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/accounts"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/versioning"
	"github.com/trufnetwork/kwil-db/node/voting"
)

var (
	ErrNoActiveMigration = fmt.Errorf("no active migration")

	// Schemas to include in the network migration snapshot.
	networkMigrationSchemas = []string{
		"kwild_voting",
		"kwild_accts",
		"kwild_internal",
		// "kwild_engine",
		// "info", // snapshotter already includes this along with the user schemas
	}

	// Tables to exclude from the network migration snapshot.
	networkMigrationExcludedTables = []string{"kwild_internal.sentry"}

	// Tables for which data should be excluded from the network migration snapshot.
	networkMigrationExcludedTableData = []string{
		"kwild_voting.voters",
	}

	metadataFileName = "metadata.json"
)

const (
	MaxChunkSize = 1 * 1000 * 1000 // around 1MB
)

// migrator is responsible for managing the migrations.
// It is responsible for tracking any in-process migrations, snapshotting
// at the appropriate height, persisting changesets for the migration for each
// block as it occurs, and making that data available via RPC for the new node.
// Similarly, if the local process is the new node, it is responsible for reading
// changesets from the external node and applying them to the local database.
// The changesets are stored from the start height of the migration to the end height (both inclusive).
type Migrator struct {
	// config
	genesisMigrationParams config.MigrationParams
	// dir is the directory where the migration data is stored.
	// It is expected to be a full path.
	dir string

	// mu protects activeMigration and lastChangeset fields.
	mu sync.RWMutex

	// activeMigration is the migration plan that is approved by the network.
	// It is nil if there is no plan for a migration.
	activeMigration *activeMigration

	// lastChangeset is the height of the last changeset that was stored.
	// If no changesets have been stored, it is -1.
	lastChangeset int64

	// interfaces
	snapshotter Snapshotter
	DB          Database
	accounts    Accounts
	validators  Validators
	Logger      log.Logger
}

// activeMigration is an in-process migration.
type activeMigration struct {
	// StartHeight is the height at which the migration starts.
	StartHeight int64
	// EndHeight is the height at which the migration ends.
	EndHeight int64
}

// SetupMigrator initializes the migrator instance with the necessary dependencies.
func SetupMigrator(ctx context.Context, db Database, snapshotter Snapshotter, accounts Accounts, dir string, migrationParams config.MigrationParams, validators Validators, logger log.Logger) (*Migrator, error) {
	// Set the migrator declared in migrations.go
	migrator = &Migrator{
		genesisMigrationParams: migrationParams,
		snapshotter:            snapshotter,
		Logger:                 logger,
		dir:                    dir,
		DB:                     db,
		accounts:               accounts,
		validators:             validators,
	}

	// Initialize the DB
	upgradeFns := map[int64]versioning.UpgradeFunc{
		0: initializeMigrationSchema,
	}
	err := versioning.Upgrade(ctx, db, migrationsSchemaName, upgradeFns, migrationSchemaVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade migrations DB: %w", err)
	}

	// retrieve migration metadata
	tx, err := db.BeginReadTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin read tx: %w", err)
	}
	defer tx.Rollback(ctx)

	m, err := getMigrationState(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to get migration state: %w", err)
	}
	migrator.activeMigration = m

	// Get the last changeset that was stored
	height, err := getLastStoredChangeset(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to get last stored changeset: %w", err)
	}
	migrator.lastChangeset = height

	return migrator, nil
}

// NotifyHeight notifies the migrator that a new block has been committed.
// It is called at the end of the block being applied, but before the block is
// committed to the database, in between tx.PreCommit and tx.Commit.
// consensusTx is needed to read the migration state from the database if any migration is active.
func (m *Migrator) NotifyHeight(ctx context.Context, block *common.BlockContext, db Database, consensusTx sql.Executor) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if block.ChainContext.NetworkParameters.MigrationStatus == types.ActivationPeriod && m.activeMigration == nil {
		// if the network is in activation period, but there is no active migration, then
		// this is the block at which the migration is approved by the network.
		activeM, err := getMigrationState(ctx, consensusTx)
		if err != nil {
			return fmt.Errorf("failed to get migration state: %w", err)
		}

		m.activeMigration = activeM
	}

	// if there is no active migration, there is nothing to do
	if m.activeMigration == nil {
		return nil
	}

	// if not in a migration, we can return early
	if block.Height < m.activeMigration.StartHeight-1 {
		return nil
	}

	if block.Height > m.activeMigration.EndHeight {
		return nil
	}

	if block.Height == m.activeMigration.StartHeight-1 {
		// set the migration in progress, so that we record the changesets starting from the next block
		block.ChainContext.NetworkUpdates[types.ParamNameMigrationStatus] = types.MigrationInProgress
		// block.ChainContext.NetworkParameters.MigrationStatus = types.MigrationInProgress
		return nil
	}

	/*
		I previously thought to make this run asynchronously, since PG dump can take a significant amount of time,
		however I decided againast it, because nodes are required to agree on the height of the old chain during the
		migration on the new chain. Im not sure of a way to guarantee this besdies literally enforcing that the old
		chain runs the migration synchronously as part of consensus.

		NOTE: https://github.com/trufnetwork/kwil-db/pull/837#discussion_r1648036539
	*/

	// if the current block height is the height at which the migration starts, then
	// we should snapshot the current DB and begin the migration. Since NotifyHeight is called
	// during PreCommit, the state changes from the current block won't be included in the snapshot,
	// and will instead need to be recorded as the first changeset of the migration.

	if block.Height == m.activeMigration.StartHeight {
		block.ChainContext.NetworkParameters.MigrationStatus = types.MigrationInProgress

		tx, snapshotId, err := db.BeginSnapshotTx(ctx)
		if err != nil {
			return err
		}
		defer func() {
			err2 := tx.Rollback(ctx)
			if err2 != nil {
				// we can mostly ignore this error, since the original err will halt the node anyways
				m.Logger.Errorf("failed to rollback transaction: %s", err2.Error())
			}
		}()

		err = m.snapshotter.CreateSnapshot(ctx, uint64(block.Height), snapshotId, networkMigrationSchemas, networkMigrationExcludedTables, networkMigrationExcludedTableData)
		if err != nil {
			return err
		}

		// Generate a genesis file for the snapshot
		// Retrieve snapshot hash
		snapshots := m.snapshotter.ListSnapshots()
		if len(snapshots) == 0 {
			return fmt.Errorf("migration is active, but no snapshots found. The node might still be creating the snapshot")
		}
		if len(snapshots) > 1 {
			return fmt.Errorf("migration is active, but more than one snapshot found. This should not happen, and is likely a bug")
		}

		// generate genesis config
		m.generateGenesisConfig(snapshots[0].SnapshotHash, m.Logger)
	}

	if block.Height == m.activeMigration.EndHeight {
		// starting from here, no more transactions of any kind will be accepted or mined.
		// block.ChainContext.NetworkParameters.MigrationStatus = types.MigrationCompleted
		block.ChainContext.NetworkUpdates[types.ParamNameMigrationStatus] = types.MigrationCompleted
		m.Logger.Info("migration to chain completed, no new transactions will be accepted")
	}

	return nil
}

// generateGenesisConfig generates the genesis config for the migration.
// It saves the genesis_info.json to the migrations directory.
// The file includes genesis app hash based on the snapshot hash, and
// the validator set at the time of the migration.
func (m *Migrator) generateGenesisConfig(snapshotHash []byte, logger log.Logger) error {
	genInfo := &types.GenesisInfo{
		AppHash:    snapshotHash,
		Validators: m.validators.GetValidators(),
	}

	bts, err := json.Marshal(genInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal genesis info: %w", err)
	}

	// Save the genesis info
	err = os.WriteFile(formatGenesisInfoFileName(m.dir), bts, 0644)
	if err != nil {
		return fmt.Errorf("failed to save genesis info: %w", err)
	}

	logger.Info("genesis config generated successfully")
	return nil
}

func (m *Migrator) PersistLastChangesetHeight(ctx context.Context, tx sql.Executor, height int64) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeMigration == nil {
		return nil
	}

	m.lastChangeset = height // safety update for inconsistent bootup. it should already be updated by the writer
	return setLastStoredChangeset(ctx, tx, height)
}

// GetMigrationMetadata gets the metadata for the genesis snapshot,
// as well as the available changesets.
func (m *Migrator) GetMigrationMetadata(ctx context.Context, status types.MigrationStatus) (*types.MigrationMetadata, error) {
	metadata := &types.MigrationMetadata{
		MigrationState: types.MigrationState{
			Status: status,
		},
		Version: MigrationVersion,
	}

	if status == types.GenesisMigration {
		metadata.MigrationState.StartHeight = m.genesisMigrationParams.StartHeight
		metadata.MigrationState.EndHeight = m.genesisMigrationParams.EndHeight
		return metadata, nil
	}

	// if there is no planned migration, return
	if status.NoneActive() {
		if m.genesisMigrationParams.StartHeight != 0 && m.genesisMigrationParams.EndHeight != 0 {
			metadata.MigrationState.StartHeight = m.genesisMigrationParams.StartHeight
			metadata.MigrationState.EndHeight = m.genesisMigrationParams.EndHeight
		}
		return metadata, nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// network is either in ActivationPeriod or MigrationInProgress or MigrationCompleted state
	if m.activeMigration == nil {
		return nil, fmt.Errorf("no active migration found")
	}

	metadata.MigrationState.StartHeight = m.activeMigration.StartHeight
	metadata.MigrationState.EndHeight = m.activeMigration.EndHeight

	// Migration is triggered but not yet started
	if status == types.ActivationPeriod {
		return metadata, nil
	}

	// Migration is in progress, retrieve the snapshot and the genesis config
	snapshots := m.snapshotter.ListSnapshots()
	if len(snapshots) == 0 {
		return nil, fmt.Errorf("migration is active, but no snapshots found. The node might still be creating the snapshot")
	}
	if len(snapshots) > 1 {
		return nil, fmt.Errorf("migration is active, but more than one snapshot found. This should not happen, and is likely a bug")
	}

	// serialize the snapshot metadata
	snapshotBts, err := json.Marshal(snapshots[0])
	if err != nil {
		return nil, err
	}

	// read the genesis config
	genCfg, err := os.ReadFile(formatGenesisInfoFileName(m.dir))
	if err != nil {
		return nil, err
	}

	// unmarshal
	var genesisInfo types.GenesisInfo
	if err := json.Unmarshal(genCfg, &genesisInfo); err != nil {
		return nil, err
	}

	metadata.GenesisInfo = &genesisInfo
	metadata.SnapshotMetadata = snapshotBts
	return metadata, nil
}

// GetGenesisSnapshotChunk gets the snapshot chunk of Index at the given height.
func (m *Migrator) GetGenesisSnapshotChunk(chunkIdx uint32) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeMigration == nil {
		return nil, ErrNoActiveMigration
	}

	return m.snapshotter.LoadSnapshotChunk(uint64(m.activeMigration.StartHeight), 0, chunkIdx)
}

// GetChangesetMetadata gets the metadata for the changeset at the given height.
func (m *Migrator) GetChangesetMetadata(height int64) (*ChangesetMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeMigration == nil {
		return nil, ErrNoActiveMigration
	}
	if height < m.activeMigration.StartHeight {
		return nil, fmt.Errorf("requested changeset height is before the start of the migration")
	}
	if height > m.activeMigration.EndHeight {
		return nil, fmt.Errorf("requested changeset height is after the end of the migration")
	}
	if height > m.lastChangeset {
		return nil, fmt.Errorf("requested changeset height has not been recorded by the node yet")
	}

	return loadChangesetMetadata(formatChangesetMetadataFilename(m.dir, height))
}

// GetChangeset gets the changeset at the given height and index.
func (m *Migrator) GetChangeset(height int64, index int64) ([]byte, error) {
	metadata, err := m.GetChangesetMetadata(height)
	if err != nil {
		return nil, err
	}

	if index < 0 || index >= metadata.Chunks {
		return nil, fmt.Errorf("requested changeset index is out of bounds")
	}

	return m.loadChangeset(height, index)
}

// Directory structure:
// migrations/
//	changesets/
//	  block-1/
//	  		metadata.json [#chunks, overallsz, hash?]
//	  		chunks/
//	  			chunk-1
//	  			chunk-2
//	  			...
//	  block-2/
//	  		metadata.json [#chunks, overallsz, hash?]
//	  		chunks/
//	  			chunk-1
//	snapshots/
//		genesis.json
//		snapshot data.....

type ChangesetMetadata struct {
	Height     int64   `json:"height"`
	Chunks     int64   `json:"chunks"`
	ChunkSizes []int64 `json:"chunk_sizes"`
}

// Serialize serializes the metadata to a file.
func (m *ChangesetMetadata) saveAs(file string) error {
	bts, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, bts, 0644)
}

// LoadChangesetMetadata loads the metadata associated with a changeset.s
// It reads the changeset metadata file and returns the metadata.
func loadChangesetMetadata(metadatafile string) (*ChangesetMetadata, error) {
	bts, err := os.ReadFile(metadatafile)
	if err != nil {
		return nil, fmt.Errorf("metadata file not found %s", err.Error())
	}

	var metadata ChangesetMetadata
	if err := json.Unmarshal(bts, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

type BlockSpends struct {
	Spends []*accounts.Spend
}

const blockSpendsVersion = 0

var _ pg.ChangeStreamer = (*BlockSpends)(nil)

func (bs BlockSpends) Prefix() byte {
	return pg.BlockSpendsType
}

func (bs BlockSpends) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}

	// version uint16
	if err := binary.Write(buf, types.SerializationByteOrder, uint16(blockSpendsVersion)); err != nil {
		return nil, err
	}

	// numSpends uint32
	if err := binary.Write(buf, types.SerializationByteOrder, uint32(len(bs.Spends))); err != nil {
		return nil, err
	}

	for _, spend := range bs.Spends {
		spendBts, err := spend.MarshalBinary()
		if err != nil {
			return nil, err
		}

		// spendBts
		if err := types.WriteBytes(buf, spendBts); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

var _ encoding.BinaryUnmarshaler = (*BlockSpends)(nil)

func (bs *BlockSpends) UnmarshalBinary(bts []byte) error {
	buf := bytes.NewReader(bts)

	// version uint16
	var version uint16
	if err := binary.Read(buf, types.SerializationByteOrder, &version); err != nil {
		return err
	}
	if version != blockSpendsVersion {
		return fmt.Errorf("invalid block spends version: %d", version)
	}

	// numSpends uint32
	var numSpends uint32
	if err := binary.Read(buf, types.SerializationByteOrder, &numSpends); err != nil {
		return err
	}

	bs.Spends = make([]*accounts.Spend, numSpends)
	for i := range numSpends {
		spendBts, err := types.ReadBytes(buf)
		if err != nil {
			return err
		}

		spend := &accounts.Spend{}
		if err := spend.UnmarshalBinary(spendBts); err != nil {
			return err
		}

		bs.Spends[i] = spend
	}

	return nil
}

type chunkWriter struct {
	dir      string
	height   int64
	chunkIdx int64 // current chunk index, zero based index

	chunkFile         *os.File // current chunk file being written to
	chunkSize         int64    // number of bytes written to the current chunk file
	totalBytesWritten int64    // total number of bytes written to disk for the changeset
	chunkSizes        []int64  // sizes of each chunk
}

func newChunkWriter(dir string, height int64) *chunkWriter {
	return &chunkWriter{
		dir:      dir,
		height:   height,
		chunkIdx: -1,
	}
}

var _ io.Writer = (*chunkWriter)(nil)

func (cw *chunkWriter) Write(bts []byte) (int, error) {
	if len(bts) == 0 {
		return 0, nil
	}

	if cw.chunkFile == nil {
		cw.chunkIdx++
		filename := formatChangesetFilename(cw.dir, cw.height, cw.chunkIdx)
		file, err := os.Create(filename)
		if err != nil {
			return 0, err
		}
		cw.chunkFile = file
		cw.chunkSizes = append(cw.chunkSizes, 0)
	}

	// write the data to the file, the file can only hold a maximum of ChunkSize bytes
	maxBytesToWrite := MaxChunkSize - cw.chunkSize
	if int64(len(bts)) >= maxBytesToWrite {
		// write the maximum number of bytes that can be written to the file
		n, err := cw.chunkFile.Write(bts[:maxBytesToWrite])
		if err != nil {
			return 0, err
		}
		cw.totalBytesWritten += int64(n)
		cw.chunkSizes[cw.chunkIdx] += int64(n)

		// close the current file
		err = cw.chunkFile.Close()
		if err != nil {
			return 0, err
		}

		// increment the chunk index
		// cw.chunkIdx++
		cw.chunkSize = 0
		cw.chunkFile = nil

		// write the remaining bytes to the next file
		nRem, err := cw.Write(bts[maxBytesToWrite:])
		if err != nil {
			return 0, err
		}
		return n + nRem, nil
	}

	// write the data to the file
	n, err := cw.chunkFile.Write(bts)
	if err != nil {
		return 0, err
	}
	cw.chunkSize += int64(n)
	cw.totalBytesWritten += int64(n)
	cw.chunkSizes[cw.chunkIdx] += int64(n)
	return n, nil
}

func (cw *chunkWriter) Close() error {
	if cw.chunkFile != nil {
		return cw.chunkFile.Close()
	}
	return nil
}

func (cw *chunkWriter) SaveMetadata() error {
	filename := formatChangesetMetadataFilename(cw.dir, cw.height)
	metadata := &ChangesetMetadata{
		Height:     cw.height,
		Chunks:     cw.chunkIdx + 1,
		ChunkSizes: cw.chunkSizes,
	}
	return metadata.saveAs(filename)
}

// storeChangeset persists a changeset to the migrations/changesets directory.
func (m *Migrator) StoreChangesets(height int64, changes <-chan any) error {
	if changes == nil {
		// no changesets to store, not in a migration
		return nil
	}

	err := ensureChangesetDir(m.dir, height)
	if err != nil {
		return err
	}

	// create a chunk writer
	chunkWriter := newChunkWriter(m.dir, height)
	defer chunkWriter.Close()

	for ch := range changes {
		switch ct := ch.(type) {
		case *pg.ChangesetEntry:
			// write the changeset to disk
			err = pg.StreamElement(chunkWriter, ct)
			if err != nil {
				return err
			}

		case *pg.Relation:
			// write the relation to disk
			err = pg.StreamElement(chunkWriter, ct)
			if err != nil {
				return err
			}
		}
	}

	// write the block spends to disk
	bs := &BlockSpends{
		Spends: m.accounts.GetBlockSpends(),
	}
	if len(bs.Spends) > 0 {
		if pg.StreamElement(chunkWriter, bs); err != nil {
			return err
		}
	}

	if err = chunkWriter.SaveMetadata(); err != nil {
		return err
	}

	// signals NotifyHeight that all changesets have been written to disk
	m.mu.Lock()
	m.lastChangeset = height
	m.mu.Unlock()

	return nil
}

// LoadChangesets loads changesets at a given height from the migration directory.
func (m *Migrator) loadChangeset(height int64, index int64) ([]byte, error) {
	file, err := os.Open(formatChangesetFilename(m.dir, height, index))
	if err != nil {
		// we don't have to have special checks for non-existence, since
		// we should check that prior to calling this function.
		return nil, err
	}
	defer file.Close()

	bts, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return bts, nil
}

const (
	changesetsDirName = "changesets"
	chunksDirName     = "chunks"
	snapshotsDirName  = "snapshots"
)

// ChangesetsDir returns the directory where changesets are stored,
// relative to the migration directory.
func ChangesetsDir(migrationDir string) string {
	return filepath.Join(migrationDir, changesetsDirName)
}

func SnapshotDir(migrationDir string) string {
	return filepath.Join(migrationDir, snapshotsDirName)
}

// ensureChangesetDir creates the directory structure for a changeset block
// if it does not exist.
// dir created: migrations/changesets/block-<height>/chunks
func ensureChangesetDir(dir string, height int64) error {
	return os.MkdirAll(formatChangsetBlockDir(dir, height), 0755)
}

func formatChangesetFilename(mdir string, height int64, index int64) string {
	chunkDir := formatChangsetBlockDir(mdir, height)
	return filepath.Join(chunkDir, fmt.Sprintf("changeset-%d", index))
}

func formatChangsetBlockDir(mdir string, height int64) string {
	return filepath.Join(mdir, changesetsDirName, fmt.Sprintf("block-%d", height), chunksDirName)
}

func formatChangesetMetadataFilename(mdir string, height int64) string {
	return filepath.Join(mdir, changesetsDirName, fmt.Sprintf("block-%d", height), metadataFileName)
}

func formatGenesisInfoFileName(mdir string) string {
	return filepath.Join(mdir, "genesis_info.json")
}

// CleanupResolutionsAtStartup is called at startup to clean up the resolutions table. It does the below things:
// - Remove all the pending migration, changeset, validator join and validator remove resolutions
// - Fix the expiry heights of all the pending resolutions
// (how to handle this for offline migrations? we have no way to know the last height of the old chain)
func CleanupResolutionsAfterMigration(ctx context.Context, db sql.DB) error {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	resolutionTypes := []string{
		voting.StartMigrationEventType,
		voting.ChangesetMigrationEventType,
		voting.ValidatorJoinEventType,
		voting.ValidatorRemoveEventType,
	}

	err = voting.DeleteResolutionsByType(ctx, tx, resolutionTypes)
	if err != nil {
		return err
	}

	// probably no need to adjust expirations, they should automatically be expired as we use timestamps
	// unlike block heights in Kwil V1.0 where the heights get reset to 0

	return tx.Commit(ctx)
}
