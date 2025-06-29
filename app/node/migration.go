package node

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/client"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/migrations"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
)

// The migrationClient type is responsible for:
//   - Polling the old chain to retrieve the genesis state required for migration.
//   - Downloading the genesis snapshot from the old chain and saves it under the
//     root directory of the node.
//   - Updating the genesis configuration such as app hash, validators and migration settings.
//   - Updating the kwild configuration with the snapshot file path and migrations listener extension.

const (
	defaultPollFrequency = time.Second * 30
)

type migrationClient struct {
	// listenAddress is the old chain's listen address to retrieve the genesis state
	listenAddress    string
	rootDir          string
	snapshotFileName string

	clt        *client.Client
	kwildCfg   *config.Config
	genesisCfg *config.GenesisConfig

	logger log.Logger
}

// PrepareForMigration initiates the migration mode for the kwild node. This is a pre-start phase where
// the node periodically polls the old chain for the genesis state. This mode is used to prepare the node
// for migration by downloading the genesis state from the old chain for the new chain to start from.
// It also updates the genesis and kwild configurations required for the migration process.
func prepareForMigration(ctx context.Context, kwildCfg *config.Config, genesisCfg *config.GenesisConfig, rootDir string, logger log.Logger) (*config.Config, *config.GenesisConfig, error) {
	if kwildCfg.Migrations.MigrateFrom == "" {
		return nil, nil, errors.New("migrate_from is mandatory for migration")
	}

	logger.Info("Entering migration mode", "migrate_from", kwildCfg.Migrations.MigrateFrom)

	snapshotFileName := config.GenesisStateFileName(rootDir)

	// if the genesis state is already downloaded, then no need to poll for genesis state
	_, err := os.Stat(snapshotFileName)
	if err == nil {
		logger.Info("Genesis state already downloaded", "genesis snapshot", snapshotFileName)

		if err := validateGenesisState(snapshotFileName, genesisCfg.StateHash); err != nil {
			return nil, nil, err
		}

		return kwildCfg, genesisCfg, nil
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("failed to check genesis state file: %w", err)
	}

	// if we reach here, then we still need to download the genesis state
	// Therefore, the genesis app hash, initial height, and migration info
	// should not already be set in the genesis config.
	if len(genesisCfg.StateHash) != 0 {
		return nil, nil, errors.New("migration genesis config should not have app hash set")
	}
	if genesisCfg.InitialHeight != 0 && genesisCfg.InitialHeight != 1 {
		// we are forcing users to adopt the height provided by the old chain
		return nil, nil, errors.New("migration genesis config should not have initial height set")
	}
	if genesisCfg.Migration.IsMigration() {
		return nil, nil, errors.New("migration genesis config should not have migration info set")
	}

	// old chain client'
	clt, err := client.NewClient(ctx, kwildCfg.Migrations.MigrateFrom, nil)
	if err != nil {
		return nil, nil, err
	}

	// Get the genesis state from the old chain
	m := &migrationClient{
		listenAddress:    kwildCfg.Migrations.MigrateFrom,
		clt:              clt,
		kwildCfg:         kwildCfg,
		genesisCfg:       genesisCfg,
		snapshotFileName: snapshotFileName,
		logger:           logger,
	}

	// poll for the genesis state
	if err = m.pollForGenesisState(ctx); err != nil {
		return nil, nil, err
	}

	return m.kwildCfg, m.genesisCfg, nil
}

// pollForGenesisState polls for the genesis state from the old chain at a regular interval until the genesis state is available.
func (m *migrationClient) pollForGenesisState(ctx context.Context) (err error) {
	// Poll for the genesis state from the old chain
	m.logger.Info("Requesting genesis state from the old chain", "listen_address", m.listenAddress)
	for {
		if err = m.downloadGenesisState(ctx); err == nil {
			return nil
		}
		m.logger.Info("Genesis state not available", "error", err, "retryAfter", defaultPollFrequency)

		// retry after defaultPollFrequency
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultPollFrequency):
		}
	}
}

// downloadGenesisState retrieves the genesis state from the old chain and stores it in the node's root directory.
// It modifies the genesis configuration parameters, including app hash, initial height, validators, and
// migration settings, and saves the updated state. Additionally, it updates the genesis-state location
// in the kwild configuration and saves it.
func (m *migrationClient) downloadGenesisState(ctx context.Context) error {
	// Get the genesis state from the old chain
	metadata, err := m.clt.GenesisState(ctx)
	if err != nil {
		return err
	}

	// this check should change in every version:
	// For backwards compatibility, we should be able to unmarshal structs from previous versions.
	// Since v0.9 is our first time supporting migration, we only need to check for v0.9.
	if metadata.Version != migrations.MigrationVersion {
		return fmt.Errorf("genesis state download is incompatible. Received version: %d, supported versions: [%d]", metadata.Version, migrations.MigrationVersion)
	}

	// Check if the genesis state is ready
	if metadata.MigrationState.Status.NoneActive() || metadata.MigrationState.Status == types.ActivationPeriod {
		return fmt.Errorf("status %s", metadata.MigrationState.Status)
	}

	// Genesis state should ready
	if metadata.SnapshotMetadata == nil || metadata.GenesisInfo == nil {
		return errors.New("genesis state not available")
	}

	// Save the genesis state
	var snapshotMetadata snapshotter.Snapshot
	if err := json.Unmarshal(metadata.SnapshotMetadata, &snapshotMetadata); err != nil {
		return fmt.Errorf("failed to unmarshal snapshot metadata: %w", err)
	}

	m.logger.Info("Genesis state available for download")

	// create snapshot file
	genesisStateFile, err := os.Create(m.snapshotFileName)
	if err != nil {
		return fmt.Errorf("failed to create genesis snapshot file: %w", err)
	}

	// retrieve all the snapshot chunks
	for i := range snapshotMetadata.ChunkCount {
		chunk, err := m.clt.GenesisSnapshotChunk(ctx, snapshotMetadata.Height, i)
		if err != nil {
			return fmt.Errorf("failed to download genesis snapshot chunk: %d  error: %w", i, err)
		}
		n, err := genesisStateFile.Write(chunk)
		if err != nil {
			return fmt.Errorf("failed to write genesis snapshot chunk: %d  error: %w", i, err)
		}
		if n != len(chunk) {
			return fmt.Errorf("incomplete write to genesis snapshot chunk. expected: %d, written: %d", len(chunk), n)
		}
	}

	// Update the genesis config
	m.genesisCfg.StateHash = metadata.GenesisInfo.AppHash
	m.genesisCfg.Migration = config.MigrationParams{
		StartHeight: metadata.MigrationState.StartHeight,
		EndHeight:   metadata.MigrationState.EndHeight,
	}
	m.genesisCfg.InitialHeight = metadata.MigrationState.StartHeight

	// if validators are not set in the genesis config, then set them.
	// Otherwise, ignore the validators from the old chain.
	if len(m.genesisCfg.Validators) == 0 {
		for _, v := range metadata.GenesisInfo.Validators {
			m.genesisCfg.Validators = append(m.genesisCfg.Validators, &types.Validator{
				AccountID: types.AccountID{
					Identifier: v.Identifier,
					KeyType:    v.KeyType,
				},
				Power: v.Power,
			})
		}
	} else {
		m.logger.Warn("Validators already set in the genesis config. Ignoring the validators from the old chain")
	}

	// persist the genesis config
	if err := m.genesisCfg.SaveAs(config.GenesisFilePath(m.rootDir)); err != nil {
		return fmt.Errorf("failed to save genesis config: %w", err)
	}

	// Update the kwild config
	m.kwildCfg.GenesisState = m.snapshotFileName

	m.logger.Info("Genesis state downloaded successfully", "genesis snapshot", m.snapshotFileName)
	return nil
}

// validateGenesisState validates the genesis state file against the app hash.
// It is the caller's responsibility to check if the file exists.
func validateGenesisState(filename string, appHash []byte) error {
	// we don't need to check if the file exists since the caller should have already checked it
	if appHash == nil {
		return errors.New("genesis file should have app hash set")
	}

	genesisStateFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open genesis state file: %w", err)
	}

	// gzip reader and hash reader
	gzipReader, err := gzip.NewReader(genesisStateFile)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	hasher := sha256.New()
	_, err = io.Copy(hasher, gzipReader)
	if err != nil {
		return fmt.Errorf("failed to hash genesis state file: %w", err)
	}

	hash := hasher.Sum(nil)

	if !bytes.Equal(hash, appHash) {
		return errors.New("app hash does not match the genesis state")
	}

	return nil
}
