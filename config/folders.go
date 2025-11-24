package config

import "path/filepath"

const (
	NodeKeyFileName = "nodekey.json"
)

// TODO: cleanup the below consts and funcs

// Top-level directory structure for the Server's systems. These are not user
// configurable.
const (
	configFileName    = "config.toml"
	migrationsDirName = "migrations"
	blockstoreDirName = "blockstore"

	// receivedSnapshotsDirName is the directory where snapshots are received
	receivedSnapshotsDirName = "received_snapshots"
	// LocalSnapshots is the directory where snapshots taken by the local node are stored
	localSnapshotsDirName = "snapshots"

	genesisStateFileName = "genesis-state.sql.gz"
	genesisFileName      = "genesis.json"

	leaderUpdatesFileName = "leader-updates.json"
	commitIntentFileName  = "commit-intent.json"
)

// BlockstoreDir returns the blockstore directory in the root directory.
func BlockstoreDir(rootDir string) string {
	return filepath.Join(rootDir, blockstoreDirName)
}

// GenesisStateFileName returns the genesis state file in the root directory.
func GenesisStateFileName(rootDir string) string {
	return filepath.Join(rootDir, genesisStateFileName)
}

// ReceivedSnapshotsDir returns the directory where snapshots are received
func ReceivedSnapshotsDir(rootDir string) string {
	return filepath.Join(rootDir, receivedSnapshotsDirName)
}

// LocalSnapshotsDir returns the directory where snapshots taken by the local node are stored
func LocalSnapshotsDir(rootDir string) string {
	return filepath.Join(rootDir, localSnapshotsDirName)
}

// ConfigFilePath returns the path to the config file
func ConfigFilePath(rootDir string) string {
	return filepath.Join(rootDir, configFileName)
}

// MigrationDir returns the directory where the node's migrations are stored
func MigrationDir(rootDir string) string {
	return filepath.Join(rootDir, migrationsDirName)
}

func GenesisFilePath(rootDir string) string {
	return filepath.Join(rootDir, genesisFileName)
}

func NodeKeyFilePath(rootDir string) string {
	return filepath.Join(rootDir, NodeKeyFileName)
}

func LeaderUpdatesFilePath(rootDir string) string {
	return filepath.Join(rootDir, leaderUpdatesFileName)
}

func CommitIntentFilePath(rootDir string) string {
	return filepath.Join(rootDir, commitIntentFileName)
}
