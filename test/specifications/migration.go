package specifications

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/config"
)

// Trigger migration
func SubmitMigrationProposal(ctx context.Context, t *testing.T, netops MigrationOpsDsl) {
	t.Log("Executing migration trigger specification")

	// Trigger migration"
	txHash, err := netops.SubmitMigrationProposal(ctx, big.NewInt(1), big.NewInt(100))
	require.NoError(t, err)

	// Ensure that the Tx is mined.
	expectTxSuccess(t, netops, ctx, txHash, defaultTxQueryTimeout)()

	// Check migration status
	migrations, err := netops.ListMigrations(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, len(migrations))
}

// Approve Migration
func ApproveMigration(ctx context.Context, t *testing.T, netops MigrationOpsDsl, pending bool) {
	t.Log("Executing migration approve specification")

	// Ensure that the migration is waiting for approval
	migrations, err := netops.ListMigrations(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, len(migrations))

	// Approve migration
	txHash, err := netops.ApproveMigration(ctx, migrations[0].ID)
	require.NoError(t, err)

	// Ensure that the Tx is mined.
	expectTxSuccess(t, netops, ctx, txHash, defaultTxQueryTimeout)()

	// Check migration status
	migrations, err = netops.ListMigrations(ctx)
	require.NoError(t, err)

	if pending {
		require.Equal(t, 1, len(migrations))
	} else {

		require.Equal(t, 0, len(migrations))
	}
}

func NonValidatorApproveMigration(ctx context.Context, t *testing.T, netops MigrationOpsDsl) {
	t.Log("Executing non-validator approve migration specification")

	// Ensure that the migration is waiting for approval
	migrations, err := netops.ListMigrations(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, len(migrations))

	// Approve migration
	txHash, err := netops.ApproveMigration(ctx, migrations[0].ID)
	require.NoError(t, err)

	// Ensure that the Tx is mined.
	expectTxFail(t, netops, ctx, txHash, defaultTxQueryTimeout)()

	// Check migration status
	migrations, err = netops.ListMigrations(ctx)
	require.NoError(t, err)

	require.Greater(t, len(migrations), 0)
}

func ConfigureNewNetwork(ctx context.Context, t *testing.T, netops MigrationOpsDsl, rootDir string, numNodes int, listenAddresses []string) {
	// Set the MigrationConfig to true and migrate_from
	// update persistent peers

	// Ensure the root directory exists
	err := os.MkdirAll(rootDir, 0755)
	require.NoError(t, err)

	for i := range numNodes {
		// Create sub nodes
		nodeDir := filepath.Join(rootDir, fmt.Sprintf("new-node%d", i))
		err = os.MkdirAll(nodeDir, 0755)
		require.NoError(t, err)

		// Update the config file
		tomlFile := filepath.Join(nodeDir, "config.toml")
		cfg, err := config.LoadConfig(tomlFile)
		require.NoError(t, err)

		cfg.Migrations.Enable = true
		cfg.Migrations.MigrateFrom = listenAddresses[i]
		cfg.P2P.BootNodes = updatePersistentPeers(cfg.P2P.BootNodes)
		err = cfg.SaveAs(tomlFile)
		require.NoError(t, err, "failed to write config file")
	}
}

func CopyFiles(src, dst string) error {
	var srcFile, dstFile *os.File
	var err error

	// Open the source file for reading
	if srcFile, err = os.Open(src); err != nil {
		return err
	}
	defer srcFile.Close()

	// Create the destination file
	if dstFile, err = os.Create(dst); err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy the contents of the source file into the destination file
	if _, err = io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	// flush the destination file
	return dstFile.Sync()
}

func updatePersistentPeers(peers []string) []string {
	var updatedPeers []string
	for _, peer := range peers {
		// Update the peer address from
		// "37b6dc4f99e00833314891ba5e2e1f253ac58635@node0:26656"
		// to "37b6dc4f99e00833314891ba5e2e1f253ac58635@node0-1:26656"
		peerParts := strings.Split(peer, "@")
		nodeId := peerParts[0]
		address := strings.Split(peerParts[1], ":")
		updatedPeers = append(updatedPeers, fmt.Sprintf("%s@new-%s:%s", nodeId, address[0], address[1]))
	}
	return updatedPeers
}
