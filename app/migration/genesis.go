package migration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/rpc"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node"
	"github.com/trufnetwork/kwil-db/node/migrations"
	"github.com/trufnetwork/kwil-db/node/snapshotter"
)

var (
	genesisFileName  = "genesis_info.json"
	snapshotFileName = "snapshot.sql.gz"

	genesisStateLong = "Download the genesis state for the new network from a trusted node on the source network. The genesis state includes the genesis info file (`genesis_info.json`) and genesis snapshot (`snapshot.sql.gz`). The genesis state is saved in the root directory specified by the `--out-dir` flag. If there is no approved migration or if the migration has not started yet, the command will return a message indicating that there is no genesis state to download. The genesis info file includes the app hash, validators and the migration settings required to manually start the new network."

	genesisStateExample = `# Download the genesis state to the default output directory (~/.genesis-state)
kwild migrate genesis-state

# Download the genesis state to a custom root directory
kwild migrate genesis-state --out-dir /path/to/out/dir`
)

func genesisStateCmd() *cobra.Command {
	var rootDir string
	cmd := &cobra.Command{
		Use:     "genesis-state",
		Short:   "Download the genesis state corresponding to the ongoing migration.",
		Long:    genesisStateLong,
		Example: genesisStateExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clt, err := rpc.AdminSvcClient(ctx, cmd)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			// Request for the genesis state {genesis file data, snapshot metadata, migration state: active, start, endHeight}
			metadata, err := clt.GenesisState(ctx)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			// this check should change in every version:
			// For backwards compatibility, we should be able to unmarshal structs from previous versions.
			// Since v0.9 is our first time supporting migration, we only need to check for v0.9.
			if metadata.Version != migrations.MigrationVersion {
				return display.PrintErr(cmd, fmt.Errorf("genesis state download is incompatible. Received version: %d, supported versions: [%d]", metadata.Version, migrations.MigrationVersion))
			}

			if metadata.MigrationState.Status == types.GenesisMigration {
				return display.PrintErr(cmd, fmt.Errorf("genesis state command should only be used against the nodes from a network being migrated from"))
			}
			// If there is no active migration or if the migration has not started yet, return the migration state
			// indicating that there is no genesis state to download.
			if metadata.MigrationState.Status.NoneActive() ||
				metadata.MigrationState.Status == types.ActivationPeriod ||
				metadata.GenesisInfo == nil || metadata.SnapshotMetadata == nil {
				return display.PrintCmd(cmd, &MigrationState{
					Info: metadata.MigrationState,
				})
			}

			// ensure the root directory exists
			expandedDir, err := node.ExpandPath(rootDir)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			if err = os.MkdirAll(expandedDir, 0755); err != nil {
				return display.PrintErr(cmd, err)
			}

			// retrieve the snapshot metadata
			var snapshotMetadata snapshotter.Snapshot
			if err = json.Unmarshal(metadata.SnapshotMetadata, &snapshotMetadata); err != nil {
				return display.PrintErr(cmd, err)
			}

			genInfo := &genesisInfo{
				AppHash:     metadata.GenesisInfo.AppHash,
				Validators:  metadata.GenesisInfo.Validators,
				StartHeight: metadata.MigrationState.StartHeight,
				EndHeight:   metadata.MigrationState.EndHeight,
			}

			// Print the genesis state to the genesis.json file
			genesisFile := filepath.Join(expandedDir, genesisFileName)
			err = genInfo.saveAs(genesisFile)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			// create snapshot file
			snapshotFile := filepath.Join(expandedDir, snapshotFileName)
			snapshot, err := os.Create(snapshotFile)
			if err != nil {
				return display.PrintErr(cmd, err)
			}
			defer snapshot.Close()

			// retrieve all the snapshot chunks
			for i := range snapshotMetadata.ChunkCount {
				chunk, err := clt.GenesisSnapshotChunk(ctx, snapshotMetadata.Height, i)
				if err != nil {
					return display.PrintErr(cmd, err)
				}
				n, err := snapshot.Write(chunk)
				if err != nil {
					return display.PrintErr(cmd, err)
				}
				if n != len(chunk) {
					return display.PrintErr(cmd, fmt.Errorf("failed to write snapshot chunk to file"))
				}
			}

			// Print the migration state
			return display.PrintCmd(cmd, &MigrationState{
				Info:        metadata.MigrationState,
				GenesisFile: genesisFile,
				Snapshot:    snapshotFile,
			})

		},
	}

	rpc.BindRPCFlags(cmd)
	cmd.Flags().StringVarP(&rootDir, "out-dir", "o", "~/.genesis-state", "The target directory for downloading the genesis state files.")
	return cmd
}

type genesisInfo struct {
	// AppHash is the application hash of the old network at the StartHeight
	AppHash []byte `json:"app_hash"`
	// Validators is the list of validators that the new network should start with
	Validators []*types.Validator `json:"validators"`

	StartHeight int64 `json:"start_height"`
	EndHeight   int64 `json:"end_height"`
}

func (g *genesisInfo) saveAs(file string) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(file, data, 0644)
}

type MigrationState struct {
	Info        types.MigrationState `json:"state"`
	GenesisFile string               `json:"genesis_file"`
	Snapshot    string               `json:"snapshot"`
}

func (m *MigrationState) MarshalText() ([]byte, error) {
	if m.Info.Status == types.NoActiveMigration {
		return []byte("No active migration found."), nil
	}

	if m.Info.Status == types.ActivationPeriod {
		return []byte(fmt.Sprintf("No genesis state to download yet. Migration is set to start at block height: %d", m.Info.StartHeight)), nil
	}

	if m.GenesisFile == "" {
		return []byte("No genesis.json file data found."), nil
	}

	if m.Snapshot == "" {
		return []byte("No snapshot.sql.gz file data found."), nil
	}

	return []byte(fmt.Sprintf("Migration State:\n"+
		"\tStart Height: %d\n"+
		"\tEnd Height: %d\n"+
		"\tGenesis Info File: %s\n"+
		"\tSnapshot File: %s\n",
		m.Info.StartHeight, m.Info.EndHeight, m.GenesisFile, m.Snapshot)), nil
}

func (m *MigrationState) MarshalJSON() ([]byte, error) {
	type alias MigrationState
	return json.Marshal((*alias)(m)) // slice off methods to avoid recursive call
}
