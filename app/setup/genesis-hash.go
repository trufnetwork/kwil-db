package setup

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/node"
)

var (
	genesisHashLong = `Compute the genesis hash a snapshot file can be provided to compute the genesis hash from a snapshot file instead of the database. The snapshot can either be a .sql or .sql.gz file.

By default, it will print the genesis hash to stdout. To specify a genesis file to update as well specify the path to the genesis file as the second argument.

NOTE: To create a new snapshot file, use the ` + "`snapshot create`" + ` command.`

	genesisHashExample = `# Compute the genesis hash from a snapshot file and update a genesis file
kwild setup genesis-hash /path/to/snapshot.sql.gz [~/.kwild/genesis.json]`
)

func GenesisHashCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "genesis-hash",
		Short:             "Compute genesis hash from a snapshot file, and optionally update genesis.json.",
		Long:              genesisHashLong,
		Example:           genesisHashExample,
		Args:              cobra.RangeArgs(1, 2),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			appHash, err := appHashFromSnapshotFile(args[0])
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			if len(args) > 1 {
				err := writeAndReturnGenesisHash(args[1], appHash)
				if err != nil {
					return display.PrintErr(cmd, err)
				}
			}
			return display.PrintCmd(cmd, &genesisHashRes{
				Hash: base64.StdEncoding.EncodeToString(appHash),
			})
		},
	}

	return cmd
}

// appHashFromSnapshotFile computes the app hash from a snapshot file.
func appHashFromSnapshotFile(filePath string) ([]byte, error) {
	filePath, err := node.ExpandPath(filePath)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var reader io.Reader
	if filepath.Ext(filePath) == ".gz" {
		reader, err = gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
	} else {
		reader = file
	}

	hash := sha256.New()

	_, err = io.Copy(hash, reader)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func writeAndReturnGenesisHash(genesisFile string, appHash []byte) error {
	genesisFile, err := node.ExpandPath(genesisFile)
	if err != nil {
		return err
	}

	cfg, err := config.LoadGenesisConfig(genesisFile)
	if err != nil {
		return err
	}

	cfg.StateHash = appHash

	return cfg.SaveAs(genesisFile)
}

type genesisHashRes struct {
	Hash string `json:"genesis_hash"`
}

func (g *genesisHashRes) MarshalJSON() ([]byte, error) {
	type Alias genesisHashRes
	return json.Marshal(*(*Alias)(g))
}

func (g *genesisHashRes) MarshalText() (text []byte, err error) {
	return []byte("Genesis App Hash: " + g.Hash), nil
}
