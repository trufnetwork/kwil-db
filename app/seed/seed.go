package seed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/key"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/peers/seeder"
)

func SeedCmd() *cobra.Command {
	var dir, chainID string
	var bootnodes []string

	cmd := &cobra.Command{
		Use:   "seed",
		Short: "Run a network seeder",
		Long:  "The `seed` command starts a peer seeder process to crawl and bootstrap the network. This does not use the kwild node config. It will bind to TCP port 6609, and store config and data in the specified directory.",
		Args:  cobra.NoArgs,

		RunE: func(cmd *cobra.Command, args []string) error {
			logger := log.New(log.WithWriter(os.Stdout), log.WithFormat(log.FormatUnstructured),
				log.WithName("SEEDER"))
			dir, err := expandPath(dir)
			if err != nil {
				return err
			}

			keyFile := filepath.Join(dir, config.NodeKeyFileName)
			nodeKey, err := key.LoadNodeKey(keyFile)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return err
				}
				nodeKey, err = crypto.GeneratePrivateKey(crypto.KeyTypeSecp256k1)
				if err != nil {
					return err
				}
				key.SaveNodeKey(keyFile, nodeKey)
			}

			cfg := &seeder.Config{
				Dir:        dir,
				ChainID:    chainID,
				Logger:     logger,
				ListenAddr: "0.0.0.0:6609",
				PeerKey:    nodeKey,
			}
			s, err := seeder.NewSeeder(cfg)
			if err != nil {
				return err
			}

			err = s.Start(cmd.Context(), bootnodes...)
			if err != nil && !errors.Is(err, context.Canceled) {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "~/.kwilseed", "seeder data directory")
	cmd.Flags().StringVar(&chainID, "chain-id", "kwil-testnet", "chain ID of the network to crawl")
	cmd.Flags().StringSliceVar(&bootnodes, "bootnodes", []string{}, "bootstrap nodes")

	return cmd
}

func expandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[2:])
	}
	return filepath.Abs(path)
}
