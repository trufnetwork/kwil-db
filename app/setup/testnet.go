package setup

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/custom"
	"github.com/trufnetwork/kwil-db/app/key"
	"github.com/trufnetwork/kwil-db/app/shared/bind"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/core/utils"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
	"github.com/trufnetwork/kwil-db/node"
)

// accept: #vals, #n-vals and set the first validator as the leader.

func TestnetCmd() *cobra.Command {
	var numVals, numNVals int
	var noPex, uniquePorts bool
	var startingPort uint64
	var outDir, chainID string
	var hostnames, allocs []string
	var paramFlags networkParams

	cmd := &cobra.Command{

		Use:   "testnet",
		Short: "Generate configuration for a new test network with multiple nodes",
		Long: "The `testnet` command generates a configuration for a new test network with multiple nodes.\n\n" +
			"For a configuration set that can be run on the same host, use the `--unique-ports` flag.",
		// Override the root command's PersistentPreRunE, so that we don't
		// try to read the config from a ~/.kwild directory
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			genCfg := config.DefaultGenesisConfig()
			genCfg, err := mergeNetworkParamFlags(genCfg, cmd, &paramFlags)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			// parse the allocs flag
			if cmd.Flags().Changed(allocsFlag) {
				allocs, err := parseAllocs(allocs)
				if err != nil {
					return display.PrintErr(cmd, err)
				}

				genCfg.Allocs = allocs
			}

			err = GenerateTestnetConfigs(&TestnetConfig{
				RootDir:      outDir,
				NumVals:      numVals,
				NumNVals:     numNVals,
				NoPex:        noPex,
				StartingPort: startingPort,
				Hostnames:    hostnames,
				ChainID:      chainID,
			}, &ConfigOpts{
				UniquePorts: uniquePorts,
				DnsHost:     false,
			}, genCfg)
			if err != nil {
				return display.PrintErr(cmd, err)
			}

			return display.PrintCmd(cmd, display.RespString(fmt.Sprintf("Generated testnet configuration in %s", outDir)))
		},
	}

	// root dir does not apply to this command. NOTE: probably this means we
	// need a top level "node" command with root and all the other config binds.
	// On the other hand, `setup reset` applies to a specific node instance...
	cmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		cmd.InheritedFlags().MarkHidden(bind.RootFlagName)
		cmd.Parent().HelpFunc()(c, s)
	})

	cmd.Flags().IntVarP(&numVals, "vals", "v", 3, "number of validators (includes the one leader)")
	cmd.Flags().IntVarP(&numNVals, "non-vals", "n", 0, "number of non-validators (default 0)")
	cmd.Flags().BoolVar(&noPex, "no-pex", false, "disable peer exchange")
	cmd.Flags().Uint64VarP(&startingPort, "port", "p", 6600, "starting P2P port for the nodes")
	cmd.Flags().StringVarP(&outDir, "out-dir", "o", ".testnet", "output directory for generated node root directories")
	cmd.Flags().BoolVarP(&uniquePorts, "unique-ports", "u", false, "use unique ports for each node")
	cmd.Flags().StringSliceVarP(&hostnames, "hostnames", "H", nil, "comma separated list of hostnames for the nodes")
	cmd.Flags().StringVarP(&chainID, "chain-id", "c", "kwil-testnet", "chain ID for the network")
	cmd.Flags().StringSliceVar(&allocs, allocsFlag, nil, "address and initial balance allocation(s) in the format id#keyType:amount")

	bindNetworkParamsFlags(cmd, &paramFlags)
	return cmd
}

type TestnetConfig struct {
	RootDir       string
	ChainID       string
	NumVals       int
	NumNVals      int
	NoPex         bool
	StartingPort  uint64
	StartingIP    string
	DnsNamePrefix string // optional and only used if DnsHost is true (default: node)
	Hostnames     []string
	Allocs        []string
}

type ConfigOpts struct {
	// UniquePorts is a flag to generate unique listening addresses
	// (JSON-RPC, HTTP, Admin, P2P, node RPC) for each node.
	// This is useful for testing multiple nodes on the same machine.
	// If it is used for generating a single config, it has no effect.
	UniquePorts bool

	// DnsHost is a flag to use DNS hostname as host in the config
	// instead of ip. It will be used together with DnsNamePrefix to generate
	// hostnames.
	// This is useful for testing nodes inside docker containers.
	DnsHost bool
}

func GenerateTestnetConfigs(cfg *TestnetConfig, opts *ConfigOpts, gencfg *config.GenesisConfig) error {
	if len(cfg.Hostnames) > 0 && len(cfg.Hostnames) != cfg.NumVals+cfg.NumNVals {
		return fmt.Errorf("if set, the number of hostnames %d must be equal to number of validators + number of non-validators %d",
			len(cfg.Hostnames), cfg.NumVals+cfg.NumNVals)
	}

	// ensure that the directory exists
	// expand the directory path
	outDir, err := node.ExpandPath(cfg.RootDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// generate Keys, so that the connection strings and the validator set can be generated before the node config files are generated
	var keys []*crypto.Secp256k1PrivateKey
	for range cfg.NumVals + cfg.NumNVals {
		priv := node.NewKey(rand.Reader)
		keys = append(keys, priv)
	}

	// key 0 is leader
	leaderPub := keys[0].Public()

	var bootNodes []string
	for i := range cfg.NumVals + cfg.NumNVals {
		pubKey := keys[i].Public()

		hostname := cfg.StartingIP
		if cfg.StartingIP == "" {
			hostname = "127.0.0.1"
		}
		if len(cfg.Hostnames) > 0 {
			hostname = cfg.Hostnames[i]
		}

		if opts.DnsHost {
			hostname = fmt.Sprintf("%s%d", cfg.DnsNamePrefix, i)
		}

		port := 6600
		if opts.UniquePorts {
			port = 6600 + i
		}

		bootNodes = append(bootNodes, node.FormatPeerString(pubKey.Bytes(), pubKey.Type(), hostname, port))
	}

	chainID := cfg.ChainID
	if chainID == "" {
		chainID = "kwil-testnet"
	}

	// update the rest of the genesis configuration (non network parameters)
	gencfg.ChainID = chainID
	gencfg.Leader = types.PublicKey{PublicKey: leaderPub}
	gencfg.Validators = make([]*types.Validator, cfg.NumVals)
	if gencfg.DBOwner == "" {
		signer := auth.GetUserSigner(keys[0])
		ident, err := authExt.GetIdentifierFromSigner(signer)
		if err != nil {
			return fmt.Errorf("failed to get identifier from user signer for dbOwner: %w", err)
		}
		gencfg.DBOwner = ident
	}

	for i := range cfg.NumVals {
		gencfg.Validators[i] = &types.Validator{
			AccountID: types.AccountID{
				Identifier: keys[i].Public().Bytes(),
				KeyType:    keys[i].Type(),
			},
			Power: 1,
		}
	}

	// generate the configuration for the nodes
	portOffset := 0
	for i := range cfg.NumVals + cfg.NumNVals {
		if opts.UniquePorts {
			portOffset = i
		}

		var externalAddress string
		if len(cfg.Hostnames) > 0 {
			externalAddress = cfg.Hostnames[i]
		}

		err = GenerateNodeRoot(&NodeGenConfig{
			PortOffset:      portOffset,
			IP:              cfg.StartingIP,
			NoPEX:           cfg.NoPex,
			RootDir:         filepath.Join(outDir, fmt.Sprintf("node%d", i)),
			NodeKey:         keys[i],
			Genesis:         gencfg,
			BootNodes:       bootNodes,
			ExternalAddress: externalAddress,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

type NodeGenConfig struct {
	RootDir    string
	PortOffset int
	DBPort     uint16 // leave zero for default plus any offset
	IP         string
	NoPEX      bool
	NodeKey    *crypto.Secp256k1PrivateKey
	Genesis    *config.GenesisConfig

	BootNodes       []string
	ExternalAddress string
}

func GenerateNodeRoot(ncfg *NodeGenConfig) error {
	cfg := custom.DefaultConfig() // not config.DefaultConfig(), so custom command config is used

	// P2P
	port := uint64(ncfg.PortOffset + 6600)
	host := "0.0.0.0"
	if ncfg.IP != "" {
		host = ncfg.IP
	}
	cfg.P2P.ListenAddress = net.JoinHostPort(host, strconv.FormatUint(port, 10))
	cfg.P2P.Pex = !ncfg.NoPEX
	cfg.P2P.BootNodes = ncfg.BootNodes
	cfg.P2P.ExternalAddress = ncfg.ExternalAddress

	// Consensus
	cfg.Consensus.EmptyBlockTimeout = cfg.Consensus.ProposeTimeout

	// DB
	dbPort := ncfg.DBPort
	if dbPort == 0 {
		dbPort = uint16(5432 + ncfg.PortOffset)
	}
	cfg.DB.Port = strconv.FormatUint(uint64(dbPort), 10)

	// RPC
	cfg.RPC.ListenAddress = net.JoinHostPort("0.0.0.0", strconv.FormatUint(uint64(8484+ncfg.PortOffset), 10))

	// Admin RPC
	cfg.Admin.ListenAddress = net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(8584+ncfg.PortOffset), 10))

	return GenerateNodeDir(ncfg.RootDir, ncfg.Genesis, cfg, ncfg.NodeKey, "")
}

type TestnetNodeConfig struct {
	// Config is the node configuration.
	Config *config.Config
	// DirName is the directory name of the node.
	// If the testnetDir is "testnet" and the DirName is "node0",
	// the full path of the node is "testnet/node0".
	DirName string
	// PrivateKey is the private key of the node.
	PrivateKey *crypto.Secp256k1PrivateKey
}

// GenerateTestnetDir generates a testnet configuration for multiple nodes.
// It is a minimal function that takes full configurations.
// Most users should use GenerateTestnetConfigs instead.
// copies the snapshot file to each node directory if it is not empty.
func GenerateTestnetDir(testnetDir string, genesis *config.GenesisConfig, nodes []*TestnetNodeConfig, snapshot string) error {
	if err := os.MkdirAll(testnetDir, 0755); err != nil {
		return err
	}

	for _, node := range nodes {
		if err := GenerateNodeDir(filepath.Join(testnetDir, node.DirName), genesis, node.Config, node.PrivateKey, snapshot); err != nil {
			return err
		}
	}

	return nil
}

// GenerateNodeDir generates a node configuration directory.
// It is a minimal function that takes a full configuration.
// Most users should use GenerateNodeRoot instead.
func GenerateNodeDir(rootDir string, genesis *config.GenesisConfig, node *config.Config, privateKey *crypto.Secp256k1PrivateKey, snapshot string) error {
	if err := os.MkdirAll(rootDir, 0755); err != nil {
		return err
	}

	if snapshot != "" {
		node.GenesisState = "genesis-state.sql.gz"
		if err := utils.CopyFile(snapshot, config.GenesisStateFileName(rootDir)); err != nil {
			return err
		}
	}

	if err := node.SaveAs(config.ConfigFilePath(rootDir)); err != nil {
		return err
	}

	if err := genesis.SaveAs(config.GenesisFilePath(rootDir)); err != nil {
		return err
	}

	return key.SaveNodeKey(config.NodeKeyFilePath(rootDir), privateKey)
}
