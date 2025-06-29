package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/trufnetwork/kwil-db/app/setup"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node"
	ethdeployer "github.com/trufnetwork/kwil-db/test/integration/eth-deployer"
)

var userGroupID = flag.String("ugid", "", "user id and group id to use for the test containers; format: <user_id>:<group_id>")

func getFlagUserGroupID() (ids *[2]string, err error) {
	if *userGroupID == "" {
		return ids, nil
	}

	if !strings.Contains(*userGroupID, ":") {
		return ids, fmt.Errorf("invalid user id and group id format: %s", *userGroupID)
	}

	segs := strings.Split(*userGroupID, ":")
	if len(segs) != 2 {
		return ids, fmt.Errorf("invalid user id and group id format: %s", *userGroupID)
	}

	ids = new([2]string)
	ids[0] = segs[0]
	ids[1] = segs[1]
	return ids, nil
}

// TestConfig is the configuration for the test
type TestConfig struct {
	// REQUIRED: ClientDriver is the driver to use for the client
	ClientDriver ClientDriver
	// REQUIRED: Network is the network configuration
	Network *NetworkConfig
	// OPTIONAL: ContainerStartTimeout is the timeout for starting a container.
	// If not set, it will default to 30 seconds.
	ContainerStartTimeout time.Duration
	// OPTIONAL: InitialServices are the services that should be run during setup
	InitialServices []string
	// OPTIONAL: DockerNetwork is the name of the docker network to use, if not set,
	// creates a new network with a random name
	DockerNetwork string
	// ServicesPrefix is the prefix to use for the kwild and pg services
	ServicesPrefix string
	// PortOffset is the offset to use for the kwild and pg service ports
	PortOffset int
}

func (c *TestConfig) ensureDefaults(t *testing.T) {
	if c.ContainerStartTimeout == 0 {
		c.ContainerStartTimeout = 30 * time.Second
	}

	if c.Network == nil {
		t.Fatal("Network is required")
	}

	if c.ClientDriver == "" {
		t.Fatal("ClientDriver is required")
	}

	c.Network.ensureDefaults(t)
}

// NetworkConfig is the configuration for a test network
type NetworkConfig struct {
	// REQUIRED: Nodes is the list of nodes in the network
	Nodes []*NodeConfig

	// OPTIONAL: DBOwner is the initial wallet address that owns the database.
	DBOwner string

	// OPTIONAL: ConfigureGenesis is a function that alters the genesis configuration
	ConfigureGenesis func(*config.GenesisConfig)

	GenesisSnapshot string
	// OPTIONAL: ExtraServices are services that should be run with the test. The test
	// Automatically runs kwild and Postgres, but this allows for geth, kgw,
	// etc. to run as well.
	ExtraServices []*CustomService // TODO: we need more in this service definition struct. Will come back when I am farther along
}

func (n *NetworkConfig) ensureDefaults(t *testing.T) {
	if n.ConfigureGenesis == nil {
		n.ConfigureGenesis = func(*config.GenesisConfig) {}
	}

	if n.DBOwner == "" {
		n.DBOwner = "0xabc"
	}

	if n.Nodes == nil {
		t.Fatal("Nodes is required")
	}
}

// NodeConfig is a configuration that allows external users to specify properties of the node
type NodeConfig struct {
	// OPTIONAL: DockerImage is the docker image to use
	// By default, it is "kwild:latest"
	DockerImage   string
	NoHealthCheck bool

	// OPTIONAL: Validator is true if the node is a validator
	// By default, it is true.
	Validator bool

	// OPTIONAL: PrivateKey is the private key to use for the node.
	// If not set, a random key will be generated.
	PrivateKey *crypto.Secp256k1PrivateKey

	// OPTIONAL: Configure is a function that alter's the node's configuration
	Configure func(*config.Config)
}

// DefaultNodeConfig returns a default node configuration
func DefaultNodeConfig() *NodeConfig {
	pk, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &NodeConfig{
		DockerImage: "kwild:latest",
		Validator:   true,
		PrivateKey:  pk.(*crypto.Secp256k1PrivateKey),
		Configure:   func(*config.Config) {},
	}
}

// CustomNodeConfig provides a default node configuration that can be customized
func CustomNodeConfig(f func(*NodeConfig)) *NodeConfig {
	cfg := DefaultNodeConfig()
	f(cfg)
	return cfg
}

type ExtraNode struct {
	ServiceName       string
	ExposedChainRPC   string
	UnexposedChainRPC string
}

type Testnet struct {
	Nodes   []KwilNode
	testCtx *testingContext
	EthNode *EthNode

	// include kgw
	// TODO: merge EthNode
	ExtraNodes []*ExtraNode
}

func (t *Testnet) SearchExtraNode(name string) (*ExtraNode, bool) {
	for _, node := range t.ExtraNodes {
		if node.ServiceName == name {
			return node, true
		}
	}
	return nil, false
}

func (t *Testnet) TestDir() string {
	return t.testCtx.tmpdir
}

// ExtraServiceEndpoint gets the endpoint for an extra service that was configured in the testnet
func (t *Testnet) ExtraServiceEndpoint(ctx context.Context, serviceName string, protocol string, port string) (string, error) {
	ct, ok := t.testCtx.containers[serviceName]
	if !ok {
		return "", fmt.Errorf("container not found")
	}

	exposed, unexposed, err := getEndpoints(ct, ctx, nat.Port(port), protocol)
	fmt.Printf("exposed: %s, unexposed: %s\n", exposed, unexposed)
	return exposed, err
}

func CreateDockerNetwork(ctx context.Context, t *testing.T) (*testcontainers.DockerNetwork, error) {
	dockerNetwork, err := ensureNetworkExist(ctx, t.Name())
	require.NoError(t, err)

	// the network will be removed by the testSetup that created it
	t.Cleanup(func() {
		if !t.Failed() {
			t.Logf("teardown docker network %s from %s", dockerNetwork.Name, t.Name())
			err := dockerNetwork.Remove(ctx)
			require.NoErrorf(t, err, "failed to teardown network %s", dockerNetwork.Name)
		}
	})

	return dockerNetwork, nil
}

func DeployETHNode(t *testing.T, ctx context.Context, dockerName string, privKey *crypto.Secp256k1PrivateKey) *EthNode {
	tmpDir, err := os.MkdirTemp("", "TestKwil")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("using temp dir for deploying Eth node %v", tmpDir)

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Retaining data for failed test at path %v", tmpDir)
			return
		}
		os.RemoveAll(tmpDir)
	})

	hardHatService := &CustomService{
		ServiceName:  "hardhat",
		DockerImage:  "kwildb/hardhat:latest",
		ExposedPort:  "8545",
		InternalPort: "8545",
	}
	services := []*CustomService{hardHatService}

	ugids, err := getFlagUserGroupID()
	require.NoError(t, err)

	composePath, _, err := generateCompose(dockerName, tmpDir, nil, services, ugids, "", 0)
	require.NoError(t, err)

	testCtx := &testingContext{
		containers:  make(map[string]*testcontainers.DockerContainer),
		networkName: dockerName,
		composePath: composePath,
	}

	runDockerCompose(ctx, t, testCtx, composePath, []*ServiceDefinition{{Name: "hardhat"}}, 30*time.Second)

	// check if the hardhat service is running
	ctr, ok := testCtx.containers["hardhat"]
	require.True(t, ok, "hardhat service not found")

	// get the endpoint for the hardhat service
	exposedChainRPC, unexposedChainRPC, err := getEndpoints(ctr, ctx, "8545", "ws")
	require.NoError(t, err, "failed to get endpoints for hardhat service")

	var deployers []*ethdeployer.Deployer

	// Deploy 2 escrow contracts
	for i := range 2 {
		ethDeployer, err := ethdeployer.NewDeployer(exposedChainRPC, privKey, 5)
		require.NoError(t, err, "failed to get eth deployer")

		// Deploy Token and Escrow contracts
		err = ethDeployer.Deploy()
		require.NoError(t, err, "failed to deploy contracts")

		deployers = append(deployers, ethDeployer)
		t.Logf("Deployed escrow contract %d at address %s", i, ethDeployer.EscrowAddress())
	}

	return &EthNode{
		ExposedChainRPC:   exposedChainRPC,
		UnexposedChainRPC: unexposedChainRPC,
		Deployers:         deployers,
	}
}

func SetupTests(t *testing.T, testConfig *TestConfig) *Testnet {
	testConfig.ensureDefaults(t)

	// we create a temporary directory to store the testnet configs
	tmpDir, err := os.MkdirTemp("", "TestKwil")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("using temp dir %v", tmpDir)

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Retaining data for failed test at path %v", tmpDir)
			return
		}
		os.RemoveAll(tmpDir)
	})
	ctx := context.Background()

	var dockerNetworkName string
	if testConfig.DockerNetwork == "" {
		dockerNetwork, err := CreateDockerNetwork(ctx, t)
		require.NoError(t, err)
		dockerNetworkName = dockerNetwork.Name
	} else {
		dockerNetworkName = testConfig.DockerNetwork
	}

	ugids, err := getFlagUserGroupID()
	require.NoError(t, err)

	composePath, nodeInfo, err := generateCompose(dockerNetworkName, tmpDir, testConfig.Network.Nodes, testConfig.Network.ExtraServices, ugids, testConfig.ServicesPrefix, testConfig.PortOffset) //TODO: need user id and groups
	require.NoError(t, err)

	require.Equal(t, len(testConfig.Network.Nodes), len(nodeInfo)) // ensure that the number of nodes is the same as the number of node info
	if len(nodeInfo) == 0 {
		t.Fatal("at least one node is required")
	}

	testCtx := &testingContext{
		config:          testConfig,
		containers:      make(map[string]*testcontainers.DockerContainer),
		composePath:     composePath, // used if we need to add more services later
		generatedConfig: nil,
		networkName:     dockerNetworkName,
		tmpdir:          tmpDir,
	}

	genesisConfig := config.DefaultGenesisConfig()
	genesisConfig.DBOwner = testConfig.Network.DBOwner
	testConfig.Network.ConfigureGenesis(genesisConfig)

	generatedNodes := make([]*kwilNode, len(testConfig.Network.Nodes))
	testnetNodeConfigs := make([]*setup.TestnetNodeConfig, len(testConfig.Network.Nodes))
	serviceSet := map[string]struct{}{}
	servicesToRun := []*ServiceDefinition{}

	serviceFilter := make(map[string]struct{})
	for _, node := range testConfig.InitialServices {
		serviceFilter[node] = struct{}{}
	}
	filterServices := len(serviceFilter) > 0

	generatedConfig := &generatedNodeConfig{
		nodeConfigs: make(map[string]*config.Config),
	}

	for i, nodeCfg := range testConfig.Network.Nodes {
		var firstNode *kwilNode
		if i == 0 {
			firstNode = nil
		} else {
			firstNode = generatedNodes[0]
		}

		generatedNodes[i], err = nodeCfg.makeNode(nodeInfo[i], i == 0, firstNode)
		require.NoError(t, err)

		// ensure unique service names for kwild and Postgres
		_, ok := serviceSet[nodeInfo[i].KwilNodeServiceName]
		require.Falsef(t, ok, "duplicate service name %s", nodeInfo[i].KwilNodeServiceName)
		serviceSet[nodeInfo[i].KwilNodeServiceName] = struct{}{}

		_, ok = serviceSet[nodeInfo[i].PostgresServiceName]
		require.Falsef(t, ok, "duplicate service name %s", nodeInfo[i].PostgresServiceName)
		serviceSet[nodeInfo[i].PostgresServiceName] = struct{}{}

		// we append two services for each node: kwild and Postgres
		// kwild:
		if _, ok := serviceFilter[nodeInfo[i].KwilNodeServiceName]; ok || !filterServices {
			servicesToRun = append(servicesToRun, &ServiceDefinition{
				Name:    nodeInfo[i].KwilNodeServiceName,
				WaitMsg: &kwildWaitMsg,
			})
		}

		// Postgres:
		if _, ok := serviceFilter[nodeInfo[i].PostgresServiceName]; ok || !filterServices {
			servicesToRun = append(servicesToRun, &ServiceDefinition{
				Name:    nodeInfo[i].PostgresServiceName,
				WaitMsg: &postgresWaitMsg,
			})
		}

		// if i == 0, then it is the first node and will be the leader.
		// All nodes that are validators, including the leader, will be added to the Validator list
		if i == 0 {
			if !nodeCfg.Validator {
				t.Fatal("first node must be a validator")
			}

			genesisConfig.Leader = types.PublicKey{PublicKey: nodeCfg.PrivateKey.Public()}
		}

		if nodeCfg.Validator {
			genesisConfig.Validators = append(genesisConfig.Validators, &types.Validator{
				AccountID: types.AccountID{
					Identifier: nodeCfg.PrivateKey.Public().Bytes(),
					KeyType:    nodeCfg.PrivateKey.Type(),
				},
				Power: 1,
			})
		}

		testnetNodeConfigs[i] = &setup.TestnetNodeConfig{
			PrivateKey: nodeCfg.PrivateKey,
			DirName:    generatedNodes[i].generatedInfo.KwilNodeServiceName,
			Config:     generatedNodes[i].config,
		}

		generatedConfig.nodeConfigs[nodeInfo[i].KwilNodeServiceName] = generatedNodes[i].config
	}

	generatedConfig.genesisConfig = genesisConfig
	require.NoError(t, genesisConfig.SanityChecks())

	// validate the user-provided services
	for _, svc := range testConfig.Network.ExtraServices {
		_, ok := serviceSet[svc.ServiceName]
		require.Falsef(t, ok, "duplicate service name %s", svc.ServiceName)
		serviceSet[svc.ServiceName] = struct{}{}

		var waitMsg *string
		if svc.WaitMsg != "" {
			waitMsg = &svc.WaitMsg
		}

		servicesToRun = append(servicesToRun, &ServiceDefinition{
			Name:    svc.ServiceName,
			WaitMsg: waitMsg,
		})
	}

	err = setup.GenerateTestnetDir(tmpDir, genesisConfig, testnetNodeConfigs, testConfig.Network.GenesisSnapshot)
	require.NoError(t, err)

	testCtx.generatedConfig = generatedConfig

	runDockerCompose(ctx, t, testCtx, composePath, servicesToRun, testConfig.ContainerStartTimeout)

	tp := &Testnet{
		testCtx: testCtx,
	}

	for _, node := range generatedNodes {
		node.testCtx = testCtx
		tp.Nodes = append(tp.Nodes, node)
	}

	for _, svc := range testConfig.Network.ExtraServices {
		// check if that service is running
		ctr, ok := testCtx.containers[svc.ServiceName]
		require.True(t, ok, "%s service not found", svc.ServiceName)

		// get the endpoint for the hardhat service
		exposedChainRPC, unexposedChainRPC, err := getEndpoints(ctr, ctx, nat.Port(svc.InternalPort), svc.ServiceProto)
		require.NoError(t, err, "failed to get endpoints for hardhat service")

		tp.ExtraNodes = append(tp.ExtraNodes, &ExtraNode{
			ServiceName:       svc.ServiceName,
			ExposedChainRPC:   exposedChainRPC,
			UnexposedChainRPC: unexposedChainRPC,
		})
	}

	return tp
}

func (tt *Testnet) ServiceContainer(t *testing.T, serviceName string) (*testcontainers.DockerContainer, error) {
	ct, ok := tt.testCtx.containers[serviceName]
	if !ok {
		return nil, fmt.Errorf("container %s not found", serviceName)
	}
	return ct, nil
}

func (t *Testnet) NetworkName() string {
	return t.testCtx.networkName
}

var (
	kwildWaitMsg    string = "Committed Block"
	postgresWaitMsg string = `listening on IPv4 address "0.0.0.0", port 5432`
)

// ServiceDefinition is a definition of a service in a docker-compose file
type ServiceDefinition struct {
	Name    string
	WaitMsg *string // if nil, no wait
}

// runDockerCompose runs docker-compose with the given compose file
func runDockerCompose(ctx context.Context, t *testing.T, testCtx *testingContext, composePath string, services []*ServiceDefinition, startTimeout time.Duration) {
	var dc compose.ComposeStack
	var err error
	dc, err = compose.NewDockerCompose(composePath)
	require.NoError(t, err)

	ctxUp, cancel := context.WithCancel(ctx)

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Stopping but keeping containers for inspection after failed test: %v", dc.Services())
			time.Sleep(5 * time.Second)
			svcs := dc.Services()
			slices.Sort(svcs)
			for _, svc := range svcs {
				ct, err := dc.ServiceContainer(ctx, svc)
				if err != nil {
					t.Logf("could not get container %v: %v", svc, err)
					continue
				}
				err = ct.Stop(ctx, nil)
				if err != nil {
					t.Logf("could not stop container %v: %v", svc, err)
				}
			}
			return
		}
		t.Logf("teardown %s", dc.Services())
		err := dc.Down(ctx, compose.RemoveVolumes(true))
		require.NoErrorf(t, err, "failed to teardown %s", dc.Services())
		cancel() // no context leak
	})

	serviceNames := make([]string, len(services))
	for i, svc := range services {
		if svc.WaitMsg != nil {
			// wait for the service to be ready
			dc = dc.WaitForService(svc.Name, wait.NewLogStrategy(*svc.WaitMsg).WithStartupTimeout(startTimeout))
		}
		serviceNames[i] = svc.Name
	}

	err = dc.Up(ctxUp, compose.Wait(true), compose.RunServices(serviceNames...))
	t.Log("docker-compose up done")
	// wait as some protection against RPC errors with chain_info.
	// This was in the old tests, so I retain it here.
	time.Sleep(3 * time.Second)
	require.NoError(t, err)

	for _, svc := range services {
		ct, err := dc.ServiceContainer(ctx, svc.Name)
		require.NoError(t, err)
		require.NotNil(t, ct)
		testCtx.containers[svc.Name] = ct
	}
}

// makeNode prepares a node for the test network.
// It takes the node's config specified by the user, the node's info generated as part
// of the network setup, and the first node's info (used for bootstrapping).
func (c *NodeConfig) makeNode(generated *generatedNodeInfo, isFirstNode bool, firstNode *kwilNode) (*kwilNode, error) {
	defaultConf := config.DefaultConfig()
	conf := config.DefaultConfig()

	// set this to 1sec by default for tests, can be configured by the user to something else
	// through configure function depending on the test
	conf.Consensus.EmptyBlockTimeout = types.Duration(1 * time.Second)

	c.Configure(conf)

	// there are some configurations that the user cannot set, as they will screw up the test.
	// These are:
	// --admin.listen
	// --rpc.listen
	// --p2p.listen
	// --db.host
	// --db.port
	// --db.user
	// --db.password
	// --db.name
	// --p2p.bootnodes
	ensureEq := func(name string, a, b interface{}) error {
		if a != b {
			return fmt.Errorf("configuration %s cannot be custom configured in tests", name)
		}
		return nil
	}
	err := errors.Join(
		ensureEq("admin.listen", conf.Admin.ListenAddress, defaultConf.Admin.ListenAddress),
		ensureEq("rpc.listen", conf.RPC.ListenAddress, defaultConf.RPC.ListenAddress),
		ensureEq("p2p.listen", conf.P2P.ListenAddress, defaultConf.P2P.ListenAddress),
		ensureEq("db.host", conf.DB.Host, defaultConf.DB.Host),
		ensureEq("db.port", conf.DB.Port, defaultConf.DB.Port),
		ensureEq("db.user", conf.DB.User, defaultConf.DB.User),
		ensureEq("db.password", conf.DB.Pass, defaultConf.DB.Pass),
		ensureEq("db.name", conf.DB.DBName, defaultConf.DB.DBName),
		ensureEq("p2p.bootnodes", len(conf.P2P.BootNodes), len(defaultConf.P2P.BootNodes)), // []string is not comparable, but it should be empty anyways
	)
	if err != nil {
		return nil, err
	}

	// these configurations set here will be combined with the configs hard-coded
	// in node-compose.yml.template. There, we hardcore things like Postgres connection
	// info, rpc endpoints (which don't concern us since the container maps ports to the host),
	// and other things that are not relevant to the test.

	// setting p2p configs
	if !isFirstNode {
		// if this is not the first node, we should set the first node as the bootnode
		conf.P2P.BootNodes = []string{node.FormatPeerString(firstNode.nodeTestConfig.PrivateKey.Public().Bytes(), firstNode.nodeTestConfig.PrivateKey.Public().Type(), firstNode.generatedInfo.KwilNodeServiceName, p2pPort)}

		if conf.StateSync.Enable {
			conf.StateSync.TrustedProviders = conf.P2P.BootNodes
		}
	}

	return &kwilNode{
		config:         conf,
		nodeTestConfig: c,
		generatedInfo:  generated,
	}, nil
}

func KwildServiceDefinition(name string) *ServiceDefinition {
	return &ServiceDefinition{
		Name:    name,
		WaitMsg: &kwildWaitMsg,
	}
}

func PostgresServiceDefinition(name string) *ServiceDefinition {
	return &ServiceDefinition{
		Name:    name,
		WaitMsg: &postgresWaitMsg,
	}
}

func NewServiceDefinition(name string, waitMsg string) *ServiceDefinition {
	return &ServiceDefinition{
		Name:    name,
		WaitMsg: &waitMsg,
	}
}

func (tt *Testnet) RunServices(t *testing.T, ctx context.Context, services []*ServiceDefinition, startTimeout time.Duration) {
	runDockerCompose(ctx, t, tt.testCtx, tt.testCtx.composePath, services, startTimeout)
}

type generatedNodeConfig struct {
	genesisConfig *config.GenesisConfig
	nodeConfigs   map[string]*config.Config // string is the kwild node service name
}

type testingContext struct {
	config          *TestConfig
	composePath     string
	containers      map[string]*testcontainers.DockerContainer
	generatedConfig *generatedNodeConfig
	networkName     string
	tmpdir          string
}
type kwilNode struct {
	config         *config.Config
	nodeTestConfig *NodeConfig
	testCtx        *testingContext
	generatedInfo  *generatedNodeInfo
}

type EthNode struct {
	ExposedChainRPC   string
	UnexposedChainRPC string

	Deployers []*ethdeployer.Deployer
}

func (k *kwilNode) PrivateKey() *crypto.Secp256k1PrivateKey {
	return k.nodeTestConfig.PrivateKey
}

func (k *kwilNode) PublicKey() *crypto.Secp256k1PublicKey {
	return k.nodeTestConfig.PrivateKey.Public().(*crypto.Secp256k1PublicKey)
}

func (k *kwilNode) IsValidator() bool {
	return k.nodeTestConfig.Validator
}

func (k *kwilNode) Config() *config.Config {
	return k.config
}

func (k *kwilNode) JSONRPCClient(t *testing.T, ctx context.Context, opts *ClientOptions) JSONRPCClient {
	container, ok := k.testCtx.containers[k.generatedInfo.KwilNodeServiceName]
	if !ok {
		t.Fatalf("container %s not found", k.generatedInfo.KwilNodeServiceName)
	}

	endpoint, _, err := kwildJSONRPCEndpoints(container, ctx)
	require.NoError(t, err)

	if opts != nil && opts.Endpoint != "" {
		endpoint = opts.Endpoint
	}

	client, err := getNewClientFn(k.testCtx.config.ClientDriver)(ctx, endpoint, t.Logf, k.testCtx, opts)
	require.NoError(t, err)

	return client
}

func (k *kwilNode) AdminClient(t *testing.T, ctx context.Context) *AdminClient {
	container, ok := k.testCtx.containers[k.generatedInfo.KwilNodeServiceName]
	if !ok {
		t.Fatalf("container %s not found", k.generatedInfo.KwilNodeServiceName)
	}

	return &AdminClient{
		container: container,
	}
}

func (k *kwilNode) JSONRPCEndpoint(t *testing.T, ctx context.Context) (string, string, error) {
	container, ok := k.testCtx.containers[k.generatedInfo.KwilNodeServiceName]
	if !ok {
		t.Fatalf("container %s not found", k.generatedInfo.KwilNodeServiceName)
	}

	return kwildJSONRPCEndpoints(container, ctx)
}

// PeerID returns the peer ID of the node.
// This is of the format <hexPubKey#keyType>
func (k *kwilNode) PeerID() string {
	pubkey := k.PrivateKey().Public()
	return fmt.Sprintf("%s#%s", hex.EncodeToString(pubkey.Bytes()), pubkey.Type())
}

func (k *kwilNode) PostgresEndpoint(t *testing.T, ctx context.Context, name string) (string, string, error) {
	container, ok := k.testCtx.containers[name]
	if !ok {
		t.Fatalf("container %s not found", name)
	}

	return getEndpoints(container, ctx, "5432", "tcp")
}

type KwilNode interface {
	PrivateKey() *crypto.Secp256k1PrivateKey
	PublicKey() *crypto.Secp256k1PublicKey
	IsValidator() bool
	Config() *config.Config
	JSONRPCEndpoint(t *testing.T, ctx context.Context) (exposed string, unexposed string, err error)
	JSONRPCClient(t *testing.T, ctx context.Context, opts *ClientOptions) JSONRPCClient
	AdminClient(t *testing.T, ctx context.Context) *AdminClient
	PeerID() string
	PostgresEndpoint(t *testing.T, ctx context.Context, name string) (exposed string, unexposed string, err error)
}
