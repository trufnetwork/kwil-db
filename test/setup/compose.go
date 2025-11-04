package setup

import (
	"bytes"
	_ "embed"
	"os"
	"strconv"
	"text/template"
)

var (
	//go:embed node-compose.yml.template
	nodeComposeTemplateString string
	nodeComposeTemplate       = template.Must(template.New("node-compose-template").Parse(nodeComposeTemplateString))

	//go:embed header-compose.yml.template
	headerComposeTemplateString string
	headerComposeTemplate       = template.Must(template.New("header-compose-template").Parse(headerComposeTemplateString))

	//go:embed other-compose.yml.template
	otherComposeTemplateString string
	otherComposeTemplate       = template.Must(template.New("other-compose-template").Parse(otherComposeTemplateString))
)

// nodeTemplate works with the node-compose.yml.template file to generate
// part of the docker-compose.yml file
type nodeTemplate struct {
	// Network is the name of the network
	Network string
	// NodeNumber is a unique number for the node
	NodeNumber int
	// NodeServicePrefix is the prefix used for the hostname of the container within
	// the docker network. It will be appended with the NodeNumber to create the
	// full hostname
	NodeServicePrefix string
	NoHealthCheck     bool
	// PGServicePrefix is the name of the postgres service
	PGServicePrefix string
	// TestnetDir is the directory to use for the testnet
	TestnetDir string
	// ExposedJSONRPCPort is the port that the JSONRPC server is exposed on
	ExposedJSONRPCPort int
	// ExposedP2PPort is the port that the P2P server is exposed on
	ExposedP2PPort int
	// DockerImage is the Kwil docker image to use
	DockerImage string
	// UserID is the user ID to run the node as
	UserID string
	// GroupID is the group ID to run the node as
	GroupID string
}

func (n *nodeTemplate) generate() (string, error) {
	var res bytes.Buffer
	err := nodeComposeTemplate.Execute(&res, n)
	if err != nil {
		return "", err
	}

	return res.String(), nil
}

// headerTemplate works with the header-compose.yml.template file to generate
// part of the docker-compose.yml file
type headerTemplate struct {
	Network string
}

// generateCompose generates a full docker-compose.yml file for a given number of nodes.
// It takes a network name, docker image, and node count.
// Optionally, it can also be given a user and group, which if set, will be used to run the nodes as.
func generateCompose(dockerNetwork string, testnetDir string, nodeConfs []*NodeConfig, otherSvcs []*CustomService, userAndGroupIDs *[2]string, networkPrefix string, portsOffset int,
) (composeFilepath string, nodeGeneratedInfo []*generatedNodeInfo, err error) {
	var res bytes.Buffer
	err = headerComposeTemplate.Execute(&res, &headerTemplate{Network: dockerNetwork})
	if err != nil {
		return "", nil, err
	}

	nodePrefix := networkPrefix + "node"
	pgPrefix := networkPrefix + "pg"

	var nodes []*generatedNodeInfo
	for i, nodeConf := range nodeConfs {
		node := &nodeTemplate{
			Network:            dockerNetwork,
			NodeNumber:         i,
			NodeServicePrefix:  nodePrefix,
			NoHealthCheck:      nodeConf.NoHealthCheck,
			PGServicePrefix:    pgPrefix,
			TestnetDir:         testnetDir,
			ExposedJSONRPCPort: 8484 + i + portsOffset,
			ExposedP2PPort:     6600 + i + portsOffset,
			DockerImage:        nodeConf.DockerImage,
		}

		if userAndGroupIDs != nil {
			node.UserID = userAndGroupIDs[0]
			node.GroupID = userAndGroupIDs[1]
		}

		nodeYml, err := node.generate()
		if err != nil {
			return "", nil, err
		}
		res.WriteString(nodeYml)

		nodes = append(nodes, &generatedNodeInfo{
			ExposedJSONRPCPort:  node.ExposedJSONRPCPort,
			KwilNodeServiceName: nodePrefix + strconv.Itoa(i),
			PostgresServiceName: pgPrefix + strconv.Itoa(i),
		})
	}

	for _, svc := range otherSvcs {
		svcTmpl := &serviceTemplate{
			Network:      dockerNetwork,
			ServiceName:  svc.ServiceName,
			DockerImage:  svc.DockerImage,
			Command:      svc.Command,
			ExposedPort:  svc.ExposedPort,
			InternalPort: svc.InternalPort,
			DependsOn:    svc.DependsOn,
		}

		if userAndGroupIDs != nil {
			svcTmpl.UserID = userAndGroupIDs[0]
			svcTmpl.GroupID = userAndGroupIDs[1]
		}

		err = svcTmpl.generate(&res)
		if err != nil {
			return "", nil, err
		}
	}

	err = os.MkdirAll(testnetDir, 0755)
	if err != nil {
		return "", nil, err
	}

	fp := testnetDir + "/docker-compose.yml"
	err = os.WriteFile(fp, res.Bytes(), 0644)
	if err != nil {
		return "", nil, err
	}

	return fp, nodes, nil
}

type generatedNodeInfo struct {
	// the port that the docker container exposes the JSONRPC server on.
	// This should be accessed by the tests
	ExposedJSONRPCPort int
	// the hostname of the node on the docker network
	KwilNodeServiceName string
	// the service name of the postgres container
	PostgresServiceName string
}

// serviceTemplate is used to generate part of a docker-compose.yml file for
// any service that is not kwild or postgres.
type serviceTemplate struct {
	// Network is the name of the network
	Network string
	// ServiceName is the name of the service
	ServiceName string
	// DockerImage is the docker image to use
	DockerImage string
	// UserID is the user ID to run the service as
	// It can be empty
	UserID string
	// GroupID is the group ID to run the service as
	// It can be empty if UserID is empty
	GroupID string
	// Command is the command to run the service with
	// It can be empty
	Command string
	// ExposedPort is the port that the service is exposed on.
	// It can be empty
	ExposedPort string
	// InternalPort is the port that the service is running on internally.
	// It must be set if ExposedPort is set
	InternalPort string
	DependsOn    string
}

func (s *serviceTemplate) generate(r *bytes.Buffer) error {
	return otherComposeTemplate.Execute(r, s)
}

// CustomService allows for the creation of a custom service that is not kwild or postgres
type CustomService struct {
	// REQUIRED: ServiceName is the name of the service
	ServiceName string
	// REQUIRED: DockerImage is the docker image to use
	DockerImage string
	// OPTIONAL: Command is the command to run the service with
	Command string
	// OPTIONAL: ExposedPort is the port that the service is exposed on.
	// If set, InternalPort must also be set
	ExposedPort string
	// OPTIONAL: InternalPort is the port that the service is running on internally.
	// It must be set if ExposedPort is set
	InternalPort string
	// OPTIONAL: ServiceProto is the proto that the service use.
	ServiceProto string
	// OPTIONAL: WaitMsg is a log that Docker will wait for before considering the service to be up
	WaitMsg string
	// OPTIONAL: DependsOn specify a service that needs to be healthy
	DependsOn string
}
