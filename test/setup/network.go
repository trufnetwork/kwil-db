package setup

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	dockerNet "github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/trufnetwork/kwil-db/core/utils/random"
)

const (
	jsonRPCPort = 8484
	p2pPort     = 6600

	kgwRPCPort = 8090
)

// EnsureNetworkExist creates a new docker network with a random UUID name.
func ensureNetworkExist(ctx context.Context, testName string) (
	*testcontainers.DockerNetwork, error) {
	// random subnet 10.A.B.0/20 with 4096 addresses each, not overlapping
	rng := random.New()
	randA := strconv.Itoa(rng.IntN(255))
	randB := strconv.Itoa(rng.IntN(16) * 16)
	subnet := "10." + randA + "." + randB + ".0/20"
	net, err := network.New(ctx,
		network.WithCheckDuplicate(),
		network.WithAttachable(),
		network.WithIPAM(&dockerNet.IPAM{
			Driver:  "default",
			Options: map[string]string{},
			Config: []dockerNet.IPAMConfig{
				{
					Subnet: subnet,
				},
			},
		}),
		//network.WithInternal(), // we need to expose the network to the host
		network.WithLabels(map[string]string{"test": "integration"}),
		network.WithDriver("bridge"),
	)

	fmt.Printf("subnet: %s\n", subnet)

	if err != nil {
		return nil, fmt.Errorf("failed to create docker network for %s: %w", testName, err)
	} else {
		fmt.Printf("docker network created: %s(%s) for %s\n", net.Name, net.ID, testName)
		return net, nil
	}
}

// getEndpoints returns proto://host:port exposed/unexposed string for given exposed port.
func getEndpoints(ctr *testcontainers.DockerContainer, ctx context.Context,
	port nat.Port, proto string) (exposed string, unexposed string, err error) {
	exposed, err = ctr.PortEndpoint(ctx, port, proto)
	if err != nil {
		return
	}

	ctrInspect, err := ctr.Inspect(ctx)
	if err != nil {
		return
	}

	// NOTE: sometime the container name is returned with leading slash
	ctrName := strings.TrimPrefix(ctrInspect.Name, "/")
	unexposed = fmt.Sprintf("%s://%s:%s", proto, ctrName, port.Port())
	return
}

func kwildJSONRPCEndpoints(ctr *testcontainers.DockerContainer, ctx context.Context) (string, string, error) {
	exposed, unexposed, err := getEndpoints(ctr, ctx, nat.Port(fmt.Sprint(jsonRPCPort)), "http")
	return exposed, unexposed, err
}
