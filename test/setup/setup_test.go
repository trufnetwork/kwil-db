package setup_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/test/setup"
)

// this is a simple test to ensure that the setup package is working
// TODO: we can probably delete this because it is implicitly tested by the other tests
// It is just here while I test this out
func Test_Setup(t *testing.T) {
	p := setup.SetupTests(t, &setup.TestConfig{
		ClientDriver: setup.CLI,
		Network: &setup.NetworkConfig{
			Nodes: []*setup.NodeConfig{
				setup.DefaultNodeConfig(),
				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
					nc.Configure = func(c *config.Config) {
						c.P2P.Pex = false
					}
				}),
			},
			DBOwner: "0xabc",
		},
	})

	ctx := context.Background()

	ping, err := p.Nodes[0].JSONRPCClient(t, ctx, nil).Ping(ctx)
	require.NoError(t, err)

	require.Equal(t, "pong", ping)
}
