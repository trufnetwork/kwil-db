package integration

import (
	"context"
	"crypto/rand"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/kwilteam/kwil-db/config"
	"github.com/kwilteam/kwil-db/core/crypto"
	"github.com/kwilteam/kwil-db/core/crypto/auth"
	"github.com/kwilteam/kwil-db/core/types"
	authExt "github.com/kwilteam/kwil-db/extensions/auth"
	ethdeposits "github.com/kwilteam/kwil-db/extensions/listeners/eth_deposits"
	"github.com/kwilteam/kwil-db/test/setup"
	"github.com/kwilteam/kwil-db/test/specifications"
	"github.com/stretchr/testify/require"
)

var (
	OwnerAddress = "0xc89D42189f0450C2b2c3c61f58Ec5d628176A1E7"
	UserPrivkey1 = func() crypto.PrivateKey {
		privk, err := crypto.Secp256k1PrivateKeyFromHex("f1aa5a7966c3863ccde3047f6a1e266cdc0c76b399e256b8fede92b1c69e4f4e")
		if err != nil {
			panic(err)
		}
		return privk
	}()

	defaultContainerTimeout = 30 * time.Second
)

// TestKwildDatabaseIntegration is to ensure that nodes are able to
// produce blocks and accept db related transactions and agree on the
// state of the database
func TestKwildDatabaseIntegration(t *testing.T) {
	userPrivKey, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err, "failed to generate user private key")

	signer := auth.GetUserSigner(userPrivKey)
	ident, err := authExt.GetIdentifierFromSigner(signer)
	require.NoError(t, err)

	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
					},
					DBOwner: ident,
				},
			})

			ctx := context.Background()

			clt := p.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: userPrivKey,
			})

			ping, err := clt.Ping(ctx)
			require.NoError(t, err)

			require.Equal(t, "pong", ping)

			specifications.CreateNamespaceSpecification(ctx, t, clt, false)
			specifications.CreateSchemaSpecification(ctx, t, clt)

			user := &specifications.User{Id: 1, Name: "Alice", Age: 25}
			specifications.AddUserSpecification(ctx, t, clt, user)
			specifications.ListUsersSpecification(ctx, t, clt, false, 1)
		})
	}
}

// TestKwildValidatorUpdates is to test the functionality of
// validators joining and leaving the network.
func TestKwildValidatorUpdates(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: setup.CLI,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
						}),
					},
					// ConfigureGenesis: func(genDoc *config.GenesisConfig) {
					// 	genDoc.JoinExpiry = 5 // 5 sec at 1block/sec
					// },
					DBOwner: "0xabc",
				},
			})

			ctx := context.Background()

			// wait for all the nodes to discover each other
			time.Sleep(2 * time.Second)

			n0Admin := p.Nodes[0].AdminClient(t, ctx)
			n1Admin := p.Nodes[1].AdminClient(t, ctx)
			n2Admin := p.Nodes[2].AdminClient(t, ctx)
			n3Admin := p.Nodes[3].AdminClient(t, ctx)

			// Ensure that the network has 2 validators
			specifications.CurrentValidatorsSpecification(ctx, t, n0Admin, 2)

			// Reject join requests from an existing validator
			specifications.JoinExistingValidatorSpecification(ctx, t, n0Admin, p.Nodes[1].PrivateKey())

			// Reject leave requests from a non-validator
			specifications.NonValidatorLeaveSpecification(ctx, t, n3Admin)

			// Reject leave requests from the leader
			specifications.InvalidLeaveSpecification(ctx, t, n0Admin)

			time.Sleep(2 * time.Second)

			// Node0 and 1 are Validators and Node2 will issue a join request and requires approval from both validators
			specifications.ValidatorNodeJoinSpecification(ctx, t, n2Admin, p.Nodes[2].PrivateKey(), 2)

			// Nodes can't self approve join requests
			specifications.NodeApprovalFailSpecification(ctx, t, n2Admin, p.Nodes[2].PrivateKey())

			// Non validators can't approve join requests
			specifications.NodeApprovalFailSpecification(ctx, t, n3Admin, p.Nodes[2].PrivateKey())

			// node0 approves the join request
			specifications.ValidatorNodeApproveSpecification(ctx, t, n0Admin, p.Nodes[2].PrivateKey(), 2, 2, false)

			// node1 approves the join request and the node2 becomes a validator
			specifications.ValidatorNodeApproveSpecification(ctx, t, n1Admin, p.Nodes[2].PrivateKey(), 2, 3, true)

			// Ensure that the network has 3 validators
			specifications.CurrentValidatorsSpecification(ctx, t, n0Admin, 3)
			specifications.CurrentValidatorsSpecification(ctx, t, n3Admin, 3)

			/*
				Leave Process:
				- node2 issues a leave request -> removes it from the validator list
				- Validator set count should be reduced by 1
			*/
			specifications.ValidatorNodeLeaveSpecification(ctx, t, n2Admin)

			// Node should be able to rejoin the network
			specifications.ValidatorNodeJoinSpecification(ctx, t, n2Admin, p.Nodes[2].PrivateKey(), 2)
			time.Sleep(2 * time.Second)
			specifications.ValidatorNodeApproveSpecification(ctx, t, n0Admin, p.Nodes[2].PrivateKey(), 2, 2, false)
			specifications.ValidatorNodeApproveSpecification(ctx, t, n1Admin, p.Nodes[2].PrivateKey(), 2, 3, true)
			time.Sleep(2 * time.Second)
			specifications.CurrentValidatorsSpecification(ctx, t, n3Admin, 3)
		})
	}
}

func TestValidatorJoinExpirySpecification(t *testing.T) {
	p := setup.SetupTests(t, &setup.TestConfig{
		ClientDriver: setup.CLI,
		Network: &setup.NetworkConfig{
			Nodes: []*setup.NodeConfig{
				setup.DefaultNodeConfig(),
				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
					nc.Validator = false
				}),
			},
			ConfigureGenesis: func(genDoc *config.GenesisConfig) {
				genDoc.JoinExpiry = types.Duration(5 * time.Second)
			},
			DBOwner: "0xabc",
		},
	})

	ctx := context.Background()

	// wait for all the nodes to discover each other
	time.Sleep(2 * time.Second)

	n0Admin := p.Nodes[0].AdminClient(t, ctx)
	n1Admin := p.Nodes[1].AdminClient(t, ctx)

	// Ensure that the network has 2 validators
	specifications.CurrentValidatorsSpecification(ctx, t, n0Admin, 1)

	// Reject join requests from an existing validator
	specifications.ValidatorJoinExpirySpecification(ctx, t, n1Admin, p.Nodes[1].PrivateKey(), 10*time.Second)
}

func TestKwildValidatorRemoveSpecification(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
					},
					DBOwner: "0xabc",
				},
			})

			ctx := context.Background()

			// wait for all the nodes to discover each other
			time.Sleep(2 * time.Second)

			n0Admin := p.Nodes[0].AdminClient(t, ctx)
			n1Admin := p.Nodes[1].AdminClient(t, ctx)
			n2Admin := p.Nodes[2].AdminClient(t, ctx)

			// 4 validators, remove one validator, requires approval from 2 validators
			specifications.ValidatorNodeRemoveSpecificationV4R1(ctx, t, n0Admin, n1Admin, n2Admin, p.Nodes[3].PrivateKey())

			// Node3 is no longer a validator
			specifications.CurrentValidatorsSpecification(ctx, t, n0Admin, 3)

			// leader can't be removed from the validator set
			specifications.InvalidRemovalSpecification(ctx, t, n1Admin, p.Nodes[0].PrivateKey())
		})
	}
}

func TestKwildBlockSync(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
						}),
					},
					DBOwner: OwnerAddress,
				},
				InitialServices: []string{"node0", "node1", "node2", "pg0", "pg1", "pg2"}, // should bringup only node 0,1,2
			})
			ctx := context.Background()
			// wait for all the nodes to discover each other
			time.Sleep(2 * time.Second)

			clt := p.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{PrivateKey: UserPrivkey1})

			// Deploy some tables and insert some data
			specifications.CreateNamespaceSpecification(ctx, t, clt, false)
			specifications.CreateSchemaSpecification(ctx, t, clt)
			user := &specifications.User{Id: 1, Name: "Alice", Age: 25}
			specifications.AddUserSpecification(ctx, t, clt, user)
			specifications.ListUsersSpecification(ctx, t, clt, false, 1)

			// bring up node3, pg3 and ensure that it does blocksync correctly
			p.RunServices(t, ctx, []*setup.ServiceDefinition{
				setup.KwildServiceDefinition("node3"),
				setup.PostgresServiceDefinition("pg3"),
			}, defaultContainerTimeout)

			// time for node to blocksync and catch up
			time.Sleep(4 * time.Second)

			clt3 := p.Nodes[3].JSONRPCClient(t, ctx, &setup.ClientOptions{PrivateKey: UserPrivkey1})

			// ensure that the node is in sync with the network
			specifications.ListUsersEventuallySpecification(ctx, t, clt3, false, 1)
		})
	}
}

func TestStatesync(t *testing.T) {
	/*
		Node 1, 2, 3 has snapshots enabled
		Node 4 tries to sync with the network, with statesync enabled.
		Node4 should be able to sync with the network and catch up with the latest state (maybe check for the existence of some kind of data)
	*/
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = func(conf *config.Config) {
								conf.Snapshots.Enable = true
								conf.Snapshots.RecurringHeight = 50
							}
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = func(conf *config.Config) {
								conf.Snapshots.Enable = true
								conf.Snapshots.RecurringHeight = 50
							}
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
							nc.Configure = func(conf *config.Config) {
								conf.StateSync.Enable = true
								conf.StateSync.CatalogTimeout = types.Duration(10 * time.Second)
								conf.StateSync.ChunkTimeout = types.Duration(30 * time.Second)
								conf.StateSync.MetadataTimeout = types.Duration(15 * time.Second)
								// conf.StateSync.TrustedProviders = conf.P2P.BootNodes
							}
						}),
					},
					DBOwner: OwnerAddress,
				},
				InitialServices: []string{"node0", "node1", "node2", "pg0", "pg1", "pg2"}, // should bringup only node 0,1,2
			})
			ctx := context.Background()

			// wait for all the nodes to discover each other and to produce snapshots
			time.Sleep(50 * time.Second)

			clt := p.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})

			specifications.CreateNamespaceSpecification(ctx, t, clt, false)
			specifications.CreateSchemaSpecification(ctx, t, clt)

			user := &specifications.User{Id: 1, Name: "Alice", Age: 25}
			specifications.AddUserSpecification(ctx, t, clt, user)
			specifications.ListUsersSpecification(ctx, t, clt, false, 1)

			// bring up node3, pg3 and ensure that it does blocksync correctly
			p.RunServices(t, ctx, []*setup.ServiceDefinition{
				setup.KwildServiceDefinition("node3"),
				setup.PostgresServiceDefinition("pg3"),
			}, 2*time.Minute)

			// time for node to blocksync and catch up
			time.Sleep(4 * time.Second)

			// ensure that all nodes are in sync
			info, err := p.Nodes[3].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
			require.NoError(t, err)
			require.Greater(t, info.BlockHeight, uint64(50))

			clt3 := p.Nodes[3].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})
			specifications.ListUsersSpecification(ctx, t, clt3, false, 1)
		})
	}
}

// TestStatesyncWithValidatorUpdates verifies that nodes using statesync
// correctly reflect changes to the validator set and maintain the
// correct resolution state in the Votestore.
func TestStatesyncWithValidatorUpdates(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = func(conf *config.Config) {
								conf.Snapshots.Enable = true
								conf.Snapshots.RecurringHeight = 50
							}
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
							nc.Configure = func(conf *config.Config) {
								conf.Snapshots.Enable = true
								conf.Snapshots.RecurringHeight = 50
							}
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
							nc.Configure = func(conf *config.Config) {
								conf.StateSync.Enable = true
								conf.StateSync.CatalogTimeout = types.Duration(10 * time.Second)
								conf.StateSync.ChunkTimeout = types.Duration(30 * time.Second)
								conf.StateSync.MetadataTimeout = types.Duration(15 * time.Second)
							}
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
							nc.Configure = func(conf *config.Config) {
								conf.StateSync.Enable = true
								conf.StateSync.CatalogTimeout = types.Duration(10 * time.Second)
								conf.StateSync.ChunkTimeout = types.Duration(30 * time.Second)
								conf.StateSync.MetadataTimeout = types.Duration(15 * time.Second)
							}
						}),
					},
					DBOwner: OwnerAddress,
				},
				InitialServices: []string{"node0", "node1", "pg0", "pg1"}, // should bringup only node 0,1
			})
			ctx := context.Background()

			// wait for all the nodes to discover each other and to produce snapshots
			clt := p.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})

			specifications.CreateNamespaceSpecification(ctx, t, clt, false)
			specifications.CreateSchemaSpecification(ctx, t, clt)

			user := &specifications.User{Id: 1, Name: "Alice", Age: 25}
			specifications.AddUserSpecification(ctx, t, clt, user)
			specifications.ListUsersSpecification(ctx, t, clt, false, 1)

			// node1 issues a join request to become a validator and before node0 approves the request
			// node2 joins the network and should see the join request from node1
			n1Admin := p.Nodes[1].AdminClient(t, ctx)
			specifications.ValidatorNodeJoinSpecification(ctx, t, n1Admin, p.Nodes[1].PrivateKey(), 1)

			time.Sleep(45 * time.Second) // wait for the node0 to produce a snapshot

			// bring up node2, pg2 and ensure that it does blocksync correctly
			p.RunServices(t, ctx, []*setup.ServiceDefinition{
				setup.KwildServiceDefinition("node2"),
				setup.PostgresServiceDefinition("pg2"),
			}, 2*time.Minute)

			// time for node to blocksync and catch up
			time.Sleep(4 * time.Second)

			// ensure that all nodes are in sync
			info, err := p.Nodes[2].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
			require.NoError(t, err)
			require.Greater(t, info.BlockHeight, uint64(50))

			clt2 := p.Nodes[2].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})
			specifications.ListUsersSpecification(ctx, t, clt2, false, 1)

			// node2 should see the join request from node1
			n2Admin := p.Nodes[2].AdminClient(t, ctx)
			specifications.ValidatorJoinStatusSpecification(ctx, t, n2Admin, p.Nodes[1].PrivateKey(), 1)

			// node0 approves the join request
			n0Admin := p.Nodes[0].AdminClient(t, ctx)
			specifications.ValidatorNodeApproveSpecification(ctx, t, n0Admin, p.Nodes[1].PrivateKey(), 1, 2, true)

			time.Sleep(50 * time.Second) // wait for the node0,1 to produce a snapshot

			p.RunServices(t, ctx, []*setup.ServiceDefinition{
				setup.KwildServiceDefinition("node3"),
				setup.PostgresServiceDefinition("pg3"),
			}, 2*time.Minute)

			time.Sleep(4 * time.Second)

			// node3 should see the updated validator set
			n3Admin := p.Nodes[3].AdminClient(t, ctx)
			specifications.CurrentValidatorsSpecification(ctx, t, n3Admin, 2)

			clt3 := p.Nodes[3].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})
			specifications.ListUsersSpecification(ctx, t, clt3, false, 1)
		})
	}
}

func TestOfflineMigrations(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			net1 := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
						}),
					},
					DBOwner: OwnerAddress,
				},
			})

			ctx := context.Background()
			time.Sleep(2 * time.Second)

			clt := net1.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})

			specifications.CreateNamespaceSpecification(ctx, t, clt, false)
			specifications.CreateSchemaSpecification(ctx, t, clt)

			user := &specifications.User{Id: 1, Name: "Alice", Age: 25}
			specifications.AddUserSpecification(ctx, t, clt, user)
			specifications.ListUsersSpecification(ctx, t, clt, false, 1)

			_, hostname, err := net1.Nodes[0].PostgresEndpoint(t, ctx, "pg0")
			require.NoError(t, err)
			parts := strings.Split(hostname, ":")
			require.Len(t, parts, 3)
			host := strings.Trim(parts[1], "/")

			// Create a network snapshot
			n0Admin := net1.Nodes[0].AdminClient(t, ctx)
			_, hash, err := n0Admin.CreateSnapshot(ctx, host, parts[2], "kwild", "kwild", "/app/kwil/gensnaps")
			require.NoError(t, err)

			// Create second network with this snapshot
			net2 := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: setup.CLI,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
					},
					DBOwner: OwnerAddress,
					ConfigureGenesis: func(genDoc *config.GenesisConfig) {
						genDoc.ChainID = "kwil-testnet2"
						genDoc.StateHash = hash
					},
					GenesisSnapshot: filepath.Join(net1.TestDir(), "node0", "gensnaps", "snapshot.sql.gz"),
				},
				PortOffset:     100,
				ServicesPrefix: "new-",
			})

			time.Sleep(5 * time.Second)

			// Verify the existence of some data
			clt = net2.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})
			specifications.ListUsersSpecification(ctx, t, clt, false, 1)
		})
	}
}

func TestLongRunningNetworkMigrations(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			net1 := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
						setup.DefaultNodeConfig(),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Validator = false
						}),
					},
					DBOwner: OwnerAddress,
				},
			})

			ctx := context.Background()
			time.Sleep(2 * time.Second)

			// Trigger a network migration request
			var listenAddresses []string
			for _, node := range net1.Nodes {
				_, addr, err := node.JSONRPCEndpoint(t, ctx)
				require.NoError(t, err)
				listenAddresses = append(listenAddresses, addr)
			}

			n0Admin := net1.Nodes[0].AdminClient(t, ctx)
			n1Admin := net1.Nodes[1].AdminClient(t, ctx)
			// n2Admin := net1.Nodes[2].AdminClient(t, ctx)
			n3Admin := net1.Nodes[3].AdminClient(t, ctx)

			clt := net1.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})

			// Deploy some tables and insert some data
			specifications.CreateNamespaceSpecification(ctx, t, clt, false)
			specifications.CreateSchemaSpecification(ctx, t, clt)
			user := &specifications.User{Id: 1, Name: "Alice", Age: 25}
			specifications.AddUserSpecification(ctx, t, clt, user)
			specifications.ListUsersSpecification(ctx, t, clt, false, 1)

			specifications.SubmitMigrationProposal(ctx, t, n0Admin)

			// node1 approves the migration again and verifies that the migration is still pending
			specifications.ApproveMigration(ctx, t, n0Admin, true)

			// non validator can't approve the migration
			specifications.NonValidatorApproveMigration(ctx, t, n3Admin)

			// node1 approves the migration and verifies that the migration is no longer pending
			specifications.ApproveMigration(ctx, t, n1Admin, false)

			// Setup a new network with the same keys and enter the activation phase
			net2 := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.PrivateKey = net1.Nodes[0].PrivateKey()
							nc.Configure = func(conf *config.Config) {
								conf.Migrations.Enable = true
								conf.Migrations.MigrateFrom = listenAddresses[0]

								conf.Snapshots.Enable = true
								conf.Snapshots.RecurringHeight = 25
							}
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.PrivateKey = net1.Nodes[1].PrivateKey()
							nc.Configure = func(conf *config.Config) {
								conf.Migrations.Enable = true
								conf.Migrations.MigrateFrom = listenAddresses[1]

								conf.Snapshots.Enable = true
								conf.Snapshots.RecurringHeight = 25
							}
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.PrivateKey = net1.Nodes[2].PrivateKey()
							nc.Configure = func(conf *config.Config) {
								conf.Migrations.Enable = true
								conf.Migrations.MigrateFrom = listenAddresses[2]
							}
							nc.Validator = false
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.PrivateKey = net1.Nodes[3].PrivateKey()
							nc.Configure = func(conf *config.Config) {
								conf.Migrations.Enable = true
								conf.Migrations.MigrateFrom = listenAddresses[3]

								conf.StateSync.Enable = true
								conf.StateSync.DiscoveryTimeout = types.Duration(5 * time.Second)
								conf.StateSync.CatalogTimeout = types.Duration(10 * time.Second)
								conf.StateSync.ChunkTimeout = types.Duration(30 * time.Second)
								conf.StateSync.MetadataTimeout = types.Duration(15 * time.Second)
							}
							nc.Validator = false
						}),
					},
					// DBOwner: OwnerAddress,
					ConfigureGenesis: func(genDoc *config.GenesisConfig) {
						genDoc.ChainID = "kwil-testnet2"
					},
				},
				ContainerStartTimeout: 2 * time.Minute,
				InitialServices:       []string{"new-node0", "new-node1", "new-node2", "new-pg0", "new-pg1", "new-pg2"}, // should bringup only node 0,1,2
				ServicesPrefix:        "new-",
				PortOffset:            100,
				DockerNetwork:         net1.NetworkName(),
			})

			user2 := &specifications.User{Id: 2, Name: "Bob", Age: 30}
			specifications.AddUserActionSpecification(ctx, t, clt, user2)
			specifications.ListUsersSpecification(ctx, t, clt, false, 2)

			// time for node to do statesync and catchup
			net2.RunServices(t, ctx, []*setup.ServiceDefinition{
				setup.KwildServiceDefinition("new-node3"),
				setup.PostgresServiceDefinition("new-pg3"),
			}, 5*time.Minute)

			// time for node to blocksync and catch up
			time.Sleep(4 * time.Second)

			// ensure that all nodes are in sync
			clt2 := net2.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
				ChainID:    "kwil-testnet2",
			})
			// Verify that the genesis state and the changesets are correctly applied
			// on the new chain and the data is in sync with the old network
			specifications.ListUsersSpecification(ctx, t, clt2, false, 2)

			clt3 := net2.Nodes[2].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
				ChainID:    "kwil-testnet2",
			})

			// Test that the statesync node is able to sync with the network
			// and the database state is in sync
			specifications.ListUsersSpecification(ctx, t, clt3, false, 2)
		})
	}
}

func TestKwildPrivateNetworks(t *testing.T) {
	userPrivKey, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err, "failed to generate user private key")

	signer := auth.GetUserSigner(userPrivKey)
	ident, err := authExt.GetIdentifierFromSigner(signer)
	require.NoError(t, err)

	// 1 validators and 2 non-validator in a private network

	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = func(conf *config.Config) {
								conf.P2P.PrivateMode = true
							}
							nc.NoHealthCheck = true
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = func(conf *config.Config) {
								conf.P2P.PrivateMode = true
							}
							nc.NoHealthCheck = true
							nc.Validator = false
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = func(conf *config.Config) {
								conf.P2P.PrivateMode = true
							}
							nc.NoHealthCheck = true
							nc.Validator = false
						}),
					},
					DBOwner: ident,
					ConfigureGenesis: func(genDoc *config.GenesisConfig) {
						genDoc.JoinExpiry = types.Duration(20 * time.Second)
					},
				},
				InitialServices: []string{"node0", "pg0"},
			})

			// bringup node1 and node2
			msgStr := "Initial Node state"
			p.RunServices(t, context.Background(), []*setup.ServiceDefinition{
				{Name: "node1", WaitMsg: &msgStr},
				{Name: "node2", WaitMsg: &msgStr},
				setup.PostgresServiceDefinition("pg1"),
				setup.PostgresServiceDefinition("pg2"),
			}, defaultContainerTimeout)

			ctx := context.Background()

			// wait for all the nodes to discover each other
			time.Sleep(2 * time.Second)

			// adminClient for the nodes
			n0Admin := p.Nodes[0].AdminClient(t, ctx)
			n1Admin := p.Nodes[1].AdminClient(t, ctx)
			n2Admin := p.Nodes[2].AdminClient(t, ctx)

			nID0, nID1, nID2 := p.Nodes[0].PeerID(), p.Nodes[1].PeerID(), p.Nodes[2].PeerID()

			// Ensure that the whitelisted peers information is correct and
			// the nodes are not connected to any other nodes
			specifications.ListPeersSpecification(ctx, t, n0Admin, []string{})
			specifications.ListPeersSpecification(ctx, t, n1Admin, []string{})
			specifications.ListPeersSpecification(ctx, t, n2Admin, []string{})

			// Create a namespace and n0 verifies that the users created but not by n1 or n2
			n0Clt := p.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{PrivateKey: userPrivKey})
			n1Clt := p.Nodes[1].JSONRPCClient(t, ctx, &setup.ClientOptions{PrivateKey: userPrivKey})
			n2Clt := p.Nodes[2].JSONRPCClient(t, ctx, &setup.ClientOptions{PrivateKey: userPrivKey})
			specifications.CreateNamespaceSpecification(ctx, t, n0Clt, false)
			specifications.CreateSchemaSpecification(ctx, t, n0Clt)

			user := &specifications.User{Id: 1, Name: "Alice", Age: 25}
			specifications.AddUserSpecification(ctx, t, n0Clt, user)
			specifications.ListUsersSpecification(ctx, t, n0Clt, false, 1)
			specifications.ListUsersSpecification(ctx, t, n1Clt, true, 0)

			// connect n0 and n1
			specifications.AddPeerSpecification(ctx, t, n0Admin, nID1)
			specifications.AddPeerSpecification(ctx, t, n1Admin, nID0)

			// verify peers
			specifications.ListPeersSpecification(ctx, t, n0Admin, []string{nID1})
			specifications.ListPeersSpecification(ctx, t, n1Admin, []string{nID0})
			specifications.ListPeersSpecification(ctx, t, n2Admin, []string{})

			time.Sleep(30 * time.Second) // wait for the nodes to discover each other and blocksync
			// pex discovers new peers for every 20 secs

			// Now ensure that the n1 sees the data that was created by n0 but not n2
			specifications.ListUsersSpecification(ctx, t, n1Clt, false, 1)
			specifications.ListUsersSpecification(ctx, t, n2Clt, true, 0)

			// connect n0 and n2
			specifications.AddPeerSpecification(ctx, t, n0Admin, nID2)
			specifications.AddPeerSpecification(ctx, t, n2Admin, nID0)

			// verify peers
			specifications.ListPeersSpecification(ctx, t, n0Admin, []string{nID1, nID2})
			specifications.ListPeersSpecification(ctx, t, n2Admin, []string{nID0})
			specifications.ListPeersSpecification(ctx, t, n1Admin, []string{nID0})

			// check peer connectivity
			// specifications.PeerConnectivitySpecification(ctx, t, n2Admin, nID1, false)
			// specifications.PeerConnectivitySpecification(ctx, t, n2Admin, nID0, true)
			// specifications.PeerConnectivitySpecification(ctx, t, n0Admin, nID2, true)
			// specifications.PeerConnectivitySpecification(ctx, t, n1Admin, nID2, false)

			time.Sleep(30 * time.Second) // wait for the nodes to discover each other and blocksync

			specifications.ListUsersSpecification(ctx, t, n2Clt, false, 1)

			// allow n1 to accept connections from n2 and not the other way around
			specifications.AddPeerSpecification(ctx, t, n1Admin, nID2)
			specifications.ListPeersSpecification(ctx, t, n1Admin, []string{nID0, nID2})
			specifications.ListPeersSpecification(ctx, t, n2Admin, []string{nID0})

			// check that the peers are not connected
			// specifications.PeerConnectivitySpecification(ctx, t, n2Admin, nID1, false)
			// specifications.PeerConnectivitySpecification(ctx, t, n1Admin, nID2, false)

			// now make n1 a validator, this should make n2 trust n1
			specifications.ValidatorNodeJoinSpecification(ctx, t, n1Admin, p.Nodes[1].PrivateKey(), 1)
			specifications.ValidatorNodeApproveSpecification(ctx, t, n0Admin, p.Nodes[1].PrivateKey(), 1, 2, true)
			time.Sleep(5 * time.Second)

			specifications.CurrentValidatorsSpecification(ctx, t, n0Admin, 2)
			specifications.CurrentValidatorsSpecification(ctx, t, n2Admin, 2)

			// check that n1 is a trusted peer of n2
			specifications.ListPeersSpecification(ctx, t, n2Admin, []string{nID0, nID1})
			specifications.ListPeersSpecification(ctx, t, n1Admin, []string{nID0, nID2})

			// n1 removes n2 as a peer
			specifications.RemovePeerSpecification(ctx, t, n1Admin, nID2)
			specifications.ListPeersSpecification(ctx, t, n1Admin, []string{nID0})
			specifications.ListPeersSpecification(ctx, t, n2Admin, []string{nID0, nID1})

			// n2 sends a join request and expires leaving n2 untrusted
			specifications.ValidatorNodeJoinSpecification(ctx, t, n2Admin, p.Nodes[2].PrivateKey(), 2)
			specifications.ListPeersSpecification(ctx, t, n1Admin, []string{nID0}) // n2 is still not a trusted peer

			// n2 approves the join request of n1 and adds it as a trusted peer
			specifications.ValidatorNodeApproveSpecification(ctx, t, n1Admin, p.Nodes[2].PrivateKey(), 2, 2, false)
			specifications.ListPeersSpecification(ctx, t, n1Admin, []string{nID0, nID2})

			time.Sleep(30 * time.Second) // let the join request expire
			specifications.CurrentValidatorsSpecification(ctx, t, n0Admin, 2)

			// n1 should remove n2 as a peer when the join request expires
			specifications.ListPeersSpecification(ctx, t, n1Admin, []string{nID0})
		})
	}
}

func TestSingleNodeKwildEthDepositsOracleIntegration(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			ctx := context.Background()

			dockerNetwork, err := setup.CreateDockerNetwork(ctx, t)
			require.NoError(t, err)

			// deploy the hardhat service
			// I couldn't easily integrate it into Setup tests, as we need to first run the
			// eth node and deploy contracts and use these contracts to configure and run the
			// kwild nodes. So, I am keeping the deployment separate for now.
			ethNode := setup.DeployETHNode(t, ctx, dockerNetwork.Name, UserPrivkey1.(*crypto.Secp256k1PrivateKey))
			require.NotNil(t, ethNode)

			// ensure that both the contracts are deployed
			require.Equal(t, 2, len(ethNode.Deployers))
			deployer := ethNode.Deployers[0]

			// start mining
			deployerCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			err = deployer.KeepMining(deployerCtx)
			require.NoError(t, err)

			privk, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
			require.NoError(t, err)
			privKey := (*crypto.Secp256k1PrivateKey)(privk)
			signer := &auth.Secp256k1Signer{
				Secp256k1PrivateKey: *privKey,
			}
			addr := signer.CompactID()

			// Configure Kwil nodes to use the deployed contracts
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = func(conf *config.Config) {
								conf.Extensions = make(map[string]map[string]string)
								cfg := ethdeposits.EthDepositConfig{
									RPCProvider:          ethNode.UnexposedChainRPC,
									ContractAddress:      deployer.EscrowAddress(),
									StartingHeight:       0,
									ReconnectionInterval: 30,
									MaxRetries:           20,
									BlockSyncChunkSize:   1000,
								}
								conf.Extensions["eth_deposits"] = cfg.Map()
							}
							nc.PrivateKey = privKey
						}),
					},
					DBOwner: OwnerAddress,
					ConfigureGenesis: func(genDoc *config.GenesisConfig) {
						genDoc.DisabledGasCosts = false
						alloc := config.GenesisAlloc{
							ID:      config.KeyHexBytes{HexBytes: addr},
							KeyType: "secp256k1",
							Amount:  big.NewInt(100000000000000),
						}
						genDoc.Allocs = append(genDoc.Allocs, alloc)
					},
				},
				DockerNetwork: dockerNetwork.Name,
			})

			// Deposit the amount to the escrow
			specifications.ApproveSpecification(ctx, t, deployer)
			amount := big.NewInt(10)
			rpcClient := p.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})

			// execute sql statement without enough balance
			specifications.DeployDbInsufficientFundsSpecification(ctx, t, deployer, rpcClient)

			specifications.DepositSuccessSpecification(ctx, t, deployer, rpcClient, amount)
		})
	}
}

// TestKwildEthDepositFundTransfer tests out the ways in which the validator accounts can be funded
// One way is during network bootstrapping using allocs in the genesis file
// Other, is through transfer from one kwil account to another
func TestKwildEthDepositFundTransfer(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			ctx := context.Background()

			dockerNetwork, err := setup.CreateDockerNetwork(ctx, t)
			require.NoError(t, err)

			// deploy the hardhat service
			// I couldn't easily integrate it into Setup tests, as we need to first run the
			// eth node and deploy contracts and use these contracts to configure and run the
			// kwild nodes. So, I am keeping the deployment separate for now.
			ethNode := setup.DeployETHNode(t, ctx, dockerNetwork.Name, UserPrivkey1.(*crypto.Secp256k1PrivateKey))
			require.NotNil(t, ethNode)

			// ensure that both the contracts are deployed
			require.Equal(t, 2, len(ethNode.Deployers))
			deployer := ethNode.Deployers[0]

			// start mining
			deployerCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			err = deployer.KeepMining(deployerCtx)
			require.NoError(t, err)

			privk, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
			require.NoError(t, err)
			privKey := (*crypto.Secp256k1PrivateKey)(privk)
			signer := &auth.Secp256k1Signer{
				Secp256k1PrivateKey: *privKey,
			}
			addr := signer.CompactID()

			// Configure Kwil nodes to use the deployed contracts
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = func(conf *config.Config) {
								conf.Extensions = make(map[string]map[string]string)
								cfg := ethdeposits.EthDepositConfig{
									RPCProvider:          ethNode.UnexposedChainRPC,
									ContractAddress:      deployer.EscrowAddress(),
									StartingHeight:       0,
									ReconnectionInterval: 30,
									MaxRetries:           20,
									BlockSyncChunkSize:   1000,
								}
								conf.Extensions["eth_deposits"] = cfg.Map()
							}
							nc.PrivateKey = privKey
						}),
					},
					DBOwner: OwnerAddress,
					ConfigureGenesis: func(genDoc *config.GenesisConfig) {
						genDoc.DisabledGasCosts = false
						alloc := config.GenesisAlloc{
							ID: config.KeyHexBytes{
								HexBytes: addr,
							},
							KeyType: "secp256k1",
							Amount:  big.NewInt(100000000000000),
						}
						genDoc.Allocs = append(genDoc.Allocs, alloc)
					},
				},
				DockerNetwork: dockerNetwork.Name,
			})

			clt := p.Nodes[0].JSONRPCClient(t, ctx, &setup.ClientOptions{
				PrivateKey: UserPrivkey1,
			})

			specifications.FundValidatorSpecification(ctx, t, deployer, clt, privKey)
		})
	}
}

func TestKwildEthDepositOracleValidatorUpdates(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			ctx := context.Background()

			dockerNetwork, err := setup.CreateDockerNetwork(ctx, t)
			require.NoError(t, err)

			// deploy the hardhat service
			// I couldn't easily integrate it into Setup tests, as we need to first run the
			// eth node and deploy contracts and use these contracts to configure and run the
			// kwild nodes. So, I am keeping the deployment separate for now.
			ethNode := setup.DeployETHNode(t, ctx, dockerNetwork.Name, UserPrivkey1.(*crypto.Secp256k1PrivateKey))
			require.NotNil(t, ethNode)

			// ensure that both the contracts are deployed
			require.Equal(t, 2, len(ethNode.Deployers))
			deployer := ethNode.Deployers[0]

			// start mining
			deployerCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			err = deployer.KeepMining(deployerCtx)
			require.NoError(t, err)

			var validators []*crypto.Secp256k1PrivateKey
			for range 3 {
				privk, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
				require.NoError(t, err)
				privKey := (*crypto.Secp256k1PrivateKey)(privk)
				validators = append(validators, privKey)
			}

			ethConfig := ethdeposits.EthDepositConfig{
				RPCProvider:          ethNode.UnexposedChainRPC,
				ContractAddress:      deployer.EscrowAddress(),
				StartingHeight:       0,
				ReconnectionInterval: 30,
				MaxRetries:           20,
				BlockSyncChunkSize:   1000,
			}

			extFn := func(conf *config.Config) {
				conf.Extensions = make(map[string]map[string]string)
				cfg := ethConfig
				conf.Extensions["eth_deposits"] = cfg.Map()
			}

			byzFn := func(conf *config.Config) {
				conf.Extensions = make(map[string]map[string]string)
				cfg := ethConfig
				cfg.ContractAddress = ethNode.Deployers[1].EscrowAddress()
				conf.Extensions["eth_deposits"] = cfg.Map()
			}

			// Configure Kwil nodes to use the deployed contracts
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = extFn
							nc.PrivateKey = validators[0]
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = byzFn
							nc.PrivateKey = validators[1]
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
							nc.Configure = extFn
							nc.PrivateKey = validators[2]
						}),
					},
					DBOwner: OwnerAddress,
					ConfigureGenesis: func(genDoc *config.GenesisConfig) {
						genDoc.DisabledGasCosts = true
					},
				},
				DockerNetwork: dockerNetwork.Name,
			})

			rpcClients := make([]setup.JSONRPCClient, 3)
			adminClients := make([]*setup.AdminClient, 3)
			for i := range 3 {
				rpcClients[i] = p.Nodes[i].JSONRPCClient(t, ctx, &setup.ClientOptions{
					PrivateKey: UserPrivkey1,
				})
				adminClients[i] = p.Nodes[i].AdminClient(t, ctx)
			}

			// Deposit the amount to the escrow and verify the balance
			amount := big.NewInt(10)
			specifications.EthDepositSpecification(ctx, t, deployer, rpcClients[0], amount, false)

			// Node2 leaves it's validator role
			specifications.ValidatorNodeLeaveSpecification(ctx, t, adminClients[2])

			// verify that the validator set has been updated
			specifications.CurrentValidatorsSpecification(ctx, t, adminClients[0], 2)

			// make a deposit to the escrow, it should not be successful
			specifications.EthDepositSpecification(ctx, t, deployer, rpcClients[0], amount, true)

			// Node2 rejoins the network as a validator
			// And catches up with all the events it missed and votes for the observed events
			// The last deposit should now get approved and credited to the account
			specifications.ValidatorNodeJoinSpecification(ctx, t, adminClients[2], validators[2], 2)

			// 2 validators should approve the join request
			specifications.ValidatorNodeApproveSpecification(ctx, t, adminClients[0], validators[2], 2, 2, false)

			// get the balance of the account
			sender, err := specifications.SenderAccountID(t)
			require.NoError(t, err)

			acct1, err := rpcClients[0].GetAccount(ctx, sender, 0)
			require.NoError(t, err)

			// second approval
			specifications.ValidatorNodeApproveSpecification(ctx, t, adminClients[1], validators[2], 2, 3, true)
			specifications.CurrentValidatorsSpecification(ctx, t, adminClients[0], 3)

			// ensure that the balance has been updated
			require.Eventually(t, func() bool {
				acct2, err := rpcClients[0].GetAccount(ctx, sender, 0)
				require.NoError(t, err)
				return acct2.Balance.Cmp(acct1.Balance) == 1
			}, 60*time.Second, 3*time.Second)
		})
	}
}

func TestKwildReplaceLeader(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(), // node0 -> leader
						setup.DefaultNodeConfig(), // node1 -> validator
						setup.DefaultNodeConfig(), // node2 -> validator
						setup.DefaultNodeConfig(), // node3 -> validator
						setup.DefaultNodeConfig(), // node4 -> validator  (will start later)
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) { // node5 -> sentry
							nc.Validator = false
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) { // node6 -> sentry (for blocksync)
							nc.Validator = false
						}),
					},
				},

				InitialServices: []string{"node0", "pg0", "node1", "pg1", "node2", "pg2", "node3", "pg3", "node5", "pg5"},
			})

			ctx := context.Background()
			// wait for the nodes to discover each other
			time.Sleep(2 * time.Second)

			// leader update to node1 (node1,2 approves)
			// n0, n3 --> leader n0, whereas n1,n2 -> leader (n1)
			// there no blocks will be produced until n4 joins the network and votes for n0's proposal
			// this should revert the n1 and n2 to accept n0 as the leader
			n0Admin := p.Nodes[0].AdminClient(t, ctx)
			n1Admin := p.Nodes[1].AdminClient(t, ctx)
			n2Admin := p.Nodes[2].AdminClient(t, ctx)
			n3Admin := p.Nodes[3].AdminClient(t, ctx)
			n5Admin := p.Nodes[5].AdminClient(t, ctx)

			// node1 and node2 promotes node1 as the leader
			n1PubK := p.Nodes[1].PrivateKey().Public()
			n0PubK := p.Nodes[0].PrivateKey().Public()
			n1Admin.PromoteValidator(ctx, n1PubK.Bytes(), n1PubK.Type(), big.NewInt(30))
			n2Admin.PromoteValidator(ctx, n1PubK.Bytes(), n1PubK.Type(), big.NewInt(30))

			time.Sleep(30 * time.Second)
			// not enough majority to change the leader, also not enough majority to produce blocks, so the network is stuck
			info, err := p.Nodes[0].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
			require.NoError(t, err)
			require.Equal(t, uint64(29), info.BlockHeight) // block 30 never gets committed.

			// bringup node4, this should give the previous leader the majority and the previous leader
			// should continue to be the leader and produce blocks
			msgStr := "Block sync completed"
			p.RunServices(t, ctx, []*setup.ServiceDefinition{
				{Name: "node4", WaitMsg: &msgStr},
				setup.PostgresServiceDefinition("pg4"),
			}, defaultContainerTimeout)

			// wait for the nodes to discover each other and should start seeing blocks
			require.Eventually(t, func() bool {
				info, err := p.Nodes[3].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
				require.NoError(t, err)
				return info.BlockHeight > uint64(30)
			}, 20*time.Second, 1*time.Second)

			n4Admin := p.Nodes[4].AdminClient(t, ctx)

			// ensure that n0, n1 have the same leader
			p0, err := n0Admin.Params(ctx)
			require.NoError(t, err)
			require.Equal(t, n0PubK, p0.Leader.PublicKey)

			// n1 is unrecoverable until we restart it.
			// lets work with the rest of the validators

			// retry again in 30 blocks and this time enough validators agreed to the promotion
			info, err = p.Nodes[0].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
			require.NoError(t, err)
			height := int64(info.BlockHeight) + int64(40)

			n2PubK := p.Nodes[2].PrivateKey().Public()
			n2Admin.PromoteValidator(ctx, n2PubK.Bytes(), n2PubK.Type(), big.NewInt(height))
			n3Admin.PromoteValidator(ctx, n2PubK.Bytes(), n2PubK.Type(), big.NewInt(height))
			n4Admin.PromoteValidator(ctx, n2PubK.Bytes(), n2PubK.Type(), big.NewInt(height))

			time.Sleep(30 * time.Second)

			// ensure that the previous leader correctly accepted the new leader
			require.Eventually(t, func() bool {
				infoT, err := p.Nodes[0].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
				require.NoError(t, err)
				return infoT.BlockHeight > uint64(height)
			}, 20*time.Second, 1*time.Second)

			p0, err = n0Admin.Params(ctx)
			require.NoError(t, err)
			require.Equal(t, n2PubK, p0.Leader.PublicKey)

			// sentry node should also have the updated leader
			p5, err := n5Admin.Params(ctx)
			require.NoError(t, err)
			require.Equal(t, n2PubK, p5.Leader.PublicKey)

			info, err = p.Nodes[0].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
			require.NoError(t, err)
			height = int64(info.BlockHeight)

			info, err = p.Nodes[1].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
			require.NoError(t, err)
			// ensure that the node1 (failed leader promotion) is not stuck and is catching up
			require.Greater(t, info.BlockHeight, uint64(30))

			// node6 blocksync and joins the network and should catchup correctly
			p.RunServices(t, ctx, []*setup.ServiceDefinition{
				{Name: "node6", WaitMsg: &msgStr},
				setup.PostgresServiceDefinition("pg6"),
			}, defaultContainerTimeout)

			require.Eventually(t, func() bool {
				info, err := p.Nodes[5].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
				require.NoError(t, err)
				return info.BlockHeight >= uint64(height)
			}, 20*time.Second, 1*time.Second)

			// check that the leader is updated on node6
			n6Admin := p.Nodes[5].AdminClient(t, ctx)
			p6, err := n6Admin.Params(ctx)
			require.NoError(t, err)
			require.Equal(t, n2PubK, p6.Leader.PublicKey)
		})
	}
}

func TestKwildNetworkParamsLeaderUpdate(t *testing.T) {
	for _, driver := range setup.AllDrivers {
		t.Run(driver.String()+"_driver", func(t *testing.T) {
			p := setup.SetupTests(t, &setup.TestConfig{
				ClientDriver: driver,
				Network: &setup.NetworkConfig{
					Nodes: []*setup.NodeConfig{
						setup.DefaultNodeConfig(), // node0 -> leader
						setup.DefaultNodeConfig(), // node1 -> validator
						setup.DefaultNodeConfig(), // node2 -> validator
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) { // node3 -> sentry
							nc.Validator = false
						}),
						setup.CustomNodeConfig(func(nc *setup.NodeConfig) { // node4 -> sentry (for blocksync)
							nc.Validator = false
						}),
					},
				},
				InitialServices: []string{"node0", "pg0", "node1", "pg1", "node2", "pg2", "node3", "pg3"},
			})

			ctx := context.Background()

			// make proposal for node1 to become the leader
			n0Admin := p.Nodes[0].AdminClient(t, ctx)
			n1Admin := p.Nodes[1].AdminClient(t, ctx)

			n1PubK := p.Nodes[1].PrivateKey().Public()
			updates := types.ParamUpdates{}
			updates[types.ParamNameLeader] = types.PublicKey{
				PublicKey: n1PubK,
			}

			txid, uuid, err := n1Admin.ProposeParamUpdates(ctx, &updates, "leader_update")
			require.NoError(t, err)
			specifications.ExpectTxSuccess(t, n0Admin, ctx, txid)

			// ensure that the proposal exists
			proposals, err := n0Admin.ListParamUpdateProposals(ctx)
			require.NoError(t, err)
			contains := slices.ContainsFunc(proposals, func(p *types.ConsensusParamUpdateProposal) bool {
				return p.ID == uuid
			})
			require.True(t, contains)

			// verify that the proposal is not yet approved
			status, err := n0Admin.ParamUpdateStatus(ctx, uuid)
			require.NoError(t, err)
			// count number of approvals
			resolution := status.ResStatus.PendingResolution
			var approvals int
			for _, v := range resolution.Approved {
				if v {
					approvals++
				}
			}
			require.Equal(t, 1, approvals)

			// node2 approves the proposal
			n2Admin := p.Nodes[2].AdminClient(t, ctx)
			txid, err = n2Admin.ApproveParamUpdates(ctx, uuid)
			require.NoError(t, err)
			specifications.ExpectTxSuccess(t, n0Admin, ctx, txid)

			// ensure that the proposal is approved
			_, err = n0Admin.ParamUpdateStatus(ctx, uuid)
			require.Error(t, err) // not found

			// check that the leader is updated
			p0, err := n0Admin.Params(ctx)
			require.NoError(t, err)
			require.Equal(t, n1PubK, p0.Leader.PublicKey)

			// get the block height
			info, err := p.Nodes[0].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
			require.NoError(t, err)
			height := info.BlockHeight

			// sentry node should also have the updated leader
			require.Eventually(t, func() bool {
				infoT, err := p.Nodes[3].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
				require.NoError(t, err)
				return infoT.BlockHeight >= height
			}, 20*time.Second, 1*time.Second)

			n3Admin := p.Nodes[3].AdminClient(t, ctx)
			p3, err := n3Admin.Params(ctx)
			require.NoError(t, err)
			require.Equal(t, n1PubK, p3.Leader.PublicKey)

			// node4 blocksync and joins the network and should catchup correctly
			msgStr := "Block sync completed"
			p.RunServices(t, ctx, []*setup.ServiceDefinition{
				{Name: "node4", WaitMsg: &msgStr},
				setup.PostgresServiceDefinition("pg4"),
			}, defaultContainerTimeout)
			require.Eventually(t, func() bool {
				info, err := p.Nodes[4].JSONRPCClient(t, ctx, nil).ChainInfo(ctx)
				require.NoError(t, err)
				return info.BlockHeight > height
			}, 30*time.Second, 1*time.Second)

			// ensure that the leader is updated on node4
			n4Admin := p.Nodes[4].AdminClient(t, ctx)
			p4, err := n4Admin.Params(ctx)
			require.NoError(t, err)
			require.Equal(t, n1PubK, p4.Leader.PublicKey)

		})
	}
}

// TODO: There is no straightforward way to test the oracle expiry and refund
// as we can't update the resolution expiry on fly. Can run these two tests with a
// custom build with a very short Expiration period.
// func TestKwildEthDepositOracleExpiryIntegration(t *testing.T) {
// 	ctx := context.Background()

// 	dockerNetwork, err := setup.CreateDockerNetwork(ctx, t)
// 	require.NoError(t, err)
// 	ethNode := setup.DeployETHNode(t, ctx, dockerNetwork.Name)
// 	require.NotNil(t, ethNode)

// 	// ensure that both the contracts are deployed
// 	require.Equal(t, 2, len(ethNode.Deployers))
// 	fmt.Println(ethNode.Deployers[0].EscrowAddress(), ethNode.Deployers[1].EscrowAddress())

// 	deployer := ethNode.Deployers[1]

// 	// start mining on the second contract and only one node will be
// 	// listening on the contract -> node1
// 	deployerCtx, cancel := context.WithCancel(ctx)
// 	defer cancel()
// 	err = deployer.KeepMining(deployerCtx)
// 	require.NoError(t, err)

// 	var validators []*crypto.Secp256k1PrivateKey
// 	for i := 0; i < 4; i++ {
// 		privk, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
// 		require.NoError(t, err)
// 		privKey := (*crypto.Secp256k1PrivateKey)(privk)
// 		validators = append(validators, privKey)
// 	}

// 	extFn := func(conf *config.Config) {
// 		conf.Extensions = make(map[string]map[string]string)
// 		cfg := ethdeposits.EthDepositConfig{
// 			RPCProvider:          ethNode.UnexposedChainRPC,
// 			ContractAddress:      ethNode.Deployers[0].EscrowAddress(),
// 			StartingHeight:       0,
// 			ReconnectionInterval: 30,
// 			MaxRetries:           20,
// 			BlockSyncChunkSize:   1000,
// 		}
// 		conf.Extensions["eth_deposits"] = cfg.Map()
// 	}

// 	byzFn := func(conf *config.Config) {
// 		conf.Extensions = make(map[string]map[string]string)
// 		cfg := ethdeposits.EthDepositConfig{
// 			RPCProvider:          ethNode.UnexposedChainRPC,
// 			ContractAddress:      ethNode.Deployers[1].EscrowAddress(),
// 			StartingHeight:       0,
// 			ReconnectionInterval: 30,
// 			MaxRetries:           20,
// 			BlockSyncChunkSize:   1000,
// 		}
// 		conf.Extensions["eth_deposits"] = cfg.Map()
// 	}

// 	// Configure Kwil nodes to use the deployed contracts
// 	p := setup.SetupTests(t, &setup.TestConfig{
// 		ClientDriver: setup.CLI,
// 		Network: &setup.NetworkConfig{
// 			Nodes: []*setup.NodeConfig{
// 				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
// 					nc.Configure = byzFn // only leader can create resolutions, so it has to be listening on the byzantine escrow contract which none of the validators are listening on
// 					nc.PrivateKey = validators[0]
// 				}),
// 				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
// 					nc.Configure = extFn
// 					nc.PrivateKey = validators[1]
// 				}),
// 				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
// 					nc.Configure = extFn
// 					nc.PrivateKey = validators[2]
// 				}),
// 				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
// 					nc.Configure = extFn
// 					nc.PrivateKey = validators[3]
// 				}),
// 			},
// 			DBOwner: OwnerAddress,
// 			ConfigureGenesis: func(genDoc *config.GenesisConfig) {
// 				genDoc.DisabledGasCosts = false
// 				genDoc.VoteExpiry = 10
// 				for _, val := range validators {
// 					alloc := config.GenesisAlloc{
// 						ID:      hex.EncodeToString(val.Public().Bytes()),
// 						Amount:  big.NewInt(100000000000000),
// 						KeyType: "secp256k1",
// 					}
// 					genDoc.Allocs = append(genDoc.Allocs, alloc)
// 				}
// 			},
// 		},
// 		DockerNetwork: dockerNetwork.Name,
// 	})
// 	fmt.Println(ethNode.Deployers[0].EscrowAddress(), ethNode.Deployers[1].EscrowAddress())

// 	clt := p.Nodes[0].JSONRPCClient(t, ctx, false, setup.UserPubKey1)
// 	specifications.DepositResolutionExpirySpecification(ctx, t, deployer, clt, validators)
// }

// func TestKwildEthDepositOracleExpiryRefundIntegration(t *testing.T) {
// 	ctx := context.Background()

// 	dockerNetwork, err := setup.CreateDockerNetwork(ctx, t)
// 	require.NoError(t, err)
// 	ethNode := setup.DeployETHNode(t, ctx, dockerNetwork.Name)
// 	require.NotNil(t, ethNode)

// 	// ensure that both the contracts are deployed
// 	require.Equal(t, 2, len(ethNode.Deployers))
// 	deployer := ethNode.Deployers[0]

// 	// start mining
// 	deployerCtx, cancel := context.WithCancel(ctx)
// 	defer cancel()
// 	err = deployer.KeepMining(deployerCtx)
// 	require.NoError(t, err)

// 	var validators []*crypto.Secp256k1PrivateKey
// 	for i := 0; i < 4; i++ {
// 		privk, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
// 		require.NoError(t, err)
// 		privKey := (*crypto.Secp256k1PrivateKey)(privk)
// 		validators = append(validators, privKey)
// 	}

// 	ethCfg := ethdeposits.EthDepositConfig{
// 		RPCProvider:          ethNode.UnexposedChainRPC,
// 		ContractAddress:      deployer.EscrowAddress(),
// 		StartingHeight:       0,
// 		ReconnectionInterval: 30,
// 		MaxRetries:           20,
// 		BlockSyncChunkSize:   1000,
// 	}

// 	extFn := func(conf *config.Config) {
// 		conf.Extensions = make(map[string]map[string]string)
// 		cfg := ethCfg
// 		conf.Extensions["eth_deposits"] = cfg.Map()
// 	}

// 	byzFn := func(conf *config.Config) {
// 		conf.Extensions = make(map[string]map[string]string)
// 		cfg := ethCfg
// 		cfg.ContractAddress = ethNode.Deployers[1].EscrowAddress()
// 		conf.Extensions["eth_deposits"] = cfg.Map()
// 	}

// 	// Configure Kwil nodes to use the deployed contracts
// 	p := setup.SetupTests(t, &setup.TestConfig{
// 		ClientDriver: setup.CLI,
// 		Network: &setup.NetworkConfig{
// 			Nodes: []*setup.NodeConfig{
// 				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
// 					nc.Configure = extFn
// 					nc.PrivateKey = validators[0]
// 				}),
// 				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
// 					nc.Configure = extFn
// 					nc.PrivateKey = validators[1]
// 				}),
// 				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
// 					nc.Configure = byzFn
// 					nc.PrivateKey = validators[2]
// 				}),
// 				setup.CustomNodeConfig(func(nc *setup.NodeConfig) {
// 					nc.Configure = byzFn
// 					nc.PrivateKey = validators[3]
// 				}),
// 			},
// 			DBOwner: OwnerAddress,
// 			ConfigureGenesis: func(genDoc *config.GenesisConfig) {
// 				genDoc.DisabledGasCosts = false
// 				genDoc.VoteExpiry = 10
// 				for _, val := range validators {
// 					alloc := config.GenesisAlloc{
// 						ID:      hex.EncodeToString(val.Public().Bytes()),
// 						Amount:  big.NewInt(100000000000000),
// 						KeyType: "secp256k1",
// 					}
// 					genDoc.Allocs = append(genDoc.Allocs, alloc)
// 				}
// 			},
// 		},
// 		DockerNetwork: dockerNetwork.Name,
// 	})

// 	clt := p.Nodes[0].JSONRPCClient(t, ctx, false, setup.UserPubKey1)

// 	// 4 nodes -> 2 listening on escrow contract 1 and 2 listening on byzantine contract
// 	// 2 validators approve the deposit, but the deposit is not resolved
// 	// 2 validators get the refund after expiry
// 	specifications.DepositResolutionExpiryRefundSpecification(ctx, t, deployer, clt, validators)
// }
