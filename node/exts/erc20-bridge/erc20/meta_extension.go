// package erc20reward implements a meta extension that manages all rewards on a Kwil network.
// It is used to create other extensions with which users can distribute erc20 tokens
// to users.
// It works by exposing an action to the DB owner which allows creation of new extensions
// for specific erc20s. When the action is called, it starts event listeners which sync
// information about the escrow contract, erc20, and multisig from the EVM chain.
// When an extension is in this state, we consider it "pending".
// Once synced, the extension is no longer "pending", but instead ready.
// At this point, users can access the extension's namespace to distribute rewards.
// Internally, the node will start another event listener which is responsible for tracking
// the escrow contract's Deposit event. When a deposit event is detected, the node will update the
// reward balance of the intended recipient.
package erc20

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/container/lru"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/core/utils/order"
	"github.com/trufnetwork/kwil-db/extensions/hooks"
	"github.com/trufnetwork/kwil-db/extensions/listeners"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/abigen"
	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
	evmsync "github.com/trufnetwork/kwil-db/node/exts/evm-sync"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/utils/syncmap"
)

const (
	RewardMetaExtensionName = "kwil_erc20_meta"
	uint256Precision        = 78

	rewardMerkleTreeLRUSize = 1000

	// EthereumSignedMessagePrefix is the prefix used for EIP-191 compliant message signing.
	// This matches OpenZeppelin's MessageHashUtils.toEthSignedMessageHash() format.
	EthereumSignedMessagePrefix = "\x19Ethereum Signed Message:\n32"
)

var (
	rewardExtUUIDNamespace = *types.MustParseUUID("b1f140d1-91cf-4bbe-8f78-8f17f6282fc2")
	minEpochPeriod         = time.Minute * 10
	maxEpochPeriod         = time.Hour * 24 * 7 // 1 week
	// uint256Numeric is a numeric that is big enough to hold a uint256
	uint256Numeric = func() *types.DataType {
		dt, err := types.NewNumericType(78, 0)
		if err != nil {
			panic(err)
		}

		return dt
	}()

	// the below are used to identify different types of logs from ethereum
	// so that we know how to decode them
	logTypeDeposit        = []byte("rcpdepst")
	logTypeConfirmedEpoch = []byte("cnfepch")
	logTypeWithdrawal     = []byte("wthdrwl")

	mtLRUCache = lru.NewMap[[32]byte, []byte](rewardMerkleTreeLRUSize) // tree root => tree body

	_SINGLETON *extensionInfo

	// runningSigners tracks which instance IDs have active validator signer goroutines
	// to prevent duplicate signers if OnStart is called multiple times
	runningSigners = make(map[string]bool)

	// runningSignerCancels stores cancel functions for active signer goroutines
	// to allow graceful shutdown when instances are disabled
	runningSignerCancels = make(map[string]context.CancelFunc)

	// runningSignersMu protects both runningSigners and runningSignerCancels maps
	runningSignersMu sync.Mutex

	// runningDepositListeners tracks which instance IDs have active deposit listeners
	// to prevent duplicate listeners if OnStart is called multiple times (e.g., when adding a new bridge instance via USE statement)
	runningDepositListeners = make(map[string]bool)

	// runningWithdrawalListeners tracks which instance IDs have active withdrawal listeners
	// to prevent duplicate listeners if OnStart is called multiple times
	runningWithdrawalListeners = make(map[string]bool)

	// runningListenersMu protects both runningDepositListeners and runningWithdrawalListeners maps
	runningListenersMu sync.Mutex
)

// generates a deterministic UUID for the chain and escrow
func uuidForChainAndEscrow(chain string, escrow string) types.UUID {
	return types.NewUUIDV5WithNamespace(rewardExtUUIDNamespace, []byte(chain+escrow))
}

// generates a unique name for the state poller
func statePollerUniqueName(id types.UUID) string {
	return statePollerPrefix + id.String()
}

// idFromStatePollerUniqueName extracts the id from the unique name
func idFromStatePollerUniqueName(name string) (*types.UUID, error) {
	if !strings.HasPrefix(name, statePollerPrefix) {
		return nil, fmt.Errorf("invalid state poller name %s", name)
	}

	return types.ParseUUID(strings.TrimPrefix(name, statePollerPrefix))
}

const (
	statePollerPrefix             = "erc20_state_poll_"
	depositListenerPrefix         = "erc20_transfer_listener_" // retain prefix for stored topics
	depositEventResolutionName    = "erc20_transfer_sync"
	withdrawalListenerPrefix      = "erc20_withdrawal_listener_"
	withdrawalEventResolutionName = "erc20_withdrawal_sync"
	statePollResolutionName       = "erc20_state_poll_sync"
)

// depositListenerUniqueName generates a unique name for the deposit listener
func depositListenerUniqueName(id types.UUID) string {
	return depositListenerPrefix + id.String()
}

// idFromDepositListenerUniqueName extracts the id from the unique name
func idFromDepositListenerUniqueName(name string) (*types.UUID, error) {
	if !strings.HasPrefix(name, depositListenerPrefix) {
		return nil, fmt.Errorf("invalid deposit listener name %s", name)
	}

	return types.ParseUUID(strings.TrimPrefix(name, depositListenerPrefix))
}

// withdrawalListenerUniqueName generates a unique name for the withdrawal listener
func withdrawalListenerUniqueName(id types.UUID) string {
	return withdrawalListenerPrefix + id.String()
}

// idFromWithdrawalListenerUniqueName extracts the id from the unique name
func idFromWithdrawalListenerUniqueName(name string) (*types.UUID, error) {
	if !strings.HasPrefix(name, withdrawalListenerPrefix) {
		return nil, fmt.Errorf("invalid withdrawal listener name %s", name)
	}

	return types.ParseUUID(strings.TrimPrefix(name, withdrawalListenerPrefix))
}

// generateEpochID generates a deterministic UUID for an epoch
func generateEpochID(instanceID *types.UUID, startheight int64) *types.UUID {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(startheight))
	id := types.NewUUIDV5WithNamespace(*instanceID, buf)
	return &id
}

/*
This extension is quite complex, because it manages a number of lifetimes and sub extensions.
It is interacted with using "top-level" extensions (e.g. USE erc20 {...} AS alias).
It also interacts with two different event listeners: one for polling state of on-chain contracts
(e.g. the configured erc20 and multisig for an escrow), and one for listening to RewardDistributor
Deposit events to reward users with incoming tokens.

Therefore, we break down the extension into "Instances". Instances are defined by a Chain ID and an
escrow address, which is then hashed to create a UUID. This UUID is used to track the extension in the
database. Each instance has its own erc20, multisig, and set of rewards.

Instances have two separate types of states: synchronization and activation.
Synchronization refers to whether we have synced relevant metadata from the EVM chain.
This includes things like the escrow's erc20 address, multisig address, etc.
The second state is activation, which refers to whether the current network is using the extension.
Since extensions can never be fully dropped (as any rewards that are distributed but unclaimed would
effectively be lost), we only deactivate them, and re-activate them when needed.

The most complex part of this extension is the "prepare" method. This method is called when we should
start a new extension, or re-activate a de-activated extension. Therefore, on "prepare", there are 4 states
to consider:
- Extension has never existed: register it in the database and start the state poller
- Extension has existed but is deactivated, and is not synced: start the state poller and inform the DB that it is active
- Extension has existed but is deactivated, and is synced: inform the DB that it is activated and ready, and start the Transfer listener
- Extension has existed and is active: return an error

The other most complex part of this extension is the startup. On startup, we read all existing rewards from the DB,
which may also be in any of the above states. We will store all instance info in memory, and do the following
depending on the state:
- Inactive, Unsynced: do nothing
- Inactive, Synced: do nothing
- Active, Unsynced: start the state poller
- Active, Synced: start the Transfer listener

Upon successful synchronization, the extension is considered "ready".
In other words, ready = synced && activated.
Once an extensiuon is ready, it can be used to distribute rewards to users.
It will also start a listener for Deposit events on the reward distributor, to update user balances.
*/

func init() {
	/*
		for simplicity, we use a singleton to manage all instances.
		This singleton manages state for all reward instances.
		We can break down everywhere it is referenced into 4 categories:
		1. Extension methods
		2. Resolution extensions (used for resolving synced contract state and events)
		3. End block hooks (used for proposing epochs and resolving ordered events from a listener)
		4. Event listeners (used for listening to events or polling for state on the EVM chain)

		Resolutions and hooks run as part of consensus process.
		Methods _usually_ run as part of consensus, however they can
		run in a read-only context (if marked with VIEW).

		Therefore, we need to account for state being read and written
		concurrently.

		Event listeners run outside of consensus, and thus we have potential
		concurrency issues. All variables provided to event listeners
		are copied; this avoids concurrency issues, as well as ensures that
		the listeners don't cause non-deterministic behavior by modifying
		state.

		I considered making a global singleton instead of defining it here, but I felt
		that it was more clear to track where it was used by defining it here.
	*/

	// Initialize singleton in init function - will be replaced by getSingleton() logic

	evmsync.RegisterEventResolution(depositEventResolutionName, func(ctx context.Context, app *common.App, block *common.BlockContext, uniqueName string, logs []*evmsync.EthLog) error {
		id, err := idFromDepositListenerUniqueName(uniqueName)
		if err != nil {
			return err
		}

		for _, log := range logs {
			if bytes.HasPrefix(log.Metadata, logTypeDeposit) {
				var fromAddr *ethcommon.Address
				if len(log.Metadata) >= len(logTypeDeposit)+20 {
					addr := ethcommon.BytesToAddress(log.Metadata[len(logTypeDeposit) : len(logTypeDeposit)+20])
					fromAddr = &addr
				}

				err := applyDepositLog(ctx, app, id, *log.Log, block, fromAddr)
				if err != nil {
					return err
				}
			} else if bytes.HasPrefix(log.Metadata, logTypeConfirmedEpoch) {
				err := applyConfirmedEpochLog(ctx, app, *log.Log)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("unknown log type %x", log.Metadata)
			}
		}

		return nil
	})

	evmsync.RegisterEventResolution(withdrawalEventResolutionName, func(ctx context.Context, app *common.App, block *common.BlockContext, uniqueName string, logs []*evmsync.EthLog) error {
		id, err := idFromWithdrawalListenerUniqueName(uniqueName)
		if err != nil {
			return err
		}

		for _, log := range logs {
			if bytes.HasPrefix(log.Metadata, logTypeWithdrawal) {
				// Pass Kwil block height as deterministic timestamp
				err := applyWithdrawalLog(ctx, app, id, *log.Log, block.Height)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("unknown log type %x", log.Metadata)
			}
		}

		return nil
	})

	evmsync.RegisterStatePollResolution(statePollResolutionName, func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext, uniqueName string, decodedData []byte) error {
		id, err := idFromStatePollerUniqueName(uniqueName)
		if err != nil {
			return err
		}

		info, ok := getSingleton().instances.Get(*id)
		if !ok {
			return fmt.Errorf("reward extension with id %s not found", id)
		}

		info.mu.RLock()

		if info.synced {
			info.mu.RUnlock()
			// signals a serious internal bug
			return fmt.Errorf("duplicate sync resolution for extension with id %s", id)
		}

		var data syncedRewardData
		err = data.UnmarshalBinary(decodedData)
		if err != nil {
			info.mu.RUnlock()
			return fmt.Errorf("failed to unmarshal synced reward data: %v", err)
		}

		err = setRewardSynced(ctx, app, id, block.Height, &data)
		if err != nil {
			info.mu.RUnlock()
			return err
		}

		info.mu.RUnlock()
		info.mu.Lock()

		info.synced = true
		info.syncedAt = block.Height
		info.syncedRewardData = data
		info.ownedBalance = types.MustParseDecimalExplicit("0", 78, 0)

		err = evmsync.StatePoller.UnregisterPoll(uniqueName)
		if err != nil {
			info.mu.Unlock()
			return err
		}

		// if active, we should start the deposit listener
		// Otherwise, we will just wait until it is activated
		if info.active {
			// we need to unlock before we call start because it
			// will acquire the write lock
			info.mu.Unlock()

			// Start both deposit and withdrawal listeners
			depositErr, depositStarted := info.startDepositListener()
			if depositErr != nil {
				return depositErr
			}

			withdrawalErr, _ := info.startWithdrawalListener()
			if withdrawalErr != nil {
				// Cleanup: Only unregister deposit listener if WE started it
				if depositStarted {
					instanceIDStr := id.String()
					cleanupErr := evmsync.EventSyncer.UnregisterListener(depositListenerUniqueName(*id))
					if cleanupErr != nil {
						logger := app.Service.Logger
						if logger != nil {
							logger.Warnf("failed to cleanup deposit listener after withdrawal listener failure: %v", cleanupErr)
						}
					}
					// Remove tracking entry
					runningListenersMu.Lock()
					delete(runningDepositListeners, instanceIDStr)
					runningListenersMu.Unlock()
				}
				return withdrawalErr
			}
			return nil
		}

		info.mu.Unlock()

		return nil
	})

	err := precompiles.RegisterInitializer(RewardMetaExtensionName,
		func(ctx context.Context, service *common.Service, db sql.DB, alias string, metadata map[string]any) (precompiles.Precompile, error) {
			return precompiles.Precompile{
				Cache: getSingleton(),
				OnUse: func(ctx *common.EngineContext, app *common.App) error {
					err := createSchema(ctx.TxContext.Ctx, app)
					if err != nil {
						return err
					}
					return setVersionToCurrent(ctx.TxContext.Ctx, app)
				},
				OnStart: func(ctx context.Context, app *common.App) error {
					// Check version and upgrade if needed (automatic migration)
					version, notYetSet, err := getVersion(ctx, app)
					if err != nil {
						// Only skip if the namespace truly doesn't exist yet
						if !errors.Is(err, engine.ErrNamespaceNotFound) {
							return fmt.Errorf("failed to get extension version: %w", err)
						}
					} else if !notYetSet && version < currentVersion {
						// Safe to run createSchema here because it uses IF NOT EXISTS and
						// we've updated it to be idempotent.
						err = createSchema(ctx, app)
						if err != nil {
							return err
						}
						err = setVersionToCurrent(ctx, app)
						if err != nil {
							return err
						}
					}

					// if the schema exists, we should read all existing reward instances
					instances, err := getStoredRewardInstances(ctx, app)
					switch {
					case err == nil:
						// do nothing
					case errors.Is(err, engine.ErrNamespaceNotFound):
						// if the schema doesnt exist, then we just return
						// since genesis has not been run yet
						return nil
					default:
						return err
					}

					// we dont need to worry about locking the instances yet
					// because we just read them from the db
					for _, instance := range instances {
						// if instance is active, we should start one of its
						// two listeners. If it is synced, we should start the
						// deposit listener. Otherwise, we should start the state poller
						if instance.active {
							if instance.synced {
								// Start both deposit and withdrawal listeners
								// These methods are idempotent - safe to call multiple times
								depositErr, depositStarted := instance.startDepositListener()
								if depositErr != nil {
									return depositErr
								}

								withdrawalErr, _ := instance.startWithdrawalListener()
								if withdrawalErr != nil {
									// Cleanup: Only unregister deposit listener if WE started it
									if depositStarted {
										instanceIDStr := instance.ID.String()
										cleanupErr := evmsync.EventSyncer.UnregisterListener(depositListenerUniqueName(*instance.ID))
										if cleanupErr != nil && app.Service != nil && app.Service.Logger != nil {
											app.Service.Logger.Warnf("failed to cleanup deposit listener after withdrawal listener failure: %v", cleanupErr)
										}
										// Remove tracking entry
										runningListenersMu.Lock()
										delete(runningDepositListeners, instanceIDStr)
										runningListenersMu.Unlock()
									}
									return withdrawalErr
								}
							} else {
								err = instance.startStatePoller()
								if err != nil {
									return err
								}
							}
						}

						getSingleton().instances.Set(*instance.ID, instance)
					}

					// Start validator signer services for non-custodial withdrawals
					// This runs in background and submits validator signatures via transactions
					for _, instance := range instances {
						if instance.active && instance.synced {
							instanceIDStr := instance.ID.String()

							// Check if signer is already running for this instance
							runningSignersMu.Lock()
							alreadyRunning := runningSigners[instanceIDStr]
							if !alreadyRunning {
								runningSigners[instanceIDStr] = true
							}
							runningSignersMu.Unlock()

							if alreadyRunning {
								if app.Service != nil && app.Service.Logger != nil {
									app.Service.Logger.Debugf("validator signer already running for instance %s, skipping", instance.ID)
								}
								continue
							}

							// Try to get validator signer
							signer, err := getValidatorSigner(app, instance.ID)
							if err != nil {
								if app.Service != nil && app.Service.Logger != nil {
									app.Service.Logger.Warnf("failed to get validator signer for instance %s: %v", instance.ID, err)
								}
								// Clean up tracking maps on error
								runningSignersMu.Lock()
								delete(runningSigners, instanceIDStr)
								delete(runningSignerCancels, instanceIDStr)
								runningSignersMu.Unlock()
								continue
							}
							if signer != nil {
								// Create cancellable context so we can stop the signer when instance is disabled
								// Use context.Background() as parent so signer runs for node lifetime (until cancelled)
								signerCtx, cancel := context.WithCancel(context.Background())

								// Store cancel function for cleanup on disable
								runningSignersMu.Lock()
								runningSignerCancels[instanceIDStr] = cancel
								runningSignersMu.Unlock()

								// Start background signer with cancellable context
								go signer.Start(signerCtx)
							} else {
								// No signer available, clean up tracking maps
								runningSignersMu.Lock()
								delete(runningSigners, instanceIDStr)
								delete(runningSignerCancels, instanceIDStr)
								runningSignersMu.Unlock()
							}
						}
					}

					return nil
				},
				Methods: []precompiles.Method{
					{
						// prepare begins the sync process for a new reward extension.
						Name: "prepare",
						Parameters: []precompiles.PrecompileValue{
							{Name: "chain", Type: types.TextType},
							{Name: "escrow", Type: types.TextType},
							{Name: "period", Type: types.TextType},
						},
						Returns: &precompiles.MethodReturn{
							Fields: []precompiles.PrecompileValue{
								{Name: "id", Type: types.UUIDType},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.SYSTEM},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) (err error) {
							chain := inputs[0].(string)
							escrow := inputs[1].(string)
							period := inputs[2].(string)

							if !ethcommon.IsHexAddress(escrow) {
								return fmt.Errorf("escrow address %s is not a valid ethereum address", escrow)
							}
							escrowAddress := ethcommon.HexToAddress(escrow)

							id := uuidForChainAndEscrow(chain, escrow)

							dur, err := time.ParseDuration(period) // ensure period is a valid time
							if err != nil {
								return err
							}

							if dur < minEpochPeriod || dur > maxEpochPeriod {
								return fmt.Errorf("epoch period %s is not within the range [%s, %s]", dur, minEpochPeriod, maxEpochPeriod)
							}

							trunced := dur.Truncate(time.Second) // truncate to seconds
							if trunced != dur {
								return fmt.Errorf("epoch period %s is not a whole number of seconds", dur)
							}

							chainConst := chains.Chain(chain) // ensure chain exists
							err = chainConst.Valid()
							if err != nil {
								return err
							}

							chainInfo, ok := chains.GetChainInfo(chainConst)
							if !ok {
								return fmt.Errorf("chain with name %s not found", chain)
							}

							info, ok := getSingleton().instances.Get(id)
							// if the instance already exists, it can be in two states:
							// 1. active: we should return an error
							// 2. inactive
							// If inactive, we should check if it is synced. If it is, we should
							// start the deposit listener. Otherwise, we should get it synced by
							// starting the state poller.
							if ok {
								info.mu.RLock()
								if info.active {
									info.mu.RUnlock()
									return fmt.Errorf(`reward extension with chain "%s" and escrow "%s" is already active`, chain, escrow)
								}
								if info.synced {
									// if it is already synced, we should just make sure to start listening
									// to transfer events and activate it

									// period could be updated when re-use extension
									err = reuseRewardInstance(ctx.TxContext.Ctx, app, &id, int64(dur.Seconds()))
									if err != nil {
										info.mu.RUnlock()
										return err
									}

									info.mu.RUnlock()
									info.mu.Lock()
									info.active = true
									info.DistributionPeriod = int64(dur.Seconds())
									info.mu.Unlock()

									info.mu.RLock()
									defer info.mu.RUnlock()

									// Start deposit listener
									depositErr, depositStarted := info.startDepositListener()
									if depositErr != nil {
										return depositErr
									}

									// Start withdrawal listener
									withdrawalErr, _ := info.startWithdrawalListener()
									if withdrawalErr != nil {
										// Cleanup: Only unregister deposit listener if WE started it
										if depositStarted {
											instanceIDStr := id.String()
											cleanupErr := evmsync.EventSyncer.UnregisterListener(depositListenerUniqueName(id))
											if cleanupErr != nil && app.Service != nil && app.Service.Logger != nil {
												app.Service.Logger.Warnf("failed to cleanup deposit listener after withdrawal listener failure: %v", cleanupErr)
											}
											// Remove tracking entry
											runningListenersMu.Lock()
											delete(runningDepositListeners, instanceIDStr)
											runningListenersMu.Unlock()
										}
										return withdrawalErr
									}

									return resultFn([]any{id})
								} else {
									defer info.mu.RUnlock()
								}
								// do nothing, we will proceed below to start the state poller
							} else {
								err = evmsync.EventSyncer.RegisterNewTopic(ctx.TxContext.Ctx, db, app.Engine, depositListenerUniqueName(id), depositEventResolutionName)
								if err != nil {
									return err
								}

								// Register withdrawal topic
								// Safe to register for all instances (old contracts simply won't emit Withdraw events)
								err = evmsync.EventSyncer.RegisterNewTopic(ctx.TxContext.Ctx, db, app.Engine, withdrawalListenerUniqueName(id), withdrawalEventResolutionName)
								if err != nil {
									return err
								}

								firstEpoch := newPendingEpoch(&id, ctx.TxContext.BlockContext)
								// if not synced, register the new reward extension
								info = &rewardExtensionInfo{
									userProvidedData: userProvidedData{
										ID:                 &id,
										ChainInfo:          &chainInfo,
										EscrowAddress:      escrowAddress,
										DistributionPeriod: int64(dur.Seconds()),
									},
									currentEpoch: firstEpoch,
									active:       true,
								}

								info.mu.RLock()
								defer info.mu.RUnlock()

								// we may face a transactionality issue if either of these error, since there is already state that has been
								// committed to the DB. I think it is very unlikely because both of these are simple operations that store
								// some data and all validations should have already been performed, but it is something to keep an eye on
								err = createNewRewardInstance(ctx.TxContext.Ctx, app, &info.userProvidedData)
								if err != nil {
									return err
								}

								// create the first epoch
								err = createEpoch(ctx.TxContext.Ctx, app, firstEpoch, &id)
								if err != nil {
									return err
								}
							}

							err = info.startStatePoller()
							if err != nil {
								return err
							}

							// we wait until here to add it in case there is an error
							// in RegisterPoll. This only matters if it is new, otherwise
							// we are just setting the same info in the map again
							getSingleton().instances.Set(id, info)

							return resultFn([]any{id})
						},
					},
					{
						// disable disables a reward extension.
						Name: "disable",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.SYSTEM},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)

							info, ok := getSingleton().instances.Get(*id)
							if !ok {
								return fmt.Errorf("reward extension with id %s not found", id)
							}

							// Later we will need a write lock, but we start with a read lock because
							// setActiveStatus makes a recursive call to the engine. This will require a read lock
							// to copy the in-memory state of this extension. Therefore, if we acquire a write lock
							// here, we will deadlock.
							info.mu.RLock()

							if !info.active {
								info.mu.RUnlock()
								// Already disabled - this is idempotent, return success
								// This allows UNUSE to complete namespace cleanup even when called multiple times
								return nil
							}

							err := setActiveStatus(ctx.TxContext.Ctx, app, id, false)
							if err != nil {
								return err
							}

							info.mu.RUnlock()
							info.mu.Lock()
							info.active = false
							info.mu.Unlock()

							// Stop validator signer goroutine if running
							instanceIDStr := id.String()
							runningSignersMu.Lock()
							if cancel, ok := runningSignerCancels[instanceIDStr]; ok {
								cancel() // Signal signer to stop
								delete(runningSigners, instanceIDStr)
								delete(runningSignerCancels, instanceIDStr)
								if app.Service != nil && app.Service.Logger != nil {
									app.Service.Logger.Debugf("stopped validator signer for instance %s", id)
								}
							}
							runningSignersMu.Unlock()

							// Clean up listener tracking
							runningListenersMu.Lock()
							delete(runningDepositListeners, instanceIDStr)
							delete(runningWithdrawalListeners, instanceIDStr)
							runningListenersMu.Unlock()

							// stopAllListeners does not require a lock.
							// Any error returned here suggests some sort of critical bug
							// in the code, and not a user error.
							return info.stopAllListeners()
						},
					},
					{
						// info returns information about a reward extension.
						Name: "info",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
						},
						Returns: &precompiles.MethodReturn{
							Fields: []precompiles.PrecompileValue{
								{Name: "chain", Type: types.TextType},
								{Name: "escrow", Type: types.TextType},
								{Name: "epoch_period", Type: types.TextType},
								{Name: "erc20", Type: types.TextType, Nullable: true},
								{Name: "decimals", Type: types.IntType, Nullable: true},
								{Name: "balance", Type: uint256Numeric, Nullable: true}, // total unspent balance
								{Name: "synced", Type: types.BoolType},
								{Name: "synced_at", Type: types.IntType, Nullable: true},
								{Name: "enabled", Type: types.BoolType},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)

							info, ok := getSingleton().instances.Get(*id)
							if !ok {
								return fmt.Errorf("reward extension with id %s not found", id)
							}

							info.mu.RLock()
							defer info.mu.RUnlock()

							// these values can be null if the extension is not synced
							var erc20Address *string
							var ownedBalance *types.Decimal
							var decimals, syncedAt *int64

							dur := time.Duration(info.userProvidedData.DistributionPeriod) * time.Second

							if info.synced {
								erc20Addr := info.syncedRewardData.Erc20Address.Hex()
								erc20Address = &erc20Addr
								decimals = &info.syncedRewardData.Erc20Decimals
								ownedBalance = info.ownedBalance
								syncedAt = &info.syncedAt
							}

							return resultFn([]any{
								info.userProvidedData.ChainInfo.Name.String(),
								info.userProvidedData.EscrowAddress.Hex(),
								dur.String(),
								erc20Address,
								decimals,
								ownedBalance,
								info.synced,
								syncedAt,
								info.active,
							})
						},
					},
					{
						// id returns the ID of a reward extension.
						Name: "id",
						Parameters: []precompiles.PrecompileValue{
							{Name: "chain", Type: types.TextType},
							{Name: "escrow", Type: types.TextType},
						},
						Returns: &precompiles.MethodReturn{
							Fields: []precompiles.PrecompileValue{
								{Name: "id", Type: types.UUIDType},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							chain := inputs[0].(string)
							escrow := inputs[1].(string)

							id := uuidForChainAndEscrow(chain, escrow)

							return resultFn([]any{id})
						},
					},
					{
						// list returns a list of all reward extensions.
						Name: "list",
						Returns: &precompiles.MethodReturn{
							IsTable: true,
							Fields: []precompiles.PrecompileValue{
								{Name: "id", Type: types.UUIDType},
								{Name: "chain", Type: types.TextType},
								{Name: "escrow", Type: types.TextType},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							return getSingleton().ForEachInstance(true, func(id *types.UUID, info *rewardExtensionInfo) error {
								return resultFn([]any{id, info.userProvidedData.ChainInfo.Name.String(), info.userProvidedData.EscrowAddress.Hex()})
							})
						},
					},
					{
						// issue issues a reward to a user.
						Name: "issue",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "user", Type: types.TextType},
							{Name: "amount", Type: uint256Numeric},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.SYSTEM},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							user := inputs[1].(string)
							amount := inputs[2].(*types.Decimal)

							return getSingleton().issueTokens(ctx.TxContext.Ctx, app, id, user, amount)
						},
					},
					{
						// transfer transfers tokens from the caller to another address.
						Name: "transfer",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "to", Type: types.TextType},
							{Name: "amount", Type: uint256Numeric},
						},
						// anybody can call this as long as they have the tokens.
						// There is no security risk if somebody calls this directly
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							to := inputs[1].(string)
							amount := inputs[2].(*types.Decimal)

							if amount.IsNegative() {
								return fmt.Errorf("amount cannot be negative")
							}

							from, err := ethAddressFromHex(ctx.TxContext.Caller)
							if err != nil {
								return err
							}

							toAddr, err := ethAddressFromHex(to)
							if err != nil {
								return err
							}

							// Check sufficient balance before transfer
							currentBalance, err := balanceOf(ctx.TxContext.Ctx, app, id, from)
							if err != nil {
								return err
							}

							// If user has no balance record, treat as zero balance
							if currentBalance == nil {
								return fmt.Errorf("insufficient balance: have 0, need %s", amount)
							}

							cmp, err := currentBalance.Cmp(amount)
							if err != nil {
								return err
							}
							if cmp < 0 {
								return fmt.Errorf("insufficient balance: have %s, need %s", currentBalance, amount)
							}

							return transferTokens(ctx, app, id, from, toAddr, amount)
						},
					},
					{
						// locks takes tokens from a user's balance and gives them to the network.
						// The network can then distribute these tokens to other users, either via
						// unlock or issue.
						Name: "lock",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "amount", Type: uint256Numeric},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							amount := inputs[1].(*types.Decimal)

							if amount.IsNegative() {
								return fmt.Errorf("amount cannot be negative")
							}

							return getSingleton().lockTokens(ctx.TxContext.Ctx, app, id, ctx.TxContext.Caller, amount)
						},
					},
					{
						// lock_admin is a privileged version of lock that allows the network to lock
						// tokens on behalf of a user.
						Name: "lock_admin",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "user", Type: types.TextType},
							{Name: "amount", Type: uint256Numeric},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.SYSTEM},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							user := inputs[1].(string)
							amount := inputs[2].(*types.Decimal)

							if amount.IsNegative() {
								return fmt.Errorf("amount cannot be negative")
							}

							return getSingleton().lockTokens(ctx.TxContext.Ctx, app, id, user, amount)
						},
					},
					{
						// unlock returns tokens to a user's balance that were previously locked.
						// It returns the tokens so that the user can spend them.
						// It can only be called by the network when it wishes to return tokens to a user.
						Name: "unlock",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "user", Type: types.TextType},
							{Name: "amount", Type: uint256Numeric},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.SYSTEM},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							user := inputs[1].(string)
							amount := inputs[2].(*types.Decimal)

							if amount.IsNegative() {
								return fmt.Errorf("amount cannot be negative")
							}

							addr, err := ethAddressFromHex(user)
							if err != nil {
								return err
							}

							info, err := getSingleton().getUsableInstance(id)
							if err != nil {
								return err
							}

							info.mu.RLock()
							// we cannot defer an RUnlock here because we need to unlock
							// the read lock before we can acquire the write lock, which
							// we do at the end of this

							//NOTE: we don't want to use types.DecimalSub() since it will use max precision/scale
							left, err := decMath(info.ownedBalance, amount, types.DecimalSub)
							if err != nil {
								info.mu.RUnlock()
								return err
							}

							if left.IsNegative() {
								info.mu.RUnlock()
								return fmt.Errorf("network does not have enough balance to unlock %s for %s", amount, user)
							}

							err = transferTokensFromNetworkToUser(ctx.TxContext.Ctx, app, id, addr, amount)
							if err != nil {
								info.mu.RUnlock()
								return err
							}

							info.mu.RUnlock()
							info.mu.Lock()
							info.ownedBalance = left
							info.mu.Unlock()
							return nil
						},
					},
					{
						// balance returns the balance of a user.
						Name: "balance",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "user", Type: types.TextType},
						},
						Returns: &precompiles.MethodReturn{
							Fields: []precompiles.PrecompileValue{
								{Name: "balance", Type: uint256Numeric},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							user := inputs[1].(string)

							addr, err := ethAddressFromHex(user)
							if err != nil {
								return err
							}

							bal, err := balanceOf(ctx.TxContext.Ctx, app, id, addr)
							if err != nil {
								return err
							}

							if bal == nil {
								bal, _ = erc20ValueFromBigInt(big.NewInt(0))
							}

							return resultFn([]any{bal})
						},
					},
					{
						// bridge issues tokens from the caller's balance and optionally directs them to a specified recipient
						Name: "bridge",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "recipient", Type: types.TextType},
							{Name: "amount", Type: uint256Numeric, Nullable: true},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							recipient := inputs[1].(string)
							if recipient == "" {
								return fmt.Errorf("recipient must be provided")
							}

							var amount *types.Decimal
							// if 'amount' is omitted, withdraw all balance
							if inputs[2] == nil {
								callerAddr, err := ethAddressFromHex(ctx.TxContext.Caller)
								if err != nil {
									return err
								}

								amount, err = balanceOf(ctx.TxContext.Ctx, app, id, callerAddr)
								if err != nil {
									return err
								}
							} else {
								amount = inputs[2].(*types.Decimal)
							}

							return getSingleton().lockAndIssueTokens(ctx, app, id, ctx.TxContext.Caller, recipient, amount, ctx.TxContext.BlockContext)
						},
					},
					{
						Name: "decimals",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
						},
						Returns: &precompiles.MethodReturn{
							Fields: []precompiles.PrecompileValue{
								{Name: "decimals", Type: types.IntType},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)

							info, err := getSingleton().getUsableInstance(id)
							if err != nil {
								return err
							}

							info.mu.RLock()
							defer info.mu.RUnlock()

							return resultFn([]any{info.syncedRewardData.Erc20Decimals})
						},
					},
					{
						// scale down scales an int down to the number of decimals of the erc20 token.
						Name: "scale_down",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "amount", Type: uint256Numeric},
						},
						Returns: &precompiles.MethodReturn{
							Fields: []precompiles.PrecompileValue{
								{Name: "scaled", Type: types.TextType},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							amount := inputs[1].(*types.Decimal)

							info, err := getSingleton().getUsableInstance(id)
							if err != nil {
								return err
							}

							info.mu.RLock()
							defer info.mu.RUnlock()

							scaled, err := scaleDownUint256(amount, uint16(info.syncedRewardData.Erc20Decimals))
							if err != nil {
								return err
							}

							return resultFn([]any{scaled.String()})
						},
					},
					{
						// scale up scales an int up to the number of decimals of the erc20 token.
						Name: "scale_up",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "amount", Type: types.TextType},
						},
						Returns: &precompiles.MethodReturn{
							Fields: []precompiles.PrecompileValue{
								{Name: "scaled", Type: uint256Numeric},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							amount := inputs[1].(string)

							info, err := getSingleton().getUsableInstance(id)
							if err != nil {
								return err
							}

							info.mu.RLock()
							defer info.mu.RUnlock()

							parsed, err := types.ParseDecimalExplicit(amount, 78, uint16(info.syncedRewardData.Erc20Decimals))
							if err != nil {
								return err
							}

							scaled, err := scaleUpUint256(parsed, uint16(info.syncedRewardData.Erc20Decimals))
							if err != nil {
								return err
							}

							return resultFn([]any{scaled})
						},
					},
					{
						// get only active epochs: finalized epoch and collecting epoch
						Name: "get_active_epochs",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
						},
						Returns: &precompiles.MethodReturn{
							IsTable: true,
							Fields: []precompiles.PrecompileValue{
								{Name: "id", Type: types.UUIDType},
								{Name: "start_height", Type: types.IntType},
								{Name: "start_timestamp", Type: types.IntType},
								{Name: "end_height", Type: types.IntType, Nullable: true},
								{Name: "reward_root", Type: types.ByteaType, Nullable: true},
								{Name: "reward_amount", Type: uint256Numeric, Nullable: true},
								{Name: "end_block_hash", Type: types.ByteaType, Nullable: true},
								{Name: "confirmed", Type: types.BoolType},
								{Name: "voters", Type: types.TextArrayType, Nullable: true},
								{Name: "vote_nonces", Type: types.IntArrayType, Nullable: true},
								{Name: "voter_signatures", Type: types.ByteaArrayType, Nullable: true},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)

							return getActiveEpochs(ctx.TxContext.Ctx, app, id, func(e *Epoch) error {
								var voters []string
								if len(e.Voters) > 0 {
									for _, item := range e.Voters {
										voters = append(voters, item.String())
									}
								}

								return resultFn([]any{e.ID, e.StartHeight, e.StartTime, *e.EndHeight, e.Root, e.Total, e.BlockHash, e.Confirmed,
									voters,
									e.VoteNonces,
									e.VoteSigs,
								})
							})
						}},
					{
						// lists epochs after(non-include) given height, in ASC order.
						Name: "list_epochs",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "after", Type: types.IntType},
							{Name: "limit", Type: types.IntType},
						},
						Returns: &precompiles.MethodReturn{
							IsTable: true,
							Fields: []precompiles.PrecompileValue{
								{Name: "id", Type: types.UUIDType},
								{Name: "start_height", Type: types.IntType},
								{Name: "start_timestamp", Type: types.IntType},
								{Name: "end_height", Type: types.IntType, Nullable: true},
								{Name: "reward_root", Type: types.ByteaType, Nullable: true},
								{Name: "reward_amount", Type: uint256Numeric, Nullable: true},
								{Name: "end_block_hash", Type: types.ByteaType, Nullable: true},
								{Name: "confirmed", Type: types.BoolType},
								{Name: "voters", Type: types.TextArrayType, Nullable: true},
								{Name: "vote_nonces", Type: types.IntArrayType, Nullable: true},
								{Name: "voter_signatures", Type: types.ByteaArrayType, Nullable: true},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							after := inputs[1].(int64)
							limit := inputs[2].(int64)

							return getEpochs(ctx.TxContext.Ctx, app, id, after, limit, func(e *Epoch) error {
								var voters []string
								if len(e.Voters) > 0 {
									for _, item := range e.Voters {
										voters = append(voters, item.String())
									}
								}

								return resultFn([]any{e.ID, e.StartHeight, e.StartTime, *e.EndHeight, e.Root, e.Total, e.BlockHash, e.Confirmed,
									voters,
									e.VoteNonces,
									e.VoteSigs,
								})
							})
						},
					},
					{
						// get all rewards associated with given epoch_id
						Name: "get_epoch_rewards",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "epoch_id", Type: types.UUIDType},
						},
						Returns: &precompiles.MethodReturn{
							IsTable: true,
							Fields: []precompiles.PrecompileValue{
								{Name: "recipient", Type: types.TextType},
								{Name: "amount", Type: types.TextType},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							//id := inputs[0].(*types.UUID)
							epochID := inputs[1].(*types.UUID)
							return getRewardsForEpoch(ctx.TxContext.Ctx, app, epochID, func(reward *EpochReward) error {
								return resultFn([]any{reward.Recipient.String(), reward.Amount.String()})
							})
						},
					},
					{
						Name: "vote_epoch",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "epoch_id", Type: types.UUIDType},
							{Name: "nonce", Type: types.IntType},
							{Name: "signature", Type: types.ByteaType},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							//id := inputs[0].(*types.UUID)
							epochID := inputs[1].(*types.UUID)
							nonce := inputs[2].(int64)
							signature := inputs[3].([]byte)

							if len(signature) != utils.GnosisSafeSigLength {
								return fmt.Errorf("signature is not 65 bytes")
							}

							from, err := ethAddressFromHex(ctx.TxContext.Caller)
							if err != nil {
								return err
							}

							ok, err := canVoteEpoch(ctx.TxContext.Ctx, app, epochID)
							if err != nil {
								return fmt.Errorf("check epoch can vote: %w", err)
							}

							if !ok {
								return fmt.Errorf("epoch cannot be voted")
							}

							// For nonce=0 we must distinguish custodial (Safe) vs non-custodial (validator) votes.
							// Custodial: signature is over Safe tx hash (V=31/32). Do not verify here; Poster/Safe verify on-chain.
							// Non-custodial: signature is over (reward_root, block_hash) (V=27/28). Verify and run threshold.
							const nonCustodialNonce = 0
							if nonce == nonCustodialNonce && !utils.IsGnosisStyleSignature(signature) {
								// Non-custodial validator vote: verify signature over (reward_root, block_hash)
								result, err := app.DB.Execute(ctx.TxContext.Ctx, `
									SELECT reward_root, block_hash
									FROM kwil_erc20_meta.epochs
									WHERE id = $1
								`, epochID)
								if err != nil {
									return fmt.Errorf("failed to query epoch data for signature verification: %w", err)
								}
								if len(result.Rows) == 0 {
									return fmt.Errorf("epoch %s not found for signature verification", epochID)
								}

								// Extract reward_root and block_hash with nil checks
								if result.Rows[0][0] == nil || result.Rows[0][1] == nil {
									return fmt.Errorf("epoch %s missing reward_root or block_hash (not finalized yet)", epochID)
								}
								rewardRoot, ok := result.Rows[0][0].([]byte)
								if !ok {
									return fmt.Errorf("invalid reward_root type for epoch %s", epochID)
								}
								blockHash, ok := result.Rows[0][1].([]byte)
								if !ok {
									return fmt.Errorf("invalid block_hash type for epoch %s", epochID)
								}

								// Compute the message hash that validators sign
								messageHash, err := computeEpochMessageHash(rewardRoot, blockHash)
								if err != nil {
									return fmt.Errorf("failed to compute epoch message hash: %w", err)
								}

								// Add Ethereum signed message prefix to match contract expectation
								prefix := []byte(EthereumSignedMessagePrefix)
								ethSignedMessageHash := crypto.Keccak256(append(prefix, messageHash...))

								// Verify signature against caller's address
								// Use standard Ethereum signature verification (V=27/28) for OpenZeppelin compatibility
								err = utils.EthStandardVerifyDigest(signature, ethSignedMessageHash, from.Bytes())
								if err != nil {
									return fmt.Errorf("signature verification failed for address %s: %w", from.Hex(), err)
								}

								// Signature is valid - proceed to store vote
								if app.Service != nil && app.Service.Logger != nil {
									app.Service.Logger.Debugf("signature verified for epoch %s from validator %s", epochID, from.Hex())
								}
							}

							// Store the vote (only reached if signature verification passed for nonce=0)
							err = voteEpoch(ctx.TxContext.Ctx, app, epochID, from, nonce, signature)
							if err != nil {
								return err
							}

							// For non-custodial only: check threshold and confirm. Never confirm custodial (Safe) epochs here;
							// those are confirmed by the listener when the on-chain event is seen.
							if nonce == nonCustodialNonce && !utils.IsGnosisStyleSignature(signature) {
								hasSafeVote, err := epochHasGnosisStyleVote(ctx.TxContext.Ctx, app, epochID)
								if err != nil {
									return fmt.Errorf("check custodial votes for epoch %s: %w", epochID, err)
								}
								if hasSafeVote {
									// Custodial epoch (Safe owners voted); listener will confirm on on-chain event
									return nil
								}
								// Calculate BFT threshold (2/3 of total validator voting power)
								totalPower, thresholdPower, err := calculateBFTThreshold(app)
								if err != nil {
									if app.Service != nil && app.Service.Logger != nil {
										app.Service.Logger.Errorf("failed to calculate BFT threshold: %v", err)
									}
									return fmt.Errorf("failed to calculate BFT threshold: %w", err)
								}

								// Sum voting power of all validators who voted for this epoch
								votingPower, err := sumEpochVotingPower(ctx.TxContext.Ctx, app, epochID)
								if err != nil {
									if app.Service != nil && app.Service.Logger != nil {
										app.Service.Logger.Errorf("failed to sum voting power for epoch %s: %v", epochID, err)
									}
									return fmt.Errorf("failed to sum voting power for epoch %s: %w", epochID, err)
								}

								if app.Service != nil && app.Service.Logger != nil {
									app.Service.Logger.Debugf("epoch %s: voting_power=%d, threshold=%d, total_power=%d",
										epochID, votingPower, thresholdPower, totalPower)
								}

								// Check if threshold reached (BFT: >= 2/3 of validator voting power)
								if votingPower >= thresholdPower {
									// Get epoch merkle root for confirmation
									result, err := app.DB.Execute(ctx.TxContext.Ctx, `
										SELECT reward_root FROM kwil_erc20_meta.epochs
										WHERE id = $1
									`, epochID)
									if err != nil {
										if app.Service != nil && app.Service.Logger != nil {
											app.Service.Logger.Errorf("failed to get epoch merkle root: %v", err)
										}
										return fmt.Errorf("failed to get epoch merkle root: %w", err)
									}

									if len(result.Rows) > 0 {
										// Check for nil merkle root before type assertion
										if result.Rows[0][0] == nil {
											if app.Service != nil && app.Service.Logger != nil {
												app.Service.Logger.Warnf("epoch %s has nil reward_root, cannot confirm", epochID)
											}
											return fmt.Errorf("epoch %s has nil reward_root, cannot confirm", epochID)
										}
										merkleRoot, ok := result.Rows[0][0].([]byte)
										if !ok {
											if app.Service != nil && app.Service.Logger != nil {
												app.Service.Logger.Errorf("epoch %s reward_root is not []byte type", epochID)
											}
											return fmt.Errorf("epoch %s reward_root has invalid type %T", epochID, result.Rows[0][0])
										}
										err = confirmEpoch(ctx.TxContext.Ctx, app, merkleRoot)
										if err != nil {
											if app.Service != nil && app.Service.Logger != nil {
												app.Service.Logger.Errorf("failed to confirm epoch %s: %v", epochID, err)
											}
											return fmt.Errorf("failed to confirm epoch %s: %w", epochID, err)
										}
										if app.Service != nil && app.Service.Logger != nil {
											app.Service.Logger.Infof("epoch %s confirmed with voting_power=%d (threshold=%d)",
												epochID, votingPower, thresholdPower)
										}
									}
								}
							}

							return nil
						},
					},
					{
						// list all the rewards of the given wallet;
						// if pending=true, the results will include all finalized(not necessary confirmed) rewards
						Name: "list_wallet_rewards",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "wallet", Type: types.TextType},
							{Name: "pending", Type: types.BoolType},
						},
						Returns: &precompiles.MethodReturn{
							IsTable: true,
							Fields: []precompiles.PrecompileValue{
								{Name: "chain", Type: types.TextType},
								{Name: "chain_id", Type: types.TextType},
								{Name: "contract", Type: types.TextType},
								{Name: "created_at", Type: types.IntType},
								{Name: "param_recipient", Type: types.TextType},
								{Name: "param_amount", Type: uint256Numeric},
								{Name: "param_block_hash", Type: types.ByteaType},
								{Name: "param_root", Type: types.ByteaType},
								{Name: "param_proofs", Type: types.ByteaArrayType},
								{Name: "param_signatures", Type: types.ByteaArrayType}, // Validator signatures
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							wallet := inputs[1].(string)
							walletAddr, err := ethAddressFromHex(wallet)
							if err != nil {
								return err
							}

							pending := inputs[2].(bool)

							info, err := getSingleton().getUsableInstance(id)
							if err != nil {
								return err
							}

							info.mu.RLock()
							defer info.mu.RUnlock()

							var epochs []*Epoch
							err = getWalletEpochs(ctx.TxContext.Ctx, app, id, walletAddr, pending, func(e *Epoch) error {
								epochs = append(epochs, e)
								return nil
							})
							if err != nil {
								return fmt.Errorf("get wallet epochs :%w", err)
							}

							var jsonTree, root []byte
							var ok bool
							for _, epoch := range epochs {
								var b32Root [32]byte
								copy(b32Root[:], epoch.Root)

								jsonTree, ok = mtLRUCache.Get(b32Root)
								if !ok {
									var b32Hash [32]byte
									copy(b32Hash[:], epoch.BlockHash)
									_, jsonTree, root, _, err = genMerkleTreeForEpoch(ctx.TxContext.Ctx, app, epoch.ID, info.EscrowAddress.Hex(), b32Hash)
									if err != nil {
										return err
									}

									if !bytes.Equal(root, epoch.Root) {
										return fmt.Errorf("internal bug: epoch root mismatch")
									}

									mtLRUCache.Put(b32Root, jsonTree)
								}

								_, proofs, _, bh, amtBig, err := utils.GetMTreeProof(jsonTree, walletAddr.String())
								if err != nil {
									return err
								}

								uint256Amt, err := erc20ValueFromBigInt(amtBig)
								if err != nil {
									return err
								}

								// Query validator signatures for this epoch
								signatures, err := getEpochSignatures(ctx.TxContext.Ctx, app, epoch.ID)
								if err != nil {
									return fmt.Errorf("get epoch signatures: %w", err)
								}

								err = resultFn([]any{info.ChainInfo.Name.String(),
									info.ChainInfo.ID,
									info.EscrowAddress.String(),
									epoch.EndHeight,
									walletAddr.String(),
									uint256Amt,
									bh,
									epoch.Root,
									proofs,
									signatures, // Add validator signatures
								})
								if err != nil {
									return err
								}
							}

							return nil
						},
					},
					{
						// get_history returns the transaction history for a given wallet address.
						Name: "get_history",
						Parameters: []precompiles.PrecompileValue{
							{Name: "id", Type: types.UUIDType},
							{Name: "wallet", Type: types.TextType},
							{Name: "limit", Type: types.IntType},
							{Name: "offset", Type: types.IntType},
						},
						Returns: &precompiles.MethodReturn{
							IsTable: true,
							Fields: []precompiles.PrecompileValue{
								{Name: "type", Type: types.TextType},
								{Name: "amount", Type: uint256Numeric},
								{Name: "from_address", Type: types.ByteaType, Nullable: true},
								{Name: "to_address", Type: types.ByteaType, Nullable: true},
								{Name: "internal_tx_hash", Type: types.ByteaType, Nullable: true},
								{Name: "external_tx_hash", Type: types.ByteaType, Nullable: true},
								{Name: "status", Type: types.TextType},
								{Name: "block_height", Type: types.IntType},
								{Name: "block_timestamp", Type: types.IntType},
								{Name: "external_block_height", Type: types.IntType, Nullable: true},
							},
						},
						AccessModifiers: []precompiles.Modifier{precompiles.PUBLIC, precompiles.VIEW},
						Handler: func(ctx *common.EngineContext, app *common.App, inputs []any, resultFn func([]any) error) error {
							id := inputs[0].(*types.UUID)
							wallet := inputs[1].(string)
							limit := inputs[2].(int64)
							offset := inputs[3].(int64)

							if limit < 0 {
								return fmt.Errorf("limit must be non-negative, got %d", limit)
							}
							if limit > 1000 {
								limit = 1000
							}
							if offset < 0 {
								return fmt.Errorf("offset must be non-negative, got %d", offset)
							}

							walletAddr, err := ethAddressFromHex(wallet)
							if err != nil {
								return err
							}

							return getHistory(ctx.TxContext.Ctx, app, id, walletAddr, limit, offset, func(rec *HistoryRecord) error {
								var fromBytes []byte
								if rec.From != nil {
									fromBytes = rec.From.Bytes()
								}
								var toBytes []byte
								if rec.To != nil {
									toBytes = rec.To.Bytes()
								}
								return resultFn([]any{
									rec.Type,
									rec.Amount,
									fromBytes,
									toBytes,
									rec.InternalTxHash,
									rec.ExternalTxHash,
									rec.Status,
									rec.BlockHeight,
									rec.BlockTimestamp,
									rec.ExternalBlockHeight,
								})
							})
						},
					},
				},
			}, nil
		})
	if err != nil {
		panic(err)
	}

	// we will create the schema at genesis
	err = hooks.RegisterGenesisHook(RewardMetaExtensionName+"_genesis", func(ctx context.Context, app *common.App, chain *common.ChainContext) error {
		version, notYetSet, err := getVersion(ctx, app)
		if err != nil {
			return err
		}
		if notYetSet {
			err = genesisExec(ctx, app)
			if err != nil {
				return err
			}

			err = setVersionToCurrent(ctx, app)
			if err != nil {
				return err
			}
		} else {
			// If we are at an older version (e.g. 1), trigger the idempotent schema update
			// and bump version to current. This enables automatic migration on startup.
			if version < currentVersion {
				err = createSchema(ctx, app)
				if err != nil {
					return err
				}

				err = setVersionToCurrent(ctx, app)
				if err != nil {
					return err
				}
			}
		}

		return nil
	})
	if err != nil {
		panic(err)
	}

	// the end block hook will be used to propose epochs
	err = hooks.RegisterEndBlockHook(RewardMetaExtensionName+"_end_block", func(ctx context.Context, app *common.App, block *common.BlockContext) error {
		// in order to avoid deadlocks, we need to acquire a read lock on the singleton.
		// Recursive calls to the interpreter (which is performs) also acquire read locks, so
		// we cannot simply acquire a write lock.
		// We make a map of new epochs that we will use to track
		// which instances need to be updated. After we are done, we will update the singleton.
		newEpochs := make(map[types.UUID]*PendingEpoch)

		err := getSingleton().ForEachInstance(true, func(id *types.UUID, info *rewardExtensionInfo) error {
			info.mu.RLock()
			defer info.mu.RUnlock()
			if !info.active {
				return nil // skip inactive (e.g. unused) instances
			}
			// DEBUG: Log entry into end_block check
			elapsedTime := block.Timestamp - info.currentEpoch.StartTime
			if app.Service != nil && app.Service.Logger != nil {
				app.Service.Logger.Infof("[ENDBLOCK] Instance %s: currentEpoch ID=%s, startHeight=%d, startTime=%d, distributionPeriod=%d, elapsed=%d",
					id, info.currentEpoch.ID, info.currentEpoch.StartHeight, info.currentEpoch.StartTime, info.userProvidedData.DistributionPeriod, elapsedTime)
			}

			// If the block is greater than or equal to the start time + distribution period: Otherwise, we should do nothing.
			if block.Timestamp-info.currentEpoch.StartTime < info.userProvidedData.DistributionPeriod {
				if app.Service != nil && app.Service.Logger != nil {
					app.Service.Logger.Debugf("[ENDBLOCK] Instance %s: Not ready to finalize (elapsed %d < period %d)", id, elapsedTime, info.userProvidedData.DistributionPeriod)
				}
				return nil
			}

			// Beacon finality check removed from epoch finalization.
			// Rationale: Epoch finalization happens on TruflationNetwork consensus based on
			// withdrawal requests that already exist in TN state. The security concern for
			// beacon finality is at deposit time (preventing deposit reorg attacks), not
			// withdrawal time. Checking arbitrary Ethereum blocks during epoch finalization
			// creates false dependencies and can block withdrawals indefinitely if beacon
			// RPC is unavailable or returns errors for empty slots.
			//
			// Security model: Deposit finality is checked when processing deposit events
			// (see applyDepositLog), ensuring only finalized Ethereum deposits are credited
			// to user balances on TN.

			// There will be always 2 epochs(except the very first epoch):
			// - finalized epoch: finalized but not confirmed, wait to be confimed
			// - current epoch: collect all new rewards, wait to be finalized
			// Thus:
			// - The first epoch should always be finalized
			// - All other epochs wait for their previous epoch to be confirmed before finalizing and creating a new one.

			// NOTE: last epoch endHeight = curren epoch startHeight
			preExists, preConfirmed, err := previousEpochConfirmed(ctx, app, id, info.currentEpoch.StartHeight)
			if err != nil {
				return err
			}

			// DEBUG: Log previous epoch check result
			if app.Service != nil && app.Service.Logger != nil {
				app.Service.Logger.Infof("[ENDBLOCK] Instance %s: Previous epoch check: exists=%v, confirmed=%v (endBlock=%d)",
					id, preExists, preConfirmed, info.currentEpoch.StartHeight)
			}

			if !preExists || // first epoch should always be finalized
				(preExists && preConfirmed) { // previous epoch exists and is confirmed
				// DEBUG: Log before generating merkle tree
				if app.Service != nil && app.Service.Logger != nil {
					app.Service.Logger.Infof("[ENDBLOCK] Instance %s: Calling genMerkleTreeForEpoch with epoch ID=%s, escrow=%s",
						id, info.currentEpoch.ID, info.EscrowAddress.Hex())
				}

				leafNum, jsonBody, root, total, err := genMerkleTreeForEpoch(ctx, app, info.currentEpoch.ID, info.EscrowAddress.Hex(), block.Hash)
				if err != nil {
					return err
				}

				if leafNum == 0 {
					if app.Service != nil && app.Service.Logger != nil {
						app.Service.Logger.Warnf("[ENDBLOCK] Instance %s: genMerkleTreeForEpoch returned 0 rewards for epoch ID=%s - delaying finalization",
							id, info.currentEpoch.ID)
					}
					return nil
				}

				// DEBUG: Log successful merkle tree generation
				if app.Service != nil && app.Service.Logger != nil {
					app.Service.Logger.Infof("[ENDBLOCK] Instance %s: Generated merkle tree with %d leaves, total=%s, root=%x",
						id, leafNum, total.String(), root)
				}

				erc20Total, err := erc20ValueFromBigInt(total)
				if err != nil {
					return err
				}

				err = finalizeEpoch(ctx, app, info.currentEpoch.ID, block.Height, block.Hash[:], root, erc20Total)
				if err != nil {
					return err
				}

				// create a new epoch
				newEpoch := newPendingEpoch(id, block)

				// DEBUG: Log new epoch creation
				if app.Service != nil && app.Service.Logger != nil {
					app.Service.Logger.Infof("[ENDBLOCK] Instance %s: Creating new epoch ID=%s, startHeight=%d, startTime=%d (old epoch ID=%s)",
						id, newEpoch.ID, newEpoch.StartHeight, newEpoch.StartTime, info.currentEpoch.ID)
				}

				err = createEpoch(ctx, app, newEpoch, id)
				if err != nil {
					return err
				}

				// put merkle tree in cache
				var b32Root [32]byte
				copy(b32Root[:], root)
				mtLRUCache.Put(b32Root, jsonBody)

				newEpochs[*id] = newEpoch
				if app.Service != nil && app.Service.Logger != nil {
					app.Service.Logger.Infof("[ENDBLOCK] Instance %s: Successfully finalized epoch and created new epoch", id)
				}
				return nil
			}

			// if previous epoch exists and not confirmed, we do nothing.
			if app.Service != nil && app.Service.Logger != nil {
				app.Service.Logger.Infof("[ENDBLOCK] Instance %s: Previous epoch not confirmed yet, skipping finalization (currentEpoch ID=%s)",
					id, info.currentEpoch.ID)
			}
			return nil
		})
		if err != nil {
			return err
		}

		// now that we are done with recursive calls, we can update the singleton
		return getSingleton().ForEachInstance(false, func(id *types.UUID, info *rewardExtensionInfo) error {
			newEpoch, ok := newEpochs[*id]
			if ok {
				info.mu.Lock()
				oldEpochID := info.currentEpoch.ID
				info.currentEpoch = newEpoch

				// DEBUG: Log epoch update in memory
				if app.Service != nil && app.Service.Logger != nil {
					app.Service.Logger.Infof("[ENDBLOCK] Instance %s: Updated in-memory currentEpoch: %s -> %s",
						id, oldEpochID, newEpoch.ID)
				}

				info.mu.Unlock()
			}
			return nil
		})
	})
	if err != nil {
		panic(err)
	}
}

func genMerkleTreeForEpoch(ctx context.Context, app *common.App, epochID *types.UUID,
	escrowAddr string, blockHash [32]byte) (leafNum int, jsonTree []byte, root []byte, total *big.Int, err error) {
	// DEBUG: Log entry into genMerkleTreeForEpoch
	if app.Service != nil && app.Service.Logger != nil {
		app.Service.Logger.Infof("[MERKLE] genMerkleTreeForEpoch called with epoch ID=%s, escrow=%s", epochID, escrowAddr)
	}

	var rewards []*EpochReward
	err = getRewardsForEpoch(ctx, app, epochID, func(reward *EpochReward) error {
		rewards = append(rewards, reward)
		return nil
	})
	if err != nil {
		if app.Service != nil && app.Service.Logger != nil {
			app.Service.Logger.Errorf("[MERKLE] getRewardsForEpoch failed for epoch ID=%s: %v", epochID, err)
		}
		return 0, nil, nil, nil, err
	}

	// DEBUG: Log number of rewards collected
	if app.Service != nil && app.Service.Logger != nil {
		app.Service.Logger.Infof("[MERKLE] Collected %d rewards for epoch ID=%s", len(rewards), epochID)
	}

	if len(rewards) == 0 { // no rewards, delay finalize current epoch
		if app.Service != nil && app.Service.Logger != nil {
			app.Service.Logger.Warnf("[MERKLE] No rewards found for epoch ID=%s, returning 0", epochID)
		}
		return 0, nil, nil, nil, nil // should skip
	}

	users := make([]string, len(rewards))
	amounts := make([]*big.Int, len(rewards))
	total = big.NewInt(0)

	for i, r := range rewards {
		users[i] = r.Recipient.Hex()
		amounts[i] = r.Amount.BigInt()
		total.Add(total, amounts[i])
	}

	jsonTree, root, err = utils.GenRewardMerkleTree(users, amounts, escrowAddr, blockHash)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	return len(rewards), jsonTree, root, total, nil
}

func genesisExec(ctx context.Context, app *common.App) error {
	// we will create the schema at genesis
	err := app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, "USE kwil_erc20_meta AS kwil_erc20_meta", nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func callPrepare(ctx *common.EngineContext, app *common.App, chain string, escrow string, period string) (*types.UUID, error) {
	var id *types.UUID
	count := 0
	res, err := app.Engine.Call(ctx, app.DB, RewardMetaExtensionName, "prepare", []any{chain, escrow, period}, func(r *common.Row) error {
		if count > 0 {
			return fmt.Errorf("internal bug: expected only one result on prepare erc20")
		}
		var ok bool
		id, ok = r.Values[0].(*types.UUID)
		if !ok {
			return fmt.Errorf("internal bug: expected UUID")
		}

		count++
		return nil
	})
	if err != nil {
		return nil, err
	}

	return id, res.Error
}

func callDisable(ctx *common.EngineContext, app *common.App, id *types.UUID) error {
	res, err := app.Engine.Call(ctx, app.DB, RewardMetaExtensionName, "disable", []any{id}, nil)
	if err != nil {
		return err
	}

	return res.Error
}

// lockTokens locks tokens from a user's balance and gives them to the network.
func (e *extensionInfo) lockTokens(ctx context.Context, app *common.App, id *types.UUID, from string, amount *types.Decimal) error {
	fromAddr, err := ethAddressFromHex(from)
	if err != nil {
		return err
	}

	if !amount.IsPositive() {
		return fmt.Errorf("amount needs to be positive")
	}

	bal, err := balanceOf(ctx, app, id, fromAddr)
	if err != nil {
		return err
	}

	cmp, err := bal.Cmp(amount)
	if err != nil {
		return err
	}

	if cmp < 0 {
		return fmt.Errorf("insufficient balance")
	}

	// we call getUsableInstance before transfer to ensure that the extension is active and synced.
	// We don't actually use the mutex lock here because it will cause a deadlock with the transfer function
	// (which recursively calls the interpreter), we just simply want to make sure that the extension
	// is active and synced.
	info, err := e.getUsableInstance(id)
	if err != nil {
		return err
	}

	// we add before we store the transfer in the DB because if we have an error in the add,
	// we dont want to store the transfer in the DB.
	// We also cannot just acquire a write lock here because transferTokensFromUserToNetwork
	// calls the engine, which acquires a read lock on this extension.
	info.mu.RLock()
	newAddedBal, err := decMath(info.ownedBalance, amount, types.DecimalAdd)
	if err != nil {
		info.mu.RUnlock()
		return err
	}
	info.mu.RUnlock()

	err = transferTokensFromUserToNetwork(ctx, app, id, fromAddr, amount)
	if err != nil {
		return err
	}

	info.mu.Lock()
	info.ownedBalance = newAddedBal
	info.mu.Unlock()

	return nil
}

// issueTokens issues tokens from network's balance.
func (e *extensionInfo) issueTokens(ctx context.Context, app *common.App, id *types.UUID, to string, amount *types.Decimal) error {
	if !amount.IsPositive() {
		return fmt.Errorf("amount needs to be positive")
	}

	// then issue to caller itself
	// because this is in one tx, we can be sure that the instance has enough balance to issue.
	info, err := e.getUsableInstance(id)
	if err != nil {
		return err
	}

	info.mu.RLock()
	// we cannot defer an RUnlock here because we need to unlock
	// the read lock before we can acquire the write lock, which
	// we do at the end of this

	newBal, err := decMath(info.ownedBalance, amount, types.DecimalSub)
	if err != nil {
		info.mu.RUnlock()
		return err
	}

	if newBal.IsNegative() {
		info.mu.RUnlock()
		return fmt.Errorf("network does not enough balance to issue %s to %s", amount, to)
	}

	addr, err := ethAddressFromHex(to)
	if err != nil {
		info.mu.RUnlock()
		return err
	}

	err = issueReward(ctx, app, id, info.currentEpoch.ID, addr, amount)
	if err != nil {
		info.mu.RUnlock()
		return err
	}

	info.mu.RUnlock()

	// it is critical that we only update the in-memory balance after the tx has been successfully executed
	info.mu.Lock()
	info.ownedBalance = newBal
	info.mu.Unlock()

	return nil
}

// lockAndIssueTokens locks tokens from the sender and issues them to the desired recipient within the current epoch.
func (e *extensionInfo) lockAndIssueTokens(ctx *common.EngineContext, app *common.App, id *types.UUID, from string, recipient string, amount *types.Decimal, block *common.BlockContext) error {
	if amount == nil {
		return fmt.Errorf("amount needs to be positive")
	}

	fromAddr, err := ethAddressFromHex(from)
	if err != nil {
		return err
	}

	recipientAddr, err := ethAddressFromHex(recipient)
	if err != nil {
		return err
	}

	if !amount.IsPositive() {
		return fmt.Errorf("amount needs to be positive")
	}

	bal, err := balanceOf(ctx.TxContext.Ctx, app, id, fromAddr)
	if err != nil {
		return err
	}

	if bal == nil {
		return fmt.Errorf("insufficient balance")
	}

	cmp, err := bal.Cmp(amount)
	if err != nil {
		return err
	}

	if cmp < 0 {
		return fmt.Errorf("insufficient balance")
	}

	// we call getUsableInstance before transfer to ensure that the extension is active and synced.
	// We don't actually use the mutex lock here because it will cause a deadlock with the transfer function
	// (which recursively calls the interpreter), we just simply want to make sure that the extension
	// is active and synced.
	info, err := e.getUsableInstance(id)
	if err != nil {
		return err
	}

	info.mu.RLock()
	defer info.mu.RUnlock()

	// DEBUG: Log withdrawal request
	if app.Service != nil && app.Service.Logger != nil {
		app.Service.Logger.Infof("[WITHDRAWAL] Instance %s: User %s requesting withdrawal to %s, amount=%s, currentEpoch ID=%s",
			id, fromAddr.Hex(), recipientAddr.Hex(), amount.String(), info.currentEpoch.ID)
	}

	// we dont need to update the cached data here since we are directly converting
	// a user balance (which is never cached) into a reward (which is also never cached)
	err = lockAndIssue(ctx.TxContext.Ctx, app, id, info.currentEpoch.ID, fromAddr, recipientAddr, amount)
	if err != nil {
		if app.Service != nil && app.Service.Logger != nil {
			app.Service.Logger.Errorf("[WITHDRAWAL] Instance %s: lockAndIssue failed for epoch ID=%s: %v",
				id, info.currentEpoch.ID, err)
		}
		return err
	}

	internalTxHash, err := hex.DecodeString(ctx.TxContext.TxID)
	if err != nil {
		return fmt.Errorf("failed to decode internal tx id %s: %w", ctx.TxContext.TxID, err)
	}

	// Record transaction history
	// Include internalTxHash to prevent UUID collisions if same user withdraws to same recipient multiple times in one epoch
	txHistoryID := types.NewUUIDV5WithNamespace(
		types.NewUUIDV5WithNamespace(*id, info.currentEpoch.ID.Bytes()),
		append(append(append([]byte("withdrawal"), fromAddr.Bytes()...), recipientAddr.Bytes()...), internalTxHash...))

	_, err = app.DB.Execute(ctx.TxContext.Ctx, `
		INSERT INTO kwil_erc20_meta.transaction_history
		(id, instance_id, type, from_address, to_address, amount, internal_tx_hash, status, block_height, block_timestamp, epoch_id)
		VALUES ($1, $2, 'withdrawal', $3, $4, $5, $6, 'pending_epoch', $7, $8, $9)
		ON CONFLICT (id) DO NOTHING
	`, txHistoryID, id, fromAddr.Bytes(), recipientAddr.Bytes(), amount, internalTxHash, block.Height, block.Timestamp, info.currentEpoch.ID)
	if err != nil {
		return fmt.Errorf("failed to record withdrawal history: %w", err)
	}

	if app.Service != nil && app.Service.Logger != nil {
		app.Service.Logger.Infof("[WITHDRAWAL] Instance %s: Successfully added withdrawal to epoch ID=%s", id, info.currentEpoch.ID)
	}
	return nil
}

// decMath is a utility function that performs decimal math, guaranteeing precision and scale AND
// guaranteeing that the x value is not modified. This is necessary because Kwil's core package
// only provides functionality for EITHER maintaining precision and scale OR maintaining the original
// value, but not both. For example, (z *types.Decimal).Add(x,y) will modify z. The types package does this
// for performance reasons, but in this package, we need to maintain strict control over when in-memory
// values are updated vs rolled back, so we need to ensure the old underlying value is not modified.
// This function should pass functions like types.DecimalAdd() RATHER than the methods on the Decimal type.
func decMath(x, y *types.Decimal, op func(*types.Decimal, *types.Decimal) (*types.Decimal, error)) (*types.Decimal, error) {
	// the types package's DecimalAdd/DecimalSub return a copy of the result, but it does not guarantee
	// precision and scale
	z, err := op(x, y)
	if err != nil {
		return nil, err
	}

	err = z.SetPrecisionAndScale(x.Precision(), x.Scale())
	if err != nil {
		return nil, err
	}

	return z, nil
}

// getUsableInstance gets an instance and ensures it is active and synced.
func (e *extensionInfo) getUsableInstance(id *types.UUID) (*rewardExtensionInfo, error) {
	info, ok := e.instances.Get(*id)
	if !ok {
		return nil, fmt.Errorf("reward extension with id %s not found", id)
	}

	info.mu.RLock()
	defer info.mu.RUnlock()

	if !info.active {
		return nil, fmt.Errorf("reward extension with id %s is not active", id)
	}

	if !info.synced {
		return nil, fmt.Errorf("reward extension with id %s is not synced", id)
	}

	return info, nil
}

// getSingleton returns the appropriate singleton (test or production)
var (
	singletonInstance *extensionInfo
	singletonInitOnce sync.Once
)

func getSingleton() *extensionInfo {
	if _SINGLETON != nil { // test build override
		return _SINGLETON
	}
	singletonInitOnce.Do(func() {
		if singletonInstance == nil {
			singletonInstance = &extensionInfo{instances: newInstanceMap()}
		}
	})
	return singletonInstance
}

func ethAddressFromHex(s string) (ethcommon.Address, error) {
	if !ethcommon.IsHexAddress(s) {
		return ethcommon.Address{}, fmt.Errorf("invalid ethereum address: %s", s)
	}
	return ethcommon.HexToAddress(s), nil
}

// newPendingEpoch creates a new epoch.
func newPendingEpoch(rewardID *types.UUID, block *common.BlockContext) *PendingEpoch {
	return &PendingEpoch{
		ID:          generateEpochID(rewardID, block.Height),
		StartHeight: block.Height,
		StartTime:   block.Timestamp,
	}
}

// PendingEpoch is an epoch that has been started but not yet finalized.
type PendingEpoch struct {
	ID          *types.UUID
	StartHeight int64
	StartTime   int64
}

// EpochReward is a reward given to a user within an epoch
type EpochReward struct {
	Recipient ethcommon.Address
	Amount    *types.Decimal // numeric(78, 0)
}

func (p *PendingEpoch) copy() *PendingEpoch {
	id := *p.ID
	return &PendingEpoch{
		ID:          &id,
		StartHeight: p.StartHeight,
		StartTime:   p.StartTime,
	}
}

type EpochVoteInfo struct {
	Voters     []ethcommon.Address
	VoteSigs   [][]byte
	VoteNonces []int64
}

// Epoch is a period in which rewards are distributed.
type Epoch struct {
	PendingEpoch
	EndHeight *int64 // nil if not finalized
	Root      []byte // merkle root of all rewards, nil if not finalized
	Total     *types.Decimal
	BlockHash []byte // hash of the block that finalized the epoch, nil if not finalized
	Confirmed bool
	EpochVoteInfo
}

type extensionInfo struct {
	// instances tracks all child reward extensions
	instances *syncmap.Map[types.UUID, *rewardExtensionInfo]
}

func newInstanceMap() *syncmap.Map[types.UUID, *rewardExtensionInfo] {
	return syncmap.New[types.UUID, *rewardExtensionInfo]()
}

// Copy implements the precompiles.Cache interface.
func (e *extensionInfo) Copy() precompiles.Cache {
	instances := newInstanceMap()
	instances.Exclusive(func(m map[types.UUID]*rewardExtensionInfo) {
		e.instances.ExclusiveRead(func(m2 map[types.UUID]*rewardExtensionInfo) {
			for k, v := range m2 {
				v.mu.RLock()
				m[k] = v.copy()
				v.mu.RUnlock()
			}
		})
	})

	return &extensionInfo{
		instances: instances,
	}
}

func (e *extensionInfo) Apply(v precompiles.Cache) {
	info := v.(*extensionInfo)
	e.instances = info.instances
}

// ForEachInstance deterministically iterates over all instances of the extension.
// If readOnly is false, can safely modify the instances. It does NOT lock the info.
func (e *extensionInfo) ForEachInstance(readOnly bool, fn func(id *types.UUID, info *rewardExtensionInfo) error) error {
	iter := e.instances.ExclusiveRead
	if !readOnly {
		iter = e.instances.Exclusive
	}

	var err error
	iter(func(m map[types.UUID]*rewardExtensionInfo) {
		orderableMap := make(map[string]*rewardExtensionInfo)
		for k, v := range m {
			orderableMap[k.String()] = v
		}

		for _, kv := range order.OrderMap(orderableMap) {
			err = fn(kv.Value.userProvidedData.ID, kv.Value)
			if err != nil {
				return
			}
		}
	})

	return err
}

// userProvidedData holds information about a reward that is known as soon
// as the `create` action is called.
type userProvidedData struct {
	ID                 *types.UUID       // auto-generated
	ChainInfo          *chains.ChainInfo // chain ID of the EVM chain
	EscrowAddress      ethcommon.Address // address of the escrow contract
	DistributionPeriod int64             // period (in seconds) between reward distributions
}

func (u *userProvidedData) copy() *userProvidedData {
	id := *u.ID
	cInfo := *u.ChainInfo
	return &userProvidedData{
		ID:                 &id,
		ChainInfo:          &cInfo,
		EscrowAddress:      u.EscrowAddress,
		DistributionPeriod: u.DistributionPeriod,
	}
}

// syncedRewardData holds information about a reward that is synced from
// on chain.
type syncedRewardData struct {
	Erc20Address  ethcommon.Address // address of the erc20 contract
	Erc20Decimals int64             // decimals of the erc20 contract
}

func (s *syncedRewardData) copy() *syncedRewardData {
	return &syncedRewardData{
		Erc20Address:  s.Erc20Address,
		Erc20Decimals: s.Erc20Decimals,
	}
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (s *syncedRewardData) MarshalBinary() ([]byte, error) {
	// Allocate 28 bytes: 20 for the address, 8 for the int64.
	b := make([]byte, 28)
	// Copy the address bytes into the first 20 bytes.
	copy(b[:20], s.Erc20Address[:])
	// Encode Erc20Decimals into the next 8 bytes using BigEndian.
	binary.BigEndian.PutUint64(b[20:], uint64(s.Erc20Decimals))
	return b, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (s *syncedRewardData) UnmarshalBinary(data []byte) error {
	// Check that the data is exactly 28 bytes.
	if len(data) != 28 {
		return fmt.Errorf("invalid data length: expected 28, got %d", len(data))
	}
	// Copy the first 20 bytes into the address.
	copy(s.Erc20Address[:], data[:20])
	// Decode the last 8 bytes into Erc20Decimals.
	s.Erc20Decimals = int64(binary.BigEndian.Uint64(data[20:28]))
	return nil
}

// rewardExtensionInfo holds information about a reward extension
type rewardExtensionInfo struct {
	// mu protects all fields in the struct
	mu sync.RWMutex
	userProvidedData
	syncedRewardData
	synced       bool
	syncedAt     int64
	active       bool
	ownedBalance *types.Decimal // balance owned by DB that can be distributed
	currentEpoch *PendingEpoch  // current epoch being proposed
}

func (r *rewardExtensionInfo) copy() *rewardExtensionInfo {
	var decCopy *types.Decimal
	if r.ownedBalance != nil {
		decCopy = types.MustParseDecimalExplicit(r.ownedBalance.String(), 78, 0)
	}
	return &rewardExtensionInfo{
		userProvidedData: *r.userProvidedData.copy(),
		syncedRewardData: *r.syncedRewardData.copy(),
		synced:           r.synced,
		syncedAt:         r.syncedAt,
		active:           r.active,
		ownedBalance:     decCopy,
		currentEpoch:     r.currentEpoch.copy(),
	}
}

// loggingContext returns a human-readable identifier for logging
// Format: "chain.escrow_suffix" (e.g., "hoodi.31554e7")
func (r *rewardExtensionInfo) loggingContext() string {
	// Use last 7 chars of escrow address for human identification
	escrowHex := r.EscrowAddress.Hex()
	if len(escrowHex) >= 7 {
		escrowSuffix := escrowHex[len(escrowHex)-7:]
		return fmt.Sprintf("%s.%s", r.ChainInfo.Name, escrowSuffix)
	}
	return string(r.ChainInfo.Name)
}

// startStatePoller starts a state poller for the reward extension.
func (r *rewardExtensionInfo) startStatePoller() error {
	synced := r.synced // copy to avoid race conditions
	escrow := r.EscrowAddress
	id := *r.ID
	chainName := r.ChainInfo.Name
	logContext := r.loggingContext() // capture for use in closure

	return evmsync.StatePoller.RegisterPoll(evmsync.PollConfig{
		Chain:          chainName,
		ResolutionName: statePollResolutionName,
		PollFunc: func(ctx context.Context, service *common.Service, eventstore listeners.EventKV, broadcast func(context.Context, []byte) error, client *ethclient.Client) {
			// It is _very_ important that we do not change the state of the struct here.
			// This function runs external to consensus, so we must not change the state of the struct.
			if synced {
				return
			}

			data, err := getSyncedRewardData(ctx, client, escrow)
			if err != nil {
				logger := service.Logger.New(statePollerUniqueName(id) + "." + logContext)
				logger.Errorf("failed to get synced reward data: %v", err)
				return
			}

			bts, err := data.MarshalBinary()
			if err != nil {
				panic(err) // internal logic bug in this package
			}

			err = broadcast(ctx, bts)
			if err != nil {
				logger := service.Logger.New(statePollerUniqueName(id) + "." + logContext)
				logger.Errorf("failed to get broadcast reward data to network: %v", err)
				return
			}

			synced = true
			// we dont update *rewardExtensionInfo here because we are outside of the consensus process.
			// It will be updated in the resolveFunc
		},
		UniqueName: statePollerUniqueName(*r.ID),
	})
}

// startDepositListener starts an event listener that listens for Deposit events on the bridge contract.
// It supports both RewardDistributor (non-indexed recipient) and TrufNetworkBridge (indexed recipient) formats.
// This method is idempotent - calling it multiple times for the same instance is safe.
//
// Returns (error, wasStarted) where:
//   - (nil, true): Successfully registered a NEW listener (caller owns cleanup responsibility)
//   - (nil, false): Listener already existed (caller should NOT clean up)
//   - (err, false): Registration failed (caller should NOT clean up)
func (r *rewardExtensionInfo) startDepositListener() (error, bool) {
	// Check if deposit listener is already running for this instance
	instanceIDStr := r.ID.String()
	runningListenersMu.Lock()
	if runningDepositListeners[instanceIDStr] {
		runningListenersMu.Unlock()
		// Already running, skip registration
		return nil, false
	}
	runningDepositListeners[instanceIDStr] = true
	runningListenersMu.Unlock()

	// Ensure we start with a clean state in the global registry
	_ = evmsync.EventSyncer.UnregisterListener(depositListenerUniqueName(*r.ID))

	// I'm not sure if copies are needed because the values should never be modified,
	// but just in case, I copy them to be used in GetLogs, which runs outside of consensus
	escrowCopy := r.EscrowAddress
	evmMaxRetries := int64(10) // retry on evm RPC request is crucial

	// we now register synchronization of the Deposit event
	err := evmsync.EventSyncer.RegisterNewListener(evmsync.EVMEventListenerConfig{
		UniqueName: depositListenerUniqueName(*r.ID),
		Chain:      r.ChainInfo.Name,
		GetLogs: func(ctx context.Context, client *ethclient.Client, startBlock, endBlock uint64, logger log.Logger) ([]*evmsync.EthLog, error) {
			if logger != nil {
				logger.Debugf("[HEARTBEAT] Deposit Listener (%s) syncing blocks %d -> %d", instanceIDStr, startBlock, endBlock)
			}
			var logs []*evmsync.EthLog

			// TODO(migration): Remove RewardDistributor fallback once all deployments migrate to TrufNetworkBridge.
			// Try RewardDistributor format first (backward compatibility)
			rewardFilt, err := abigen.NewRewardDistributorFilterer(escrowCopy, client)
			if err != nil {
				return nil, fmt.Errorf("failed to bind to RewardDistributor filterer: %w", err)
			}

			var depositIter *abigen.RewardDistributorDepositIterator
			err = utils.Retry(ctx, evmMaxRetries, func() error {
				depositIter, err = rewardFilt.FilterDeposit(&bind.FilterOpts{
					Start:   startBlock,
					End:     &endBlock,
					Context: ctx,
				})
				if err != nil {
					return fmt.Errorf("failed to get RewardDistributor deposit logs: %w", err)
				}
				return nil
			})
			var iterErr error
			if err != nil {
				logger.Warnf("RewardDistributor FilterDeposit failed (trying TrufNetworkBridge): %v", err)
			} else {
				// Successfully got RewardDistributor events
				defer depositIter.Close()
				for depositIter.Next() {
					// Deep copy the log to avoid pointing to the iterator's internal reused struct
					logCopy := depositIter.Event.Raw

					// Fetch the sender address from the transaction
					fromAddr := fetchTxSender(ctx, client, logCopy.TxHash, evmMaxRetries, logger)

					metadata := make([]byte, 0, len(logTypeDeposit)+20)
					metadata = append(metadata, logTypeDeposit...)
					if fromAddr != nil {
						metadata = append(metadata, fromAddr.Bytes()...)
					}

					logs = append(logs, &evmsync.EthLog{
						Metadata: metadata,
						Log:      &logCopy,
					})
				}
				iterErr = depositIter.Error()
				if iterErr != nil {
					// Iteration failed (likely ABI parsing error) - try TrufNetworkBridge
					logger.Warnf("RewardDistributor deposit iteration failed (trying TrufNetworkBridge): %v", iterErr)
					logs = nil // Clear any partial results
				}
			}

			// Try TrufNetworkBridge format (if RewardDistributor failed or returned no events)
			// TODO(migration): Make this the primary path and remove RewardDistributor fallback once migration complete.
			if err != nil || iterErr != nil || len(logs) == 0 {
				bridgeFilt, bridgeErr := abigen.NewTrufNetworkBridgeFilterer(escrowCopy, client)
				if bridgeErr != nil {
					return nil, fmt.Errorf("failed to bind to TrufNetworkBridge filterer: %w", bridgeErr)
				}

				var bridgeDepositIter *abigen.TrufNetworkBridgeDepositIterator
				bridgeErr = utils.Retry(ctx, evmMaxRetries, func() error {
					// nil recipient filter = get deposits for all recipients
					bridgeDepositIter, bridgeErr = bridgeFilt.FilterDeposit(&bind.FilterOpts{
						Start:   startBlock,
						End:     &endBlock,
						Context: ctx,
					}, nil)
					if bridgeErr != nil {
						return fmt.Errorf("failed to get TrufNetworkBridge deposit logs: %w", bridgeErr)
					}
					return nil
				})
				if bridgeErr != nil {
					return nil, bridgeErr
				}
				defer bridgeDepositIter.Close()

				// Clear logs from failed RewardDistributor attempt
				if err != nil {
					logs = nil
				}

				for bridgeDepositIter.Next() {
					// Deep copy the log to avoid pointing to the iterator's internal reused struct
					logCopy := bridgeDepositIter.Event.Raw

					// Fetch the sender address from the transaction
					// This runs outside consensus, so external RPC calls are safe
					fromAddr := fetchTxSender(ctx, client, logCopy.TxHash, evmMaxRetries, logger)

					metadata := make([]byte, 0, len(logTypeDeposit)+20)
					metadata = append(metadata, logTypeDeposit...)
					if fromAddr != nil {
						metadata = append(metadata, fromAddr.Bytes()...)
					}

					logs = append(logs, &evmsync.EthLog{
						Metadata: metadata,
						Log:      &logCopy,
					})
				}
				if err := bridgeDepositIter.Error(); err != nil {
					return nil, fmt.Errorf("failed to iterate TrufNetworkBridge deposit logs: %w", err)
				}
			}

			// TODO(migration): Remove RewardPosted event handling once all deployments migrate to TrufNetworkBridge.
			// TrufNetworkBridge uses local validator voting for epoch confirmation, not on-chain RewardPosted events.
			// Fetch RewardPosted events (only RewardDistributor has this)
			var postIter *abigen.RewardDistributorRewardPostedIterator
			err = utils.Retry(ctx, evmMaxRetries, func() error {
				postIter, err = rewardFilt.FilterRewardPosted(&bind.FilterOpts{
					Start:   startBlock,
					End:     &endBlock,
					Context: ctx,
				})
				if err != nil {
					return fmt.Errorf("failed to get reward posted logs: %w", err)
				}
				return nil
			})
			if err != nil {
				// TrufNetworkBridge doesn't have RewardPosted events, so this is expected to fail
				logger.Debugf("RewardPosted events not available (expected for TrufNetworkBridge): %v", err)
			} else {
				defer postIter.Close()

				for postIter.Next() {
					// Deep copy the log to avoid pointing to the iterator's internal reused struct
					logCopy := postIter.Event.Raw
					logs = append(logs, &evmsync.EthLog{
						Metadata: logTypeConfirmedEpoch,
						Log:      &logCopy,
					})
				}
				if err := postIter.Error(); err != nil {
					return nil, fmt.Errorf("failed to iterate reward posted logs: %w", err)
				}
			}

			return logs, nil
		},
	})

	if err != nil {
		// Registration failed, clean up tracking
		// Lock still held (deferred unlock)
		delete(runningDepositListeners, instanceIDStr)
		return err, false
	}

	// Successfully started a NEW listener - caller owns cleanup responsibility
	return nil, true
}

// startWithdrawalListener starts an event listener that listens for Withdraw events on the contract.
// The listener is registered for all instances but only processes events if the contract emits them.
// Old contracts (RewardDistributor) never emit Withdraw events, so the listener remains dormant for those instances.
// This method is idempotent - calling it multiple times for the same instance is safe.
//
// Returns (error, wasStarted) where:
//   - (nil, true): Successfully registered a NEW listener (caller owns cleanup responsibility)
//   - (nil, false): Listener already existed (caller should NOT clean up)
//   - (err, false): Registration failed (caller should NOT clean up)
func (r *rewardExtensionInfo) startWithdrawalListener() (error, bool) {
	// Check if withdrawal listener is already running for this instance
	instanceIDStr := r.ID.String()
	runningListenersMu.Lock()
	if runningWithdrawalListeners[instanceIDStr] {
		runningListenersMu.Unlock()
		// Already running, skip registration
		return nil, false
	}
	runningWithdrawalListeners[instanceIDStr] = true
	runningListenersMu.Unlock()

	// Ensure we start with a clean state in the global registry
	// This is the long-term fix for stale listeners after crashes
	_ = evmsync.EventSyncer.UnregisterListener(withdrawalListenerUniqueName(*r.ID))

	// Copy values to avoid race conditions in GetLogs (runs outside consensus)
	escrowCopy := r.EscrowAddress
	evmMaxRetries := int64(10) // retry on evm RPC request is crucial

	// Register withdrawal event listener
	err := evmsync.EventSyncer.RegisterNewListener(evmsync.EVMEventListenerConfig{
		UniqueName: withdrawalListenerUniqueName(*r.ID),
		Chain:      r.ChainInfo.Name,
		GetLogs: func(ctx context.Context, client *ethclient.Client, startBlock, endBlock uint64, logger log.Logger) ([]*evmsync.EthLog, error) {
			if logger != nil {
				logger.Debugf("[HEARTBEAT] Withdrawal Listener (%s) syncing blocks %d -> %d", instanceIDStr, startBlock, endBlock)
			}
			bridgeFilt, err := abigen.NewTrufNetworkBridgeFilterer(escrowCopy, client)
			if err != nil {
				return nil, fmt.Errorf("failed to bind to TrufNetworkBridge filterer: %w", err)
			}

			var logs []*evmsync.EthLog

			// Fetch Withdraw events
			var withdrawIter *abigen.TrufNetworkBridgeWithdrawIterator
			err = utils.Retry(ctx, evmMaxRetries, func() error {
				withdrawIter, err = bridgeFilt.FilterWithdraw(&bind.FilterOpts{
					Start:   startBlock,
					End:     &endBlock,
					Context: ctx,
				}, nil, nil) // nil filters = get all recipients and kwilBlockHashes
				if err != nil {
					return fmt.Errorf("failed to get withdraw logs: %w", err)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			defer withdrawIter.Close()

			for withdrawIter.Next() {
				// Deep copy the log to avoid pointing to the iterator's internal reused struct
				logCopy := withdrawIter.Event.Raw
				logs = append(logs, &evmsync.EthLog{
					Metadata: logTypeWithdrawal,
					Log:      &logCopy,
				})
			}
			if err := withdrawIter.Error(); err != nil {
				return nil, fmt.Errorf("failed to get withdraw logs: %w", err)
			}

			return logs, nil
		},
	})

	if err != nil {
		// Registration failed, clean up tracking
		// Lock still held (deferred unlock)
		delete(runningWithdrawalListeners, instanceIDStr)
		return err, false
	}

	// Successfully started a NEW listener - caller owns cleanup responsibility
	return nil, true
}

// stopAllListeners stops all event listeners for the reward extension.
// If it is synced, this means it must have active Deposit and Withdrawal listeners.
// If it is not synced, it must have an active state poller.
// NOTE: UnregisterListener doesn't unregister the topic because the reward
// instance will not be deleted when `unuse`/`disable`, we need to keep the
// topics to make sure we don't lose events.
func (r *rewardExtensionInfo) stopAllListeners() error {
	if r.synced {
		var errs []error

		// Attempt to stop deposit listener
		if err := evmsync.EventSyncer.UnregisterListener(depositListenerUniqueName(*r.ID)); err != nil {
			// Ignore "not registered" errors to make UNUSE idempotent
			if !errors.Is(err, evmsync.ErrListenerNotRegistered) {
				errs = append(errs, fmt.Errorf("failed to unregister deposit listener: %w", err))
			}
		}

		// Attempt to stop withdrawal listener
		if err := evmsync.EventSyncer.UnregisterListener(withdrawalListenerUniqueName(*r.ID)); err != nil {
			// Ignore "not registered" errors to make UNUSE idempotent
			if !errors.Is(err, evmsync.ErrListenerNotRegistered) {
				errs = append(errs, fmt.Errorf("failed to unregister withdrawal listener: %w", err))
			}
		}

		// Return combined error if any failed
		if len(errs) > 0 {
			return fmt.Errorf("listener cleanup errors: %v", errs)
		}
		return nil
	}

	err := evmsync.StatePoller.UnregisterPoll(statePollerUniqueName(*r.ID))
	if err != nil && !errors.Is(err, evmsync.ErrPollerNotFound) {
		return err
	}
	return nil
}

// nilEthFilterer is a dummy filterer that does nothing.
// Abigen requires a filter to be passed in order to parse event info from logs,
// however the client itself is never actually used.
type nilEthFilterer struct{}

func (nilEthFilterer) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]ethtypes.Log, error) {
	return nil, fmt.Errorf("filter logs was not expected to be called")
}

func (nilEthFilterer) SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- ethtypes.Log) (ethereum.Subscription, error) {
	return nil, fmt.Errorf("subscribe filter logs was not expected to be called")
}

// applyDepositLog applies a Deposit log to the reward extension.
// It supports both RewardDistributor (non-indexed recipient) and TrufNetworkBridge (indexed recipient) formats.
// The format is auto-detected based on the event log structure.
//
// SECURITY: Deposits are processed immediately for optimal UX (no finality delay).
// Withdrawals are protected by beacon finality check during epoch finalization (endBlock).
// This design prioritizes user experience while maintaining security where it matters most.
// This function runs during consensus execution and must remain deterministic.
//
// TODO(migration): Simplify to only TrufNetworkBridge format once all deployments migrated.
func applyDepositLog(ctx context.Context, app *common.App, id *types.UUID, log ethtypes.Log, block *common.BlockContext, fromAddr *ethcommon.Address) error {
	var recipient ethcommon.Address
	var amount *big.Int
	var err error

	// Detect event format based on log structure:
	// - TrufNetworkBridge: indexed recipient (topics[1]), amount in data (32 bytes)
	// - RewardDistributor: non-indexed recipient and amount in data (64 bytes)
	if len(log.Topics) >= 2 && len(log.Data) == 32 {
		// TrufNetworkBridge format (indexed recipient)
		bridgeData, parseErr := bridgeLogParser.ParseDeposit(log)
		if parseErr != nil {
			return fmt.Errorf("failed to parse TrufNetworkBridge Deposit event: %w", parseErr)
		}
		recipient = bridgeData.Recipient
		amount = bridgeData.Amount
	} else if len(log.Data) == 64 {
		// TODO(migration): Remove RewardDistributor support once migration complete.
		// RewardDistributor format (non-indexed recipient)
		rewardData, parseErr := rewardLogParser.ParseDeposit(log)
		if parseErr != nil {
			return fmt.Errorf("failed to parse RewardDistributor Deposit event: %w", parseErr)
		}
		recipient = rewardData.Recipient
		amount = rewardData.Amount
	} else {
		return fmt.Errorf("unknown Deposit event format: topics=%d, data_len=%d", len(log.Topics), len(log.Data))
	}

	// Deposit finality is now checked in the EVENT LISTENER (GetLogs function), which runs
	// EXTERNAL to consensus execution. This prevents the appHash mismatch bug that occurred
	// when finality checks ran during consensus.
	//
	// How it works:
	// 1. Each validator's event listener queries Ethereum for finalized block (background service)
	// 2. Listener only fetches deposits from finalized blocks
	// 3. Listener broadcasts resolution proposal with finalized deposits
	// 4. Validators vote on proposals (resolution voting system)
	// 5. Majority consensus determines which deposits are accepted
	// 6. THIS function (applyDepositLog) processes only the voted/confirmed deposits
	// 7. All validators see the same confirmed deposits → Same appHash ✅
	//
	// Security:
	// - Only finalized Ethereum blocks are processed (~15 min after inclusion)
	// - Prevents deposit reorg attacks (15-min window eliminated)
	// - Resolution voting ensures consensus even if validators query at different times
	//
	// Implementation:
	// - registerDepositListener() GetLogs function (line ~2369)
	// - registerWithdrawalListener() GetLogs function (line ~2561)
	//
	// Note: This function runs during consensus execution and must remain deterministic.
	// All external data fetching happens in the event listener, not here.

	val, err := erc20ValueFromBigInt(amount)
	if err != nil {
		return fmt.Errorf("failed to convert big.Int to decimal.Decimal: %w", err)
	}

	// Record transaction history
	// Include log index to prevent UUID collisions when a single Ethereum tx has multiple Deposit events
	logIndexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(logIndexBytes, uint32(log.Index))

	txHistoryID := types.NewUUIDV5WithNamespace(
		types.NewUUIDV5WithNamespace(*id, log.TxHash.Bytes()),
		append([]byte("deposit"), logIndexBytes...))

	var fromAddrBytes any
	if fromAddr != nil {
		fromAddrBytes = fromAddr.Bytes()
	}

	_, err = app.DB.Execute(ctx, `
		INSERT INTO kwil_erc20_meta.transaction_history
		(id, instance_id, type, from_address, to_address, amount, external_tx_hash, status, block_height, block_timestamp, external_block_height)
		VALUES ($1, $2, 'deposit', $3, $4, $5, $6, 'completed', $7, $8, $9)
		ON CONFLICT (id) DO NOTHING
	`, txHistoryID, id, fromAddrBytes, recipient.Bytes(), val, log.TxHash.Bytes(), block.Height, block.Timestamp, log.BlockNumber)
	if err != nil {
		return fmt.Errorf("failed to record deposit history: %w", err)
	}

	return creditBalance(ctx, app, id, recipient, val)
}

// applyConfirmedEpochLog applies a ConfirmedEpoch log to the reward extension.
// TODO(migration): Remove this function once all deployments migrate to TrufNetworkBridge.
// TrufNetworkBridge uses local validator voting for epoch confirmation, not on-chain RewardPosted events.
func applyConfirmedEpochLog(ctx context.Context, app *common.App, log ethtypes.Log) error {
	data, err := rewardLogParser.ParseRewardPosted(log)
	if err != nil {
		return fmt.Errorf("failed to parse RewardPosted event: %w", err)
	}

	return confirmEpoch(ctx, app, data.Root[:])
}

// applyWithdrawalLog applies a Withdraw log to update withdrawal status.
// This is called when a user claims a withdrawal on Ethereum, detected via the withdrawal listener.
// It updates the withdrawal record to 'claimed' status with transaction details.
//
// The claimedAt timestamp uses Kwil block height for deterministic consensus.
// TODO: Consider using Ethereum block timestamp when available in EthLog structure.
func applyWithdrawalLog(ctx context.Context, app *common.App, instanceID *types.UUID, log ethtypes.Log, kwilBlockHeight int64) error {
	// Parse the Withdraw event from TrufNetworkBridge contract
	data, err := bridgeLogParser.ParseWithdraw(log)
	if err != nil {
		return fmt.Errorf("failed to parse Withdraw event: %w", err)
	}

	// Validate parsed data
	if data == nil {
		return fmt.Errorf("parsed Withdraw event data is nil")
	}
	if data.Recipient == (ethcommon.Address{}) {
		return fmt.Errorf("Withdraw event has zero recipient address")
	}
	if data.KwilBlockHash == ([32]byte{}) {
		return fmt.Errorf("Withdraw event has empty kwilBlockHash")
	}
	if log.BlockNumber == 0 {
		return fmt.Errorf("Withdraw event has zero block number")
	}

	// Update withdrawal status to 'claimed' with transaction details
	// This matches by recipient + kwilBlockHash to ensure we update the correct epoch
	// Using Kwil block height as deterministic timestamp (not time.Now() for consensus safety)
	return updateWithdrawalStatus(
		ctx,
		app,
		instanceID,
		data.Recipient,
		data.KwilBlockHash, // Matches the epoch via kwil_block_hash
		log.TxHash.Bytes(),
		int64(log.BlockNumber),
		kwilBlockHeight, // Deterministic: Kwil block height when event was processed
	)
}

// erc20ValueFromBigInt converts a big.Int to a decimal.Decimal(78,0)
func erc20ValueFromBigInt(b *big.Int) (*types.Decimal, error) {
	dec, err := types.NewDecimalFromBigInt(b, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to convert big.Int to decimal.Decimal: %w", err)
	}
	err = dec.SetPrecisionAndScale(78, 0)
	return dec, err
}

var (
	// TODO(migration): Remove rewardLogParser once all deployments migrate to TrufNetworkBridge.
	// rewardLogParser is a pre-bound RewardDistributor filterer for parsing Deposit and RewardPosted events.
	rewardLogParser = func() irewardLogParser {
		filt, err := abigen.NewRewardDistributorFilterer(ethcommon.Address{}, nilEthFilterer{})
		if err != nil {
			panic(fmt.Sprintf("failed to bind to RewardDistributor filterer: %v", err))
		}

		return filt
	}()
)

// TODO(migration): Remove irewardLogParser interface once all deployments migrate to TrufNetworkBridge.
// irewardLogParser is an interface for parsing RewardDistributor logs.
type irewardLogParser interface {
	ParseDeposit(log ethtypes.Log) (*abigen.RewardDistributorDeposit, error)
	ParseRewardPosted(log ethtypes.Log) (*abigen.RewardDistributorRewardPosted, error)
}

// bridgeLogParser is a pre-bound TrufNetworkBridge filterer for parsing Withdraw events.
// This is used by the withdrawal listener to parse Withdraw events from the new contract.
var bridgeLogParser = func() ibridgeLogParser {
	filt, err := abigen.NewTrufNetworkBridgeFilterer(ethcommon.Address{}, nilEthFilterer{})
	if err != nil {
		panic(fmt.Sprintf("failed to bind to TrufNetworkBridge filterer: %v", err))
	}

	return filt
}()

// ibridgeLogParser is an interface for parsing TrufNetworkBridge logs.
type ibridgeLogParser interface {
	ParseWithdraw(log ethtypes.Log) (*abigen.TrufNetworkBridgeWithdraw, error)
	ParseDeposit(log ethtypes.Log) (*abigen.TrufNetworkBridgeDeposit, error)
}

// getSyncedRewardData reads on-chain data from the bridge contract and token.
// TODO(migration): Update to use TrufNetworkBridge binding once all deployments migrated.
// Currently uses RewardDistributor binding for backward compatibility, but both contracts
// have rewardToken() function with same signature, so this works for both.
// It does not get the tokens owned by escrow; it will later sync those from erc20 logs
func getSyncedRewardData(
	ctx context.Context,
	client *ethclient.Client,
	distributorAddr ethcommon.Address,
) (*syncedRewardData, error) {

	// 1) Instantiate a binding to RewardDistributor at distributorAddr.
	// TODO(migration): Change to TrufNetworkBridge binding once migration complete.
	// Works with both contracts since both have rewardToken() with same signature.
	distributor, err := abigen.NewRewardDistributor(distributorAddr, client)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to RewardDistributor: %w", err)
	}

	// 2) Read the rewardToken address from the RewardDistributor
	// TrufNetworkBridge also has rewardToken() function (alias for getBridgedToken)
	rewardTokenAddr, err := distributor.RewardToken(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("failed to get rewardToken from RewardDistributor: %w", err)
	}

	// 4) Instantiate a binding to the ERC20 at rewardTokenAddr and read its decimals
	erc20, err := abigen.NewErc20(rewardTokenAddr, client)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to ERC20: %w", err)
	}
	decimalsBig, err := erc20.Decimals(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("failed to get decimals from ERC20: %w", err)
	}

	// Convert the decimals from uint8 to int64
	erc20Decimals := int64(decimalsBig)

	// 6) Assemble the result struct
	result := &syncedRewardData{
		Erc20Address:  rewardTokenAddr,
		Erc20Decimals: erc20Decimals,
	}

	return result, nil
}

// scaleUpUint256 turns a decimal into uint256, i.e. (11.22, 4) -> 112200
func scaleUpUint256(amount *types.Decimal, decimals uint16) (*types.Decimal, error) {
	unit, err := types.ParseDecimal("1" + strings.Repeat("0", int(decimals)))
	if err != nil {
		return nil, fmt.Errorf("create decimal unit failed: %w", err)
	}

	n, err := types.DecimalMul(amount, unit)
	if err != nil {
		return nil, fmt.Errorf("expand amount decimal failed: %w", err)
	}

	err = n.SetPrecisionAndScale(uint256Precision, 0)
	if err != nil {
		return nil, fmt.Errorf("expand amount decimal failed: %w", err)
	}

	return n, nil
}

// scaleDownUint256 turns an uint256 to a decimal, i.e. (112200, 4) -> 11.22
func scaleDownUint256(amount *types.Decimal, decimals uint16) (*types.Decimal, error) {
	unit, err := types.ParseDecimal("1" + strings.Repeat("0", int(decimals)))
	if err != nil {
		return nil, fmt.Errorf("create decimal unit failed: %w", err)
	}

	n, err := types.DecimalDiv(amount, unit)
	if err != nil {
		return nil, fmt.Errorf("expand amount decimal failed: %w", err)
	}

	scale := n.Scale()
	if scale > decimals {
		scale = decimals
	}

	err = n.SetPrecisionAndScale(uint256Precision-decimals, scale)
	if err != nil {
		return nil, fmt.Errorf("expand amount decimal failed: %w", err)
	}

	return n, nil
}

// ============================================================================
// Validator Signing for Non-Custodial Withdrawals
// ============================================================================

// getValidatorSigner returns a ValidatorSigner wrapper for the node's validator key.
// For non-custodial validator voting, this MUST use the node's validator key (not bridge signer key)
// to ensure signatures map to the validator's registered identity in the validator set.
// Returns nil if no validator signer is available.
func getValidatorSigner(app *common.App, instanceID *types.UUID) (*ValidatorSigner, error) {
	// Use the ValidatorSigner from Service
	// This provides controlled access to signing without exposing the raw private key
	if app.Service.ValidatorSigner == nil {
		return nil, nil // No validator signer available
	}

	// Get Ethereum address for the validator
	addressBytes, err := app.Service.ValidatorSigner.EthereumAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to get validator Ethereum address: %w", err)
	}

	// Create ValidatorSigner with the interface
	return NewValidatorSignerFromInterface(app, instanceID, app.Service.ValidatorSigner, addressBytes), nil
}

// computeEpochMessageHash computes the message hash that validators sign.
// This matches the format expected by TrufNetworkBridge contract:
// keccak256(abi.encode(merkleRoot, kwilBlockHash))
func computeEpochMessageHash(merkleRoot []byte, blockHash []byte) ([]byte, error) {
	// Use go-ethereum's ABI encoder
	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create bytes32 type: %w", err)
	}

	arguments := abi.Arguments{
		{Type: bytes32Type},
		{Type: bytes32Type},
	}

	// Validate inputs are exactly 32 bytes before copying
	if len(merkleRoot) != 32 {
		return nil, fmt.Errorf("invalid merkleRoot size: expected 32 bytes, got %d bytes", len(merkleRoot))
	}
	if len(blockHash) != 32 {
		return nil, fmt.Errorf("invalid blockHash size: expected 32 bytes, got %d bytes", len(blockHash))
	}

	// Convert to fixed-size arrays
	var rootBytes32 [32]byte
	var hashBytes32 [32]byte
	copy(rootBytes32[:], merkleRoot)
	copy(hashBytes32[:], blockHash)

	// ABI encode
	packed, err := arguments.Pack(rootBytes32, hashBytes32)
	if err != nil {
		return nil, fmt.Errorf("failed to pack arguments: %w", err)
	}

	// Keccak256 hash
	messageHash := crypto.Keccak256(packed)
	return messageHash, nil
}

// calculateBFTThreshold calculates the BFT threshold (2/3 of total validator voting power).
// Returns (totalPower, thresholdPower, error).
// Uses ceiling division to ensure >= 2/3 of voting power is required.
func calculateBFTThreshold(app *common.App) (int64, int64, error) {
	// Get all validators and sum their voting power
	validators := app.Validators.GetValidators()

	var totalPower int64
	for _, v := range validators {
		totalPower += v.Power
	}

	if totalPower == 0 {
		return 0, 0, fmt.Errorf("no validators with voting power")
	}

	// Calculate 2/3 threshold using ceiling division: ceil(totalPower * 2 / 3)
	// Formula: (totalPower * 2 + 3 - 1) / 3 = (totalPower * 2 + 2) / 3
	thresholdPower := (totalPower*2 + 2) / 3

	return totalPower, thresholdPower, nil
}

// sumEpochVotingPower calculates the total voting power of validators who voted for an epoch.
// Only counts non-custodial validator signatures (nonce=0).
//
// IMPORTANT: This function only counts voting power for validators using secp256k1 keys.
// Non-custodial validator voting requires EthPersonalSigner (Ethereum addresses), which
// necessitates secp256k1 keys. Validators with other key types (e.g., ed25519) will not
// participate in non-custodial withdrawal voting, though they remain fully functional
// validators in the network's BFT consensus.
//
// Note: This function cannot use ctx.TxContext because it's called from a handler.
// It matches votes by Ethereum address, which requires validators to use EthPersonalSigner.
func sumEpochVotingPower(ctx context.Context, app *common.App, epochID *types.UUID) (int64, error) {
	const nonCustodialNonce = 0

	// Get all votes for this epoch (stores Ethereum addresses as voters)
	result, err := app.DB.Execute(ctx, `
		SELECT voter
		FROM kwil_erc20_meta.epoch_votes
		WHERE epoch_id = $1 AND nonce = $2
	`, epochID, nonCustodialNonce)
	if err != nil {
		return 0, fmt.Errorf("failed to query epoch votes: %w", err)
	}

	// For each vote, we need to find the corresponding validator
	// Unfortunately, epoch_votes stores Ethereum addresses, not validator pubkeys
	// We need to iterate through validators and match their Ethereum address
	validators := app.Validators.GetValidators()

	// Build a map of validator Ethereum addresses -> power
	// This requires computing each validator's Ethereum address from their pubkey
	validatorPowerMap := make(map[string]int64)
	if app.Service != nil && app.Service.Logger != nil {
		app.Service.Logger.Debugf("building validator power map from %d validators", len(validators))
	}
	for _, v := range validators {
		if app.Service != nil && app.Service.Logger != nil {
			app.Service.Logger.Debugf("validator: pubkey=%x, keytype=%s, power=%d", v.Identifier, v.KeyType, v.Power)
		}
		// Compute Ethereum address from validator pubkey
		// Assumes validator is using secp256k1 key (EthPersonalSigner requirement)
		if v.KeyType == kwilcrypto.KeyTypeSecp256k1 {
			// Parse the pubkey and derive Ethereum address
			ethAddr, err := ethAddressFromPubKey(v.Identifier)
			if err != nil {
				// Skip validators with invalid keys
				if app.Service != nil && app.Service.Logger != nil {
					app.Service.Logger.Warnf("failed to derive Ethereum address for validator %x: %v", v.Identifier, err)
				}
				continue
			}
			if app.Service != nil && app.Service.Logger != nil {
				app.Service.Logger.Debugf("mapped validator %x -> eth address %s with power %d", v.Identifier, ethAddr.Hex(), v.Power)
			}
			validatorPowerMap[ethAddr.Hex()] = v.Power
		}
	}
	if app.Service != nil && app.Service.Logger != nil {
		app.Service.Logger.Debugf("validator power map has %d entries", len(validatorPowerMap))
	}

	// Sum voting power for all voters
	var votingPower int64
	for _, row := range result.Rows {
		voterBytes, ok := row[0].([]byte)
		if !ok {
			continue
		}

		// Convert voter bytes to Ethereum address
		if len(voterBytes) != 20 {
			continue
		}
		voter := ethcommon.BytesToAddress(voterBytes)

		// Look up voting power
		if power, ok := validatorPowerMap[voter.Hex()]; ok {
			votingPower += power
		}
	}

	return votingPower, nil
}

// ethAddressFromPubKey derives an Ethereum address from a secp256k1 public key.
// The pubKey should be 33 bytes (compressed) or 65 bytes (uncompressed).
func ethAddressFromPubKey(pubKey []byte) (ethcommon.Address, error) {
	// Parse the public key
	pubkey, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		// Try decompressing if it's a 33-byte compressed key
		if len(pubKey) == 33 {
			pubkey, err = crypto.DecompressPubkey(pubKey)
			if err != nil {
				return ethcommon.Address{}, fmt.Errorf("failed to decompress pubkey: %w", err)
			}
		} else {
			return ethcommon.Address{}, fmt.Errorf("failed to parse pubkey: %w", err)
		}
	}

	// Derive Ethereum address from public key
	address := crypto.PubkeyToAddress(*pubkey)
	return address, nil
}

// getEpochSignatures retrieves all validator signatures for an epoch.
// Returns array of signatures (65 bytes each: r||s||v format).
// Only returns signatures with nonce=0 (validator-verified signatures).
func getEpochSignatures(ctx context.Context, app *common.App, epochID *types.UUID) ([][]byte, error) {
	query := `{kwil_erc20_meta}SELECT signature FROM epoch_votes
	          WHERE epoch_id = $epoch_id AND nonce = 0
	          ORDER BY voter`

	// Initialize as empty slice (not nil) to ensure non-nullable column compatibility
	signatures := make([][]byte, 0)
	err := app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, query, map[string]any{
		"epoch_id": epochID,
	}, func(row *common.Row) error {
		if len(row.Values) != 1 {
			return nil
		}
		sig, ok := row.Values[0].([]byte)
		if !ok {
			return fmt.Errorf("signature should be []byte, got %T", row.Values[0])
		}
		signatures = append(signatures, sig)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("query epoch signatures: %w", err)
	}

	return signatures, nil
}

// fetchTxSender fetches and derives the sender of an Ethereum transaction.
// Returns nil address and logs a warning on failure.
// This is used during the event listener phase (outside consensus).
func fetchTxSender(ctx context.Context, client *ethclient.Client, txHash ethcommon.Hash, maxRetries int64, logger log.Logger) *ethcommon.Address {
	var addr ethcommon.Address
	err := utils.Retry(ctx, maxRetries, func() error {
		tx, isPending, err := client.TransactionByHash(ctx, txHash)
		if err != nil {
			return fmt.Errorf("failed to get tx %s: %w", txHash.Hex(), err)
		}
		if isPending {
			// Deposit events come from finalized blocks; a pending tx suggests RPC inconsistency.
			return fmt.Errorf("transaction %s is still pending", txHash.Hex())
		}
		// Derive sender
		addr, err = ethtypes.Sender(ethtypes.LatestSignerForChainID(tx.ChainId()), tx)
		if err != nil {
			return fmt.Errorf("failed to derive sender for tx %s: %w", txHash.Hex(), err)
		}
		return nil
	})
	if err != nil {
		if logger != nil {
			logger.Warnf("failed to fetch sender for tx %s: %v", txHash.Hex(), err)
		}
		return nil
	}
	return &addr
}
