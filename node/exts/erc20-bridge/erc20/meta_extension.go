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
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/container/lru"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/trufnetwork/kwil-db/common"
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
			if bytes.Equal(log.Metadata, logTypeDeposit) {
				err := applyDepositLog(ctx, app, id, *log.Log)
				if err != nil {
					return err
				}
			} else if bytes.Equal(log.Metadata, logTypeConfirmedEpoch) {
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
			if bytes.Equal(log.Metadata, logTypeWithdrawal) {
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
			if err := info.startDepositListener(); err != nil {
				return err
			}
			return info.startWithdrawalListener()
		}

		info.mu.Unlock()

		return nil
	})

	err := precompiles.RegisterInitializer(RewardMetaExtensionName,
		func(ctx context.Context, service *common.Service, db sql.DB, alias string, metadata map[string]any) (precompiles.Precompile, error) {
			return precompiles.Precompile{
				Cache: getSingleton(),
				OnUse: func(ctx *common.EngineContext, app *common.App) error {
					return createSchema(ctx.TxContext.Ctx, app)
				},
				OnStart: func(ctx context.Context, app *common.App) error {
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
								err = instance.startDepositListener()
								if err != nil {
									return err
								}
								err = instance.startWithdrawalListener()
								if err != nil {
									return err
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

									// an error from startDepositListener is a critical error
									// in the code, not a user error. Therefore, not too concerned with
									// rolling back the above changes
									err = info.startDepositListener()
									if err != nil {
										return err
									}

									err = info.startWithdrawalListener()
									if err != nil {
										return err
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

							return transferTokens(ctx.TxContext.Ctx, app, id, from, toAddr, amount)
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

							return getSingleton().lockAndIssueTokens(ctx.TxContext.Ctx, app, id, ctx.TxContext.Caller, recipient, amount)
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

							// NOTE: if we have safe address and safe nonce, we can verify the signature
							// But if we only have safe address, and safeNonce from the input, then it's no point

							ok, err := canVoteEpoch(ctx.TxContext.Ctx, app, epochID)
							if err != nil {
								return fmt.Errorf("check epoch can vote: %w", err)
							}

							if !ok {
								return fmt.Errorf("epoch cannot be voted")
							}

							return voteEpoch(ctx.TxContext.Ctx, app, epochID, from, nonce, signature)
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

								err = resultFn([]any{info.ChainInfo.Name.String(),
									info.ChainInfo.ID,
									info.EscrowAddress.String(),
									epoch.EndHeight,
									walletAddr.String(),
									uint256Amt,
									bh,
									epoch.Root,
									proofs,
								})
								if err != nil {
									return err
								}
							}

							return nil
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
			// in the future, we will handle version upgrades here
			if version != currentVersion {
				return fmt.Errorf("reward extension version mismatch: expected %d, got %d", currentVersion, version)
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
			// If the block is greater than or equal to the start time + distribution period: Otherwise, we should do nothing.
			if block.Timestamp-info.currentEpoch.StartTime < info.userProvidedData.DistributionPeriod {
				return nil
			}

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

			if !preExists || // first epoch should always be finalized
				(preExists && preConfirmed) { // previous epoch exists and is confirmed
				leafNum, jsonBody, root, total, err := genMerkleTreeForEpoch(ctx, app, info.currentEpoch.ID, info.EscrowAddress.Hex(), block.Hash)
				if err != nil {
					return err
				}

				if leafNum == 0 {
					app.Service.Logger.Debug("no rewards to distribute, delay finalized current epoch")
					return nil
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
				err = createEpoch(ctx, app, newEpoch, id)
				if err != nil {
					return err
				}

				// put merkle tree in cache
				var b32Root [32]byte
				copy(b32Root[:], root)
				mtLRUCache.Put(b32Root, jsonBody)

				newEpochs[*id] = newEpoch
				return nil
			}

			// if previous epoch exists and not confirmed, we do nothing.
			app.Service.Logger.Debug("previous epoch is not confirmed yet, skip finalize current epoch")
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
				info.currentEpoch = newEpoch
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
	var rewards []*EpochReward
	err = getRewardsForEpoch(ctx, app, epochID, func(reward *EpochReward) error {
		rewards = append(rewards, reward)
		return nil
	})
	if err != nil {
		return 0, nil, nil, nil, err
	}

	if len(rewards) == 0 { // no rewards, delay finalize current epoch
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
func (e *extensionInfo) lockAndIssueTokens(ctx context.Context, app *common.App, id *types.UUID, from string, recipient string, amount *types.Decimal) error {
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

	bal, err := balanceOf(ctx, app, id, fromAddr)
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

	// we dont need to update the cached data here since we are directly converting
	// a user balance (which is never cached) into a reward (which is also never cached)
	err = lockAndIssue(ctx, app, id, info.currentEpoch.ID, fromAddr, recipientAddr, amount)
	if err != nil {
		return err
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

// startStatePoller starts a state poller for the reward extension.
func (r *rewardExtensionInfo) startStatePoller() error {
	synced := r.synced // copy to avoid race conditions
	escrow := r.EscrowAddress
	id := *r.ID
	chainName := r.ChainInfo.Name

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
				logger := service.Logger.New(statePollerUniqueName(id))
				logger.Errorf("failed to get synced reward data: %v", err)
				return
			}

			bts, err := data.MarshalBinary()
			if err != nil {
				panic(err) // internal logic bug in this package
			}

			err = broadcast(ctx, bts)
			if err != nil {
				logger := service.Logger.New(statePollerUniqueName(id))
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

// startDepositListener starts an event listener that listens for Deposit events on the RewardDistributor escrow
func (r *rewardExtensionInfo) startDepositListener() error {
	// I'm not sure if copies are needed because the values should never be modified,
	// but just in case, I copy them to be used in GetLogs, which runs outside of consensus
	escrowCopy := r.EscrowAddress
	evmMaxRetries := int64(10) // retry on evm RPC request is crucial

	// we now register synchronization of the Deposit event
	return evmsync.EventSyncer.RegisterNewListener(evmsync.EVMEventListenerConfig{
		UniqueName: depositListenerUniqueName(*r.ID),
		Chain:      r.ChainInfo.Name,
		GetLogs: func(ctx context.Context, client *ethclient.Client, startBlock, endBlock uint64, logger log.Logger) ([]*evmsync.EthLog, error) {
			escrowFilt, err := abigen.NewRewardDistributorFilterer(escrowCopy, client)
			if err != nil {
				return nil, fmt.Errorf("failed to bind to RewardDistributor filterer: %w", err)
			}

			var logs []*evmsync.EthLog

			var depositIter *abigen.RewardDistributorDepositIterator
			err = utils.Retry(ctx, evmMaxRetries, func() error {
				depositIter, err = escrowFilt.FilterDeposit(&bind.FilterOpts{
					Start:   startBlock,
					End:     &endBlock,
					Context: ctx,
				})
				if err != nil {
					return fmt.Errorf("failed to get deposit logs: %w", err)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			defer depositIter.Close()

			for depositIter.Next() {
				logs = append(logs, &evmsync.EthLog{
					Metadata: logTypeDeposit,
					Log:      &depositIter.Event.Raw,
				})
			}
			if err := depositIter.Error(); err != nil {
				return nil, fmt.Errorf("failed to get deposit logs: %w", err)
			}

			var postIter *abigen.RewardDistributorRewardPostedIterator
			err = utils.Retry(ctx, evmMaxRetries, func() error {
				postIter, err = escrowFilt.FilterRewardPosted(&bind.FilterOpts{
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
				return nil, err
			}
			defer postIter.Close()

			for postIter.Next() {
				logs = append(logs, &evmsync.EthLog{
					Metadata: logTypeConfirmedEpoch,
					Log:      &postIter.Event.Raw,
				})
			}
			if err := postIter.Error(); err != nil {
				return nil, fmt.Errorf("failed to get reward posted logs: %w", err)
			}

			return logs, nil
		},
	})
}

// startWithdrawalListener starts an event listener that listens for Withdraw events on the contract.
// The listener is registered for all instances but only processes events if the contract emits them.
// Old contracts (RewardDistributor) never emit Withdraw events, so the listener remains dormant for those instances.
func (r *rewardExtensionInfo) startWithdrawalListener() error {
	// Copy values to avoid race conditions in GetLogs (runs outside consensus)
	escrowCopy := r.EscrowAddress
	evmMaxRetries := int64(10) // retry on evm RPC request is crucial

	// Register withdrawal event listener
	return evmsync.EventSyncer.RegisterNewListener(evmsync.EVMEventListenerConfig{
		UniqueName: withdrawalListenerUniqueName(*r.ID),
		Chain:      r.ChainInfo.Name,
		GetLogs: func(ctx context.Context, client *ethclient.Client, startBlock, endBlock uint64, logger log.Logger) ([]*evmsync.EthLog, error) {
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
				logs = append(logs, &evmsync.EthLog{
					Metadata: logTypeWithdrawal,
					Log:      &withdrawIter.Event.Raw,
				})
			}
			if err := withdrawIter.Error(); err != nil {
				return nil, fmt.Errorf("failed to get withdraw logs: %w", err)
			}

			return logs, nil
		},
	})
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
			errs = append(errs, fmt.Errorf("failed to unregister deposit listener: %w", err))
		}

		// Attempt to stop withdrawal listener
		if err := evmsync.EventSyncer.UnregisterListener(withdrawalListenerUniqueName(*r.ID)); err != nil {
			errs = append(errs, fmt.Errorf("failed to unregister withdrawal listener: %w", err))
		}

		// Return combined error if any failed
		if len(errs) > 0 {
			return fmt.Errorf("listener cleanup errors: %v", errs)
		}
		return nil
	}
	return evmsync.StatePoller.UnregisterPoll(statePollerUniqueName(*r.ID))
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
func applyDepositLog(ctx context.Context, app *common.App, id *types.UUID, log ethtypes.Log) error {
	data, err := rewardLogParser.ParseDeposit(log)
	if err != nil {
		return fmt.Errorf("failed to parse Deposit event: %w", err)
	}

	val, err := erc20ValueFromBigInt(data.Amount)
	if err != nil {
		return fmt.Errorf("failed to convert big.Int to decimal.Decimal: %w", err)
	}

	return creditBalance(ctx, app, id, data.Recipient, val)
}

// applyConfirmedEpochLog applies a ConfirmedEpoch log to the reward extension.
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
	// rewardLogParser is a pre-bound RewardDistributor filterer for parsing Deposit and RewardPosted events.
	rewardLogParser = func() irewardLogParser {
		filt, err := abigen.NewRewardDistributorFilterer(ethcommon.Address{}, nilEthFilterer{})
		if err != nil {
			panic(fmt.Sprintf("failed to bind to RewardDistributor filterer: %v", err))
		}

		return filt
	}()
)

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
}

// getSyncedRewardData reads on-chain data from both the RewardDistributor and the Gnosis Safe
// it references, returning them in a syncedRewardData struct.
// It does not get the tokens owned by escrow; it will later sync those from erc20 logs
func getSyncedRewardData(
	ctx context.Context,
	client *ethclient.Client,
	distributorAddr ethcommon.Address,
) (*syncedRewardData, error) {

	// 1) Instantiate a binding to RewardDistributor at distributorAddr.
	distributor, err := abigen.NewRewardDistributor(distributorAddr, client)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to RewardDistributor: %w", err)
	}

	// 2) Read the rewardToken address from the RewardDistributor
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
