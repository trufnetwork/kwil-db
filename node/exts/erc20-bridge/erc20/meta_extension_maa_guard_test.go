//go:build kwiltest

package erc20

import (
	"context"
	"strings"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/common"
	kwilcrypto "github.com/trufnetwork/kwil-db/core/crypto"
	coreauth "github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node/exts/evm-sync/chains"
	orderedsync "github.com/trufnetwork/kwil-db/node/exts/ordered-sync"
)

// These tests pin the token-boundary half of the MAA safety promise: when an
// execution runs AS a Modular Agent Address under its RESTRICTED key
// (TxContext.MAARestricted, set only by the maa_exec route), the exit
// primitives — transfer, bridge — and the privileged ops an action body can
// wrap — issue, lock_admin — must be rejected by the method handlers
// themselves, regardless of call depth or which action wraps them. lock and
// unlock must stay available, or allow-listed trading (collateral escrow,
// matching payouts, refunds) breaks. The guard must fire before any state is
// read or written, so the rejection cases below run with no usable App at all.

const maaGuardErr = "restricted agent (MAA) execution"

// maaMetaMethod instantiates the registered kwil_erc20_meta precompile and
// returns the named method, so tests exercise the REAL registered handlers.
func maaMetaMethod(t *testing.T, name string) precompiles.Method {
	t.Helper()
	init, ok := precompiles.RegisteredPrecompiles()[RewardMetaExtensionName]
	require.True(t, ok, "meta extension must be registered")
	p, err := init(context.Background(), nil, nil, RewardMetaExtensionName, nil)
	require.NoError(t, err)
	for _, m := range p.Methods {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("method %q not found on %s", name, RewardMetaExtensionName)
	return precompiles.Method{}
}

func maaEngineCtx(restricted bool, caller string) *common.EngineContext {
	return &common.EngineContext{
		TxContext: &common.TxContext{
			Ctx:           context.Background(),
			TxID:          "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Caller:        caller,
			MAARestricted: restricted,
			BlockContext:  &common.BlockContext{Height: 500, Timestamp: 1600000500},
		},
	}
}

func maaNoResult([]any) error { return nil }

func maaDec(t *testing.T, s string) *types.Decimal {
	t.Helper()
	return types.MustParseDecimalExplicit(s, 78, 0)
}

// TestMAARestrictedGuard_BlocksExitPrimitives: under a restricted MAA
// execution, the four gated methods must be rejected by the guard BEFORE any
// instance/balance state is touched (app is nil — reaching state would panic,
// proving nothing ran past the guard).
func TestMAARestrictedGuard_BlocksExitPrimitives(t *testing.T) {
	id := uuidForChainAndEscrow("1", "0x00000000000000000000000000000000000000cc")
	maa := ethcommon.HexToAddress("0x3333333333333333333333333333333333333333").Hex()
	other := ethcommon.HexToAddress("0x4444444444444444444444444444444444444444").Hex()
	ctx := maaEngineCtx(true, maa)

	for _, tc := range []struct {
		method string
		inputs []any
	}{
		{"transfer", []any{&id, other, maaDec(t, "10")}},
		{"bridge", []any{&id, other, maaDec(t, "10")}},
		// bridge with an omitted amount means "withdraw the WHOLE caller
		// balance" — the guard must fire before that branch is reachable.
		{"bridge", []any{&id, other, nil}},
		{"issue", []any{&id, other, maaDec(t, "10")}},
		{"lock_admin", []any{&id, other, maaDec(t, "10")}},
	} {
		err := maaMetaMethod(t, tc.method).Handler(ctx, nil, tc.inputs, maaNoResult)
		require.Error(t, err, "%s must be rejected under restricted MAA execution", tc.method)
		require.ErrorContains(t, err, maaGuardErr, "%s must fail with the guard error", tc.method)
	}
}

// maaLeaderProposer generates a secp256k1 proposer key and returns it with its
// eth_personal_sign sender address — what @leader_sender resolves to for the
// fee transfer's recipient.
func maaLeaderProposer(t *testing.T) (kwilcrypto.PublicKey, ethcommon.Address) {
	t.Helper()
	_, pub, err := kwilcrypto.GenerateSecp256k1Key(nil)
	require.NoError(t, err)
	secpPub, ok := pub.(*kwilcrypto.Secp256k1PublicKey)
	require.True(t, ok)
	return pub, ethcommon.BytesToAddress(kwilcrypto.EthereumAddressFromPubKey(secpPub))
}

// maaEngineCtxWithLeader is maaEngineCtx with the proposer and authenticator a
// real block execution carries — the inputs the leader-fee exception keys on.
func maaEngineCtxWithLeader(restricted bool, caller string, proposer kwilcrypto.PublicKey, authenticator string) *common.EngineContext {
	ctx := maaEngineCtx(restricted, caller)
	ctx.TxContext.BlockContext.Proposer = proposer
	ctx.TxContext.Authenticator = authenticator
	return ctx
}

// TestMAARestrictedGuard_LeaderFeeException: the ONE carve-out in the token
// boundary — a restricted MAA execution may transfer to the block leader's
// sender address (the protocol write-fee, @leader_sender in fee-charging
// actions) and to no one else. The allowed case is proven by the handler
// proceeding PAST the guard into its own amount validation (app is nil, so
// reaching state would panic — nothing ran past the validation). Every
// degraded context — no proposer, wrong authenticator, non-secp proposer —
// must fail CLOSED with the guard error, even with the leader as recipient.
func TestMAARestrictedGuard_LeaderFeeException(t *testing.T) {
	id := uuidForChainAndEscrow("1", "0x00000000000000000000000000000000000000cc")
	maa := ethcommon.HexToAddress("0x3333333333333333333333333333333333333333").Hex()
	other := ethcommon.HexToAddress("0x4444444444444444444444444444444444444444").Hex()
	proposer, leaderAddr := maaLeaderProposer(t)

	// Allowed: recipient IS the leader → past the guard, into amount validation.
	ctx := maaEngineCtxWithLeader(true, maa, proposer, coreauth.EthPersonalSignAuth)
	err := maaMetaMethod(t, "transfer").Handler(ctx, nil, []any{&id, leaderAddr.Hex(), maaDec(t, "-1")}, maaNoResult)
	require.ErrorContains(t, err, "amount cannot be negative", "a leader-fee transfer must pass the guard into the handler's own validation")
	require.NotContains(t, err.Error(), maaGuardErr)

	// The SQL fee path emits the recipient as lowercase hex without 0x — the
	// compare must be raw-byte, not string-shape sensitive.
	err = maaMetaMethod(t, "transfer").Handler(ctx, nil, []any{&id, strings.ToLower(leaderAddr.Hex()[2:]), maaDec(t, "-1")}, maaNoResult)
	require.ErrorContains(t, err, "amount cannot be negative", "lowercase no-0x leader hex must match byte-for-byte")
	require.NotContains(t, err.Error(), maaGuardErr)

	// Any other recipient stays blocked, leader present or not.
	err = maaMetaMethod(t, "transfer").Handler(ctx, nil, []any{&id, other, maaDec(t, "10")}, maaNoResult)
	require.ErrorContains(t, err, maaGuardErr, "a non-leader recipient must stay blocked")

	// The exception is transfer-only: bridge to the leader is still an exit.
	err = maaMetaMethod(t, "bridge").Handler(ctx, nil, []any{&id, leaderAddr.Hex(), maaDec(t, "10")}, maaNoResult)
	require.ErrorContains(t, err, maaGuardErr, "bridge must stay blocked even toward the leader")

	// Fail closed: no proposer in context.
	err = maaMetaMethod(t, "transfer").Handler(maaEngineCtx(true, maa), nil, []any{&id, leaderAddr.Hex(), maaDec(t, "10")}, maaNoResult)
	require.ErrorContains(t, err, maaGuardErr, "no proposer → no exception")

	// Fail closed: a non-address authenticator scheme (sender is a pubkey, so
	// @leader_sender can never be a transfer recipient).
	err = maaMetaMethod(t, "transfer").Handler(
		maaEngineCtxWithLeader(true, maa, proposer, coreauth.Secp256k1Auth), nil,
		[]any{&id, leaderAddr.Hex(), maaDec(t, "10")}, maaNoResult)
	require.ErrorContains(t, err, maaGuardErr, "non-eth authenticator → no exception")

	// Fail closed: an ed25519 proposer has no eth address.
	_, edPub, err := kwilcrypto.GenerateEd25519Key(nil)
	require.NoError(t, err)
	err = maaMetaMethod(t, "transfer").Handler(
		maaEngineCtxWithLeader(true, maa, edPub, coreauth.EthPersonalSignAuth), nil,
		[]any{&id, leaderAddr.Hex(), maaDec(t, "10")}, maaNoResult)
	require.ErrorContains(t, err, maaGuardErr, "non-secp proposer → no exception")
}

// TestMAARestrictedGuard_LockAndUnlockNotGated: lock (collateral escrow) and
// unlock (network paying a user) must NOT carry the guard — trading depends on
// them. With a negative amount the handlers reach their own validation, which
// sits past the point where a guard would fire, and do so without touching any
// state (app is nil).
func TestMAARestrictedGuard_LockAndUnlockNotGated(t *testing.T) {
	id := uuidForChainAndEscrow("1", "0x00000000000000000000000000000000000000cc")
	maa := ethcommon.HexToAddress("0x3333333333333333333333333333333333333333").Hex()
	ctx := maaEngineCtx(true, maa)

	err := maaMetaMethod(t, "lock").Handler(ctx, nil, []any{&id, maaDec(t, "-1")}, maaNoResult)
	require.ErrorContains(t, err, "amount cannot be negative", "lock must run its own validation, not the guard")
	require.NotContains(t, err.Error(), maaGuardErr)

	err = maaMetaMethod(t, "unlock").Handler(ctx, nil, []any{&id, maa, maaDec(t, "-1")}, maaNoResult)
	require.ErrorContains(t, err, "amount cannot be negative", "unlock must run its own validation, not the guard")
	require.NotContains(t, err.Error(), maaGuardErr)
}

// TestMAARestrictedGuard_InactiveWhenUnflagged: without the flag (a normal
// signer, or the unrestricted owner acting as the MAA), the gated handlers
// proceed past the guard into their own logic.
func TestMAARestrictedGuard_InactiveWhenUnflagged(t *testing.T) {
	id := uuidForChainAndEscrow("1", "0x00000000000000000000000000000000000000cc")
	// An invalid caller makes transfer fail at its own address parsing —
	// which sits past the guard — without touching any state.
	ctx := maaEngineCtx(false, "not-an-address")

	err := maaMetaMethod(t, "transfer").Handler(ctx, nil, []any{&id, "also-not-an-address", maaDec(t, "10")}, maaNoResult)
	require.Error(t, err)
	require.NotContains(t, err.Error(), maaGuardErr, "unflagged execution must not trip the guard")
}

// TestMAARestrictedBoundary_TradingSurvivesExitsBlocked is the DB-backed
// matrix: with a real instance and balances, a restricted MAA execution can
// still lock collateral and have the network pay a counterparty (the
// matching-engine shape), while transfer/bridge are rejected and move nothing;
// the same transfer succeeds once unflagged (the owner path).
func TestMAARestrictedBoundary_TradingSurvivesExitsBlocked(t *testing.T) {
	ctx := context.Background()
	db, err := newTestDB()
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	orderedsync.ForTestingReset()
	defer orderedsync.ForTestingReset()
	ForTestingResetSingleton()
	defer ForTestingResetSingleton()

	app := setup(t, tx)

	// Instance + epoch, synced and active in the singleton (withdrawal-test idiom).
	id := newUUID()
	chainInfo, ok := chains.GetChainInfoByID("1")
	require.True(t, ok, "chain 1 should be registered")
	upd := &userProvidedData{
		ID:                 id,
		ChainInfo:          &chainInfo,
		EscrowAddress:      ethcommon.HexToAddress("0x00000000000000000000000000000000000000cc"),
		DistributionPeriod: 3600,
	}
	require.NoError(t, createNewRewardInstance(ctx, app, upd))
	require.NoError(t, setRewardSynced(ctx, app, id, 1, &syncedRewardData{
		Erc20Address:  ethcommon.HexToAddress("0x00000000000000000000000000000000000000bb"),
		Erc20Decimals: 18,
	}))
	epochID := newUUID()
	pending := &PendingEpoch{ID: epochID, StartHeight: 10, StartTime: 100}
	require.NoError(t, createEpoch(ctx, app, pending, id))
	getSingleton().instances.Set(*id, &rewardExtensionInfo{
		userProvidedData: *upd,
		currentEpoch:     pending,
		synced:           true,
		active:           true,
		ownedBalance:     maaDec(t, "0"),
	})

	maa := ethcommon.HexToAddress("0x3333333333333333333333333333333333333333")
	counterparty := ethcommon.HexToAddress("0x4444444444444444444444444444444444444444")
	require.NoError(t, creditBalance(ctx, app, id, maa, maaDec(t, "100")))

	restrictedCtx := maaEngineCtx(true, maa.Hex())
	unflaggedCtx := maaEngineCtx(false, maa.Hex())

	balance := func(addr ethcommon.Address) string {
		bal, err := balanceOf(ctx, app, id, addr)
		require.NoError(t, err)
		if bal == nil {
			return "0"
		}
		return bal.String()
	}

	// 1) Collateral escrow (the place_buy_order shape) must keep working.
	require.NoError(t, maaMetaMethod(t, "lock").Handler(restrictedCtx, app, []any{id, maaDec(t, "10")}, maaNoResult))
	require.Equal(t, "90", balance(maa))

	// 2) The network paying a counterparty (the matching/refund shape) must
	//    keep working even while the execution is flagged restricted.
	require.NoError(t, maaMetaMethod(t, "unlock").Handler(restrictedCtx, app, []any{id, counterparty.Hex(), maaDec(t, "4")}, maaNoResult))
	require.Equal(t, "4", balance(counterparty))

	// 3) transfer is rejected and moves nothing.
	err = maaMetaMethod(t, "transfer").Handler(restrictedCtx, app, []any{id, counterparty.Hex(), maaDec(t, "10")}, maaNoResult)
	require.ErrorContains(t, err, maaGuardErr)
	require.Equal(t, "90", balance(maa))
	require.Equal(t, "4", balance(counterparty))

	// 4) bridge (the L1 off-ramp) is rejected and moves nothing — including
	//    the omitted-amount whole-balance form.
	err = maaMetaMethod(t, "bridge").Handler(restrictedCtx, app, []any{id, counterparty.Hex(), nil}, maaNoResult)
	require.ErrorContains(t, err, maaGuardErr)
	require.Equal(t, "90", balance(maa))

	// 5) Control: the SAME transfer succeeds once unflagged — the boundary
	//    keys on the flag, not on the caller being an MAA, so the owner's
	//    withdrawal path stays open.
	require.NoError(t, maaMetaMethod(t, "transfer").Handler(unflaggedCtx, app, []any{id, counterparty.Hex(), maaDec(t, "10")}, maaNoResult))
	require.Equal(t, "80", balance(maa))
	require.Equal(t, "14", balance(counterparty))

	// 6) The leader-fee exception on real balances: a RESTRICTED execution can
	//    pay the protocol write-fee (transfer to @leader_sender) and the funds
	//    actually move — while the same amount to anyone else still bounces.
	proposer, leaderAddr := maaLeaderProposer(t)
	leaderCtx := maaEngineCtxWithLeader(true, maa.Hex(), proposer, coreauth.EthPersonalSignAuth)
	require.NoError(t, maaMetaMethod(t, "transfer").Handler(leaderCtx, app, []any{id, leaderAddr.Hex(), maaDec(t, "5")}, maaNoResult))
	require.Equal(t, "75", balance(maa))
	require.Equal(t, "5", balance(leaderAddr))
	err = maaMetaMethod(t, "transfer").Handler(leaderCtx, app, []any{id, counterparty.Hex(), maaDec(t, "5")}, maaNoResult)
	require.ErrorContains(t, err, maaGuardErr)
	require.Equal(t, "75", balance(maa))
}
