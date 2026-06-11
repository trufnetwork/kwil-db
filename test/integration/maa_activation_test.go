package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/core/client"
	clientTypes "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	rpcclient "github.com/trufnetwork/kwil-db/core/rpc/client"
	"github.com/trufnetwork/kwil-db/core/types"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
	"github.com/trufnetwork/kwil-db/test/setup"
	"github.com/trufnetwork/kwil-db/test/specifications"
)

// TestMAAExecActivation rehearses the coordinated MAA rollout on a real
// 3-validator network, end to end through the literal maaExecRoute:
//
//  1. The network genesises WITHOUT MAA activation (maa_activation_height
//     is absent, i.e. zero) — exactly like a live network that predates the
//     parameter. A well-formed MAAExec is rejected at broadcast.
//  2. Operators schedule activation with a param_updates resolution — the
//     production rollout step — and every node reports the parameter.
//  3. Below the scheduled height the transaction is still rejected.
//  4. From the activation height on, the same transaction executes: the
//     inner action runs with @caller rewritten to the MAA, with identical
//     results on every node; a signer that is neither of the instance's
//     keys still fails deterministically.
//  5. Every node reports the same AppHash at every height — the
//     determinism sweep over the activation fork.
func TestMAAExecActivation(t *testing.T) {
	ctx := context.Background()

	// The owner deploys the schema (DB owner) and is the instance's
	// unrestricted key; the agent is the restricted key submitting MAAExec.
	ownerKey, ownerPub, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	agentKey, agentPub, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)
	strangerKey, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)

	ownerSigner := auth.GetUserSigner(ownerKey)
	ownerIdent, err := authExt.GetIdentifierFromSigner(ownerSigner)
	require.NoError(t, err)

	ownerAddr := crypto.EthereumAddressFromPubKey(ownerPub.(*crypto.Secp256k1PublicKey))
	agentAddr := crypto.EthereumAddressFromPubKey(agentPub.(*crypto.Secp256k1PublicKey))
	// The MAA instance's address: any 20 bytes distinct from both keys (the
	// route looks it up, it is never derived here), plus a 32-byte rule id.
	maaAddr := append([]byte{0x77}, make([]byte, 19)...)
	ruleID := append([]byte{0x55}, make([]byte, 31)...)

	p := setup.SetupTests(t, &setup.TestConfig{
		ClientDriver: setup.Go,
		Network: &setup.NetworkConfig{
			Nodes: []*setup.NodeConfig{
				setup.DefaultNodeConfig(),
				setup.DefaultNodeConfig(),
				setup.DefaultNodeConfig(),
			},
			DBOwner: ownerIdent,
			// No ConfigureGenesis: maa_activation_height stays at its zero
			// value, like a network that genesised before the parameter.
		},
	})

	// A raw core client per node (the harness driver does not expose raw
	// transaction broadcast or the chain RPC service).
	clients := make([]*client.Client, len(p.Nodes))
	for i, n := range p.Nodes {
		endpoint, _, err := n.JSONRPCEndpoint(t, ctx)
		require.NoError(t, err)
		cl, err := client.NewClient(ctx, endpoint, &clientTypes.Options{
			Signer: &auth.EthPersonalSigner{Key: *ownerKey.(*crypto.Secp256k1PrivateKey)},
		})
		require.NoError(t, err)
		clients[i] = cl
	}
	owner := clients[0]
	chainID := owner.ChainID()

	// Deploy a minimal MAA surface mirroring the node's rule-store getters
	// byte for byte in signature and projection (BYTEA params, '0x'-hex text
	// columns), backed by directly-seeded tables, plus a probe action that
	// records @caller — the proof of the route's caller rewrite.
	execSQL := func(stmt string, params map[string]any) {
		t.Helper()
		txHash, err := owner.ExecuteSQL(ctx, stmt, params)
		require.NoError(t, err)
		resp, err := owner.WaitTx(ctx, txHash, 250*time.Millisecond)
		require.NoError(t, err)
		require.Equalf(t, uint32(types.CodeOk), resp.Result.Code, "statement failed: %s: %s", stmt, resp.Result.Log)
	}

	execSQL(`CREATE TABLE maa_instances_t (
		maa_address BYTEA PRIMARY KEY,
		rule_id BYTEA NOT NULL,
		restricted_addr BYTEA NOT NULL,
		unrestricted_addr BYTEA NOT NULL,
		created_at INT8 NOT NULL
	)`, nil)
	execSQL(`CREATE TABLE maa_allowed_t (
		rule_id BYTEA NOT NULL,
		namespace TEXT NOT NULL,
		action TEXT NOT NULL,
		body_hash BYTEA,
		PRIMARY KEY (rule_id, namespace, action)
	)`, nil)
	execSQL(`CREATE TABLE maa_probe_log (
		note TEXT PRIMARY KEY,
		caller TEXT NOT NULL
	)`, nil)
	execSQL(`CREATE ACTION maa_get_instance($maa_address BYTEA) PUBLIC VIEW RETURNS TABLE(
		maa_address TEXT,
		rule_id TEXT,
		restricted_addr TEXT,
		unrestricted_addr TEXT,
		created_at INT8
	) {
		for $r in
			SELECT
				'0x' || encode(maa_address, 'hex')       AS maa_a,
				'0x' || encode(rule_id, 'hex')           AS rid,
				'0x' || encode(restricted_addr, 'hex')   AS restr_a,
				'0x' || encode(unrestricted_addr, 'hex') AS unrestr_a,
				created_at AS ca
			FROM maa_instances_t
			WHERE maa_address = $maa_address
		{
			RETURN NEXT $r.maa_a, $r.rid, $r.restr_a, $r.unrestr_a, $r.ca;
		}
	}`, nil)
	execSQL(`CREATE ACTION maa_get_allowed_actions($rule_id BYTEA) PUBLIC VIEW RETURNS TABLE(
		namespace TEXT,
		action TEXT,
		body_hash TEXT
	) {
		for $r in
			SELECT namespace, action,
				CASE WHEN body_hash IS NULL THEN NULL ELSE '0x' || encode(body_hash, 'hex') END AS bh
			FROM maa_allowed_t
			WHERE rule_id = $rule_id
			ORDER BY namespace ASC, action ASC
		{
			RETURN NEXT $r.namespace, $r.action, $r.bh;
		}
	}`, nil)
	execSQL(`CREATE ACTION maa_probe($note TEXT) PUBLIC {
		INSERT INTO maa_probe_log (note, caller) VALUES ($note, @caller);
	}`, nil)
	execSQL(`INSERT INTO maa_instances_t (maa_address, rule_id, restricted_addr, unrestricted_addr, created_at)
		VALUES ($maa, $rule, $restricted, $unrestricted, 1)`, map[string]any{
		"maa": maaAddr, "rule": ruleID, "restricted": agentAddr, "unrestricted": ownerAddr,
	})
	execSQL(`INSERT INTO maa_allowed_t (rule_id, namespace, action) VALUES ($rule, 'main', 'maa_probe')`,
		map[string]any{"rule": ruleID})

	// broadcastMAAExec hand-builds and signs a raw MAAExec transaction —
	// the wire path an SDK will use — and broadcasts it through node 0.
	broadcastMAAExec := func(key crypto.PrivateKey, nonce uint64, note string, wait rpcclient.BroadcastWait) (types.Hash, error) {
		t.Helper()
		ev, err := types.EncodeValue(note)
		require.NoError(t, err)
		tx, err := types.CreateTransaction(&types.MAAExec{
			MAAAddress: maaAddr,
			Namespace:  "main",
			Action:     "maa_probe",
			Arguments:  []*types.EncodedValue{ev},
		}, chainID, nonce)
		require.NoError(t, err)
		require.NoError(t, tx.Sign(&auth.EthPersonalSigner{Key: *key.(*crypto.Secp256k1PrivateKey)}))
		return owner.SvcClient().Broadcast(ctx, tx, wait)
	}

	// 1) Not activated: rejected at broadcast, reading like an unknown
	// payload type — the same answer a pre-MAA binary gives.
	_, err = broadcastMAAExec(agentKey, 1, "pre-activation", rpcclient.BroadcastWaitAccept)
	require.Error(t, err)
	require.ErrorContains(t, err, "maa_exec is not activated")

	// 2) Schedule activation via a param_updates resolution — the
	// production rollout step. With three validators, the proposer's
	// implicit approval plus one more passes the >50% threshold.
	info, err := owner.ChainInfo(ctx)
	require.NoError(t, err)
	activation := int64(info.BlockHeight) + 10

	n0Admin := p.Nodes[0].AdminClient(t, ctx)
	txid, proposalID, err := n0Admin.ProposeParamUpdates(ctx, &types.ParamUpdates{
		types.ParamNameMAAActivationHeight: activation,
	}, "activate maa_exec")
	require.NoError(t, err)
	specifications.ExpectTxSuccess(t, n0Admin, ctx, txid)

	n1Admin := p.Nodes[1].AdminClient(t, ctx)
	txid, err = n1Admin.ApproveParamUpdates(ctx, proposalID)
	require.NoError(t, err)
	specifications.ExpectTxSuccess(t, n1Admin, ctx, txid)

	// Every node converges on the scheduled height.
	for i, n := range p.Nodes {
		adm := n.AdminClient(t, ctx)
		require.Eventuallyf(t, func() bool {
			params, err := adm.Params(ctx)
			return err == nil && params.MAAActivationHeight == activation
		}, 30*time.Second, 500*time.Millisecond, "node %d must report the activation height", i)
	}

	// 3) Scheduled but not reached: still rejected. Guarded, in case the
	// chain raced past the activation height under CI load.
	info, err = owner.ChainInfo(ctx)
	require.NoError(t, err)
	if int64(info.BlockHeight)+1 < activation {
		_, err = broadcastMAAExec(agentKey, 1, "pre-height", rpcclient.BroadcastWaitAccept)
		require.Error(t, err)
		require.ErrorContains(t, err, "activates at height")
	} else {
		t.Log("chain raced past the activation height; skipping the pre-height rejection assert")
	}

	// 4) From the activation height on, the same transaction executes.
	require.Eventuallyf(t, func() bool {
		info, err := owner.ChainInfo(ctx)
		return err == nil && int64(info.BlockHeight) >= activation
	}, 90*time.Second, 500*time.Millisecond, "chain must reach activation height %d", activation)

	txHash, err := broadcastMAAExec(agentKey, 1, "post-activation", rpcclient.BroadcastWaitCommit)
	require.NoError(t, err)
	resp, err := owner.TxQuery(ctx, txHash)
	require.NoError(t, err)
	require.Equalf(t, uint32(types.CodeOk), resp.Result.Code, "maa_exec must succeed after activation: %s", resp.Result.Log)

	// The probe ran AS the MAA: @caller is the MAA's address (the route
	// emits the checksummed form; compare case-insensitively), identically
	// on every node.
	wantCaller := "0x" + hex.EncodeToString(maaAddr)
	for i, cl := range clients {
		require.Eventuallyf(t, func() bool {
			qr, err := cl.Query(ctx, "SELECT note, caller FROM maa_probe_log", nil, true)
			if err != nil || len(qr.Values) != 1 || len(qr.Values[0]) != 2 {
				return false
			}
			note, _ := qr.Values[0][0].(string)
			caller, _ := qr.Values[0][1].(string)
			return note == "post-activation" && strings.EqualFold(caller, wantCaller)
		}, 30*time.Second, 500*time.Millisecond, "node %d must show the probe row written as the MAA", i)
	}

	// A signer that is neither of the instance's keys passes the activation
	// gate but fails authorization in the route, deterministically.
	txHash, err = broadcastMAAExec(strangerKey, 1, "stranger", rpcclient.BroadcastWaitCommit)
	require.NoError(t, err)
	resp, err = owner.TxQuery(ctx, txHash)
	require.NoError(t, err)
	require.NotEqual(t, uint32(types.CodeOk), resp.Result.Code, "a stranger must not act as the MAA")
	require.Contains(t, resp.Result.Log, "neither the restricted nor the unrestricted key")

	// 5) Determinism sweep: every node reports the same AppHash at every
	// height through the activation fork and the executed MAAExec.
	sweepTo := int64(-1)
	for _, cl := range clients {
		info, err := cl.ChainInfo(ctx)
		require.NoError(t, err)
		if h := int64(info.BlockHeight); sweepTo == -1 || h < sweepTo {
			sweepTo = h
		}
	}
	require.Greater(t, sweepTo, activation, "the sweep must cover the activation fork")
	for h := int64(1); h <= sweepTo; h++ {
		var ref types.Hash
		for i, cl := range clients {
			_, commitInfo, err := cl.ChainClient().BlockByHeight(ctx, h)
			require.NoError(t, err)
			require.NotNil(t, commitInfo)
			if i == 0 {
				ref = commitInfo.AppHash
			} else {
				require.Equalf(t, ref, commitInfo.AppHash, "apphash divergence at height %d between node 0 and node %d", h, i)
			}
		}
	}
}
