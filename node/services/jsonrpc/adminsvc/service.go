package adminsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	adminjson "github.com/trufnetwork/kwil-db/core/rpc/json/admin"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	types "github.com/trufnetwork/kwil-db/core/types/admin"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
	"github.com/trufnetwork/kwil-db/node/peers"
	rpcserver "github.com/trufnetwork/kwil-db/node/services/jsonrpc"
	ntypes "github.com/trufnetwork/kwil-db/node/types"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"
	"github.com/trufnetwork/kwil-db/version"
)

// BlockchainTransactor specifies the methods required for the admin service to
// interact with the blockchain.
type Node interface {
	Status(context.Context) (*types.Status, error)
	Peers(context.Context) ([]*types.PeerInfo, error)
	BroadcastTx(ctx context.Context, tx *ktypes.Transaction, sync uint8) (ktypes.Hash, *ktypes.TxResult, error)
	Role() ntypes.Role
	AbortBlockExecution(height int64, txIDs []ktypes.Hash) error
	PromoteLeader(leader crypto.PublicKey, height int64) error
}

type Whitelister interface { // maybe merge with Node since it's same job
	// AddPeer adds a peer to the node's peer whitelist and persists it.
	AddPeer(nodeID string) error

	// RemovePeer removes a peer from the node's peer whitelist permanently.
	RemovePeer(nodeID string) error

	// List returns the list of peers in the node's whitelist.
	List() []string
}

type Blacklister interface {
	// BlacklistPeer adds a peer to the blacklist with reason and duration
	// If duration is 0, the peer is permanently blacklisted
	BlacklistPeer(nodeID string, reason string, duration time.Duration) error

	// RemoveFromBlacklist removes a peer from the blacklist
	RemoveFromBlacklist(nodeID string) error

	// ListBlacklisted returns all active blacklist entries
	ListBlacklisted() ([]peers.BlacklistEntry, error)
}

type App interface {
	// AccountInfo returns the unconfirmed account info for the given identifier.
	// If unconfirmed is true, the account found in the mempool is returned.
	// Otherwise, the account found in the blockchain is returned.
	AccountInfo(ctx context.Context, db sql.DB, identifier *ktypes.AccountID, unconfirmed bool) (balance *big.Int, nonce int64, err error)
	Price(ctx context.Context, db sql.DB, tx *ktypes.Transaction) (*big.Int, error)
	BlockExecutionStatus() *ktypes.BlockExecutionStatus
}

type Validators interface {
	SetValidatorPower(ctx context.Context, tx sql.Executor, pubKey []byte, pubKeyType crypto.KeyType, power int64) error
	GetValidatorPower(ctx context.Context, pubKey []byte, pubKeyType crypto.KeyType) (int64, error)
	GetValidators() []*ktypes.Validator
}

// parsePeerID accepts both Kwil node IDs (e.g., "<hex>#secp256k1") and libp2p PeerIDs.
// It returns the libp2p peer.ID for blacklist operations.
func parsePeerID(peerIDStr string) (peer.ID, error) {
	// Check if it's a Kwil node ID format (contains "#")
	if strings.Contains(peerIDStr, "#") {
		// Use peers package to convert Kwil node ID to libp2p peer ID
		pubkey, err := peers.NodeIDToPubKey(peerIDStr)
		if err != nil {
			return "", fmt.Errorf("invalid Kwil node ID: %w", err)
		}
		peerID, err := peers.PeerIDFromPubKey(pubkey)
		if err != nil {
			return "", fmt.Errorf("failed to convert node ID to peer ID: %w", err)
		}
		return peerID, nil
	}

	// Otherwise assume it's a libp2p peer ID
	peerID, err := peer.Decode(peerIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid libp2p peer ID: %w", err)
	}
	return peerID, nil
}

// Blacklist-specific errors for better client feedback
var (
	ErrInvalidPeerID  = errors.New("invalid peer ID")
	ErrNotBlacklisted = errors.New("peer not found in blacklist")
)

// BlacklisterAdapter adapts PeerMan for the Blacklister interface
type BlacklisterAdapter struct {
	pm *peers.PeerMan
}

func NewBlacklisterAdapter(pm *peers.PeerMan) *BlacklisterAdapter {
	return &BlacklisterAdapter{pm: pm}
}

func (ba *BlacklisterAdapter) BlacklistPeer(nodeID string, reason string, duration time.Duration) error {
	peerID, err := parsePeerID(nodeID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidPeerID, err.Error())
	}
	ba.pm.BlacklistPeer(peerID, reason, duration)
	return nil
}

func (ba *BlacklisterAdapter) RemoveFromBlacklist(nodeID string) error {
	peerID, err := parsePeerID(nodeID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidPeerID, err.Error())
	}
	removed := ba.pm.RemoveFromBlacklist(peerID)
	if !removed {
		return ErrNotBlacklisted
	}
	return nil
}

func (ba *BlacklisterAdapter) ListBlacklisted() ([]peers.BlacklistEntry, error) {
	return ba.pm.ListBlacklisted(), nil
}

type Service struct {
	log log.Logger

	blockchain Node // node is the local node that can accept transactions.
	app        App
	voting     Validators
	db         sql.DelayedReadTxMaker
	whitelist  Whitelister
	blacklist  Blacklister

	cfg     *config.Config
	chainID string
	signer  auth.Signer // ed25519 signer derived from the node's private key
}

const (
	apiVerMajor = 0
	apiVerMinor = 2
	apiVerPatch = 0

	serviceName = "admin"
)

// API version log
//
// apiVerMinor = 2 indicates the presence of the peer whitelist, resolution, and
// health methods added in Kwil v0.9

var (
	apiSemver = fmt.Sprintf("%d.%d.%d", apiVerMajor, apiVerMinor, apiVerPatch)
)

func verHandler(context.Context, *userjson.VersionRequest) (*userjson.VersionResponse, *jsonrpc.Error) {
	return &userjson.VersionResponse{
		Service:     serviceName,
		Version:     apiSemver,
		Major:       apiVerMajor,
		Minor:       apiVerMinor,
		Patch:       apiVerPatch,
		KwilVersion: version.KwilVersion,
	}, nil
}

// The admin Service must be usable as a Svc registered with a JSON-RPC Server.
var _ rpcserver.Svc = (*Service)(nil)

func (svc *Service) Name() string {
	return serviceName
}

func (svc *Service) Health(ctx context.Context) (json.RawMessage, bool) {
	healthResp, jsonErr := svc.HealthMethod(ctx, &userjson.HealthRequest{})
	if jsonErr != nil { // unable to even perform the health check
		// This is not for a JSON-RPC client.
		svc.log.Error("health check failure", "error", jsonErr)
		resp, _ := json.Marshal(struct {
			Healthy bool `json:"healthy"`
		}{}) // omit everything else since
		return resp, false
	}

	resp, _ := json.Marshal(healthResp)

	return resp, healthResp.Healthy
}

// HealthMethod is a JSON-RPC method handler for service health.
func (svc *Service) HealthMethod(ctx context.Context, _ *userjson.HealthRequest) (*adminjson.HealthResponse, *jsonrpc.Error) {
	vals, jsonErr := svc.ListValidators(ctx, &adminjson.ListValidatorsRequest{})
	if jsonErr != nil {
		return nil, jsonErr
	}

	status, err := svc.blockchain.Status(ctx)
	if err != nil {
		svc.log.Error("chain status error", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "status failure", nil)
	}

	// health criteria: presently, nothing, we're just here.
	// Being a validator may be a concern to the consumer.
	happy := true

	return &adminjson.HealthResponse{
		Healthy:       happy,
		Version:       apiSemver,
		PubKey:        status.Validator.Identifier,
		NumValidators: len(vals.Validators),
	}, nil
	// slices.ContainsFunc(vals.Validators, func(v *ktypes.Validator) bool { return bytes.Equal(v.PubKey, status.Validator.PubKey) })
}

func (svc *Service) Methods() map[jsonrpc.Method]rpcserver.MethodDef {
	return map[jsonrpc.Method]rpcserver.MethodDef{
		adminjson.MethodVersion: rpcserver.MakeMethodDef(verHandler,
			"retrieve the API version of the admin service",    // method description
			"service info including semver and kwild version"), // return value description
		adminjson.MethodStatus: rpcserver.MakeMethodDef(svc.Status,
			"retrieve node status",
			"node information including name, chain id, sync, identity, etc."),
		adminjson.MethodPeers: rpcserver.MakeMethodDef(svc.Peers,
			"get the current peers of the node",
			"a list of the node's current peers"),
		adminjson.MethodConfig: rpcserver.MakeMethodDef(svc.GetConfig,
			"retrieve the current effective node config",
			"the raw bytes of the effective config TOML document"),
		adminjson.MethodValApprove: rpcserver.MakeMethodDef(svc.Approve,
			"approve a validator join request",
			"the hash of the broadcasted validator approve transaction"),
		adminjson.MethodValJoin: rpcserver.MakeMethodDef(svc.Join,
			"request the node to become a validator",
			"the hash of the broadcasted validator join transaction"),
		adminjson.MethodValJoinStatus: rpcserver.MakeMethodDef(svc.JoinStatus,
			"query for the status of a validator join request",
			"the pending join request details, if it exists"),
		adminjson.MethodValListJoins: rpcserver.MakeMethodDef(svc.ListPendingJoins,
			"list active validator join requests",
			"all pending join requests including the current approvals and the join expiry"),
		adminjson.MethodValList: rpcserver.MakeMethodDef(svc.ListValidators,
			"list the current validators",
			"the list of current validators and their power"),
		adminjson.MethodValLeave: rpcserver.MakeMethodDef(svc.Leave,
			"leave the validator set",
			"the hash of the broadcasted validator leave transaction"),
		adminjson.MethodValRemove: rpcserver.MakeMethodDef(svc.Remove,
			"vote to remote a validator",
			"the hash of the broadcasted validator remove transaction"),
		adminjson.MethodValPromote: rpcserver.MakeMethodDef(svc.Promote,
			"promote a validator to leader starting from the specified height", ""),
		adminjson.MethodAddPeer: rpcserver.MakeMethodDef(svc.AddPeer,
			"add a peer to the network", ""),
		adminjson.MethodRemovePeer: rpcserver.MakeMethodDef(svc.RemovePeer,
			"add a peer to the network",
			""),
		adminjson.MethodListPeers: rpcserver.MakeMethodDef(svc.ListPeers,
			"list the peers from the node's whitelist",
			"the list of peers from which the node can accept connections from."),
		adminjson.MethodBlacklistPeer: rpcserver.MakeMethodDef(svc.BlacklistPeer,
			"add a peer to the blacklist with optional reason and duration",
			"success confirmation"),
		adminjson.MethodRemoveBlacklistedPeer: rpcserver.MakeMethodDef(svc.RemoveBlacklistedPeer,
			"remove a peer from the blacklist",
			"removal confirmation"),
		adminjson.MethodListBlacklistedPeers: rpcserver.MakeMethodDef(svc.ListBlacklistedPeers,
			"list all currently blacklisted peers",
			"list of blacklisted peers with metadata"),
		adminjson.MethodCreateResolution: rpcserver.MakeMethodDef(svc.CreateResolution,
			"create a resolution",
			"the hash of the broadcasted create resolution transaction",
		),
		adminjson.MethodApproveResolution: rpcserver.MakeMethodDef(svc.ApproveResolution,
			"approve a resolution",
			"the hash of the broadcasted approve resolution transaction",
		),
		// adminjson.MethodDeleteResolution: rpcserver.MakeMethodDef(svc.DeleteResolution,
		// 	"delete a resolution",
		// 	"the hash of the broadcasted delete resolution transaction",
		// ),
		adminjson.MethodResolutionStatus: rpcserver.MakeMethodDef(svc.ResolutionStatus,
			"get the status of a resolution",
			"the status of the resolution"),
		adminjson.MethodHealth: rpcserver.MakeMethodDef(svc.HealthMethod,
			"check the admin service health",
			"the health status and other relevant of the services health",
		),
		adminjson.MethodBlockExecStatus: rpcserver.MakeMethodDef(svc.BlockExecStatus,
			"get the status of the ongoing block execution",
			"the status of the ongoing block execution",
		),
		adminjson.MethodAbortBlockExecution: rpcserver.MakeMethodDef(svc.AbortBlockExecution,
			"cancel the block execution at the given height and discard the specified transactions from the mempool",
			"",
		),
	}
}

func (svc *Service) Handlers() map[jsonrpc.Method]rpcserver.MethodHandler {
	handlers := make(map[jsonrpc.Method]rpcserver.MethodHandler)
	for method, def := range svc.Methods() {
		handlers[method] = def.Handler
	}
	return handlers
}

// NewService constructs a new Service.
func NewService(db sql.DelayedReadTxMaker, blockchain Node, app App,
	vs Validators, wl Whitelister, bl Blacklister, txSigner auth.Signer, cfg *config.Config,
	chainID string, logger log.Logger) *Service {
	return &Service{
		blockchain: blockchain,
		whitelist:  wl,
		blacklist:  bl,
		app:        app,
		voting:     vs,
		signer:     txSigner,
		chainID:    chainID,
		cfg:        cfg,
		log:        logger,
		db:         db,
	}
}

func convertSyncInfo(si *types.SyncInfo) *adminjson.SyncInfo {
	return &adminjson.SyncInfo{
		AppHash:         si.AppHash,
		BestBlockHash:   si.BestBlockHash,
		BestBlockHeight: si.BestBlockHeight,
		BestBlockTime:   si.BestBlockTime.UnixMilli(),
		Syncing:         si.Syncing,
	}
}

func (svc *Service) Status(ctx context.Context, req *adminjson.StatusRequest) (*adminjson.StatusResponse, *jsonrpc.Error) {
	status, err := svc.blockchain.Status(ctx)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "node status unavailable", nil)
	}

	var power int64
	power, _ = svc.voting.GetValidatorPower(ctx, status.Validator.Identifier, status.Validator.KeyType)

	var rpcAddr string
	if srv, ok := ctx.Value(rpcserver.ServerCtx).(*rpcserver.Server); ok {
		rpcAddr = srv.Addr()
	}

	// A different type from blockchain.Status that has no RPCAddr would be less
	// error prone but more types...
	nodeInfo := *status.Node
	nodeInfo.RPCAddr = rpcAddr

	return &adminjson.StatusResponse{
		Node: &nodeInfo,
		Sync: convertSyncInfo(status.Sync),
		Validator: &adminjson.Validator{
			AccountID: ktypes.AccountID{
				Identifier: status.Validator.Identifier,
				KeyType:    status.Validator.KeyType,
			},
			Power: power,
		},
	}, nil
}

func (svc *Service) Peers(ctx context.Context, _ *adminjson.PeersRequest) (*adminjson.PeersResponse, *jsonrpc.Error) {
	peers, err := svc.blockchain.Peers(ctx)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "node peers unavailable", nil)
	}
	return &adminjson.PeersResponse{
		Peers: peers,
	}, nil
}

// sendTx makes a transaction and sends it to the local node.
func (svc *Service) sendTx(ctx context.Context, payload ktypes.Payload) (*userjson.BroadcastResponse, *jsonrpc.Error) {
	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	acct, err := ktypes.GetSignerAccount(svc.signer)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "unable to get signer account: "+err.Error(), nil)
	}

	// Get the latest nonce for the account, if it exists.
	_, nonce, err := svc.app.AccountInfo(ctx, readTx, acct, true)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorAccountInternal, "account info error: "+err.Error(), nil)
	}

	tx, err := ktypes.CreateNodeTransaction(payload, svc.chainID, uint64(nonce+1))
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "unable to create transaction: "+err.Error(), nil)
	}

	fee, err := svc.app.Price(ctx, readTx, tx)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorTxInternal, "unable to price transaction: "+err.Error(), nil)
	}

	tx.Body.Fee = fee

	// Sign the transaction.
	err = tx.Sign(svc.signer)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "signing transaction failed: "+err.Error(), nil)
	}

	txHash, result, err := svc.blockchain.BroadcastTx(ctx, tx, uint8(userjson.BroadcastSyncAccept))
	if err != nil {
		errCode := ktypes.BroadcastErrorToCode(err)
		if errCode == ktypes.CodeUnknownError {
			svc.log.Error("failed to broadcast tx", "error", err)
		}

		errData := &userjson.BroadcastError{
			ErrCode: uint32(errCode), // e.g. invalid nonce, wrong chain, etc.
			Hash:    tx.Hash().String(),
			Message: err.Error(),
		}
		data, _ := json.Marshal(errData)
		return nil, jsonrpc.NewError(jsonrpc.ErrorBroadcastRejected, "broadcast error", data)
	}

	svc.log.Info("broadcast transaction", "hash", txHash, "nonce", tx.Body.Nonce)
	return &userjson.BroadcastResponse{
		TxHash: txHash,
		Result: result,
	}, nil

}

func (svc *Service) Approve(ctx context.Context, req *adminjson.ApproveRequest) (*userjson.BroadcastResponse, *jsonrpc.Error) {
	return svc.sendTx(ctx, &ktypes.ValidatorApprove{
		Candidate: req.PubKey,
		KeyType:   req.PubKeyType,
	})
}

func (svc *Service) Join(ctx context.Context, req *adminjson.JoinRequest) (*userjson.BroadcastResponse, *jsonrpc.Error) {
	return svc.sendTx(ctx, &ktypes.ValidatorJoin{
		Power: 1,
	})
}

func (svc *Service) Remove(ctx context.Context, req *adminjson.RemoveRequest) (*userjson.BroadcastResponse, *jsonrpc.Error) {
	return svc.sendTx(ctx, &ktypes.ValidatorRemove{
		Validator: req.PubKey,
		KeyType:   req.PubKeyType,
	})
}

func (svc *Service) Promote(ctx context.Context, req *adminjson.PromoteRequest) (*adminjson.PromoteResponse, *jsonrpc.Error) {
	// convert this into crypto.PublicKey
	pubKey, err := crypto.UnmarshalPublicKey(req.PubKey, req.PubKeyType)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to unmarshal public key: "+err.Error(), nil)
	}

	err = svc.blockchain.PromoteLeader(pubKey, req.Height)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to promote leader: "+err.Error(), nil)
	}

	return nil, nil
}

func (svc *Service) JoinStatus(ctx context.Context, req *adminjson.JoinStatusRequest) (*adminjson.JoinStatusResponse, *jsonrpc.Error) {
	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)
	ids, err := voting.GetResolutionIDsByTypeAndProposer(ctx, readTx, voting.ValidatorJoinEventType, req.PubKey, req.PubKeyType)
	if err != nil {
		svc.log.Error("failed to retrieve join request", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorDBInternal, "failed to retrieve join request", nil)
	}
	if len(ids) == 0 {
		return nil, jsonrpc.NewError(jsonrpc.ErrorValidatorNotFound, "no active join request", nil)
	}

	resolution, err := voting.GetResolutionInfo(ctx, readTx, ids[0])
	if err != nil {
		svc.log.Error("failed to retrieve join request", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorDBInternal, "failed to retrieve join request details", nil)
	}

	voters := svc.voting.GetValidators()

	pendingJoin, err := svc.toPendingInfo(resolution, voters)
	if err != nil {
		svc.log.Error("failed to convert join request", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorResultEncoding, "failed to convert join request", nil)
	}

	return &adminjson.JoinStatusResponse{
		JoinRequest: pendingJoin,
	}, nil
}

func (svc *Service) Leave(ctx context.Context, req *adminjson.LeaveRequest) (*userjson.BroadcastResponse, *jsonrpc.Error) {
	return svc.sendTx(ctx, &ktypes.ValidatorLeave{})
}

func (svc *Service) ListValidators(ctx context.Context, req *adminjson.ListValidatorsRequest) (*adminjson.ListValidatorsResponse, *jsonrpc.Error) {
	vals := svc.voting.GetValidators()

	pbValidators := make([]*adminjson.Validator, len(vals))
	for i, vi := range vals {
		pbValidators[i] = &adminjson.Validator{
			AccountID: ktypes.AccountID{
				Identifier: vi.Identifier,
				KeyType:    vi.KeyType,
			},
			Power: vi.Power,
		}
	}

	return &adminjson.ListValidatorsResponse{
		Validators: pbValidators,
	}, nil
}

func (svc *Service) ListPendingJoins(ctx context.Context, req *adminjson.ListJoinRequestsRequest) (*adminjson.ListJoinRequestsResponse, *jsonrpc.Error) {
	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	activeJoins, err := voting.GetResolutionsByType(ctx, readTx, voting.ValidatorJoinEventType)
	if err != nil {
		svc.log.Error("failed to retrieve active join requests", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorDBInternal, "failed to retrieve active join requests", nil)
	}

	voters := svc.voting.GetValidators()

	pbJoins := make([]*adminjson.PendingJoin, len(activeJoins))
	for i, ji := range activeJoins {
		pbJoins[i], err = svc.toPendingInfo(ji, voters)
		if err != nil {
			svc.log.Error("failed to convert join request", "error", err)
			return nil, jsonrpc.NewError(jsonrpc.ErrorResultEncoding, "failed to convert join request", nil)
		}
	}

	return &adminjson.ListJoinRequestsResponse{
		JoinRequests: pbJoins,
	}, nil
}

// toPendingInfo gets the pending information for an active join from a resolution
func (svc *Service) toPendingInfo(resolution *resolutions.Resolution, allVoters []*ktypes.Validator) (*adminjson.PendingJoin, error) {
	resolutionBody := &voting.UpdatePowerRequest{}
	if err := resolutionBody.UnmarshalBinary(resolution.Body); err != nil {
		return nil, fmt.Errorf("failed to unmarshal join request")
	}

	board, approvals := svc.approvalsInfo(resolution, allVoters)

	return &adminjson.PendingJoin{
		Candidate: &ktypes.AccountID{
			Identifier: resolutionBody.PubKey,
			KeyType:    resolutionBody.PubKeyType,
		},
		Power:     resolutionBody.Power,
		ExpiresAt: resolution.Expiration,
		Board:     board,
		Approved:  approvals,
	}, nil
}

func (svc *Service) approvalsInfo(resolution *resolutions.Resolution, allVoters []*ktypes.Validator) ([]*ktypes.AccountID, []bool) {
	// to create the board, we will take a list of all approvers and append the voters.
	// we will then remove any duplicates the second time we see them.
	// this will result with all approvers at the start of the list, and all voters at the end.
	// finally, the approvals will be true for the length of the approvers, and false for found.length - voters.length
	board := make([]*ktypes.AccountID, 0, len(allVoters))
	approvals := make([]bool, len(allVoters))
	for i, v := range resolution.Voters {
		board = append(board, &ktypes.AccountID{
			Identifier: v.Identifier,
			KeyType:    v.KeyType,
		})
		approvals[i] = true
	}
	for _, v := range allVoters {
		board = append(board, &ktypes.AccountID{
			Identifier: v.Identifier,
			KeyType:    v.KeyType,
		})
	}

	// we will now remove duplicates from the board.
	found := make(map[string]struct{})
	for i := 0; i < len(board); i++ {
		nodeKey := fmt.Sprintf("%s:%s", string(board[i].Identifier), board[i].KeyType)
		if _, ok := found[nodeKey]; ok {
			board = append(board[:i], board[i+1:]...)
			i--
			continue
		}
		found[nodeKey] = struct{}{}
	}

	return board, approvals
}

func (svc *Service) GetConfig(ctx context.Context, req *adminjson.GetConfigRequest) (*adminjson.GetConfigResponse, *jsonrpc.Error) {
	bts, err := svc.cfg.ToTOML()
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorResultEncoding, "failed to encode node config", nil)
	}

	return &adminjson.GetConfigResponse{
		Config: bts,
	}, nil
}

func (svc *Service) AddPeer(ctx context.Context, req *adminjson.PeerRequest) (*adminjson.PeerResponse, *jsonrpc.Error) {
	err := svc.whitelist.AddPeer(req.PeerID)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to add a peer. Reason: "+err.Error(), nil)
	}
	return &adminjson.PeerResponse{}, nil
}

func (svc *Service) RemovePeer(ctx context.Context, req *adminjson.PeerRequest) (*adminjson.PeerResponse, *jsonrpc.Error) {
	err := svc.whitelist.RemovePeer(req.PeerID)
	if err != nil {
		svc.log.Error("failed to remove peer", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to remove peer : "+err.Error(), nil)
	}
	return &adminjson.PeerResponse{}, nil
}

func (svc *Service) ListPeers(ctx context.Context, req *adminjson.PeersRequest) (*adminjson.ListPeersResponse, *jsonrpc.Error) {
	return &adminjson.ListPeersResponse{
		Peers: svc.whitelist.List(),
	}, nil
}

func (svc *Service) CreateResolution(ctx context.Context, req *adminjson.CreateResolutionRequest) (*userjson.BroadcastResponse, *jsonrpc.Error) {
	res := &ktypes.CreateResolution{
		Resolution: &ktypes.VotableEvent{
			Type: req.ResolutionType,
			Body: req.Resolution,
		},
	}

	return svc.sendTx(ctx, res)
}

func (svc *Service) ApproveResolution(ctx context.Context, req *adminjson.ApproveResolutionRequest) (*userjson.BroadcastResponse, *jsonrpc.Error) {
	res := &ktypes.ApproveResolution{
		ResolutionID: req.ResolutionID,
	}

	return svc.sendTx(ctx, res)
}

/* disabled until the tx route is tested
func (svc *Service) DeleteResolution(ctx context.Context, req *adminjson.DeleteResolutionRequest) (*userjson.BroadcastResponse, *jsonrpc.Error) {
	res := &ktypes.DeleteResolution{
		ResolutionID: req.ResolutionID,
	}

	return svc.sendTx(ctx, res)
}
*/

func (svc *Service) ResolutionStatus(ctx context.Context, req *adminjson.ResolutionStatusRequest) (*adminjson.ResolutionStatusResponse, *jsonrpc.Error) {
	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	uuid := req.ResolutionID
	resolution, err := voting.GetResolutionInfo(ctx, readTx, uuid)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorDBInternal, "failed to retrieve resolution", nil)
	}

	voters := svc.voting.GetValidators()

	board, approvals := svc.approvalsInfo(resolution, voters)

	return &adminjson.ResolutionStatusResponse{
		Status: &ktypes.PendingResolution{
			Type:         resolution.Type,
			ResolutionID: req.ResolutionID,
			ExpiresAt:    resolution.Expiration,
			Board:        board,
			Approved:     approvals,
		},
	}, nil
}

func (svc *Service) BlockExecStatus(ctx context.Context, req *adminjson.BlockExecStatusRequest) (*adminjson.BlockExecStatusResponse, *jsonrpc.Error) {
	status := svc.app.BlockExecutionStatus()

	if status == nil {
		return nil, nil
	}

	resp := &types.BlockExecutionStatus{
		Height:    status.Height,
		StartTime: status.StartTime,
		EndTime:   status.EndTime,
	}
	txInfo := make([]*types.TxInfo, len(status.TxIDs))
	for i, txID := range status.TxIDs {
		txInfo[i] = &types.TxInfo{
			ID:     txID,
			Status: status.TxStatus[txID],
		}
	}
	resp.TxInfo = txInfo
	return &adminjson.BlockExecStatusResponse{
		Status: resp,
	}, nil
}

func (svc *Service) AbortBlockExecution(ctx context.Context, req *adminjson.AbortBlockExecRequest) (*adminjson.AbortBlockExecResponse, *jsonrpc.Error) {
	if svc.blockchain.Role() != ntypes.RoleLeader {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "only the leader can abort block execution", nil)
	}

	txIds := make([]ktypes.Hash, len(req.Txs))
	for i, tx := range req.Txs {
		txId, err := ktypes.NewHashFromString(tx)
		if err != nil {
			svc.log.Error("failed to parse tx hash", "error", err)
			return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to parse hexadecimal string into a Hash", nil)
		}
		txIds[i] = txId
	}

	err := svc.blockchain.AbortBlockExecution(req.Height, txIds)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to rollback block", nil)
	}

	return &adminjson.AbortBlockExecResponse{}, nil
}

func (svc *Service) BlacklistPeer(ctx context.Context, req *adminjson.BlacklistPeerRequest) (*adminjson.BlacklistPeerResponse, *jsonrpc.Error) {
	// Parse duration if provided
	var duration time.Duration
	if req.Duration != "" {
		var err error
		duration, err = time.ParseDuration(req.Duration)
		if err != nil {
			return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "invalid duration format: "+err.Error(), nil)
		}
		if duration < 0 {
			return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "invalid duration format: negative durations not allowed", nil)
		}
	} // duration = 0 means permanent

	// Trim whitespace and use default reason if not provided or empty after trimming
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "manual"
	}

	err := svc.blacklist.BlacklistPeer(req.PeerID, reason, duration)
	if err != nil {
		// Check for user-actionable errors
		if errors.Is(err, ErrInvalidPeerID) {
			return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, err.Error(), nil)
		}
		// For unexpected errors, return internal error
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to blacklist peer: "+err.Error(), nil)
	}

	return &adminjson.BlacklistPeerResponse{}, nil
}

func (svc *Service) RemoveBlacklistedPeer(ctx context.Context, req *adminjson.RemoveBlacklistedPeerRequest) (*adminjson.RemoveBlacklistedPeerResponse, *jsonrpc.Error) {
	err := svc.blacklist.RemoveFromBlacklist(req.PeerID)
	if err != nil {
		// Check for user-actionable errors
		if errors.Is(err, ErrInvalidPeerID) || errors.Is(err, ErrNotBlacklisted) {
			return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, err.Error(), nil)
		}
		// For unexpected errors, return internal error
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to remove blacklisted peer: "+err.Error(), nil)
	}

	return &adminjson.RemoveBlacklistedPeerResponse{Removed: true}, nil
}

func (svc *Service) ListBlacklistedPeers(ctx context.Context, req *adminjson.ListBlacklistedPeersRequest) (*adminjson.ListBlacklistedPeersResponse, *jsonrpc.Error) {
	entries, err := svc.blacklist.ListBlacklisted()
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to list blacklisted peers: "+err.Error(), nil)
	}

	// Convert to JSON format
	jsonEntries := make([]adminjson.BlacklistEntryJSON, len(entries))
	for i, entry := range entries {
		// Convert PeerID back to Kwil node ID format for consistency
		nodeID, err := peers.NodeIDFromPeerID(entry.PeerID.String())
		if err != nil {
			// Fallback to PeerID string if conversion fails
			nodeID = entry.PeerID.String()
		}

		jsonEntries[i] = adminjson.BlacklistEntryJSON{
			PeerID:    nodeID,
			Reason:    entry.Reason,
			Timestamp: entry.Timestamp.Format(time.RFC3339),
			Permanent: entry.Permanent,
			ExpiresAt: func() string {
				if entry.Permanent || entry.ExpiresAt.IsZero() {
					return ""
				}
				return entry.ExpiresAt.Format(time.RFC3339)
			}(),
		}
	}

	return &adminjson.ListBlacklistedPeersResponse{
		BlacklistedPeers: jsonEntries,
	}, nil
}
