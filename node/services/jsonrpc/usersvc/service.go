package usersvc

import (
	// errors from engine

	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	"github.com/trufnetwork/kwil-db/core/types"
	adminTypes "github.com/trufnetwork/kwil-db/core/types/admin"
	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
	nodeConsensus "github.com/trufnetwork/kwil-db/node/consensus"
	"github.com/trufnetwork/kwil-db/node/engine"
	bridgeUtils "github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
	"github.com/trufnetwork/kwil-db/node/metrics"
	"github.com/trufnetwork/kwil-db/node/migrations"
	rpcserver "github.com/trufnetwork/kwil-db/node/services/jsonrpc"
	"github.com/trufnetwork/kwil-db/node/services/jsonrpc/ratelimit"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"
	"github.com/trufnetwork/kwil-db/version"
)

type EngineReader interface {
	Call(ctx *common.EngineContext, tx sql.DB, namespace, action string, args []any, resultFn func(*common.Row) error) (*common.CallResult, error)
	Execute(ctx *common.EngineContext, tx sql.DB, query string, params map[string]any, resultFn func(*common.Row) error) error
}

type BlockchainTransactor interface {
	Status(ctx context.Context) (*adminTypes.Status, error)
	Peers(context.Context) ([]*adminTypes.PeerInfo, error)
	ConsensusParams() *types.NetworkParameters
	BroadcastTx(ctx context.Context, tx *types.Transaction, sync uint8) (types.Hash, *types.TxResult, error)
	TxQuery(ctx context.Context, hash types.Hash, prove bool) (*types.TxQueryResponse, error)
}

type NodeApp interface {
	AccountInfo(ctx context.Context, db sql.DB, account *types.AccountID, pending bool) (balance *big.Int, nonce int64, err error)
	NumAccounts(ctx context.Context, db sql.Executor) (count, height int64, err error)
	Price(ctx context.Context, dbTx sql.DB, tx *types.Transaction) (*big.Int, error)
	GetMigrationMetadata(ctx context.Context) (*types.MigrationMetadata, error)
}

type Validators interface {
	GetValidatorPower(ctx context.Context, pubKey []byte, pubKeyType crypto.KeyType) (int64, error)
	GetValidators() []*types.Validator
}

type Migrator interface {
	GetChangesetMetadata(height int64) (*migrations.ChangesetMetadata, error)
	GetChangeset(height int64, index int64) ([]byte, error)
	GetGenesisSnapshotChunk(chunkIdx uint32) ([]byte, error)
}

var _ metrics.RPCMetrics = metrics.RPC // var mets, when needed

// Service is the "user" RPC service, also known as txsvc in other contexts.
type Service struct {
	log             log.Logger
	readTxTimeout   time.Duration
	blockAgeThresh  time.Duration
	privateMode     bool
	challengeExpiry time.Duration

	engine      EngineReader
	db          DB // this should only ever make a read-only tx
	nodeApp     NodeApp
	chainClient BlockchainTransactor
	validators  Validators
	migrator    Migrator

	// challenges issued to the clients
	challengeMtx     sync.Mutex
	challenges       map[[32]byte]time.Time
	challengeLimiter *ratelimit.IPRateLimiter
}

type DB interface {
	sql.ReadTxMaker
	sql.DelayedReadTxMaker
}

type serviceCfg struct {
	readTxTimeout      time.Duration
	privateMode        bool
	challengeExpiry    time.Duration
	challengeRateLimit float64 // challenge requests/sec, sustained
	blockAgeThresh     time.Duration
}

// Opt is a Service option.
type Opt func(*serviceCfg)

// WithReadTxTimeout sets a timeout for read-only DB transactions, as used by
// the Query and Call methods of Service.
func WithReadTxTimeout(timeout time.Duration) Opt {
	return func(cfg *serviceCfg) {
		cfg.readTxTimeout = timeout
	}
}

func WithPrivateMode(privateMode bool) Opt {
	return func(cfg *serviceCfg) {
		cfg.privateMode = privateMode
	}
}

func WithChallengeExpiry(expiry time.Duration) Opt {
	return func(cfg *serviceCfg) {
		cfg.challengeExpiry = expiry
	}
}

func WithChallengeRateLimit(limit float64) Opt {
	return func(cfg *serviceCfg) {
		cfg.challengeRateLimit = limit
	}
}

func WithBlockAgeHealth(ageThresh time.Duration) Opt {
	return func(cfg *serviceCfg) {
		cfg.blockAgeThresh = ageThresh
	}
}

const (
	defaultReadTxTimeout      = 5 * time.Second
	defaultChallengeExpiry    = 10 * time.Second // TODO: or maybe more?
	defaultChallengeRateLimit = 10.0
	defaultAgeThresh          = 6 * time.Minute
)

// NewService creates a new instance of the user RPC service.
func NewService(db DB, engine EngineReader, chainClient BlockchainTransactor,
	nodeApp NodeApp, vals Validators, migrator Migrator, logger log.Logger, opts ...Opt) *Service {
	cfg := &serviceCfg{
		readTxTimeout:      defaultReadTxTimeout,
		challengeExpiry:    defaultChallengeExpiry,
		challengeRateLimit: defaultChallengeRateLimit,
		blockAgeThresh:     defaultAgeThresh,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	svc := &Service{
		log:              logger,
		readTxTimeout:    cfg.readTxTimeout,
		blockAgeThresh:   cfg.blockAgeThresh,
		engine:           engine,
		nodeApp:          nodeApp,
		chainClient:      chainClient,
		validators:       vals,
		db:               db,
		migrator:         migrator,
		privateMode:      cfg.privateMode,
		challengeExpiry:  cfg.challengeExpiry,
		challenges:       make(map[[32]byte]time.Time),
		challengeLimiter: ratelimit.NewIPRateLimiter(cfg.challengeRateLimit, int(6*defaultChallengeRateLimit)), // allow many calls at start of block
	}

	// Start the expiry goroutine, unsupervised for now since services don't
	// "start" or "stop", but their lifetime is roughly that of the process.
	if cfg.privateMode {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				svc.expireChallenges()
			}
		}()
	}

	return svc
}

// The "user" service is versioned by these values. However, despite this API
// level versioning, methods can be versioned. For example "user.account.v2".
// The APIs minor version can indicate which new methods (or method versions)
// are available, while the API major version would be bumped for method removal
// or any other breaking changes.
const (
	apiVerMajor = 0
	apiVerMinor = 2
	apiVerPatch = 0

	serviceName = "user"
)

// API version log
//
// apiVerMinor = 2 indicates the presence of the migration, challenge, and
// health methods added in Kwil v0.9

var (
	apiVerSemver = fmt.Sprintf("%d.%d.%d", apiVerMajor, apiVerMinor, apiVerPatch)
)

// The user Service must be usable as a Svc registered with a JSON-RPC Server.
var _ rpcserver.Svc = (*Service)(nil)

func (svc *Service) Name() string {
	return serviceName
}

// Health for the user service responds with details from publicly available
// information from the chain_info response such as best block age. The health
// boolean also considers node state.
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
func (svc *Service) HealthMethod(ctx context.Context, _ *userjson.HealthRequest) (*userjson.HealthResponse, *jsonrpc.Error) {
	status, err := svc.chainClient.Status(ctx)
	if err != nil {
		svc.log.Error("chain status error", "error", err)
		jsonErr := jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "status failure", nil)
		return nil, jsonErr
	}

	peers, err := svc.chainClient.Peers(ctx)
	if err != nil {
		svc.log.Error("chain peers error", "error", err)
		jsonErr := jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "peers list failure", nil)
		return nil, jsonErr
	}

	blockAge := time.Since(status.Sync.BestBlockTime)

	svcMode := types.ModeOpen
	if svc.privateMode {
		svcMode = types.ModePrivate
	}

	// For heath checks, apply the criterion:
	happy := !status.Sync.Syncing && blockAge < svc.blockAgeThresh
	// although, in any sensible deployment:
	// && (statusResp.PeerCount > 0 || (isValidator && numValidators == 1)
	// isValidator := status.Validator.Power > 0

	healthResp := &userjson.HealthResponse{
		Healthy: happy,
		Version: apiVerSemver,
		ChainInfo: userjson.ChainInfoResponse{
			ChainID:     status.Node.ChainID,
			BlockHeight: uint64(status.Sync.BestBlockHeight),
			BlockHash:   status.Sync.BestBlockHash,
		},
		BlockTimestamp: status.Sync.BestBlockTime.UnixMilli(),
		BlockAge:       blockAge.Milliseconds(),
		Syncing:        status.Sync.Syncing,
		Height:         status.Sync.BestBlockHeight,
		AppHash:        status.Sync.AppHash,
		PeerCount:      len(peers),

		Mode: svcMode,
	}

	return healthResp, nil
}

func (svc *Service) Methods() map[jsonrpc.Method]rpcserver.MethodDef {
	return map[jsonrpc.Method]rpcserver.MethodDef{
		userjson.MethodUserVersion: rpcserver.MakeMethodDef(
			verHandler,
			"retrieve the API version of the user service",
			"service info including semver and kwild version",
		),
		userjson.MethodAccount: rpcserver.MakeMethodDef(
			svc.Account,
			"get an account's status",
			"balance and nonce of an accounts",
		),
		userjson.MethodNumAccounts: rpcserver.MakeMethodDef(
			svc.NumAccounts,
			"get the current number of accounts on the DB node",
			"the number of accounts",
		),
		userjson.MethodBroadcast: rpcserver.MakeMethodDef(
			svc.Broadcast,
			"broadcast a transaction",
			"the hash of the transaction",
		),
		userjson.MethodCall: rpcserver.MakeMethodDef(
			svc.Call,
			"call an action",
			"the result of the action call as a encoded records",
		),
		userjson.MethodChainInfo: rpcserver.MakeMethodDef(
			svc.ChainInfo,
			"get current blockchain info",
			"chain info including chain ID and best block",
		),
		userjson.MethodPing: rpcserver.MakeMethodDef(
			svc.Ping,
			"ping the server",
			"a message back from the server",
		),
		userjson.MethodPrice: rpcserver.MakeMethodDef(
			svc.EstimatePrice,
			"estimate the price of a transaction",
			"balance and nonce of an accounts",
		),
		userjson.MethodQuery: rpcserver.MakeMethodDef(
			svc.Query,
			"perform an ad-hoc SQL query",
			"the result of the query as a collection of records",
		),
		userjson.MethodAuthenticatedQuery: rpcserver.MakeMethodDef(
			svc.AuthenticatedQuery,
			"perform an authenticated ad-hoc SQL query",
			"the result of the query as a collection of records",
		),
		userjson.MethodTxQuery: rpcserver.MakeMethodDef(
			svc.TxQuery,
			"query for the status of a transaction",
			"the execution status of a transaction",
		),

		// Migration methods
		userjson.MethodListMigrations: rpcserver.MakeMethodDef(svc.ListPendingMigrations,
			"list active migration resolutions",
			"the list of all the pending migration resolutions",
		),
		userjson.MethodLoadChangesetMetadata: rpcserver.MakeMethodDef(svc.LoadChangesetMetadata,
			"get the changeset metadata for a given height",
			"the changesets metadata for the given height",
		),
		userjson.MethodLoadChangeset: rpcserver.MakeMethodDef(svc.LoadChangeset,
			"load a changeset for a given height and index",
			"the changeset for the given height and index",
		),
		userjson.MethodMigrationMetadata: rpcserver.MakeMethodDef(svc.MigrationMetadata,
			"get the migration information",
			"the metadata for the given migration",
		),
		userjson.MethodMigrationGenesisChunk: rpcserver.MakeMethodDef(svc.MigrationGenesisChunk,
			"get a genesis snapshot chunk of given idx",
			"the genesis chunk for the given index",
		),
		userjson.MethodMigrationStatus: rpcserver.MakeMethodDef(svc.MigrationStatus,
			"get the migration status",
			"the status of the migration",
		),
		userjson.MethodListUpdateProposals: rpcserver.MakeMethodDef(svc.ListPendingConsensusUpdates,
			"list active consensus parameter update proposals",
			"the list of all the active consensus parameter update proposals",
		),
		userjson.MethodUpdateProposalStatus: rpcserver.MakeMethodDef(svc.ListPendingConsensusUpdates,
			"list active consensus parameter update proposals",
			"the list of all the active consensus parameter update proposals",
		),

		// Challenge method
		userjson.MethodChallenge: rpcserver.MakeMethodDef(svc.CallChallenge,
			"request a call challenge",
			"the challenge value for the client to include in a call request signature",
		),

		userjson.MethodHealth: rpcserver.MakeMethodDef(svc.HealthMethod,
			"check the user service health",
			"the health status and other relevant of the services health",
		),

		// Withdrawal proof method
		userjson.MethodGetWithdrawalProof: rpcserver.MakeMethodDef(svc.GetWithdrawalProof,
			"get withdrawal proof and validator signatures for an epoch",
			"merkle proof, validator signatures, and withdrawal status",
		),
	}
}

func verHandler(context.Context, *userjson.VersionRequest) (*userjson.VersionResponse, *jsonrpc.Error) {
	return &userjson.VersionResponse{
		Service:     serviceName,
		Version:     apiVerSemver,
		Major:       apiVerMajor,
		Minor:       apiVerMinor,
		Patch:       apiVerPatch,
		KwilVersion: version.KwilVersion,
	}, nil
}

func (svc *Service) Handlers() map[jsonrpc.Method]rpcserver.MethodHandler {
	handlers := make(map[jsonrpc.Method]rpcserver.MethodHandler)
	for method, def := range svc.Methods() {
		handlers[method] = def.Handler
	}
	return handlers
}

func (svc *Service) ChainInfo(ctx context.Context, req *userjson.ChainInfoRequest) (*userjson.ChainInfoResponse, *jsonrpc.Error) {
	status, err := svc.chainClient.Status(ctx)
	if err != nil {
		svc.log.Error("chain status error", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "status failure", nil)
	}
	gasEnabled := !svc.chainClient.ConsensusParams().DisabledGasCosts
	return &userjson.ChainInfoResponse{
		ChainID:     status.Node.ChainID,
		BlockHeight: uint64(status.Sync.BestBlockHeight),
		BlockHash:   status.Sync.BestBlockHash,
		Gas:         gasEnabled,
	}, nil
}

func (svc *Service) Broadcast(ctx context.Context, req *userjson.BroadcastRequest) (*userjson.BroadcastResponse, *jsonrpc.Error) {
	// NOTE: it's mostly pointless to have the structured transaction in the
	// request rather than the serialized transaction, except that a client only
	// has to serialize the *body* to sign.

	var sync = userjson.BroadcastSyncAccept // default to accept, not commit
	if req.Sync != nil {
		sync = *req.Sync
	}
	txHash, result, err := svc.chainClient.BroadcastTx(ctx, req.Tx, uint8(sync))
	if err != nil {
		errCode := types.BroadcastErrorToCode(err)
		if errCode == types.CodeUnknownError {
			svc.log.Error("failed to broadcast tx", "error", err)
		}

		errData := &userjson.BroadcastError{
			ErrCode: uint32(errCode), // e.g. invalid nonce, wrong chain, etc.
			Hash:    req.Tx.Hash().String(),
			Message: err.Error(),
		}
		data, _ := json.Marshal(errData)
		return nil, jsonrpc.NewError(jsonrpc.ErrorBroadcastRejected, "broadcast error", data)
	}

	svc.log.Info("broadcast transaction", "hash", txHash,
		"sync", sync, "nonce", req.Tx.Body.Nonce)
	return &userjson.BroadcastResponse{
		TxHash: txHash,
		Result: result,
	}, nil
}

/* Most broadcast capabilities are bytes, not an object. We should support the following:

type BroadcastRawRequest struct {
	Raw  []byte                 `json:"raw,omitempty"`
	Sync *jsonrpc.BroadcastSync `json:"sync,omitempty"`
}
type BroadcastRawResponse struct {
	TxHash types.HexBytes `json:"tx_hash,omitempty"`
}

func (svc *Service) BroadcastRaw(ctx context.Context, req *BroadcastRawRequest) (*BroadcastRawResponse, *jsonrpc.Error) {
	var sync = jsonrpc.BroadcastSyncSync // default to sync, not async or commit
	if req.Sync != nil {
		sync = *req.Sync
	}
	res, err := svc.chainClient.BroadcastTx(ctx, req.Raw, uint8(sync))
	if err != nil {
		svc.log.Error("failed to broadcast tx", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorTxInternal, "failed to broadcast transaction", nil)
	}

	// If we want details, like Sender, Nonce, etc.:
	// var tx transactions.Transaction
	// tx.UnmarshalBinary(req.Raw) //	serialize.Decode(req.Raw, &tx)

	code, txHash := res.Code, res.Hash.Bytes()

	if txCode := transactions.TxCode(code); txCode != transactions.CodeOk {
		errData := &jsonrpc.BroadcastError{
			TxCode:  txCode.Uint32(), // e.g. invalid nonce, wrong chain, etc.
			Hash:    hex.EncodeToString(txHash),
			Message: res.Log,
		}
		data, _ := json.Marshal(errData)
		return nil, jsonrpc.NewError(jsonrpc.ErrorTxExecFailure, "broadcast error", data)
	}

	svc.log.Info("broadcast transaction", log.String("TxHash", hex.EncodeToString(txHash)), log.Uint("sync", sync))
	return &BroadcastRawResponse{
		TxHash: txHash,
	}, nil
}
*/

func (svc *Service) EstimatePrice(ctx context.Context, req *userjson.EstimatePriceRequest) (*userjson.EstimatePriceResponse, *jsonrpc.Error) {
	svc.log.Debug("Estimating price", "payload_type", req.Tx.Body.PayloadType)
	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	price, err := svc.nodeApp.Price(ctx, readTx, req.Tx)
	if err != nil {
		svc.log.Error("failed to estimate price", "error", err) // why not tell the client though?
		return nil, jsonrpc.NewError(jsonrpc.ErrorTxInternal, "failed to estimate price", nil)
	}

	return &userjson.EstimatePriceResponse{
		Price: price.String(),
	}, nil
}

func (svc *Service) Query(ctx context.Context, req *userjson.QueryRequest) (*userjson.QueryResponse, *jsonrpc.Error) {
	ctxExec, cancel := context.WithTimeout(ctx, svc.readTxTimeout)
	defer cancel()

	if svc.privateMode {
		return nil, jsonrpc.NewError(jsonrpc.ErrorNoQueryWithPrivateRPC,
			"query is prohibited when authenticated calls are enforced (private mode)", nil)
	}

	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	params := make(map[string]any)
	for k, v := range req.Params {
		var err error
		params[k], err = v.Decode()
		if err != nil {
			return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "failed to decode parameter: "+err.Error(), nil)
		}
	}

	r := &rowReader{}
	err := svc.engine.Execute(&common.EngineContext{
		TxContext: &common.TxContext{
			Ctx: ctxExec,
			BlockContext: &common.BlockContext{
				Height: -1, // cannot know the height here.
			},
		}}, readTx, req.Query, params, r.read)
	if err != nil {
		// We don't know for sure that it's an invalid argument, but an invalid
		// user-provided query isn't an internal server error.
		return nil, engineError(err)
	}
	return &userjson.QueryResponse{
		ColumnNames: r.qr.ColumnNames,
		ColumnTypes: r.qr.ColumnTypes,
		Values:      r.qr.Values,
	}, nil
}

func (svc *Service) AuthenticatedQuery(ctx context.Context, req *userjson.AuthenticatedQueryRequest) (*userjson.QueryResponse, *jsonrpc.Error) {
	ctxExec, cancel := context.WithTimeout(ctx, svc.readTxTimeout)
	defer cancel()

	sigText, err := req.SigText()
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "failed to create signature text: "+err.Error(), nil)
	}

	if jsonRPCErr := svc.authenticate(req.SignatureData, req.Challenge, req.Sender, req.AuthType, sigText); jsonRPCErr != nil {
		return nil, jsonRPCErr
	}

	params := make(map[string]any)
	for _, v := range req.Body.Parameters {
		var err error
		params[v.Name], err = v.Value.Decode()
		if err != nil {
			return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "failed to decode parameter: "+err.Error(), nil)
		}
	}

	txCtx, jsonRPCErr := svc.txCtx(ctxExec, req.Sender, req.AuthType)
	if jsonRPCErr != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to create tx context: "+jsonRPCErr.Error(), nil)
	}

	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	r := &rowReader{}
	err = svc.engine.Execute(&common.EngineContext{
		TxContext: txCtx}, readTx, req.Body.Statement, params, r.read)
	if err != nil {
		// We don't know for sure that it's an invalid argument, but an invalid
		// user-provided query isn't an internal server error.
		return nil, engineError(err)
	}
	return &userjson.QueryResponse{
		ColumnNames: r.qr.ColumnNames,
		ColumnTypes: r.qr.ColumnTypes,
		Values:      r.qr.Values,
	}, nil
}

func (svc *Service) Account(ctx context.Context, req *userjson.AccountRequest) (*userjson.AccountResponse, *jsonrpc.Error) {
	// Status is presently just 0 for confirmed and 1 for pending, but there may
	// be others such as finalized and safe.
	uncommitted := req.Status != nil && *req.Status > 0

	if req.ID == nil || len(req.ID.Identifier) == 0 {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "missing account identifier", nil)
	}

	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	balance, nonce, err := svc.nodeApp.AccountInfo(ctx, readTx, req.ID, uncommitted)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorAccountInternal, "account info error", nil)
	}

	var ident *types.AccountID
	var zeroBal big.Int
	if nonce > 0 || balance.Cmp(&zeroBal) > 0 { // return nil pubkey for non-existent account
		ident = req.ID
	}

	return &userjson.AccountResponse{
		ID:      ident, // nil for non-existent account
		Nonce:   nonce,
		Balance: balance.String(),
	}, nil
}

func (svc *Service) NumAccounts(ctx context.Context, req *userjson.NumAccountsRequest) (*userjson.NumAccountsResponse, *jsonrpc.Error) {
	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)
	num, height, err := svc.nodeApp.NumAccounts(ctx, readTx)
	if err != nil {
		svc.log.Error("failed to count accounts", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorAccountInternal, "failed to count accounts", nil)
	}
	return &userjson.NumAccountsResponse{
		Count:  num,
		Height: height,
	}, nil
}

func (svc *Service) Ping(ctx context.Context, req *userjson.PingRequest) (*userjson.PingResponse, *jsonrpc.Error) {
	return &userjson.PingResponse{
		Message: "pong",
	}, nil
}

func checkEngineError(err error) (jsonrpc.ErrorCode, string) {
	if err == nil {
		return 0, "" // would not be constructing a jsonrpc.Error
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return jsonrpc.ErrorTimeout, "db timeout"
	}
	if errors.Is(err, engine.ErrNamespaceExists) {
		return jsonrpc.ErrorEngineDatasetExists, err.Error()
	}
	if errors.Is(err, engine.ErrNamespaceNotFound) {
		return jsonrpc.ErrorEngineDatasetNotFound, err.Error()
	}

	return jsonrpc.ErrorEngineInternal, err.Error()
}

func engineError(err error) *jsonrpc.Error {
	if err == nil {
		return nil // would not be constructing a jsonrpc.Error
	}
	code, msg := checkEngineError(err)
	return &jsonrpc.Error{
		Code:    code,
		Message: msg,
	}
}

func unmarshalActionCall(req *userjson.CallRequest) (*types.ActionCall, *types.CallMessage, error) {
	var actionPayload types.ActionCall
	err := actionPayload.UnmarshalBinary(req.Body.Payload)
	if err != nil {
		return nil, nil, err
	}

	cm := *req

	return &actionPayload, &cm, nil
}

func (svc *Service) verifyCallChallenge(challenge [32]byte) *jsonrpc.Error {
	svc.challengeMtx.Lock()
	challengeTime, ok := svc.challenges[challenge]
	if !ok {
		svc.challengeMtx.Unlock()
		return jsonrpc.NewError(jsonrpc.ErrorCallChallengeNotFound, "invalid challenge", nil)
	}

	// remove the challenge from the list
	delete(svc.challenges, challenge)
	svc.challengeMtx.Unlock()

	// ensure that challenge is not expired
	if time.Now().After(challengeTime) {
		return jsonrpc.NewError(jsonrpc.ErrorCallChallengeExpired, "challenge expired", nil)
	}

	return nil
}

func (svc *Service) Call(ctx context.Context, req *userjson.CallRequest) (*userjson.CallResponse, *jsonrpc.Error) {
	body, msg, err := unmarshalActionCall(req)
	if err != nil {
		// NOTE: http api needs to be able to get the error message
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "failed to convert action call: "+err.Error(), nil)
	}

	if jsonRPCErr := svc.authenticate(msg.SignatureData, msg.Body.Challenge, msg.Sender, msg.AuthType, types.CallSigText(body.Namespace, body.Action,
		msg.Body.Payload, msg.Body.Challenge)); jsonRPCErr != nil {
		return nil, jsonRPCErr
	}

	args := make([]any, len(body.Arguments))
	for i, arg := range body.Arguments {
		argVal, err := arg.Decode()
		if err != nil {
			return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "failed to decode argument: "+err.Error(), nil)
		}
		args[i] = argVal
	}

	ctxExec, cancel := context.WithTimeout(ctx, svc.readTxTimeout)
	defer cancel()

	txContext, jsonRPCErr := svc.txCtx(ctxExec, msg.Sender, msg.AuthType)
	if jsonRPCErr != nil {
		return nil, jsonRPCErr
	}

	// we use a basic read tx since we are subscribing to notices,
	// and it is therefore pointless to use a delayed tx
	readTx, err := svc.db.BeginReadTx(ctx)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to start read tx", nil)
	}
	defer readTx.Rollback(ctx)

	r := &rowReader{}
	callRes, err := svc.engine.Call(&common.EngineContext{TxContext: txContext}, readTx, body.Namespace, body.Action, args, r.read)
	if err != nil {
		return nil, engineError(err)
	}

	var execErr *string
	if callRes.Error != nil {
		e2 := callRes.Error.Error()
		execErr = &e2
	}

	return &userjson.CallResponse{
		QueryResult: &r.qr,
		Logs:        callRes.FormatLogs(),
		Error:       execErr,
	}, nil
}

// rowReader is a helper struct that writes data for a query response
type rowReader struct {
	qr types.QueryResult
}

func (r *rowReader) read(row *common.Row) error {
	if r.qr.ColumnNames == nil {
		r.qr.ColumnNames = row.ColumnNames
		r.qr.ColumnTypes = row.ColumnTypes
	}

	// since Kwil supports int64, which has a higher precision than languages
	// like JavaScript, we convert int64s to strings to avoid precision loss
	vals := make([]any, len(row.Values))
	for i, v := range row.Values {
		switch v := v.(type) {
		case int64:
			vals[i] = strconv.FormatInt(v, 10)
		case []*int64:
			var arr []*string
			for _, n := range v {
				if n == nil {
					arr = append(arr, nil)
				} else {
					i2 := strconv.FormatInt(*n, 10)
					arr = append(arr, &i2)
				}
			}
			vals[i] = arr
		default:
			vals[i] = v
		}
	}

	r.qr.Values = append(r.qr.Values, vals)
	return nil
}

// txCtx creates a transaction context from the given context and call message.
// It will do its best to determine the caller and signer, and the block context.
func (svc *Service) txCtx(ctx context.Context, sender []byte, authtype string) (*common.TxContext, *jsonrpc.Error) {
	signer := sender
	caller := "" // string representation of sender, if signed.  Otherwise, empty string
	if len(signer) > 0 && authtype != "" {
		var err error
		caller, err = authExt.GetIdentifier(authtype, signer)
		if err != nil {
			return nil, jsonrpc.NewError(jsonrpc.ErrorIdentInvalid, "failed to get caller: "+err.Error(), nil)
		}
	}

	chainStat, err := svc.chainClient.Status(ctx)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to get chain status: "+err.Error(), nil)
	}
	height, hash, stamp := chainStat.Sync.BestBlockHeight, chainStat.Sync.BestBlockHash, chainStat.Sync.BestBlockTime.Unix()
	if chainStat.Sync.Syncing { // don't use known stale height and time stamp if node is syncing
		height = -1
		hash = types.Hash{}
		stamp = -1
	}

	// Get network parameters for proposer information
	// This is safe because tx context at json rpc service only affects read-only (views) calls.
	// The context for write operations are derived from block processor.
	networkParams := svc.chainClient.ConsensusParams()

	return &common.TxContext{
		Ctx:           ctx,
		Signer:        signer,
		Caller:        caller,
		Authenticator: authtype,
		BlockContext: &common.BlockContext{
			ChainContext: &common.ChainContext{
				NetworkParameters: networkParams,
			},
			Height:    height,
			Timestamp: stamp,
			Hash:      hash,
			Proposer:  networkParams.Leader, // Add configured leader for consistency with mempool validation
		},
	}, nil
}

// authenticate enforces authentication for the given context and message
// if private mode is enabled. It returns an error if authentication fails.
func (svc *Service) authenticate(signature, challenge, sender []byte, authtype, sigTxt string) *jsonrpc.Error {
	if !svc.privateMode {
		return nil
	}

	// Authenticate by validating the challenge was server-issued, and verify
	// the signature on the serialized call message that include the challenge.

	// The message must have a sig, sender, and challenge.
	if len(signature) == 0 || len(sender) == 0 {
		return jsonrpc.NewError(jsonrpc.ErrorCallChallengeNotFound, "signed call message with challenge required", nil)
	}
	if len(challenge) != 32 {
		return jsonrpc.NewError(jsonrpc.ErrorInvalidCallChallenge, "incorrect challenge data length", nil)
	}
	// Ensure we issued the message's challenge.
	if err := svc.verifyCallChallenge([32]byte(challenge)); err != nil {
		return err
	}
	err := authExt.VerifySignature(sender, []byte(sigTxt), &auth.Signature{
		Data: signature,
		Type: authtype,
	})
	if err != nil {
		return jsonrpc.NewError(jsonrpc.ErrorInvalidCallSignature, "invalid signature on call message", nil)
	}

	return nil
}

func (svc *Service) TxQuery(ctx context.Context, req *userjson.TxQueryRequest) (*userjson.TxQueryResponse, *jsonrpc.Error) {
	// logger := svc.log.With(log.String("rpc", "TxQuery"),
	// 	log.String("TxHash", hex.EncodeToString(req.TxHash)))
	logger := svc.log

	txResult, err := svc.chainClient.TxQuery(ctx, req.TxHash, false)
	if err != nil {
		if errors.Is(err, types.ErrTxNotFound) {
			return nil, jsonrpc.NewError(jsonrpc.ErrorTxNotFound, "transaction not found", nil)
		}
		logger.Warn("failed to query tx", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to query transaction", nil)
	}

	logger.Debug("tx query result", "result", txResult)

	return txResult, nil
}

func (svc *Service) LoadChangeset(ctx context.Context, req *userjson.ChangesetRequest) (*userjson.ChangesetsResponse, *jsonrpc.Error) {
	bts, err := svc.migrator.GetChangeset(req.Height, req.Index)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to load changesets", nil)
	}

	return &userjson.ChangesetsResponse{
		Changesets: bts,
	}, nil
}

func (svc *Service) LoadChangesetMetadata(ctx context.Context, req *userjson.ChangesetMetadataRequest) (*userjson.ChangesetMetadataResponse, *jsonrpc.Error) {
	metadata, err := svc.migrator.GetChangesetMetadata(req.Height)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to load changeset metadata", nil)
	}

	return &userjson.ChangesetMetadataResponse{
		Height:     metadata.Height,
		Changesets: metadata.Chunks,
		ChunkSizes: metadata.ChunkSizes,
	}, nil
}

func (svc *Service) MigrationMetadata(ctx context.Context, req *userjson.MigrationMetadataRequest) (*userjson.MigrationMetadataResponse, *jsonrpc.Error) {
	metadata, err := svc.nodeApp.GetMigrationMetadata(ctx)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, err.Error(), nil)
	}

	return &userjson.MigrationMetadataResponse{
		Metadata: metadata,
	}, nil
}

func (svc *Service) MigrationGenesisChunk(ctx context.Context, req *userjson.MigrationSnapshotChunkRequest) (*userjson.MigrationSnapshotChunkResponse, *jsonrpc.Error) {
	bts, err := svc.migrator.GetGenesisSnapshotChunk(req.ChunkIndex)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to load genesis chunk", nil)
	}

	return &userjson.MigrationSnapshotChunkResponse{
		Chunk: bts,
	}, nil
}

func (svc *Service) ListPendingMigrations(ctx context.Context, req *userjson.ListMigrationsRequest) (*userjson.ListMigrationsResponse, *jsonrpc.Error) {
	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	resolutions, err := voting.GetResolutionsByType(ctx, readTx, voting.StartMigrationEventType)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorDBInternal, "failed to get migration resolutions", nil)
	}

	var pendingMigrations []*types.Migration

	for _, res := range resolutions {
		svc.log.Info("migration resolution", "res", res)
		mig := &migrations.MigrationDeclaration{}
		if err := mig.UnmarshalBinary(res.Body); err != nil {
			return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to unmarshal migration declaration"+err.Error(), nil)
		}
		pendingMigrations = append(pendingMigrations, &types.Migration{
			ID:               res.ID,
			ActivationPeriod: (int64)(mig.ActivationPeriod),
			Duration:         (int64)(mig.Duration),
			Timestamp:        mig.Timestamp,
		})
	}

	return &userjson.ListMigrationsResponse{
		Migrations: pendingMigrations,
	}, nil
}

func (svc *Service) MigrationStatus(ctx context.Context, req *userjson.MigrationStatusRequest) (*userjson.MigrationStatusResponse, *jsonrpc.Error) {
	metadata, err := svc.nodeApp.GetMigrationMetadata(ctx)
	if err != nil || metadata == nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "migration state unavailable", nil)
	}

	chainStatus, err := svc.chainClient.Status(ctx)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to get chain status", nil)
	}

	return &userjson.MigrationStatusResponse{
		Status: &types.MigrationState{
			Status:        metadata.MigrationState.Status,
			StartHeight:   metadata.MigrationState.StartHeight,
			EndHeight:     metadata.MigrationState.EndHeight,
			CurrentHeight: chainStatus.Sync.BestBlockHeight,
		},
	}, nil
}

func (svc *Service) ListPendingConsensusUpdates(ctx context.Context, req *userjson.ListPendingConsensusUpdatesRequest) (*userjson.ListPendingConsensusUpdatesResponse, *jsonrpc.Error) {
	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	resolutions, err := voting.GetResolutionsByType(ctx, readTx, nodeConsensus.ParamUpdatesResolutionType)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorDBInternal, "failed to get consensus updates resolutions", nil)
	}

	var pendingMigrations []*types.ConsensusParamUpdateProposal

	for _, res := range resolutions {
		up := &nodeConsensus.ParamUpdatesDeclaration{}
		if err := up.UnmarshalBinary(res.Body); err != nil {
			return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to consensus parameter update declaration", nil)
		}
		pendingMigrations = append(pendingMigrations, &types.ConsensusParamUpdateProposal{
			ID:          *res.ID,
			Description: up.Description,
			Updates:     up.ParamUpdates,
		})
	}

	return &userjson.ListPendingConsensusUpdatesResponse{
		Proposals: pendingMigrations,
	}, nil
}

func (svc *Service) expireChallenges() {
	now := time.Now().UTC()
	svc.challengeMtx.Lock()
	defer svc.challengeMtx.Unlock()
	for ch, exp := range svc.challenges {
		if now.After(exp) { // passed expiry time?
			delete(svc.challenges, ch)
		}
	}
}

// CallChallenge is the handler for the user.challenge RPC. It gives the user a
// new challenge for use with a signed call request. They are single use, and
// they expire according to the service's challenge expiry configuration.
func (svc *Service) CallChallenge(ctx context.Context, req *userjson.ChallengeRequest) (*userjson.ChallengeResponse, *jsonrpc.Error) {
	clientIP, _ := ctx.Value(rpcserver.RequestIPCtx).(string)
	if clientIP != "" && !svc.challengeLimiter.IP(clientIP).Allow() {
		return nil, jsonrpc.NewError(jsonrpc.ErrorTooFastChallengeReqs, "too many challenge requests", nil)
	}

	expiry := time.Now().Add(svc.challengeExpiry).UTC()

	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, err.Error(), nil)
	}

	svc.challengeMtx.Lock()
	if _, have := svc.challenges[challenge]; have {
		svc.challengeMtx.Unlock()
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to generate unique challenge", nil)
	} // that should not happen with 256-bits of randomness

	svc.challenges[challenge] = expiry
	svc.challengeMtx.Unlock()

	return &userjson.ChallengeResponse{
		Challenge: challenge[:],
	}, nil
}

// GetWithdrawalProof retrieves the merkle proof and validator signatures for a withdrawal.
func (svc *Service) GetWithdrawalProof(ctx context.Context, req *userjson.WithdrawalProofRequest) (*userjson.WithdrawalProofResponse, *jsonrpc.Error) {
	// Parse epoch ID
	epochID, err := types.ParseUUID(req.EpochID)
	if err != nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "invalid epoch_id: "+err.Error(), nil)
	}

	// Validate recipient address format using go-ethereum's proper validation
	if !ethcommon.IsHexAddress(req.Recipient) {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "invalid recipient: must be Ethereum address (0x...)", nil)
	}

	// Start read-only transaction
	readTx := svc.db.BeginDelayedReadTx()
	defer readTx.Rollback(ctx)

	// Create engine context (similar to Query method)
	ctxExec, cancel := context.WithTimeout(ctx, svc.readTxTimeout)
	defer cancel()

	engineCtx := &common.EngineContext{
		TxContext: &common.TxContext{
			Ctx: ctxExec,
			BlockContext: &common.BlockContext{
				Height: -1, // cannot know the height for read-only queries
			},
		},
	}

	// Query epoch information
	type EpochInfo struct {
		ID              *types.UUID
		RewardRoot      []byte
		BlockHash       []byte
		Confirmed       bool
		CreatedAtUnix   int64
		InstanceID      *types.UUID
		ChainID         string
		EscrowAddress   []byte
		DistributionPer int64
		EndedAt         *int64
	}

	var epoch *EpochInfo
	epochQuery := `
		{kwil_erc20_meta}SELECT
			e.id, e.reward_root, e.block_hash, e.confirmed, e.created_at_unix, e.ended_at,
			e.instance_id, r.chain_id, r.escrow_address, r.distribution_period
		FROM epochs e
		JOIN reward_instances r ON e.instance_id = r.id
		WHERE e.id = $epoch_id
	`

	err = svc.engine.Execute(engineCtx, readTx, epochQuery, map[string]any{
		"epoch_id": epochID,
	}, func(row *common.Row) error {
		if len(row.Values) != 10 {
			return fmt.Errorf("expected 10 values, got %d", len(row.Values))
		}

		// Use safe type assertions with ok checks
		id, ok := row.Values[0].(*types.UUID)
		if !ok {
			return fmt.Errorf("unexpected type for id column: got %T", row.Values[0])
		}

		confirmed, ok := row.Values[3].(bool)
		if !ok {
			return fmt.Errorf("unexpected type for confirmed column: got %T", row.Values[3])
		}

		createdAt, ok := row.Values[4].(int64)
		if !ok {
			return fmt.Errorf("unexpected type for created_at column: got %T", row.Values[4])
		}

		instanceID, ok := row.Values[6].(*types.UUID)
		if !ok {
			return fmt.Errorf("unexpected type for instance_id column: got %T", row.Values[6])
		}

		chainID, ok := row.Values[7].(string)
		if !ok {
			return fmt.Errorf("unexpected type for chain_id column: got %T", row.Values[7])
		}

		escrowAddress, ok := row.Values[8].([]byte)
		if !ok {
			return fmt.Errorf("unexpected type for escrow_address column: got %T", row.Values[8])
		}

		distributionPer, ok := row.Values[9].(int64)
		if !ok {
			return fmt.Errorf("unexpected type for distribution_per column: got %T", row.Values[9])
		}

		epoch = &EpochInfo{
			ID:              id,
			Confirmed:       confirmed,
			CreatedAtUnix:   createdAt,
			InstanceID:      instanceID,
			ChainID:         chainID,
			EscrowAddress:   escrowAddress,
			DistributionPer: distributionPer,
		}

		// Handle nullable reward_root
		if row.Values[1] != nil {
			rewardRoot, ok := row.Values[1].([]byte)
			if !ok {
				return fmt.Errorf("unexpected type for reward_root column: got %T", row.Values[1])
			}
			epoch.RewardRoot = rewardRoot
		}

		// Handle nullable block_hash
		if row.Values[2] != nil {
			blockHash, ok := row.Values[2].([]byte)
			if !ok {
				return fmt.Errorf("unexpected type for block_hash column: got %T", row.Values[2])
			}
			epoch.BlockHash = blockHash
		}

		// Handle nullable ended_at
		if row.Values[5] != nil {
			endedAt, ok := row.Values[5].(int64)
			if !ok {
				return fmt.Errorf("unexpected type for ended_at column: got %T", row.Values[5])
			}
			epoch.EndedAt = &endedAt
		}

		return nil
	})

	if err != nil {
		svc.log.Error("failed to query epoch", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to query epoch: "+err.Error(), nil)
	}

	if epoch == nil {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "epoch not found", nil)
	}

	// Check if epoch is finalized
	if epoch.EndedAt == nil {
		// Epoch is still active - return "pending" status
		estimatedReady := epoch.CreatedAtUnix + epoch.DistributionPer
		return &userjson.WithdrawalProofResponse{
			Recipient:        req.Recipient,
			Status:           "pending",
			EstimatedReadyAt: &estimatedReady,
		}, nil
	}

	if !epoch.Confirmed {
		// Epoch ended but not confirmed yet
		return &userjson.WithdrawalProofResponse{
			Recipient: req.Recipient,
			Status:    "pending",
		}, nil
	}

	// Epoch is confirmed - query all epoch rewards to build merkle tree
	type Reward struct {
		Recipient []byte
		Amount    *types.Decimal
	}

	var rewards []Reward
	rewardsQuery := `
		{kwil_erc20_meta}SELECT recipient, amount
		FROM epoch_rewards
		WHERE epoch_id = $epoch_id
		ORDER BY recipient
	`

	err = svc.engine.Execute(engineCtx, readTx, rewardsQuery, map[string]any{
		"epoch_id": epochID,
	}, func(row *common.Row) error {
		if len(row.Values) != 2 {
			return fmt.Errorf("expected 2 values, got %d", len(row.Values))
		}

		recipient, ok := row.Values[0].([]byte)
		if !ok {
			return fmt.Errorf("unexpected type for recipient column: got %T", row.Values[0])
		}

		amount, ok := row.Values[1].(*types.Decimal)
		if !ok {
			return fmt.Errorf("unexpected type for amount column: got %T", row.Values[1])
		}

		rewards = append(rewards, Reward{
			Recipient: recipient,
			Amount:    amount,
		})
		return nil
	})

	if err != nil {
		svc.log.Error("failed to query epoch rewards", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to query rewards: "+err.Error(), nil)
	}

	if len(rewards) == 0 {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "no rewards in epoch", nil)
	}

	// Find the recipient in rewards and build merkle tree
	var recipientAmount *types.Decimal
	recipientFound := false
	users := make([]string, len(rewards))
	amounts := make([]*big.Int, len(rewards))

	for i, r := range rewards {
		recipientAddr := fmt.Sprintf("0x%x", r.Recipient)
		users[i] = recipientAddr

		amt := r.Amount.BigInt()
		amounts[i] = amt

		if strings.EqualFold(recipientAddr, req.Recipient) {
			recipientAmount = r.Amount
			recipientFound = true
		}
	}

	if !recipientFound {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "recipient not found in epoch", nil)
	}

	// Generate merkle tree using bridge utils
	escrowAddr := fmt.Sprintf("0x%x", epoch.EscrowAddress)

	// Validate block hash length before copy
	if len(epoch.BlockHash) != 32 {
		svc.log.Error("invalid block hash length", "length", len(epoch.BlockHash))
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "invalid epoch block hash", nil)
	}

	var blockHash [32]byte
	copy(blockHash[:], epoch.BlockHash)

	jsonTree, root, err := bridgeUtils.GenRewardMerkleTree(users, amounts, escrowAddr, blockHash)
	if err != nil {
		svc.log.Error("failed to generate merkle tree", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to generate proof: "+err.Error(), nil)
	}

	// Verify root matches
	if !bytes.Equal(root, epoch.RewardRoot) {
		svc.log.Error("merkle root mismatch", "computed", fmt.Sprintf("%x", root), "stored", fmt.Sprintf("%x", epoch.RewardRoot))
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "merkle root mismatch", nil)
	}

	// Get proof for recipient using bridge utils
	mtRoot, proofs, _, bh, _, err := bridgeUtils.GetMTreeProof(jsonTree, req.Recipient)
	if err != nil {
		svc.log.Error("failed to get merkle proof", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to get proof: "+err.Error(), nil)
	}

	// Convert proofs to hex strings
	merkleProof := make([]string, len(proofs))
	for i, p := range proofs {
		merkleProof[i] = "0x" + fmt.Sprintf("%x", p)
	}

	// Query validator signatures
	type VoteSignature struct {
		Voter     []byte
		Signature []byte
	}

	var votes []VoteSignature
	votesQuery := `
		{kwil_erc20_meta}SELECT voter, signature
		FROM epoch_votes
		WHERE epoch_id = $epoch_id
		ORDER BY voter
	`

	err = svc.engine.Execute(engineCtx, readTx, votesQuery, map[string]any{
		"epoch_id": epochID,
	}, func(row *common.Row) error {
		if len(row.Values) != 2 {
			return fmt.Errorf("expected 2 values, got %d", len(row.Values))
		}

		voter, ok := row.Values[0].([]byte)
		if !ok {
			return fmt.Errorf("unexpected type for voter column at index 0: got %T", row.Values[0])
		}

		signature, ok := row.Values[1].([]byte)
		if !ok {
			return fmt.Errorf("unexpected type for signature column at index 1: got %T", row.Values[1])
		}

		votes = append(votes, VoteSignature{
			Voter:     voter,
			Signature: signature,
		})
		return nil
	})

	if err != nil {
		svc.log.Error("failed to query votes", "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "failed to query signatures: "+err.Error(), nil)
	}

	// Parse signatures into v/r/s format
	validatorSigs := make([]userjson.ValidatorSignature, 0, len(votes))
	for _, vote := range votes {
		if len(vote.Signature) != 65 {
			svc.log.Warn("invalid signature length", "length", len(vote.Signature))
			continue
		}

		// Signature format is [R || S || V] (65 bytes)
		// R: bytes 0-31, S: bytes 32-63, V: byte 64
		r := vote.Signature[0:32]
		s := vote.Signature[32:64]
		v := vote.Signature[64]

		validatorSigs = append(validatorSigs, userjson.ValidatorSignature{
			V: v,
			R: "0x" + fmt.Sprintf("%x", r),
			S: "0x" + fmt.Sprintf("%x", s),
		})
	}

	if len(validatorSigs) == 0 {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInternal, "no valid signatures found", nil)
	}

	// Check if withdrawal has been completed on the blockchain (multi-chain support)
	// Query withdrawals table to get current status
	status := "ready" // Default to ready if no tracking record exists
	var ethTxHash *string

	// Convert recipient hex string to bytes for query
	recipientBytes := ethcommon.HexToAddress(req.Recipient).Bytes()

	withdrawalQuery := `
		{kwil_erc20_meta}SELECT tx_hash, status
		FROM withdrawals
		WHERE epoch_id = $epoch_id AND recipient = $recipient
	`

	err = svc.engine.Execute(engineCtx, readTx, withdrawalQuery, map[string]any{
		"epoch_id":  epochID,
		"recipient": recipientBytes,
	}, func(row *common.Row) error {
		if len(row.Values) != 2 {
			return fmt.Errorf("expected 2 values, got %d", len(row.Values))
		}

		// Handle nullable tx_hash
		if row.Values[0] != nil {
			hash, ok := row.Values[0].([]byte)
			if !ok {
				return fmt.Errorf("unexpected type for tx_hash: got %T", row.Values[0])
			}
			hashHex := "0x" + fmt.Sprintf("%x", hash)
			ethTxHash = &hashHex
		}

		// Get status
		statusVal, ok := row.Values[1].(string)
		if !ok {
			return fmt.Errorf("unexpected type for status: got %T", row.Values[1])
		}
		status = statusVal

		return nil
	})

	if err != nil {
		// Table not existing is expected during migration (backward compatibility)
		// Other errors (connection, syntax) are more concerning and should be logged at higher level
		if strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "not found") {
			svc.log.Debug("withdrawal tracking table not yet available, using default status",
				"epoch_id", epochID.String(),
				"recipient", req.Recipient,
				"default_status", status)
		} else {
			svc.log.Error("failed to query withdrawal status, using default",
				"epoch_id", epochID.String(),
				"recipient", req.Recipient,
				"error", err,
				"default_status", status)
		}
	}
	// If callback was never invoked (no matching row), status remains "ready" (default)

	// TODO (Phase 2): Implement automatic blockchain event monitoring to update this table

	// Parse chain ID
	var chainID int64 = 1 // Default to Ethereum mainnet
	if id, err := strconv.ParseInt(epoch.ChainID, 10, 64); err == nil {
		chainID = id
	}

	return &userjson.WithdrawalProofResponse{
		Recipient:           req.Recipient,
		Amount:              recipientAmount.String(),
		KwilBlockHash:       "0x" + fmt.Sprintf("%x", bh),
		MerkleRoot:          "0x" + fmt.Sprintf("%x", mtRoot),
		MerkleProof:         merkleProof,
		ValidatorSignatures: validatorSigs,
		ContractAddress:     escrowAddr,
		ChainID:             chainID,
		Status:              status,
		EthTxHash:           ethTxHash,
	}, nil
}
