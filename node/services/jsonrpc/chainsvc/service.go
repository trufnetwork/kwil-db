package chainsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
	chainjson "github.com/trufnetwork/kwil-db/core/rpc/json/chain"
	userjson "github.com/trufnetwork/kwil-db/core/rpc/json/user"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	chaintypes "github.com/trufnetwork/kwil-db/core/types/chain"
	rpcserver "github.com/trufnetwork/kwil-db/node/services/jsonrpc"
	nodetypes "github.com/trufnetwork/kwil-db/node/types"
	"github.com/trufnetwork/kwil-db/version"
)

const (
	apiVerMajor = 0
	apiVerMinor = 2
	apiVerPatch = 0

	serviceName = "chain"
)

// API version log
//
// apiVerMinor = 1 initial api in v0.9
// apiVerMinor = 2 v0.10
//
// NOTE: we haven't stabilized the API, but it will bump major for breaking changes

var (
	apiSemver = fmt.Sprintf("%d.%d.%d", apiVerMajor, apiVerMinor, apiVerPatch)
)

// Node specifies the methods required for chain service to interact with the blockchain.
type Node interface {
	// BlockByHeight returns block info at height. If height=0, the latest block will be returned.
	BlockByHeight(height int64) (ktypes.Hash, *ktypes.Block, *ktypes.CommitInfo, error)
	BlockByHash(hash ktypes.Hash) (*ktypes.Block, *ktypes.CommitInfo, error)
	RawBlockByHeight(height int64) (ktypes.Hash, []byte, *ktypes.CommitInfo, error)
	RawBlockByHash(hash ktypes.Hash) ([]byte, *ktypes.CommitInfo, error)
	GetBlockHeader(hash ktypes.Hash) (*ktypes.BlockHeader, error)
	GetBlockHeaderByHeight(height int64) (*ktypes.BlockHeader, error)
	BlockResultByHash(hash ktypes.Hash) ([]ktypes.TxResult, error)
	ChainTx(hash ktypes.Hash) (*chaintypes.Tx, error)
	BlockHeight() int64
	ChainUnconfirmedTx(limit int) (int, []*nodetypes.Tx)
	ConsensusParams() *ktypes.NetworkParameters
}

type Validators interface {
	GetValidators() []*ktypes.Validator
}

type Service struct {
	log        log.Logger
	genesisCfg *chainjson.GenesisResponse
	voting     Validators
	blockchain Node // node is the local node that can accept transactions.
}

func NewService(log log.Logger, blockchain Node, voting Validators, genesisCfg *config.GenesisConfig) *Service {
	// Prepare the static Genesis config response.
	var allocs []chaintypes.GenesisAlloc
	for _, alloc := range genesisCfg.Allocs {
		allocs = append(allocs, chaintypes.GenesisAlloc{
			ID:      alloc.ID.HexBytes,
			KeyType: alloc.KeyType,
			Amount:  alloc.Amount.String(),
		})
	}
	genCfg := &chainjson.GenesisResponse{
		ChainID:          genesisCfg.ChainID,
		InitialHeight:    genesisCfg.InitialHeight,
		DBOwner:          genesisCfg.DBOwner,
		Leader:           genesisCfg.Leader,
		Validators:       genesisCfg.Validators,
		StateHash:        genesisCfg.StateHash,
		Allocs:           allocs,
		MaxBlockSize:     genesisCfg.MaxBlockSize,
		JoinExpiry:       genesisCfg.JoinExpiry,
		DisabledGasCosts: genesisCfg.DisabledGasCosts,
		MaxVotesPerTx:    genesisCfg.MaxVotesPerTx,
	}

	return &Service{
		log:        log,
		genesisCfg: genCfg,
		voting:     voting,
		blockchain: blockchain,
	}
}

func (svc *Service) Name() string {
	return serviceName
}

func (svc *Service) Health(ctx context.Context) (detail json.RawMessage, happy bool) {
	healthResp, jsonErr := svc.HealthMethod(ctx, &chainjson.HealthRequest{})
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

func (svc *Service) Methods() map[jsonrpc.Method]rpcserver.MethodDef {
	return map[jsonrpc.Method]rpcserver.MethodDef{
		chainjson.MethodVersion: rpcserver.MakeMethodDef(verHandler,
			"retrieve the API version of the chain service",
			"service info including semver and kwild version"),
		chainjson.MethodHealth: rpcserver.MakeMethodDef(svc.HealthMethod,
			"retrieve the health status of the chain service",
			"health status of the service"),
		chainjson.MethodBlock: rpcserver.MakeMethodDef(svc.Block,
			"retrieve certain block info",
			"block information at a certain height"),
		chainjson.MethodBlockHeader: rpcserver.MakeMethodDef(svc.BlockHeader,
			"retrieve certain block header info",
			"block header information at a certain height"),
		chainjson.MethodBlockResult: rpcserver.MakeMethodDef(svc.BlockResult,
			"retrieve certain block result info",
			"block result information at a certain height"),
		chainjson.MethodTx: rpcserver.MakeMethodDef(svc.Tx,
			"retrieve certain transaction info",
			"transaction information at a certain hash"),
		chainjson.MethodGenesis: rpcserver.MakeMethodDef(svc.Genesis,
			"retrieve the genesis info",
			"genesis information"),
		chainjson.MethodConsensusParams: rpcserver.MakeMethodDef(svc.ConsensusParams,
			"retrieve the consensus parameers",
			"consensus parameters"),
		chainjson.MethodValidators: rpcserver.MakeMethodDef(svc.Validators,
			"retrieve validator info at certain height",
			"validator information at certain height"),
		chainjson.MethodUnconfirmedTxs: rpcserver.MakeMethodDef(svc.UnconfirmedTxs,
			"retrieve unconfirmed txs",
			"unconfirmed txs"),
	}
}

func (svc *Service) HealthMethod(_ context.Context, _ *chainjson.HealthRequest) (*chainjson.HealthResponse, *jsonrpc.Error) {
	return &chainjson.HealthResponse{
		ChainID: svc.genesisCfg.ChainID,
		Height:  svc.blockchain.BlockHeight(),
		Healthy: true,
	}, nil
}

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

// Block returns block information either by block height or block hash.
// If both provided, block hash will be used.
func (svc *Service) Block(_ context.Context, req *chainjson.BlockRequest) (*chainjson.BlockResponse, *jsonrpc.Error) {
	if req.Height < 0 {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "height cannot be negative", nil)
	}

	var rawBlock []byte
	var commitInfo *ktypes.CommitInfo
	var err error
	blkHash := req.Hash

	// prioritize req.Hash over req.Height
	if req.Hash.IsZero() {
		blkHash, rawBlock, commitInfo, err = svc.blockchain.RawBlockByHeight(req.Height)
	} else {
		rawBlock, commitInfo, err = svc.blockchain.RawBlockByHash(req.Hash)
	}

	if err != nil {
		if errors.Is(err, nodetypes.ErrBlkNotFound) || errors.Is(err, nodetypes.ErrNotFound) {
			return nil, jsonrpc.NewError(jsonrpc.ErrorBlkNotFound, "block not found", nil)
		}
		svc.log.Error("block request", "height", req.Height, "hash", req.Hash, "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to get block", nil)
	}

	if req.Raw {
		return &chainjson.BlockResponse{
			Hash:       blkHash,
			RawBlock:   rawBlock,
			CommitInfo: commitInfo,
		}, nil
	}

	block, err := ktypes.DecodeBlock(rawBlock)
	if err != nil {
		svc.log.Error("failed to decode block", "height", req.Height, "hash", req.Hash, "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to decode block", nil)
	}

	return &chainjson.BlockResponse{
		Hash:       blkHash,
		Block:      block,
		CommitInfo: commitInfo,
	}, nil
}

// BlockHeader returns block header information either by block height or block
// hash. If both provided, block hash will be used. This method is similar to
// Block, but only returns the block header. It is useful for clients that only
// need the header information without the full block data.
func (svc *Service) BlockHeader(_ context.Context, req *chainjson.BlockHeaderRequest) (*chainjson.BlockHeaderResponse, *jsonrpc.Error) {
	if req.Height < 0 {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "height cannot be negative", nil)
	}

	var err error
	var blockHeader *ktypes.BlockHeader

	// prioritize req.Hash over req.Height
	if req.Hash.IsZero() {
		blockHeader, err = svc.blockchain.GetBlockHeaderByHeight(req.Height)
	} else {
		blockHeader, err = svc.blockchain.GetBlockHeader(req.Hash)
	}

	if err != nil {
		if errors.Is(err, nodetypes.ErrBlkNotFound) || errors.Is(err, nodetypes.ErrNotFound) {
			return nil, jsonrpc.NewError(jsonrpc.ErrorBlkNotFound, "block not found", nil)
		}
		svc.log.Error("block header request", "height", req.Height, "hash", req.Hash, "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to get block header", nil)
	}

	return &chainjson.BlockHeaderResponse{
		Height:            blockHeader.Height,
		Version:           blockHeader.Version,
		NumTxns:           blockHeader.NumTxns,
		PrevHash:          blockHeader.PrevHash,
		PrevAppHash:       blockHeader.PrevAppHash,
		Timestamp:         blockHeader.Timestamp,
		MerkleRoot:        blockHeader.MerkleRoot,
		ValidatorSetHash:  blockHeader.ValidatorSetHash,
		NetworkParamsHash: blockHeader.NetworkParamsHash,
		NewLeader:         blockHeader.NewLeader,
	}, nil
}

// BlockResult returns block result either by block height or bloch hash.
// If both provided, block hash will be used.
func (svc *Service) BlockResult(_ context.Context, req *chainjson.BlockResultRequest) (*chainjson.BlockResultResponse, *jsonrpc.Error) {
	if req.Height < 0 {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "height cannot be negative", nil)
	}

	if !req.Hash.IsZero() {
		blockHeader, err := svc.blockchain.GetBlockHeader(req.Hash)
		if err != nil {
			if errors.Is(err, nodetypes.ErrBlkNotFound) || errors.Is(err, nodetypes.ErrNotFound) {
				return nil, jsonrpc.NewError(jsonrpc.ErrorBlkNotFound, "block not found", nil)
			}
			svc.log.Error("block by hash", "hash", req.Hash, "error", err)
			return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to get block: "+err.Error(), nil)
		}

		txResults, err := svc.blockchain.BlockResultByHash(req.Hash)
		if err != nil {
			if errors.Is(err, nodetypes.ErrBlkNotFound) || errors.Is(err, nodetypes.ErrNotFound) {
				return nil, jsonrpc.NewError(jsonrpc.ErrorBlkNotFound, "block not found", nil)
			}
			svc.log.Error("block result by hash", "hash", req.Hash, "error", err)
			return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to get block result: "+err.Error(), nil)
		}

		return &chainjson.BlockResultResponse{
			Height:    blockHeader.Height,
			Hash:      req.Hash,
			TxResults: txResults,
		}, nil
	}

	blockHeader, err := svc.blockchain.GetBlockHeaderByHeight(req.Height)
	if err != nil {
		if errors.Is(err, nodetypes.ErrBlkNotFound) || errors.Is(err, nodetypes.ErrNotFound) {
			return nil, jsonrpc.NewError(jsonrpc.ErrorBlkNotFound, "block not found", nil)
		}
		svc.log.Error("block by height", "height", req.Height, "hash", req.Hash, "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to get block", nil)
	}

	blockHash := blockHeader.Hash()
	txResults, err := svc.blockchain.BlockResultByHash(blockHash)
	if err != nil {
		if errors.Is(err, nodetypes.ErrBlkNotFound) || errors.Is(err, nodetypes.ErrNotFound) {
			return nil, jsonrpc.NewError(jsonrpc.ErrorBlkNotFound, "block not found", nil)
		}
		svc.log.Error("block result by hash", "hash", req.Hash, "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to get block result: "+err.Error(), nil)
	}

	return &chainjson.BlockResultResponse{
		Height:    blockHeader.Height,
		Hash:      blockHash,
		TxResults: txResults,
	}, nil
}

// Tx returns a transaction by hash.
func (svc *Service) Tx(_ context.Context, req *chainjson.TxRequest) (*chainjson.TxResponse, *jsonrpc.Error) {
	if req.Hash.IsZero() {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "hash is required", nil)
	}

	tx, err := svc.blockchain.ChainTx(req.Hash)
	if err != nil {
		if errors.Is(err, nodetypes.ErrTxNotFound) || errors.Is(err, nodetypes.ErrNotFound) {
			return nil, jsonrpc.NewError(jsonrpc.ErrorTxNotFound, "transaction not found", nil)
		}
		svc.log.Error("tx by hash", "hash", req.Hash, "error", err)
		return nil, jsonrpc.NewError(jsonrpc.ErrorNodeInternal, "failed to get tx: "+err.Error(), nil)
	}

	return (*chainjson.TxResponse)(tx), nil
}

func (svc *Service) Genesis(ctx context.Context, _ *chainjson.GenesisRequest) (*chainjson.GenesisResponse, *jsonrpc.Error) {
	return svc.genesisCfg, nil
}

func (svc *Service) ConsensusParams(_ context.Context, _ *chainjson.ConsensusParamsRequest) (*chainjson.ConsensusParamsResponse, *jsonrpc.Error) {
	return svc.blockchain.ConsensusParams(), nil
}

// Validators returns validator set at the current height.
func (svc *Service) Validators(_ context.Context, _ *chainjson.ValidatorsRequest) (*chainjson.ValidatorsResponse, *jsonrpc.Error) {
	// NOTE: should be able to get validator set at req.Height
	vals := svc.voting.GetValidators()
	return &chainjson.ValidatorsResponse{
		Height:     svc.blockchain.BlockHeight(),
		Validators: vals,
	}, nil
}

// UnconfirmedTxs returns the unconfirmed txs. Default return 10 txs, max return 50 txs.
func (svc *Service) UnconfirmedTxs(_ context.Context, req *chainjson.UnconfirmedTxsRequest) (*chainjson.UnconfirmedTxsResponse, *jsonrpc.Error) {
	if req.Limit < 0 {
		return nil, jsonrpc.NewError(jsonrpc.ErrorInvalidParams, "invalid limit", nil)
	}
	if req.Limit > 50 {
		req.Limit = 50
	}
	if req.Limit == 0 {
		req.Limit = 10
	}
	total, txs := svc.blockchain.ChainUnconfirmedTx(req.Limit)
	return &chainjson.UnconfirmedTxsResponse{
		Total: total,
		Txs:   convertNamedTxs(txs),
	}, nil
}

// The chain Service must be usable as a Svc registered with a JSON-RPC Server.
var _ rpcserver.Svc = (*Service)(nil)

func convertNamedTxs(txs []*nodetypes.Tx) []chaintypes.NamedTx {
	res := make([]chaintypes.NamedTx, len(txs))
	for i, tx := range txs {
		res[i] = chaintypes.NamedTx{
			Hash: tx.Hash(),
			Tx:   tx.Transaction,
		}
	}
	return res
}
