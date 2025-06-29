package chain

import (
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
)

const (
	MethodVersion         jsonrpc.Method = "chain.version"
	MethodHealth          jsonrpc.Method = "chain.health"
	MethodBlock           jsonrpc.Method = "chain.block"
	MethodBlockHeader     jsonrpc.Method = "chain.block_header"
	MethodBlockResult     jsonrpc.Method = "chain.block_result"
	MethodTx              jsonrpc.Method = "chain.tx"
	MethodGenesis         jsonrpc.Method = "chain.genesis"
	MethodConsensusParams jsonrpc.Method = "chain.consensus_params"
	MethodValidators      jsonrpc.Method = "chain.validators"
	MethodUnconfirmedTxs  jsonrpc.Method = "chain.unconfirmed_txs"
)
