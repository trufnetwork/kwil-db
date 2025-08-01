package userjson

import jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"

const (
	MethodHealth                jsonrpc.Method = "user.health"
	MethodUserVersion           jsonrpc.Method = "user.version"
	MethodPing                  jsonrpc.Method = "user.ping"
	MethodChainInfo             jsonrpc.Method = "user.chain_info"
	MethodAccount               jsonrpc.Method = "user.account"
	MethodNumAccounts           jsonrpc.Method = "user.num_accounts"
	MethodBroadcast             jsonrpc.Method = "user.broadcast"
	MethodCall                  jsonrpc.Method = "user.call"
	MethodDatabases             jsonrpc.Method = "user.databases"
	MethodPrice                 jsonrpc.Method = "user.estimate_price"
	MethodQuery                 jsonrpc.Method = "user.query"
	MethodAuthenticatedQuery    jsonrpc.Method = "user.authenticated_query"
	MethodTxQuery               jsonrpc.Method = "user.tx_query"
	MethodSchema                jsonrpc.Method = "user.schema"
	MethodUpdateProposalStatus  jsonrpc.Method = "user.update_proposal_status"
	MethodListUpdateProposals   jsonrpc.Method = "user.list_update_proposals"
	MethodMigrationStatus       jsonrpc.Method = "user.migration_status"
	MethodListMigrations        jsonrpc.Method = "user.list_migrations"
	MethodLoadChangeset         jsonrpc.Method = "user.changeset"
	MethodLoadChangesetMetadata jsonrpc.Method = "user.changeset_metadata"
	MethodMigrationMetadata     jsonrpc.Method = "user.migration_metadata"
	MethodMigrationGenesisChunk jsonrpc.Method = "user.migration_genesis_chunk"
	MethodChallenge             jsonrpc.Method = "user.challenge"
)
