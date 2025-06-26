package adminjson

import (
	jsonrpc "github.com/trufnetwork/kwil-db/core/rpc/json"
)

const (
	MethodHealth            jsonrpc.Method = "admin.health"
	MethodVersion           jsonrpc.Method = "admin.version"
	MethodStatus            jsonrpc.Method = "admin.status"
	MethodPeers             jsonrpc.Method = "admin.peers"
	MethodConfig            jsonrpc.Method = "admin.config"
	MethodValApprove        jsonrpc.Method = "admin.val_approve"
	MethodValJoin           jsonrpc.Method = "admin.val_join"
	MethodValRemove         jsonrpc.Method = "admin.val_remove"
	MethodValLeave          jsonrpc.Method = "admin.val_leave"
	MethodValJoinStatus     jsonrpc.Method = "admin.val_join_status"
	MethodValList           jsonrpc.Method = "admin.val_list"
	MethodValListJoins      jsonrpc.Method = "admin.val_list_joins"
	MethodValPromote        jsonrpc.Method = "admin.val_promote"
	MethodAddPeer           jsonrpc.Method = "admin.add_peer"
	MethodRemovePeer        jsonrpc.Method = "admin.remove_peer"
	MethodListPeers         jsonrpc.Method = "admin.list_peers"
	MethodCreateResolution  jsonrpc.Method = "admin.create_resolution"
	MethodApproveResolution jsonrpc.Method = "admin.approve_resolution"
	MethodResolutionStatus  jsonrpc.Method = "admin.resolution_status"
	// MethodDeleteResolution  jsonrpc.Method = "admin.delete_resolution"
	MethodBlockExecStatus     jsonrpc.Method = "admin.block_exec_status"
	MethodAbortBlockExecution jsonrpc.Method = "admin.abort_block_execution"
)
