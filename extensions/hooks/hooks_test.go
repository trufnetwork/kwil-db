package hooks

import (
	"testing"

	rpcserver "github.com/trufnetwork/kwil-db/node/services/jsonrpc"

	"github.com/stretchr/testify/require"
)

func TestRegisterAdminServerHook(t *testing.T) {
	// snapshot and restore the global map to isolate this test
	snapshot := make(map[string]AdminServerHook, len(adminServerHooks))
	for k, v := range adminServerHooks {
		snapshot[k] = v
	}
	t.Cleanup(func() {
		adminServerHooks = snapshot
	})
	adminServerHooks = make(map[string]AdminServerHook)

	called := false
	hook := AdminServerHook(func(server *rpcserver.Server) error {
		called = true
		return nil
	})

	err := RegisterAdminServerHook("test_register", hook)
	require.NoError(t, err)

	// duplicate name should error
	err = RegisterAdminServerHook("test_register", hook)
	require.Error(t, err)
	require.Contains(t, err.Error(), "test_register")

	// verify hook is listed and callable
	hooks := ListAdminServerHooks()
	require.Len(t, hooks, 1)
	err = hooks[0](nil)
	require.NoError(t, err)
	require.True(t, called, "hook should have been called")
}
