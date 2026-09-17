package node

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
)

// TestNodeConfigCarriesOperatorBlockSync proves that a block_sync value an
// operator edited in kwild.toml reaches the node, rather than being replaced by
// the hardcoded fallback timeouts in the node package.
func TestNodeConfigCarriesOperatorBlockSync(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.BlockSync.IdleTimeout = types.Duration(3 * time.Second)
	cfg.BlockSync.ResponseTimeout = types.Duration(90 * time.Second)

	d := &coreDependencies{
		rootDir:    t.TempDir(),
		cfg:        cfg,
		genesisCfg: &config.GenesisConfig{ChainID: "test-chain"},
	}

	nc := nodeConfig(d, nil, nil, nil, nil, nil, nil, nil, log.DiscardLogger)

	require.Same(t, &cfg.BlockSync, nc.BlockSync,
		"node.Config.BlockSync must point at the loaded config, not a copy")
	require.Equal(t, 3*time.Second, time.Duration(nc.BlockSync.IdleTimeout))
	require.Equal(t, 90*time.Second, time.Duration(nc.BlockSync.ResponseTimeout))
}

// TestNodeConfigWiresEverySection guards the whole class of bug: a config
// section that node.Config knows about but nodeConfig never fills in. The node
// treats a nil section as "use the hardcoded defaults", so the omission is
// silent and the operator's settings are simply dropped.
func TestNodeConfigWiresEverySection(t *testing.T) {
	cfg := config.DefaultConfig()
	d := &coreDependencies{
		rootDir:    t.TempDir(),
		cfg:        cfg,
		genesisCfg: &config.GenesisConfig{ChainID: "test-chain"},
	}

	nc := nodeConfig(d, nil, nil, nil, nil, nil, nil, nil, log.DiscardLogger)

	v := reflect.ValueOf(nc).Elem()
	rt := v.Type()

	var checked int
	for i := range rt.NumField() {
		ft := rt.Field(i).Type
		if ft.Kind() != reflect.Pointer || ft.Elem().Kind() != reflect.Struct {
			continue
		}
		if ft.Elem().PkgPath() != reflect.TypeOf(config.Config{}).PkgPath() {
			continue
		}
		checked++
		require.Falsef(t, v.Field(i).IsNil(),
			"node.Config.%s is nil, so the %s settings in kwild.toml are ignored",
			rt.Field(i).Name, ft.Elem().Name())
	}

	require.NotZero(t, checked, "found no config sections on node.Config to check")
}
