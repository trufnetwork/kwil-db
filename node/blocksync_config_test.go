package node

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/config"
)

// TestDefaultBlockSyncMatchesFallbacks pins the equivalence that makes reading
// block_sync from kwild.toml safe: every shipped default is the same duration
// as the hardcoded value the node uses when no config is supplied. A node that
// never touched its config file therefore syncs exactly as it did before.
//
// If this test fails, one of the two was changed without the other, and nodes
// on a stock kwild.toml no longer behave like nodes with no config at all.
func TestDefaultBlockSyncMatchesFallbacks(t *testing.T) {
	cfg := config.DefaultConfig().BlockSync

	for _, tc := range []struct {
		key      string
		shipped  time.Duration
		fallback time.Duration
	}{
		{"block_get_timeout", time.Duration(cfg.BlockGetTimeout), defaultBlkGetTimeout},
		{"block_send_timeout", time.Duration(cfg.BlockSendTimeout), defaultBlkSendTimeout},
		{"request_timeout", time.Duration(cfg.RequestTimeout), defaultBlkReqTimeout},
		{"response_timeout", time.Duration(cfg.ResponseTimeout), defaultBlkRespTimeout},
		{"idle_timeout", time.Duration(cfg.IdleTimeout), defaultBlkIdleTimeout},
		{"announce_write_timeout", time.Duration(cfg.AnnounceWriteTimeout), defaultAnnWriteTimeout},
		{"announce_resp_timeout", time.Duration(cfg.AnnounceRespTimeout), defaultAnnRespTimeout},
		{"tx_get_timeout", time.Duration(cfg.TxGetTimeout), defaultTxGetTimeout},
		{"tx_ann_timeout", time.Duration(cfg.TxAnnTimeout), defaultTxAnnTimeout},
		{"tx_ann_timeout (response leg)", time.Duration(cfg.TxAnnTimeout), defaultTxAnnRespTimeout},
	} {
		require.Equalf(t, tc.fallback, tc.shipped,
			"block_sync.%s default (%s) differs from the fallback the node uses without it (%s)",
			tc.key, tc.shipped, tc.fallback)
	}
}
