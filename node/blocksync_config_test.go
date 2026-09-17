package node

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/config"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
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

// TestBlockSyncTimeoutRejectsZero covers what wiring the config newly exposes:
// a value an operator actually wrote. Zero reads as "no limit" in plenty of
// software, and here it would mean every deadline is already in the past, so
// the node abandons each peer before it can answer.
func TestBlockSyncTimeoutRejectsZero(t *testing.T) {
	const fallback = 7 * time.Second

	for _, tc := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{"a configured value is used", 250 * time.Millisecond, 250 * time.Millisecond},
		{"an unset value falls back", 0, fallback},
		{"a negative value falls back", -time.Second, fallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := blockSyncTimeout(ktypes.Duration(tc.configured), fallback)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestZeroBlockSyncConfigUsesFallbacks is the whole-struct version: a
// BlockSyncConfig that was never populated must leave the node behaving as if
// no config had been supplied at all, not as if every timeout were zero.
func TestZeroBlockSyncConfigUsesFallbacks(t *testing.T) {
	var zero config.BlockSyncConfig

	require.Equal(t, defaultBlkGetTimeout, blockSyncTimeout(zero.BlockGetTimeout, defaultBlkGetTimeout))
	require.Equal(t, defaultBlkSendTimeout, blockSyncTimeout(zero.BlockSendTimeout, defaultBlkSendTimeout))
	require.Equal(t, defaultBlkReqTimeout, blockSyncTimeout(zero.RequestTimeout, defaultBlkReqTimeout))
	require.Equal(t, defaultBlkRespTimeout, blockSyncTimeout(zero.ResponseTimeout, defaultBlkRespTimeout))
	require.Equal(t, defaultBlkIdleTimeout, blockSyncTimeout(zero.IdleTimeout, defaultBlkIdleTimeout))
	require.Equal(t, defaultAnnWriteTimeout, blockSyncTimeout(zero.AnnounceWriteTimeout, defaultAnnWriteTimeout))
	require.Equal(t, defaultAnnRespTimeout, blockSyncTimeout(zero.AnnounceRespTimeout, defaultAnnRespTimeout))
	require.Equal(t, defaultTxGetTimeout, blockSyncTimeout(zero.TxGetTimeout, defaultTxGetTimeout))
	require.Equal(t, defaultTxAnnTimeout, blockSyncTimeout(zero.TxAnnTimeout, defaultTxAnnTimeout))
}
