package consensus

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/store/memstore"
	"github.com/trufnetwork/kwil-db/node/types"
)

func TestRepairAppAheadOfStoreRequiresCommitIntent(t *testing.T) {
	ctx := context.Background()
	bs := memstore.NewMemBS()

	var appHash ktypes.Hash
	copy(appHash[:], bytes.Repeat([]byte{0xAB}, len(appHash)))

	blk := ktypes.NewBlock(1, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, time.Now(), nil)
	blkHash := blk.Hash()
	fetched := false

	ce := &ConsensusEngine{
		log:        log.DiscardLogger,
		blockStore: bs,
		blkRequester: func(context.Context, int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
			fetched = true
			return blkHash, ktypes.EncodeBlock(blk), &ktypes.CommitInfo{AppHash: appHash}, 1, nil
		},
	}

	err := ce.repairAppAheadOfStore(ctx, 1, appHash[:], nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "without a local commit intent")
	require.False(t, fetched, "must not fetch a block using a dump-cached app-hash")

	height, _, _, _ := bs.Best()
	require.Equal(t, int64(0), height)
}

func TestRepairAppAheadOfStoreUsesCommitIntent(t *testing.T) {
	ctx := context.Background()
	bs := memstore.NewMemBS()

	var appHash ktypes.Hash
	copy(appHash[:], bytes.Repeat([]byte{0xAB}, len(appHash)))

	blk := ktypes.NewBlock(1, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, time.Now(), nil)
	blkHash := blk.Hash()

	ce := &ConsensusEngine{
		log:        log.DiscardLogger,
		blockStore: bs,
		blkRequester: func(context.Context, int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
			return blkHash, ktypes.EncodeBlock(blk), &ktypes.CommitInfo{AppHash: appHash}, 1, nil
		},
	}

	err := ce.repairAppAheadOfStore(ctx, 1, appHash[:], &commitIntent{
		Height:    1,
		BlockHash: blkHash.String(),
	})
	require.NoError(t, err)

	height, _, storedAppHash, _ := bs.Best()
	require.Equal(t, int64(1), height)
	require.Equal(t, appHash, storedAppHash)
}

func TestRepairAppAheadOfStoreRejectsDecodedMismatch(t *testing.T) {
	ctx := context.Background()
	var appHash ktypes.Hash
	copy(appHash[:], bytes.Repeat([]byte{0xAB}, len(appHash)))

	t.Run("hash", func(t *testing.T) {
		bs := memstore.NewMemBS()
		want := ktypes.NewBlock(1, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, time.Now(), nil)
		other := ktypes.NewBlock(1, ktypes.Hash{1}, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, time.Now(), nil)
		wantHash := want.Hash()

		ce := &ConsensusEngine{
			log:        log.DiscardLogger,
			blockStore: bs,
			blkRequester: func(context.Context, int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
				return wantHash, ktypes.EncodeBlock(other), &ktypes.CommitInfo{AppHash: appHash}, 1, nil
			},
		}

		err := ce.repairAppAheadOfStore(ctx, 1, appHash[:], &commitIntent{
			Height:    1,
			BlockHash: wantHash.String(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "decoded block hash")
		height, _, _, _ := bs.Best()
		require.Equal(t, int64(0), height)
	})

	t.Run("height", func(t *testing.T) {
		bs := memstore.NewMemBS()
		blk := ktypes.NewBlock(2, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, ktypes.Hash{}, time.Now(), nil)
		blkHash := blk.Hash()

		ce := &ConsensusEngine{
			log:        log.DiscardLogger,
			blockStore: bs,
			blkRequester: func(context.Context, int64) (types.Hash, []byte, *ktypes.CommitInfo, int64, error) {
				return blkHash, ktypes.EncodeBlock(blk), &ktypes.CommitInfo{AppHash: appHash}, 1, nil
			},
		}

		err := ce.repairAppAheadOfStore(ctx, 1, appHash[:], &commitIntent{
			Height:    1,
			BlockHash: blkHash.String(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "decoded block height")
		height, _, _, _ := bs.Best()
		require.Equal(t, int64(0), height)
	})
}
