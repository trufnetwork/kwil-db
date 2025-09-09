//go:build kwiltest

package erc20

import (
	"context"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
)

// ForTestingGetInstanceID returns the deterministic reward instance ID for a chain and escrow.
func ForTestingGetInstanceID(chain, escrow string) *types.UUID {
	id := uuidForChainAndEscrow(chain, escrow)
	return &id
}

// ForTestingSetDistributionPeriod sets the distribution period (in seconds) for an instance.
func ForTestingSetDistributionPeriod(ctx context.Context, app *common.App, chain, escrow string, seconds int64) error {
	id := ForTestingGetInstanceID(chain, escrow)
	return reuseRewardInstance(ctx, app, id, seconds)
}

// ForTestingFinalizeCurrentEpoch finalizes the current epoch, computing merkle root from DB rewards,
// and creates the next pending epoch.
func ForTestingFinalizeCurrentEpoch(ctx context.Context, app *common.App, chain, escrow string, endHeight int64, endHash [32]byte) error {
	id := ForTestingGetInstanceID(chain, escrow)

	// load instance info (includes current epoch and escrow address)
	infos, err := getStoredRewardInstances(ctx, app)
	if err != nil {
		return err
	}

	var info *rewardExtensionInfo
	for _, r := range infos {
		if r.ID.String() == id.String() {
			info = r
			break
		}
	}
	if info == nil || info.currentEpoch == nil {
		return fmt.Errorf("instance or current epoch not found")
	}

	// build merkle for current epoch
	leafs, jsonBody, root, totalBI, err := genMerkleTreeForEpoch(ctx, app, info.currentEpoch.ID, info.EscrowAddress.Hex(), endHash)
	if err != nil {
		return err
	}
	if leafs == 0 {
		// nothing to finalize
		return nil
	}

	// finalize
	totalDec, err := erc20ValueFromBigInt(totalBI)
	if err != nil {
		return err
	}
	if err := finalizeEpoch(ctx, app, info.currentEpoch.ID, endHeight, endHash[:], root, totalDec); err != nil {
		return err
	}
	// cache jsonBody for potential follow-up, not strictly necessary here
	_ = jsonBody

	// create next pending epoch
	next := newPendingEpoch(id, &common.BlockContext{Height: endHeight + 1, Timestamp: info.currentEpoch.StartTime + 1})
	return createEpoch(ctx, app, next, id)
}

// ForTestingConfirmAllFinalizedEpochs confirms all finalized (ended_at != null) epochs for an instance.
func ForTestingConfirmAllFinalizedEpochs(ctx context.Context, app *common.App, chain, escrow string) error {
	id := ForTestingGetInstanceID(chain, escrow)

	// fetch all epochs (after=0, large limit)
	return getEpochs(ctx, app, id, 0, 1_000_000, func(e *Epoch) error {
		if e.EndHeight != nil && !e.Confirmed && e.Root != nil {
			return confirmEpoch(ctx, app, e.Root)
		}
		return nil
	})
}

// ForTestingLockAndIssueDirect locks from a user and issues into the current epoch, atomically.
// It bypasses SYSTEM calls and directly updates DB state like the production atomic path.
func ForTestingLockAndIssueDirect(ctx context.Context, app *common.App, chain, escrow, from string, amountText string) error {
	id := ForTestingGetInstanceID(chain, escrow)

	// get current epoch
	infos, err := getStoredRewardInstances(ctx, app)
	if err != nil {
		return err
	}
	var epochID *types.UUID
	for _, r := range infos {
		if r.ID.String() == id.String() {
			if r.currentEpoch == nil {
				return fmt.Errorf("current epoch not found")
			}
			epochID = r.currentEpoch.ID
			break
		}
	}
	if epochID == nil {
		return fmt.Errorf("instance not found")
	}

	// parse amount
	dec, err := types.ParseDecimal(amountText)
	if err != nil {
		return err
	}
	if err := dec.SetPrecisionAndScale(78, 0); err != nil {
		return err
	}

	addr := ethcommon.HexToAddress(from)
	return lockAndIssue(ctx, app, id, epochID, addr, dec)
}
