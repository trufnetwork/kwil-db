//go:build kwiltest

package erc20

import (
	"context"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	kwilTesting "github.com/trufnetwork/kwil-db/testing"
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
	var roots [][]byte
	// First pass: collect reward roots within the test transaction
	err := app.Engine.ExecuteWithoutEngineCtx(ctx, app.DB, `
	{kwil_erc20_meta}SELECT reward_root FROM epochs WHERE instance_id=$id AND ended_at IS NOT NULL AND confirmed IS NOT TRUE`,
		map[string]any{"id": id}, func(r *common.Row) error {
			if len(r.Values) != 1 {
				return nil
			}
			if r.Values[0] != nil {
				roots = append(roots, r.Values[0].([]byte))
			}
			return nil
		})
	if err != nil {
		return err
	}
	// Second pass: confirm each root outside of the row-callback to avoid nested engine calls during iteration
	for _, root := range roots {
		if len(root) == 0 {
			continue
		}
		if err := confirmEpoch(ctx, app, root); err != nil {
			return err
		}
	}
	return nil
}

// ForTestingFinalizeAndConfirmCurrentEpoch finalizes the current epoch (if it has rewards)
// and then confirms all finalized epochs. This is a convenience wrapper for tests.
func ForTestingFinalizeAndConfirmCurrentEpoch(ctx context.Context, platform *kwilTesting.Platform, chain, escrow string, endHeight int64, endHash [32]byte) error {
	// Pre-check: ensure the current epoch has rewards; if not, provide actionable error
	app := &common.App{DB: platform.DB, Engine: platform.Engine}
	id := ForTestingGetInstanceID(chain, escrow)
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
	leafs, _, _, _, err := genMerkleTreeForEpoch(ctx, app, info.currentEpoch.ID, info.EscrowAddress.Hex(), endHash)
	if err != nil {
		return err
	}
	if leafs == 0 {
		return fmt.Errorf("no rewards in current epoch; cannot finalize")
	}

	if err := ForTestingFinalizeCurrentEpoch(ctx, app, chain, escrow, endHeight, endHash); err != nil {
		return err
	}
	if err := ForTestingConfirmAllFinalizedEpochs(ctx, app, chain, escrow); err != nil {
		return err
	}

	// Post-check: ensure at least one epoch is confirmed for this instance
	confirmed := 0
	err = platform.Engine.ExecuteWithoutEngineCtx(ctx, platform.DB, `
	{kwil_erc20_meta}SELECT count(*) FROM epochs WHERE instance_id=$id AND confirmed IS TRUE`, map[string]any{"id": id}, func(r *common.Row) error {
		if len(r.Values) != 1 {
			return nil
		}
		confirmed = int(r.Values[0].(int64))
		return nil
	})
	if err != nil {
		return err
	}
	if confirmed == 0 {
		return fmt.Errorf("finalize pipeline failed: no confirmed epochs for instance %s", id.String())
	}
	return nil
}

// ForTestingLockAndIssueDirect locks from a user and issues into the current epoch, atomically.
// It bypasses SYSTEM calls and directly updates DB state like the production atomic path.
func ForTestingLockAndIssueDirect(ctx context.Context, platform *kwilTesting.Platform, chain, escrow, from string, amountText string) error {
	id := ForTestingGetInstanceID(chain, escrow)

	app := &common.App{DB: platform.DB, Engine: platform.Engine}
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

	// check address is valid
	if !ethcommon.IsHexAddress(from) {
		return fmt.Errorf("invalid address: %s", from)
	}
	addr := ethcommon.HexToAddress(from)
	return lockAndIssue(ctx, app, id, epochID, addr, addr, dec)
}
