package blockprocessor

import (
	"maps"
	"slices"
	"time"

	ktypes "github.com/trufnetwork/kwil-db/core/types"
)

type blockExecStatus struct {
	startTime, endTime time.Time
	height             int64
	txIDs              []ktypes.Hash
	txStatus           map[ktypes.Hash]bool
}

// Used by the rpc server to get the execution status of the block being processed.
// end_time is not set if the block is still being processed.
func (bp *BlockProcessor) BlockExecutionStatus() *ktypes.BlockExecutionStatus {
	bp.statusMu.RLock()
	defer bp.statusMu.RUnlock()

	if bp.status == nil {
		return nil
	}

	status := &ktypes.BlockExecutionStatus{
		StartTime: bp.status.startTime,
		EndTime:   bp.status.endTime,
		Height:    bp.status.height,
		TxIDs:     slices.Clone(bp.status.txIDs),
		TxStatus:  make(map[ktypes.Hash]bool, len(bp.status.txStatus)),
	}

	maps.Copy(status.TxStatus, bp.status.txStatus)

	return status
}

func (bp *BlockProcessor) initBlockExecutionStatus(blk *ktypes.Block) []ktypes.Hash {
	txIDs := make([]ktypes.Hash, len(blk.Txns))
	for i, tx := range blk.Txns {
		txID := tx.HashCache()
		txIDs[i] = txID
	}
	bp.statusMu.Lock()
	defer bp.statusMu.Unlock()

	status := &blockExecStatus{
		startTime: time.Now(),
		height:    blk.Header.Height,
		txStatus:  make(map[ktypes.Hash]bool, len(txIDs)),
		txIDs:     txIDs,
	}

	for _, txID := range txIDs {
		status.txStatus[txID] = false // not needed, just for clarity
	}

	bp.status = status

	return txIDs
}

func (bp *BlockProcessor) clearBlockExecutionStatus() {
	bp.statusMu.Lock()
	defer bp.statusMu.Unlock()

	bp.status = nil
}

func (bp *BlockProcessor) updateBlockExecutionStatus(txID ktypes.Hash) {
	bp.statusMu.Lock()
	defer bp.statusMu.Unlock()

	if bp.status == nil {
		return
	}

	bp.status.txStatus[txID] = true
}

func (bp *BlockProcessor) recordBlockExecEndTime() {
	bp.statusMu.Lock()
	defer bp.statusMu.Unlock()

	if bp.status == nil {
		return
	}

	bp.status.endTime = time.Now()
}
