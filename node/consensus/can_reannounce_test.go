package consensus

import (
	"testing"
)

// TestCanReannounce verifies that CanReannounce correctly returns false during
// block execution and true when committed, preventing the race condition where
// re-announced transactions fail validation with stale nonce state.
func TestCanReannounce(t *testing.T) {
	tests := []struct {
		name           string
		status         Status
		expectedResult bool
	}{
		{
			name:           "can reannounce when committed",
			status:         Committed,
			expectedResult: true,
		},
		{
			name:           "cannot reannounce when block proposed",
			status:         Proposed,
			expectedResult: false,
		},
		{
			name:           "cannot reannounce when block executing",
			status:         Executed,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ce := &ConsensusEngine{}
			ce.stateInfo.mtx.Lock()
			ce.stateInfo.status = tt.status
			ce.stateInfo.mtx.Unlock()

			result := ce.CanReannounce()

			if result != tt.expectedResult {
				t.Errorf("CanReannounce() = %v, want %v (status=%v)",
					result, tt.expectedResult, tt.status)
			}
		})
	}
}

// TestCanReannounceThreadSafety verifies that CanReannounce can be called
// concurrently without data races.
func TestCanReannounceThreadSafety(t *testing.T) {
	ce := &ConsensusEngine{}
	ce.stateInfo.mtx.Lock()
	ce.stateInfo.status = Committed
	ce.stateInfo.mtx.Unlock()

	// Run 100 concurrent CanReannounce calls
	done := make(chan bool, 100)
	for range 100 {
		go func() {
			_ = ce.CanReannounce()
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for range 100 {
		<-done
	}
}

// TestCanReannounceStateTransitions verifies that CanReannounce returns
// the correct value as the consensus engine transitions through states.
func TestCanReannounceStateTransitions(t *testing.T) {
	ce := &ConsensusEngine{}

	// Initial state should be Committed (default zero value is empty string)
	// Set it explicitly for clarity
	ce.stateInfo.status = Committed
	if !ce.CanReannounce() {
		t.Error("Expected CanReannounce=true in Committed state")
	}

	// Transition to Proposed (block received)
	ce.stateInfo.mtx.Lock()
	ce.stateInfo.status = Proposed
	ce.stateInfo.mtx.Unlock()

	if ce.CanReannounce() {
		t.Error("Expected CanReannounce=false in Proposed state")
	}

	// Transition to Executed (block execution complete)
	ce.stateInfo.mtx.Lock()
	ce.stateInfo.status = Executed
	ce.stateInfo.mtx.Unlock()

	if ce.CanReannounce() {
		t.Error("Expected CanReannounce=false in Executed state")
	}

	// Transition back to Committed (block committed)
	ce.stateInfo.mtx.Lock()
	ce.stateInfo.status = Committed
	ce.stateInfo.mtx.Unlock()

	if !ce.CanReannounce() {
		t.Error("Expected CanReannounce=true in Committed state after cycle")
	}
}
