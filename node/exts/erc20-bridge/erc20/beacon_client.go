package erc20

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// BeaconChainClient queries Ethereum beacon chain for finality status
type BeaconChainClient struct {
	beaconRPC    string
	genesisTime  int64 // Beacon chain genesis timestamp in Unix seconds (network-specific)
	slotDuration int64 // Beacon chain slot duration in seconds (typically 12)
	httpClient   *http.Client
}

// BeaconBlockResponse matches the beacon chain API response structure
// from GET /eth/v2/beacon/blocks/{block_id}
// Only the Finalized field is used; other fields are omitted for simplicity
type BeaconBlockResponse struct {
	Finalized bool `json:"finalized"`
}

// NewBeaconChainClient creates a new beacon chain client
// genesisTime: beacon chain genesis timestamp in Unix seconds (network-specific)
// slotDuration: beacon chain slot duration in seconds (typically 12 for Ethereum networks)
func NewBeaconChainClient(beaconRPC string, genesisTime, slotDuration int64) *BeaconChainClient {
	return &BeaconChainClient{
		beaconRPC:    beaconRPC,
		genesisTime:  genesisTime,
		slotDuration: slotDuration,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IsBlockFinalized checks if an Ethereum block (by timestamp) is finalized on beacon chain
// Returns:
//   - true if finalized
//   - false if not finalized or error occurred
//   - error for critical failures (nil for normal "not finalized yet" case)
func (b *BeaconChainClient) IsBlockFinalized(ctx context.Context, ethBlockTimestamp int64) (bool, error) {
	// Validate slot duration to prevent division by zero
	if b.slotDuration == 0 {
		return false, fmt.Errorf("invalid beacon client configuration: slotDuration is zero (genesisTime=%d, ethBlockTimestamp=%d)", b.genesisTime, ethBlockTimestamp)
	}

	// Calculate beacon chain slot from Ethereum block timestamp using network-specific genesis time
	slot := (ethBlockTimestamp - b.genesisTime) / b.slotDuration

	if slot < 0 {
		return false, fmt.Errorf("invalid slot: block timestamp %d before genesis %d", ethBlockTimestamp, b.genesisTime)
	}

	// Query beacon chain API
	url := fmt.Sprintf("%s/eth/v2/beacon/blocks/%d", b.beaconRPC, slot)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		// Network error - gracefully degrade, don't fail consensus
		return false, nil // Return false but no error (retry next block)
	}
	defer resp.Body.Close()

	// Handle 404 Not Found - this happens for empty slots (no block proposed)
	// In this case, we need to check if the epoch containing this slot is finalized
	// rather than checking the specific block
	if resp.StatusCode == http.StatusNotFound {
		// Empty slot - query finality checkpoint to see if epoch is finalized
		return b.isEpochFinalized(ctx, slot)
	}

	if resp.StatusCode != http.StatusOK {
		// API error - gracefully degrade, don't fail consensus
		return false, nil // Return false but no error (retry next block)
	}

	var beaconResp BeaconBlockResponse
	if err := json.NewDecoder(resp.Body).Decode(&beaconResp); err != nil {
		// Decode error - gracefully degrade, don't fail consensus
		// Malformed JSON could indicate API changes or temporary issues
		return false, nil // Return false but no error (retry next block)
	}

	return beaconResp.Finalized, nil
}

// FinalityCheckpointsResponse matches the beacon chain API response for finality checkpoints
type FinalityCheckpointsResponse struct {
	Data struct {
		Finalized struct {
			Epoch string `json:"epoch"`
		} `json:"finalized"`
	} `json:"data"`
}

// isEpochFinalized checks if a beacon epoch is finalized by querying the finality checkpoint
// This is used when a specific slot has no block (empty slot)
func (b *BeaconChainClient) isEpochFinalized(ctx context.Context, slot int64) (bool, error) {
	// Calculate beacon epoch from slot (32 slots per epoch)
	epoch := slot / 32

	// Query finality checkpoint
	url := fmt.Sprintf("%s/eth/v1/beacon/states/head/finality_checkpoints", b.beaconRPC)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil // Gracefully degrade on error
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return false, nil // Network error - retry later
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil // API error - retry later
	}

	var checkpointResp FinalityCheckpointsResponse
	if err := json.NewDecoder(resp.Body).Decode(&checkpointResp); err != nil {
		return false, nil // Decode error - retry later
	}

	// Parse finalized epoch number
	var finalizedEpoch int64
	if _, err := fmt.Sscanf(checkpointResp.Data.Finalized.Epoch, "%d", &finalizedEpoch); err != nil {
		return false, nil // Parse error - retry later
	}

	// Slot is finalized if its epoch <= finalized epoch
	return epoch <= finalizedEpoch, nil
}
