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
type BeaconBlockResponse struct {
	Finalized bool `json:"finalized"`
	Data      struct {
		Message struct {
			Slot string `json:"slot"`
			Body struct {
				ExecutionPayload struct {
					BlockNumber string `json:"block_number"`
					BlockHash   string `json:"block_hash"`
					Timestamp   string `json:"timestamp"`
				} `json:"execution_payload"`
			} `json:"body"`
		} `json:"message"`
	} `json:"data"`
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
