package erc20

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// ethereumGenesisTime is the Ethereum 2.0 genesis timestamp (December 1, 2020, 12:00:23 UTC)
	ethereumGenesisTime = 1606824023

	// slotDuration is the Ethereum beacon chain slot duration (12 seconds)
	slotDuration = 12
)

// BeaconChainClient queries Ethereum beacon chain for finality status
type BeaconChainClient struct {
	beaconRPC  string
	httpClient *http.Client
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
func NewBeaconChainClient(beaconRPC string) *BeaconChainClient {
	return &BeaconChainClient{
		beaconRPC: beaconRPC,
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
	// Calculate beacon chain slot from Ethereum block timestamp
	slot := (ethBlockTimestamp - ethereumGenesisTime) / slotDuration

	if slot < 0 {
		return false, fmt.Errorf("invalid slot: block timestamp %d before genesis", ethBlockTimestamp)
	}

	// Query beacon chain API
	url := fmt.Sprintf("%s/eth/v2/beacon/blocks/%d", b.beaconRPC, slot)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		// Network error - log but don't fail consensus
		return false, nil // Return false but no error (retry next block)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// API error - log but don't fail consensus
		return false, nil // Return false but no error (retry next block)
	}

	var beaconResp BeaconBlockResponse
	if err := json.NewDecoder(resp.Body).Decode(&beaconResp); err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}

	return beaconResp.Finalized, nil
}
