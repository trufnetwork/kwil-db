// package chains tracks the EVM chains that are supported by the node.
package chains

import (
	"fmt"
)

// ChainInfo is the information about a chain.
type ChainInfo struct {
	// Name is the name of the chain.
	// It is case-insensitive and unique.
	Name Chain
	// ID is the unique identifier of the chain.
	// e.g. Ethereum mainnet is 1.
	ID string
	// RequiredConfirmations is the number of confirmations required before an event is considered final.
	// For example, Ethereum mainnet requires 12 confirmations.
	RequiredConfirmations int64
	// BeaconRPC is the beacon chain API base URL for checking finality.
	// Empty string if the chain doesn't have a beacon chain (e.g., L2s).
	// For Ethereum mainnet and testnets that use beacon chain consensus.
	BeaconRPC string
	// BeaconGenesisTime is the beacon chain genesis timestamp in Unix seconds.
	// Only used if BeaconRPC is set. Each network has its own genesis time.
	BeaconGenesisTime int64
	// BeaconSlotDuration is the beacon chain slot duration in seconds.
	// Defaults to 12 seconds for Ethereum networks. Only used if BeaconRPC is set.
	BeaconSlotDuration int64
}

func init() {
	err := registerChain(
		ChainInfo{
			Name:                  "ethereum",
			ID:                    "1",
			RequiredConfirmations: 12,
			BeaconRPC:             "https://ethereum-beacon-api.publicnode.com",
			BeaconGenesisTime:     1606824023, // Dec 1, 2020, 12:00:23 UTC
			BeaconSlotDuration:    12,
		},
		ChainInfo{
			Name:                  "sepolia",
			ID:                    "11155111",
			RequiredConfirmations: 12,
			BeaconRPC:             "https://ethereum-sepolia-beacon-api.publicnode.com",
			BeaconGenesisTime:     1655733600, // Jun 20, 2022, 14:00:00 UTC
			BeaconSlotDuration:    12,
		},
		ChainInfo{
			Name:                  "base-sepolia",
			ID:                    "84532",
			RequiredConfirmations: 12,
			BeaconRPC:             "", // L2, no beacon chain
			BeaconGenesisTime:     0,
			BeaconSlotDuration:    0,
		},
		ChainInfo{
			Name:                  "hoodi",
			ID:                    "560048",
			RequiredConfirmations: 12,
			BeaconRPC:             "https://ethereum-hoodi-beacon-api.publicnode.com",
			BeaconGenesisTime:     1742213400, // Mar 17, 2025, 12:10:00 UTC (Hoodi testnet genesis)
			BeaconSlotDuration:    12,
		},
	)
	if err != nil {
		panic(err)
	}
}

type Chain string

const (
	Ethereum    Chain = "ethereum"
	Sepolia     Chain = "sepolia"
	BaseSepolia Chain = "base-sepolia"
	Hoodi       Chain = "hoodi"
)

func (c Chain) String() string {
	return string(c)
}

func (c Chain) Valid() error {
	switch c {
	case Ethereum, Sepolia, BaseSepolia, Hoodi:
		return nil
	default:
		return fmt.Errorf("invalid chain: %s", c)
	}
}

var registeredChains = map[Chain]ChainInfo{}
var chainIDs = map[string]Chain{}

func registerChain(chains ...ChainInfo) error {
	for _, chain := range chains {
		if err := chain.Name.Valid(); err != nil {
			return err
		}

		_, ok := registeredChains[chain.Name]
		if ok {
			return fmt.Errorf("chain already registered: %s", chain.Name)
		}

		if chain.RequiredConfirmations < 1 {
			return fmt.Errorf("required confirmations must be >= 1: %s", chain.Name)
		}

		registeredChains[chain.Name] = chain
		chainIDs[chain.ID] = chain.Name
	}

	return nil
}

// GetChainInfo returns the chain information for the given chain.
func GetChainInfo(name Chain) (ChainInfo, bool) {
	chain, ok := registeredChains[name]
	return chain, ok
}

// GetChainInfoByID returns the chain information for the given chain ID.
func GetChainInfoByID(id string) (ChainInfo, bool) {
	name, ok := chainIDs[id]
	if !ok {
		return ChainInfo{}, false
	}

	c, ok := registeredChains[name]
	return c, ok
}
