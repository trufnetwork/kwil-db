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
}

func init() {
	err := registerChain(
		ChainInfo{
			Name:                  "ethereum",
			ID:                    "1",
			RequiredConfirmations: 12,
		},
		ChainInfo{
			Name:                  "sepolia",
			ID:                    "11155111",
			RequiredConfirmations: 12,
		},
		ChainInfo{
			Name:                  "base-sepolia",
			ID:                    "84532",
			RequiredConfirmations: 12,
		},
		ChainInfo{
			Name:                  "hardhat",
			ID:                    "31337",
			RequiredConfirmations: 12,
		},
		ChainInfo{
			Name:                  "arbitrum_sepolia",
			ID:                    "421614",
			RequiredConfirmations: 2,
		},
		ChainInfo{
			Name:                  "arbitrum_one",
			ID:                    "42161",
			RequiredConfirmations: 4,
		},
	)
	if err != nil {
		panic(err)
	}
}

type Chain string

const (
	Ethereum        Chain = "ethereum"
	Sepolia         Chain = "sepolia"
	BaseSepolia     Chain = "base-sepolia"
	Hardhat         Chain = "hardhat"
	ArbitrumSepolia Chain = "arbitrum_sepolia"
	ArbitrumOne     Chain = "arbitrum_one"
)

func (c Chain) String() string {
	return string(c)
}

func (c Chain) Valid() error {
	switch c {
	case Ethereum, Sepolia, BaseSepolia, Hardhat, ArbitrumSepolia, ArbitrumOne:
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
