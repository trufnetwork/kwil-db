package utils

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"

	smt "github.com/trufnetwork/openzeppelin-merkle-tree-go/standard_merkle_tree"
)

var (
	// MerkleLeafEncoding is (recipient, amount, contract_address, kwil_block_hash).
	// There is no point to add `kwil_chain_id` in the leaf encoding, as we cannot
	// enforce the uniqueness of it.
	MerkleLeafEncoding = []string{smt.SOL_ADDRESS, smt.SOL_UINT256, smt.SOL_ADDRESS, smt.SOL_BYTES32}
)

func GenRewardMerkleTree(users []string, amounts []*big.Int, contractAddress string, kwilBlockHash [32]byte) ([]byte, []byte, error) {
	if len(users) != len(amounts) {
		return nil, nil, fmt.Errorf("users and amounts length not equal")
	}

	values := [][]interface{}{}
	for i, v := range users {
		values = append(values,
			[]interface{}{
				smt.SolAddress(v),
				amounts[i],
				smt.SolAddress(contractAddress),
				kwilBlockHash,
			})
	}

	rewardTree, err := smt.Of(values, MerkleLeafEncoding)
	if err != nil {
		return nil, nil, fmt.Errorf("create reward tree error: %w", err)
	}

	dump, err := rewardTree.TreeMarshal()
	if err != nil {
		return nil, nil, fmt.Errorf("reward tree marshal error: %w", err)
	}

	return dump, rewardTree.GetRoot(), nil
}

// GetMTreeProof returns the leaf proof along with the leaf hash, amount.
func GetMTreeProof(mtreeJson []byte, addr string) (root []byte, proof [][]byte, leafHash []byte, blockHash []byte, amount *big.Int, err error) {
	t, err := smt.Load(mtreeJson)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("load mtree error: %w", err)
	}

	entries := t.Entries()
	for i, v := range entries {
		if v.Value[0] == smt.SolAddress(addr) {
			proof, err := t.GetProofWithIndex(i)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("get proof error: %w", err)
			}

			amt, ok := v.Value[1].(*big.Int)
			if !ok {
				return nil, nil, nil, nil, nil, fmt.Errorf("internal bug: get leaf amount error: %w", err)
			}

			blockHash, ok := v.Value[3].([32]byte)
			if !ok {
				return nil, nil, nil, nil, nil, fmt.Errorf("internal bug: get leaf block hash error: %w", err)
			}

			return t.GetRoot(), proof, v.Hash, blockHash[:], amt, nil
		}
	}

	return nil, nil, nil, nil, nil, fmt.Errorf("get proof error: %w", err)
}

func GetLeafAddresses(mtreeJson string) ([]string, error) {
	t, err := smt.Load([]byte(mtreeJson))
	if err != nil {
		return nil, fmt.Errorf("load mtree error: %w", err)
	}

	addresses := make([]string, len(t.Entries()))

	for i, v := range t.Entries() {
		addr, ok := v.Value[0].(common.Address)
		if !ok {
			return nil, fmt.Errorf("internal bug: get leaf address error: %w", err)
		}

		addresses[i] = addr.String()
	}

	return addresses, nil
}
