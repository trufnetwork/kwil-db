package utils

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	smt "github.com/trufnetwork/openzeppelin-merkle-tree-go/standard_merkle_tree"
)

func Map[T1, T2 any](s []T1, f func(T1) T2) []T2 {
	r := make([]T2, len(s))
	for i, v := range s {
		r[i] = f(v)
	}
	return r
}

func TestMerkleTree(t *testing.T) {
	//networkOwner := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	user1 := "0x976EA74026E726554dB657fA54763abd0C3a0aa9"
	user2 := "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"
	user3 := "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"
	user4 := "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"
	user5 := "0xBcd4042DE499D14e55001CcbB24a551F3b954096"
	contract := "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"

	treeLeafs3 := `{"format":"standard-v1","leafEncoding":["address","uint256","address","bytes32"],"tree":["0xe36a471baa3e0c7b7d0cd9760fcb034a1e407e871ba2c7b5b0e893599726a1ce","0x103b40fa3ff3c0e485a3db71b76bc042d37ec423f8c8d7434158505860b4f4cf","0x82219da5ff9a5ea9e35efdbe1e5a3d01d82c86fc892d8f0d038697fec7ba8227","0x644f999664d65d1d2a3feefade54d643dc2b9696971e9070c36f0ec788e55f5b","0x231c2dd2ffc144d64393fc3272162eaacbb2ee3e998c2bd67f57dfc32b791315"],"values":[{"value":["0x976EA74026E726554dB657fA54763abd0C3a0aa9","100","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":3},{"value":["0x14dC79964da2C08b23698B3D3cc7Ca32193d9955","200","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":4},{"value":["0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f","100","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":2}]}`
	treeLeafs4 := `{"format":"standard-v1","leafEncoding":["address","uint256","address","bytes32"],"tree":["0x4b3a147975c7ab8323d6d0f9f53676da6aedda99cedec4cf65591523d4ef2375","0x7b13c67e72aef776185910769cd2eb4133917ed5b1f0c8f7213d8c8ee7e0b35d","0x103b40fa3ff3c0e485a3db71b76bc042d37ec423f8c8d7434158505860b4f4cf","0xb0104dd20dedc5a758a1445cbf0e20c3afbeb1868a2f239520f3defcc356dae4","0x82219da5ff9a5ea9e35efdbe1e5a3d01d82c86fc892d8f0d038697fec7ba8227","0x644f999664d65d1d2a3feefade54d643dc2b9696971e9070c36f0ec788e55f5b","0x231c2dd2ffc144d64393fc3272162eaacbb2ee3e998c2bd67f57dfc32b791315"],"values":[{"value":["0x976EA74026E726554dB657fA54763abd0C3a0aa9","100","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":5},{"value":["0x14dC79964da2C08b23698B3D3cc7Ca32193d9955","200","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":6},{"value":["0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f","100","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":4},{"value":["0xa0Ee7A142d267C1f36714E4a8F75612F20a79720","200","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":3}]}`
	treeLeafs5 := `{"format":"standard-v1","leafEncoding":["address","uint256","address","bytes32"],"tree":["0xc77e670bf878bdab7c70ad0709f8ad63db53e96ec3d12043ca93ea2b5991b76d","0x8d356f223c2b28319687d22a5c6818f2045837481a58c31047124f3c81bdeabf","0x7b13c67e72aef776185910769cd2eb4133917ed5b1f0c8f7213d8c8ee7e0b35d","0x103b40fa3ff3c0e485a3db71b76bc042d37ec423f8c8d7434158505860b4f4cf","0xfcc5bdb85d3a66a2eebd787677b2aedc61216ebe25a4b2feb16c0084b9254e4a","0xb0104dd20dedc5a758a1445cbf0e20c3afbeb1868a2f239520f3defcc356dae4","0x82219da5ff9a5ea9e35efdbe1e5a3d01d82c86fc892d8f0d038697fec7ba8227","0x644f999664d65d1d2a3feefade54d643dc2b9696971e9070c36f0ec788e55f5b","0x231c2dd2ffc144d64393fc3272162eaacbb2ee3e998c2bd67f57dfc32b791315"],"values":[{"value":["0x976EA74026E726554dB657fA54763abd0C3a0aa9","100","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":7},{"value":["0x14dC79964da2C08b23698B3D3cc7Ca32193d9955","200","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":8},{"value":["0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f","100","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":6},{"value":["0xa0Ee7A142d267C1f36714E4a8F75612F20a79720","200","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":5},{"value":["0xBcd4042DE499D14e55001CcbB24a551F3b954096","100","0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","0x1111111111111111111111111111111111111111111111111111111111111111"],"treeIndex":4}]}`

	kwilBlockHash := strings.Repeat("1", 64)
	kwilBlockHashBytes, _ := hex.DecodeString(kwilBlockHash)
	var b32Hash [32]byte
	copy(b32Hash[:], kwilBlockHashBytes)

	t.Run("genMerkleTree with 3 leafs", func(t *testing.T) {
		expectRoot := "e36a471baa3e0c7b7d0cd9760fcb034a1e407e871ba2c7b5b0e893599726a1ce"
		mt, root, err := GenRewardMerkleTree([]string{user1, user2, user3},
			Map([]string{"100", "200", "100"}, smt.SolNumber), contract, b32Hash)
		require.NoError(t, err)
		require.Equal(t, expectRoot, hex.EncodeToString(root))
		assert.JSONEq(t, treeLeafs3, string(mt))
		mtRoot, mtProof, mtLeaf, bh, amt, err := GetMTreeProof(mt, user2)
		require.NoError(t, err)
		require.Equal(t, expectRoot, hex.EncodeToString(mtRoot))
		require.Equal(t, big.NewInt(200), amt)
		require.EqualValues(t, kwilBlockHashBytes, bh)
		require.Len(t, mtProof, 2)
		assert.Equal(t, "0x644f999664d65d1d2a3feefade54d643dc2b9696971e9070c36f0ec788e55f5b", hexutil.Encode(mtProof[0]))
		assert.Equal(t, "0x82219da5ff9a5ea9e35efdbe1e5a3d01d82c86fc892d8f0d038697fec7ba8227", hexutil.Encode(mtProof[1]))
		assert.Equal(t, "0x231c2dd2ffc144d64393fc3272162eaacbb2ee3e998c2bd67f57dfc32b791315", hexutil.Encode(mtLeaf))
	})

	t.Run("genMerkleTree with 4 leafs", func(t *testing.T) {
		expectRoot := "4b3a147975c7ab8323d6d0f9f53676da6aedda99cedec4cf65591523d4ef2375"
		mt, root, err := GenRewardMerkleTree([]string{user1, user2, user3, user4},
			Map([]string{"100", "200", "100", "200"}, smt.SolNumber), contract, b32Hash)
		require.NoError(t, err)
		require.Equal(t, expectRoot, hex.EncodeToString(root))
		assert.JSONEq(t, treeLeafs4, string(mt))
		mtRoot, mtProof, mtLeaf, bh, amt, err := GetMTreeProof(mt, user2)
		require.NoError(t, err)
		require.Equal(t, expectRoot, hex.EncodeToString(mtRoot))
		require.Equal(t, big.NewInt(200), amt)
		require.EqualValues(t, kwilBlockHashBytes, bh)
		require.Len(t, mtProof, 2)
		assert.Equal(t, "0x644f999664d65d1d2a3feefade54d643dc2b9696971e9070c36f0ec788e55f5b", hexutil.Encode(mtProof[0]))
		assert.Equal(t, "0x7b13c67e72aef776185910769cd2eb4133917ed5b1f0c8f7213d8c8ee7e0b35d", hexutil.Encode(mtProof[1]))
		assert.Equal(t, "0x231c2dd2ffc144d64393fc3272162eaacbb2ee3e998c2bd67f57dfc32b791315", hexutil.Encode(mtLeaf))
	})

	t.Run("genMerkleTree with 5 leafs", func(t *testing.T) {
		expectRoot := "c77e670bf878bdab7c70ad0709f8ad63db53e96ec3d12043ca93ea2b5991b76d"
		mt, root, err := GenRewardMerkleTree([]string{user1, user2, user3, user4, user5},
			Map([]string{"100", "200", "100", "200", "100"}, smt.SolNumber), contract, b32Hash)
		require.NoError(t, err)
		require.Equal(t, expectRoot, hex.EncodeToString(root))
		assert.JSONEq(t, treeLeafs5, string(mt))
		mtRoot, mtProof, mtLeaf, bh, amt, err := GetMTreeProof(mt, user2)
		require.NoError(t, err)
		require.Equal(t, expectRoot, hex.EncodeToString(mtRoot))
		require.Equal(t, big.NewInt(200), amt)
		require.EqualValues(t, kwilBlockHashBytes, bh)
		require.Len(t, mtProof, 3)
		assert.Equal(t, "0x644f999664d65d1d2a3feefade54d643dc2b9696971e9070c36f0ec788e55f5b", hexutil.Encode(mtProof[0]))
		assert.Equal(t, "0xfcc5bdb85d3a66a2eebd787677b2aedc61216ebe25a4b2feb16c0084b9254e4a", hexutil.Encode(mtProof[1]))
		assert.Equal(t, "0x7b13c67e72aef776185910769cd2eb4133917ed5b1f0c8f7213d8c8ee7e0b35d", hexutil.Encode(mtProof[2]))
		assert.Equal(t, "0x231c2dd2ffc144d64393fc3272162eaacbb2ee3e998c2bd67f57dfc32b791315", hexutil.Encode(mtLeaf))
	})

	t.Run("genMerkleTree with 1 leaf", func(t *testing.T) {
		expectRoot := "644f999664d65d1d2a3feefade54d643dc2b9696971e9070c36f0ec788e55f5b"
		mt, root, err := GenRewardMerkleTree([]string{user1}, Map([]string{"100"}, smt.SolNumber), contract, b32Hash)
		require.NoError(t, err)
		require.Equal(t, expectRoot, hex.EncodeToString(root))
		mtRoot, mtProof, mtLeaf, bh, amt, err := GetMTreeProof(mt, user1)
		require.NoError(t, err)
		require.Equal(t, root, mtRoot)
		require.Equal(t, big.NewInt(100), amt)
		require.EqualValues(t, kwilBlockHashBytes, bh)
		require.Len(t, mtProof, 0)    // no proofs
		assert.Equal(t, root, mtLeaf) // the leaf is the root
	})
}
