package utils_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/utils"
)

func getSigner(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()

	// hardhat default 1st signer
	pk := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privateKey, err := crypto.HexToECDSA(pk)
	require.NoError(t, err)

	// Get the public key
	publicKey := privateKey.Public().(*ecdsa.PublicKey)

	// Get the Ethereum address from the public key
	address := crypto.PubkeyToAddress(*publicKey).Hex()

	require.Equal(t, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", address)
	return privateKey, publicKey
}

// TestSignHash mimic how safe-core-sdk do Safe.signHash
func TestSignHash(t *testing.T) {
	priKey, _ := getSigner(t)

	safeTxHashHex := "9572f8c1c5682c56eebc035e5e20d686c62354bf612400d32daf955766915293"
	safeTxHash, err := hex.DecodeString(safeTxHashHex)
	require.NoError(t, err)

	expected := "8e7091f38dff5127c08580adaa07ab0b3ab5326beaca194f8703da1a31efdf735a4bddb505ec92ee52714a5591db71c9af57c5144458c5cc56098054e26ad44f00"
	sig, err := crypto.Sign(accounts.TextHash(safeTxHash), priKey)
	require.NoError(t, err)
	assert.Equal(t, expected, hex.EncodeToString(sig))

	// THIS is what we want, with V adjusted
	gnosisAdjustedExpected := "8e7091f38dff5127c08580adaa07ab0b3ab5326beaca194f8703da1a31efdf735a4bddb505ec92ee52714a5591db71c9af57c5144458c5cc56098054e26ad44f1f"
	gnosisAdjustedSig, err := utils.EthGnosisSign(safeTxHash, priKey)
	require.NoError(t, err)
	assert.Equal(t, gnosisAdjustedExpected, hex.EncodeToString(gnosisAdjustedSig))
}

// TestGenSafeTx is the test confirm goimpl implements same signing algo as gnosis safe sdk.
// The test using the same parameters is in reward_contracts/test/gnosis_sdk.ts
func TestGenSafeTx(t *testing.T) {
	chainID := int64(11_155_111) // sepolia
	rewardAddress := "0x55EAC662C9D77cb537DBc9A57C0aDa90eB88132d"
	safeAddress := "0xbBeaaA74777B1dc14935f5b7E96Bb0ed6DBbD596"
	rootHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	nonce := int64(10)
	value := int64(0)
	expectedSafeTxHash := "8a4bdbe18b63f4be41193afabd32aab90547da08f5c477123284f961a1f66383"
	expectedSig := "05da477a982879422f291a445a1c4ff39bb43cfba4b1cacc3d5b157c254005112d61ff13e49e17f88557e59179e7b91b0adb09c202e3c156bbdedbfd0d6085fb1f"

	root, err := hex.DecodeString(rootHex)
	require.NoError(t, err)

	data, err := utils.GenPostRewardTxData(root, big.NewInt(21))
	require.NoError(t, err)
	fmt.Println("tx data:", hex.EncodeToString(data))

	priKey, pubKey := getSigner(t)
	sender := crypto.PubkeyToAddress(*pubKey)

	_, safeTxHash, err := utils.GenGnosisSafeTx(rewardAddress, safeAddress, value, data, chainID, nonce)
	require.NoError(t, err)
	assert.Equal(t, expectedSafeTxHash, hex.EncodeToString(safeTxHash))

	sig, err := utils.EthGnosisSign(safeTxHash, priKey)
	require.NoError(t, err)
	assert.Equal(t, expectedSig, hex.EncodeToString(sig))

	err = utils.EthGnosisVerify(sig, safeTxHash, sender.Bytes())
	require.NoError(t, err)
}
