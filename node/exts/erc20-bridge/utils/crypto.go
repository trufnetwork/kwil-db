package utils

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"slices"

	ethAccounts "github.com/ethereum/go-ethereum/accounts"
	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/trufnetwork/kwil-db/node/exts/erc20-bridge/abigen"
)

const GnosisSafeSigLength = ethCrypto.SignatureLength

func GenPostRewardTxData(root []byte, amount *big.Int) ([]byte, error) {
	// Convert the root to a common.Hash type (because it's bytes32 in Ethereum)
	//rootHash := ethCommon.HexToHash(root)
	rootHash := ethCommon.BytesToHash(root)

	rdABI, err := abigen.RewardDistributorMetaData.GetAbi()
	if err != nil {
		return nil, fmt.Errorf("failed to get ABI: %v", err)
	}

	// Encode the "postReward" function call with the given parameters
	data, err := rdABI.Pack("postReward", rootHash, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to encode function call: %v", err)
	}

	return data, nil
}

// GenGnosisSafeTx returns a safe tx, and the tx hash to be used to generate signature.
// More info: https://docs.safe.global/sdk/protocol-kit/guides/signatures/transactions
// Since Gnosis 1.3.0, ChainID is a part of the EIP-712 domain.
func GenGnosisSafeTx(to, safe string, value int64, data hexutil.Bytes, chainID int64,
	nonce int64) (*core.GnosisSafeTx, []byte, error) {
	gnosisSafeTx := core.GnosisSafeTx{
		To:        ethCommon.NewMixedcaseAddress(ethCommon.HexToAddress(to)),
		Value:     *math.NewDecimal256(value),
		Data:      &data,
		Operation: 0, // Call

		ChainId: math.NewHexOrDecimal256(chainID),
		Safe:    ethCommon.NewMixedcaseAddress(ethCommon.HexToAddress(safe)),

		// NOTE: we ignore all those parameters since we're generating off-chain
		// transaction.  The Poster will have similar parameters when post tx.
		//GasPrice:       *math.NewDecimal256(0),
		//GasToken:       ethCommon.HexToAddress(ZERO_ADDR),
		//RefundReceiver: ethCommon.HexToAddress(ZERO_ADDR),
		//BaseGas:        *ethCommon.Big0,
		//SafeTxGas:      big.Int{},
		//SafeTxGas:      *big.NewInt(*safeTxGas),

		Nonce: *big.NewInt(nonce),

		// not sure what's the purpose of this field
		InputExpHash: ethCommon.Hash{},

		// only available in output
		//Signature:  nil,
		//SafeTxHash: ethCommon.Hash{},
		//Sender:     ethCommon.NewMixedcaseAddress(ethCommon.HexToAddress(from)),
	}

	typedDataHash, _, err := apitypes.TypedDataAndHash(gnosisSafeTx.ToTypedData())
	if err != nil {
		return nil, nil, err
	}

	return &gnosisSafeTx, typedDataHash, nil
}

// EthZeppelinSign generate a OpenZeppelin compatible signature.
// The produced signature is 65-byte in the [R || S || V] format where V is 27 or 28.
func EthZeppelinSign(msg []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := ethCrypto.Sign(ethAccounts.TextHash(msg), key)
	if err != nil {
		return nil, err
	}

	sig[64] += 27
	return sig, nil
}

// EthGnosisSign generate a Gnosis(>1.3.0) signature, which is 65-byte in [R || S || V]
// format where V is 31 or 32. The message is the original message.
//
//		The Safe's expected V value for ECDSA signature is:
//		- 27 or 28, for eth_sign
//		- 31 or 32 if the message was signed with a EIP-191 prefix. Should be calculated as ECDSA V value + 4
//		Some wallets do that, some wallets don't, V > 30 is used by contracts to differentiate between
//		prefixed and non-prefixed messages. The only way to know if the message was signed with a
//		prefix is to check if the signer address is the same as the recovered address.
//
//		More info:
//		https://docs.safe.global/advanced/smart-account-signatures
//	 SDK: safe-core-sdk/packages/protocol-kit/src/utils/signatures/utils.ts `adjustVInSignature`
//
// Since we use EIP-191, the V should be 31(0x1f) or 32(0x20).
func EthGnosisSign(msg []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	return EthGnosisSignDigest(ethAccounts.TextHash(msg), key)
}

// EthGnosisVerify verify the given message to the Gnosis(>1.3.0) signature,
// which is 65-byte in [R || S || V] format and V is 31(0x1f) or 32(0x20).
func EthGnosisVerify(sig []byte, msg []byte, address []byte) error {
	digest := ethAccounts.TextHash(msg)

	return EthGnosisVerifyDigest(sig, digest, address)
}

// EthStandardSignDigest generates a standard Ethereum signature (V=27 or 28).
// This is compatible with OpenZeppelin's ECDSA.recover() which expects V to be 27 or 28.
func EthStandardSignDigest(digest []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := ethCrypto.Sign(digest, key)
	if err != nil {
		return nil, err
	}

	sig[len(sig)-1] += 27
	return sig, nil
}

func EthGnosisSignDigest(digest []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := ethCrypto.Sign(digest, key)
	if err != nil {
		return nil, err
	}

	sig[len(sig)-1] += 27 + 4
	return sig, nil
}

// IsGnosisStyleSignature reports whether the signature uses Gnosis Safe V (31 or 32).
// Used to distinguish custodial (Safe) votes from non-custodial (validator) votes when nonce=0.
func IsGnosisStyleSignature(sig []byte) bool {
	if len(sig) != ethCrypto.SignatureLength {
		return false
	}
	v := sig[ethCrypto.RecoveryIDOffset]
	return v == 31 || v == 32
}

// EthStandardVerifyDigest verifies an Ethereum signature (V=27/28 or 31/32).
// Accepts both standard personal_sign (V=27 or 28) and Gnosis Safe style (V=31 or 32).
// This avoids rejecting custodial Safe votes when Safe nonce is 0 (first tx), since
// the bridge signer produces Gnosis-style V for Safe tx hashes.
func EthStandardVerifyDigest(sig []byte, digest []byte, address []byte) error {
	// signature is 65 bytes, [R || S || V] format
	if len(sig) != ethCrypto.SignatureLength {
		return fmt.Errorf("invalid signature length: expected %d, received %d",
			ethCrypto.SignatureLength, len(sig))
	}

	v := sig[ethCrypto.RecoveryIDOffset]
	var recoveryID byte
	switch v {
	case 27, 28:
		recoveryID = v - 27
	case 31, 32:
		recoveryID = v - 31
	default:
		return fmt.Errorf("invalid signature V: expected 27, 28, 31, or 32, got %d", v)
	}

	sig = slices.Clone(sig)
	sig[ethCrypto.RecoveryIDOffset] = recoveryID

	pubkeyBytes, err := ethCrypto.Ecrecover(digest, sig)
	if err != nil {
		return fmt.Errorf("invalid signature: recover public key failed: %w", err)
	}

	addr := ethCommon.BytesToAddress(ethCrypto.Keccak256(pubkeyBytes[1:])[12:])
	if !bytes.Equal(addr.Bytes(), address) {
		return fmt.Errorf("invalid signature: expected address %x, received %x", address, addr.Bytes())
	}

	return nil
}

func EthGnosisVerifyDigest(sig []byte, digest []byte, address []byte) error {
	// signature is 65 bytes, [R || S || V] format
	if len(sig) != GnosisSafeSigLength {
		return fmt.Errorf("invalid signature length: expected %d, received %d",
			GnosisSafeSigLength, len(sig))
	}

	if sig[ethCrypto.RecoveryIDOffset] != 31 && sig[ethCrypto.RecoveryIDOffset] != 32 {
		return fmt.Errorf("invalid signature V")
	}

	sig = slices.Clone(sig)

	sig[ethCrypto.RecoveryIDOffset] -= 31

	pubkeyBytes, err := ethCrypto.Ecrecover(digest, sig)
	if err != nil {
		return fmt.Errorf("invalid signature: recover public key failed: %w", err)
	}

	addr := ethCommon.BytesToAddress(ethCrypto.Keccak256(pubkeyBytes[1:])[12:])
	if !bytes.Equal(addr.Bytes(), address) {
		return fmt.Errorf("invalid signature: expected address %x, received %x", address, addr.Bytes())
	}

	return nil
}

func EthGnosisRecoverSigner(sig []byte, digest []byte) (*ethCommon.Address, error) {
	// signature is 65 bytes, [R || S || V] format
	if len(sig) != GnosisSafeSigLength {
		return nil, fmt.Errorf("invalid signature length: expected %d, received %d",
			GnosisSafeSigLength, len(sig))
	}

	if sig[ethCrypto.RecoveryIDOffset] != 31 && sig[ethCrypto.RecoveryIDOffset] != 32 {
		return nil, fmt.Errorf("invalid signature V")
	}

	sig = slices.Clone(sig)
	sig[ethCrypto.RecoveryIDOffset] -= 31

	pubkeyBytes, err := ethCrypto.Ecrecover(digest, sig)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: recover public key failed: %w", err)
	}

	addr := ethCommon.BytesToAddress(ethCrypto.Keccak256(pubkeyBytes[1:])[12:])
	return &addr, nil
}
