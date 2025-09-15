package specifications

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	ec "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
)

const (
	senderPk = "f1aa5a7966c3863ccde3047f6a1e266cdc0c76b399e256b8fede92b1c69e4f4e"
)

var (
	deployPrice = big.NewInt(10000000000000)
)

func SenderAccountID(t *testing.T) (*types.AccountID, error) {
	bts, err := hex.DecodeString(senderPk)
	require.NoError(t, err)

	privKey, err := crypto.UnmarshalSecp256k1PrivateKey(bts)
	require.NoError(t, err)

	signer := &auth.EthPersonalSigner{
		Key: *privKey,
	}

	acctID, err := types.GetSignerAccount(signer)
	require.NoError(t, err)

	return acctID, nil
}

func ApproveSpecification(ctx context.Context, t *testing.T, deployer DeployerDsl) {
	t.Logf("Executing approve specification")

	sender, err := ec.HexToECDSA(senderPk)
	require.NoError(t, err)

	senderAddr := ec.PubkeyToAddress(sender.PublicKey)

	// I approve 20 tokens
	err = deployer.Approve(ctx, sender, big.NewInt(20))
	require.NoError(t, err)

	// I expect the allowance to be 20
	allowance, err := deployer.Allowance(ctx, senderAddr)
	require.NoError(t, err)

	// I expect the allowance to be 20
	require.Equal(t, big.NewInt(20), allowance)

	// I approve 10 tokens
	err = deployer.Approve(ctx, sender, big.NewInt(10))
	require.NoError(t, err)

	// I expect the allowance to be 10
	allowance, err = deployer.Allowance(ctx, senderAddr)
	require.NoError(t, err)

	// I expect the allowance to be 10
	require.Equal(t, big.NewInt(10), allowance)

}

func DepositSuccessSpecification(ctx context.Context, t *testing.T, deployer DeployerDsl, accounts AccountsDsl, amount *big.Int) {
	t.Logf("Executing deposit specification")

	sender, err := ec.HexToECDSA(senderPk)
	require.NoError(t, err)
	senderAddr := ec.PubkeyToAddress(sender.PublicKey)

	acct, err := SenderAccountID(t)
	require.NoError(t, err)

	// I approve 10 tokens
	err = deployer.Approve(ctx, sender, amount)
	require.NoError(t, err)

	// I expect the allowance to be 10
	allowance, err := deployer.Allowance(ctx, senderAddr)
	require.NoError(t, err)
	require.Equal(t, amount, allowance)

	// Get the escrow balance
	preBalance, err := deployer.EscrowBalance(ctx, senderAddr)
	require.NoError(t, err)

	preUserBalance, err := accounts.GetAccount(ctx, acct, 0)
	require.NoError(t, err)

	// I deposit amount into the escrow
	err = deployer.Deposit(ctx, sender, amount)
	require.NoError(t, err)

	// Get the escrow balance
	balance, err := deployer.EscrowBalance(ctx, senderAddr)
	require.NoError(t, err)

	// I expect the balance to be equal to amount
	require.Equal(t, amount, big.NewInt(0).Sub(balance, preBalance))

	require.Eventually(t, func() bool {
		// Want postUserBalance to be equal to amount + preUserBalance
		postUserBalance, err := accounts.GetAccount(ctx, acct, 0)
		require.NoError(t, err)
		return postUserBalance.Balance.Cmp(big.NewInt(0).Add(preUserBalance.Balance, amount)) == 0
	}, 1*time.Minute, 5*time.Second)

	time.Sleep(2 * time.Second)
}

func DepositFailSpecification(ctx context.Context, t *testing.T, deployer DeployerDsl) {
	t.Logf("Executing deposit fail specification")

	sender, err := ec.HexToECDSA(senderPk)
	require.NoError(t, err)
	senderAddr := ec.PubkeyToAddress(sender.PublicKey)

	// I approve 10 tokens
	err = deployer.Approve(ctx, sender, big.NewInt(10))
	require.NoError(t, err)

	// I expect the allowance to be 10
	allowance, err := deployer.Allowance(ctx, senderAddr)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(10), allowance)

	// Get the escrow balance
	preBalance, err := deployer.EscrowBalance(ctx, senderAddr)
	require.NoError(t, err)

	// I deposit 20 tokens into the escrow
	err = deployer.Deposit(ctx, sender, big.NewInt(20))
	require.NoError(t, err)

	// Get the escrow balance
	postBalance, err := deployer.EscrowBalance(ctx, senderAddr)
	require.NoError(t, err)

	// 20 tokens should not be deposited, balance should be same as before
	require.Equal(t, preBalance, postBalance)
}

func DeployDbInsufficientFundsSpecification(ctx context.Context, t *testing.T, deployer DeployerDsl, executor ExecutorDsl) {
	t.Logf("Executing deploy db insufficient funds specification")

	sender, err := ec.HexToECDSA(senderPk)
	require.NoError(t, err)
	amount := big.NewInt(10)

	acct, err := SenderAccountID(t)
	require.NoError(t, err)

	// I approve 10 tokens
	err = deployer.Approve(ctx, sender, amount)
	require.NoError(t, err)

	preUserBalance, err := executor.GetAccount(ctx, acct, 0)
	require.NoError(t, err)

	// I deposit amount into the escrow
	err = deployer.Deposit(ctx, sender, amount)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		// Want postUserBalance to be equal to amount + preUserBalance
		postUserBalance, err := executor.GetAccount(ctx, acct, 0)
		require.NoError(t, err)
		return postUserBalance.Balance.Cmp(big.NewInt(0).Add(preUserBalance.Balance, amount)) == 0
	}, 90*time.Second, 5*time.Second)

	time.Sleep(2 * time.Second)

	// Should be able to deploy database
	CreateNamespaceSpecification(ctx, t, executor, true)

	time.Sleep(2 * time.Second) // ensure sync from other nodes

	// Check the user balance
	postDeployBalance, err := executor.GetAccount(ctx, acct, 0)
	require.NoError(t, err)

	// User balance reduced to 0, as it submitted a deploy request without sufficient funds
	require.Equal(t, big.NewInt(0), postDeployBalance.Balance)
}

func FundValidatorSpecification(ctx context.Context, t *testing.T, sender DeployerDsl, executor ExecutorDsl, receiverId crypto.PrivateKey) {
	t.Logf("Executing fund validator specification")

	senderPrivKey, err := ec.HexToECDSA(senderPk)
	require.NoError(t, err)
	acct, err := SenderAccountID(t)
	require.NoError(t, err)
	valAcct := &types.AccountID{
		Identifier: receiverId.Public().Bytes(),
		KeyType:    receiverId.Type(),
	}

	// Ensure that the fee for a transfer transaction is as expected.
	var transferPrice = big.NewInt(210_000)
	var transferAmt = big.NewInt(1000000000000000000)

	// Get funds to senders address
	// amount := transferPrice + transferAmt
	amt := big.NewInt(0).Add(transferPrice, transferAmt)
	err = sender.Approve(ctx, senderPrivKey, amt)
	require.NoError(t, err)

	acct1, err := executor.GetAccount(ctx, acct, 0)
	require.NoError(t, err)

	// deposit amount into escrow
	err = sender.Deposit(ctx, senderPrivKey, amt)
	require.NoError(t, err)

	// Ensure that the sender account is credited with the amount on kwild
	var bal2 *big.Int
	var acct2 *types.Account
	require.Eventually(t, func() bool {
		acct2, err = executor.GetAccount(ctx, acct, 0)
		bal2 = acct2.Balance
		require.NoError(t, err)
		return bal2.Cmp(big.NewInt(0).Add(acct1.Balance, amt)) == 0
	}, 90*time.Second, 5*time.Second) // if receiver voted, they'd get the refund here, at same time as dep

	time.Sleep(2 * time.Second) // wait for receiver to vote if they were too late for resoln

	preValBal, err := executor.GetAccount(ctx, valAcct, 0)
	require.NoError(t, err)

	// Transfer transferAmt to the Validator
	txHash, err := executor.Transfer(ctx, valAcct, transferAmt)
	require.NoError(t, err, "failed to send transfer tx")

	// I expect success
	expectTxSuccess(t, executor, ctx, txHash, defaultTxQueryTimeout)()

	time.Sleep(2 * time.Second) // it reports the old state very briefly, wait a sec

	// Check the validator account balance
	postBal, err := executor.GetAccount(ctx, valAcct, 0)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(0).Add(preValBal.Balance, transferAmt), postBal.Balance)

	// Check the sender account balance
	postBal, err = executor.GetAccount(ctx, acct, 0)
	require.NoError(t, err)
	expected := big.NewInt(0).Sub(bal2, big.NewInt(0).Add(transferAmt, transferPrice))
	require.Zero(t, expected.Cmp(postBal.Balance), "Incorrect balance in the sender account after the transfer")
}

func DeployDbSuccessSpecification(ctx context.Context, t *testing.T, chainDeployer DeployerDsl, accounts AccountsDsl, executor ExecuteQueryDsl) {
	t.Logf("Executing deposit deploy db success specification")

	sender, err := ec.HexToECDSA(senderPk)
	require.NoError(t, err)

	// signer, err := signerFromPrivateKeyStr(t)
	// require.NoError(t, err)

	acct, err := SenderAccountID(t)
	require.NoError(t, err)

	// I approve deployPrice+10 tokens
	amount := big.NewInt(0).Add(deployPrice, big.NewInt(10))
	err = chainDeployer.Approve(ctx, sender, amount)
	require.NoError(t, err)

	preBal, err := accounts.GetAccount(ctx, acct, 0)
	require.NoError(t, err)

	// I deposit amount into the escrow
	err = chainDeployer.Deposit(ctx, sender, amount)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		// Want postUserBalance to be equal to amount + preUserBalance
		postUserBalance, err := accounts.GetAccount(ctx, acct, 0)
		require.NoError(t, err)
		return postUserBalance.Balance.Cmp(big.NewInt(0).Add(preBal.Balance, amount)) == 0
	}, 90*time.Second, 5*time.Second)

	CreateNamespaceSpecification(ctx, t, executor, false)

	time.Sleep(2 * time.Second) // ensure sync from other nodes

	// Check the user balance
	postDeploy, err := accounts.GetAccount(ctx, acct, 0)
	require.NoError(t, err)

	var diff = big.NewInt(0)
	// assume deployPrice is spent
	require.Equal(t, diff.Sub(postDeploy.Balance, preBal.Balance), big.NewInt(10))
}

// Can only be run in Byzantine mode.
func DepositResolutionExpirySpecification(ctx context.Context, t *testing.T, deployer DeployerDsl, accounts AccountsDsl, privKeys []*crypto.Secp256k1PrivateKey) {
	t.Logf("Executing deposit resolution expiry specification")

	sender, err := ec.HexToECDSA(senderPk)
	require.NoError(t, err)
	senderAcct, err := SenderAccountID(t)
	require.NoError(t, err)

	// get user balance
	preUserBalance, err := accounts.GetAccount(ctx, senderAcct, 0)
	require.NoError(t, err)

	// node0, node1, node2, node3 account balances
	preNodeBalances := make([]*big.Int, len(privKeys))
	for i, pk := range privKeys {
		acctID := &types.AccountID{
			Identifier: pk.Public().Bytes(),
			KeyType:    pk.Type(),
		}
		acct, err := accounts.GetAccount(ctx, acctID, 0)
		require.NoError(t, err)
		preNodeBalances[i] = acct.Balance
	}

	// approve 10 tokens
	err = deployer.Approve(ctx, sender, big.NewInt(10))
	require.NoError(t, err)

	// I deposit amount into the escrow
	err = deployer.Deposit(ctx, sender, big.NewInt(10))
	require.NoError(t, err)

	// can we get the block number? The event should have expired by block height = 3/4
	// only 1 node hears and votes on this event.
	time.Sleep(30 * time.Second)

	// Check that the user balance is not updated
	postUserBalance, err := accounts.GetAccount(ctx, senderAcct, 0)
	require.NoError(t, err)
	require.Equal(t, 0, postUserBalance.Balance.Cmp(preUserBalance.Balance))

	postNodeBalances := make([]*big.Int, len(privKeys))
	for i, pk := range privKeys {
		acctID := &types.AccountID{
			Identifier: pk.Public().Bytes(),
			KeyType:    pk.Type(),
		}
		acct, err := accounts.GetAccount(ctx, acctID, 0)
		require.NoError(t, err)
		postNodeBalances[i] = acct.Balance
	}

	for i := range privKeys {
		if i == 0 { // Check that the node0 issued a vote and lost the tx fee
			require.Equal(t, 1, preNodeBalances[i].Cmp(postNodeBalances[i]))
		} else { // Check that the node1,2,3 didn't issue any Votes, thus no tx fee lost
			require.Equal(t, preNodeBalances[i], postNodeBalances[i])
		}
	}
}

func DepositResolutionExpiryRefundSpecification(ctx context.Context, t *testing.T, deployer DeployerDsl, accounts AccountsDsl, privKeys []*crypto.Secp256k1PrivateKey) {
	t.Logf("Executing deposit resolution expiry specification")

	sender, err := ec.HexToECDSA(senderPk)
	require.NoError(t, err)
	senderAcct, err := SenderAccountID(t)
	require.NoError(t, err)

	// get user balance
	preUserBalance, err := accounts.GetAccount(ctx, senderAcct, 0)
	require.NoError(t, err)

	// node0, node1, node2, node3 account balances
	preNodeBalances := make([]*big.Int, len(privKeys))
	for i, key := range privKeys {
		acctID := &types.AccountID{
			Identifier: key.Public().Bytes(),
			KeyType:    key.Type(),
		}
		acct, err := accounts.GetAccount(ctx, acctID, 0)
		require.NoError(t, err)
		preNodeBalances[i] = acct.Balance
	}

	// approve 10 tokens
	err = deployer.Approve(ctx, sender, big.NewInt(10))
	require.NoError(t, err)

	// I deposit amount into the escrow
	err = deployer.Deposit(ctx, sender, big.NewInt(10))
	require.NoError(t, err)

	// can we get the block number? The event should have expired by block height = 3/4
	time.Sleep(30 * time.Second)

	// Check that the user balance is not updated
	postUserBalance, err := accounts.GetAccount(ctx, senderAcct, 0)
	require.NoError(t, err)
	require.Equal(t, preUserBalance, postUserBalance)

	postNodeBalances := make([]*big.Int, len(privKeys))
	for i, key := range privKeys {
		acctID := &types.AccountID{
			Identifier: key.Public().Bytes(),
			KeyType:    key.Type(),
		}
		acct, err := accounts.GetAccount(ctx, acctID, 0)
		require.NoError(t, err)
		postNodeBalances[i] = acct.Balance
	}

	for i := range privKeys {
		// Check that the node0,1 issued a vote but got refunded as minthreshold for expiry refund met.
		// Check that the node2,3, didn't issue any Votes, thus no tx fee lost
		require.Equal(t, preNodeBalances[i], postNodeBalances[i])
	}
}

func EthDepositSpecification(ctx context.Context, t *testing.T, deployer DeployerDsl, accounts AccountsDsl, amt *big.Int, expectFailure bool) {
	sender, err := ec.HexToECDSA(senderPk)
	require.NoError(t, err)

	acctID, err := SenderAccountID(t)
	require.NoError(t, err)

	// get user balance
	acct1, err := accounts.GetAccount(ctx, acctID, 0)
	require.NoError(t, err)

	// approve 10 tokens
	err = deployer.Approve(ctx, sender, amt)
	require.NoError(t, err)

	// I deposit amount into the escrow
	err = deployer.Deposit(ctx, sender, amt)
	require.NoError(t, err)

	var bal2 *big.Int
	// Check that the user balance is updated

	if expectFailure {
		time.Sleep(5 * time.Second) // is this timer needed?
	}

	require.Eventually(t, func() bool {
		acct2, err := accounts.GetAccount(ctx, acctID, 0)
		require.NoError(t, err)
		bal2 = acct2.Balance
		addBal := big.NewInt(0).Add(acct1.Balance, amt)
		cmp := bal2.Cmp(addBal) // success: 0, failure < 0
		return (expectFailure && cmp < 0) || (!expectFailure && cmp == 0)
	}, 90*time.Second, 5*time.Second)
}
