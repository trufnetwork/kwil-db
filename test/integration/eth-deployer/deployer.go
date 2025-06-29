package ethdeployer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ec "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/test/integration/eth-deployer/contracts"
)

type Deployer struct {
	endpoint string
	privKey  *ecdsa.PrivateKey
	chainID  *big.Int

	escrowAddr common.Address

	escrowInst *contracts.Escrow
	tokenInst  *contracts.ERC20

	ethClient *ethclient.Client

	mu sync.Mutex // what is this guarding? maybe remove
}

// NewDeployer("ws://localhost:8545","dd23ca549a97cb330b011aebb674730df8b14acaee42d211ab45692699ab8ba5")
func NewDeployer(endpoint string, secp256k1PrivKey *crypto.Secp256k1PrivateKey, chainID int64) (*Deployer, error) {
	ctx := context.Background()
	ethClient, err := ethclient.DialContext(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	privKey, err := ec.HexToECDSA(secp256k1PrivKey.Key.String())
	if err != nil {
		return nil, err
	}

	return &Deployer{
		endpoint:  endpoint,
		ethClient: ethClient,
		privKey:   privKey,
		chainID:   big.NewInt(chainID),
	}, nil
}

func (d *Deployer) Deploy() error {
	auth, err := bind.NewKeyedTransactorWithChainID(d.privKey, d.chainID)
	if err != nil {
		return err
	}

	auth.GasFeeCap = big.NewInt(1e12)
	auth.GasTipCap = big.NewInt(1e6) // avoid SuggestGasTipCap
	auth.GasLimit = 3_000_000

	tokenAddr, _, tokenInst, err := contracts.DeployERC20(auth, d.ethClient)
	if err != nil {
		return err
	}

	time.Sleep(5 * time.Second)

	auth, err = bind.NewKeyedTransactorWithChainID(d.privKey, d.chainID)
	if err != nil {
		return err
	}

	auth.GasFeeCap = big.NewInt(1e12)
	auth.GasTipCap = big.NewInt(1e6) // avoid SuggestGasTipCap
	auth.GasLimit = 3_000_000

	escrowAddr, _, escrowInst, err := contracts.DeployEscrow(auth, d.ethClient, tokenAddr)
	if err != nil {
		return err
	}

	d.escrowAddr = escrowAddr
	d.escrowInst = escrowInst
	d.tokenInst = tokenInst

	return nil
}

func (d *Deployer) EscrowAddress() string {
	return d.escrowAddr.String()
}

// Approves the escrow contract to spend the given amount of tokens from the senders account
func (d *Deployer) Approve(ctx context.Context, sender *ecdsa.PrivateKey, amount *big.Int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	auth, err := d.prepareTxAuth(ctx, sender)
	if err != nil {
		return err
	}

	_, err = d.tokenInst.Approve(auth, d.escrowAddr, amount)
	return err
}

// sender deposits given amount of tokens to the escrow contract
func (d *Deployer) Deposit(ctx context.Context, sender *ecdsa.PrivateKey, amount *big.Int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	auth, err := d.prepareTxAuth(ctx, sender)
	if err != nil {
		return err
	}

	tx, err := d.escrowInst.Deposit(auth, amount)
	if err != nil {
		return err
	}

	receipt, err := d.ethClient.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		return err
	}
	fmt.Printf("ETH tx %x, status code %d (1 means success)\n", receipt.TxHash, receipt.Status)

	return nil
}

// sender deposits given amount of tokens to the escrow contract
func (d *Deployer) DummyTx(ctx context.Context, sender *ecdsa.PrivateKey) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	auth, err := d.prepareTxAuth(ctx, sender)
	if err != nil {
		return err
	}

	_, err = d.escrowInst.Test(auth)
	return err
}

func (d *Deployer) VerifyDeposit(t *testing.T, ctx context.Context, sender *ecdsa.PrivateKey, amount *big.Int) {
	addr := ec.PubkeyToAddress(sender.PublicKey)

	preBalance, err := d.EscrowBalance(ctx, addr)
	require.NoError(t, err)

	err = d.Deposit(ctx, sender, amount)
	require.NoError(t, err)

	postBalance, err := d.EscrowBalance(ctx, addr)
	require.NoError(t, err)

	require.Equal(t, preBalance.Add(preBalance, amount), postBalance)
}

func (d *Deployer) prepareTxAuth(ctx context.Context, sender *ecdsa.PrivateKey) (*bind.TransactOpts, error) {
	addr := ec.PubkeyToAddress(sender.PublicKey)

	nonce, err := d.ethClient.PendingNonceAt(ctx, addr)
	if err != nil {
		return nil, err
	}

	auth, err := bind.NewKeyedTransactorWithChainID(sender, d.chainID)
	if err != nil {
		return nil, err
	}

	// suggest gas
	gasPrice, err := d.ethClient.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}

	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0) // in wei
	// auth.GasPrice = gasPrice
	auth.GasTipCap = big.NewInt(1e6) // avoid SuggestGasTipCap
	auth.GasFeeCap = gasPrice        // big.NewInt(1e16)
	auth.GasLimit = 3_000_000
	return auth, nil
}

// EscrowBalance returns the amount of funds deposited by a user to the escrow contract
func (d *Deployer) EscrowBalance(ctx context.Context, address common.Address) (*big.Int, error) {
	return d.escrowInst.Balance(&bind.CallOpts{Context: ctx}, address)
}

// UserBalance returns the user token balance
func (d *Deployer) UserBalance(ctx context.Context, address common.Address) (*big.Int, error) {
	return d.tokenInst.BalanceOf(&bind.CallOpts{Context: ctx}, address)
}

// Allowance returns the amount of tokens the owner has approved the escrow contract to spend
func (d *Deployer) Allowance(ctx context.Context, owner common.Address) (*big.Int, error) {
	return d.tokenInst.Allowance(&bind.CallOpts{Context: ctx}, owner, d.escrowAddr)
}

// Keep Mining
func (d *Deployer) KeepMining(ctx context.Context) error {
	// go routine to keep triggering dummy transactions
	senderPk := "43f149de89d64bf9a9099be19e1b1f7a4db784af8fa07caf6f08dc86ba65636b"
	sender, err := ec.HexToECDSA(senderPk)
	if err != nil {
		return err
	}

	go func() {
		defer d.ethClient.Close()
		for {
			d.DummyTx(ctx, sender)
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}
